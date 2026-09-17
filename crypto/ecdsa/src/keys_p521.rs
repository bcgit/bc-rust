//! ECDSA P-521 key types (FIPS 186-5 §6.2) and key-pair generation (Appendix A.2.1). Identical in
//! shape to [`crate::keys_p384`] -- see that module's docs for the general reasoning -- with
//! P-521's types and SEC 1 encoding widths substituted.
//!
//! # Reduction needs `extra_bits`'s wide form after all
//!
//! Unlike P-384 (whose 48-byte `SK_LEN` matches its 6-limb/384-bit native width exactly), P-521's
//! 66-byte `SK_LEN` is **528** bits -- 7 more than `n`'s 521, since SEC 1 octets are byte-aligned
//! and 521 is not a multiple of 8. A single conditional subtraction of `n - 1` (as
//! [`crate::keys_p384::reduce_mod_n_minus_1_plus_one`] uses) assumes the input is already within a
//! factor of 2 of `n`; raw DRBG bytes reinterpreted as a 9-limb integer can be as large as `2^528 -
//! 1`, far past that, and one subtraction silently leaves most of the value unreduced (a bug this
//! module's own tests caught: `keygen`/`sign_randomized` produced keys/signatures too broken to
//! round-trip through sign+verify, despite every fixed-input KAT -- which never exercises a raw,
//! unbounded DRBG value -- passing). So key generation and the randomised per-message secret both
//! go through [`crate::extra_bits`]'s bit-by-bit Horner reduction instead, the same machinery
//! P-256 already needs for the analogous reason (there, because its DRBG output is deliberately
//! wider than `n`'s width for bias-reduction headroom; here, because byte-alignment alone already
//! makes it wider). [`reduce_wide_bits_mod_n_minus_1`] is this module's own copy, sized for
//! P-521's 9-limb width.

use crate::keys_common::DerivePublicKey;
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{RNG, SignaturePrivateKey, SignaturePublicKey};
use bouncycastle_ec::nat;
use bouncycastle_ec::p521::P521FieldElement;
use bouncycastle_ec::p521_comb::comb_multiply_base_point;
use bouncycastle_ec::p521_scalar::{N_LIMBS, P521Scalar};
use bouncycastle_ec::p521_sec1;
use bouncycastle_rng::DefaultRNG;
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;
use bouncycastle_utils::secret::Secret;
use core::fmt;
use core::fmt::{Debug, Display, Formatter};

/// Encoded length of a P-521 private key: SEC 1 §2.3.7 integer-to-octet-string of `d`, 66 bytes.
pub const SK_LEN: usize = 66;

/// Encoded length of a P-521 public key in the canonical uncompressed form (SEC 1 §2.3.3,
/// `04 || X || Y`); [`ECDSAP521PublicKey::from_bytes`] also accepts the 67-byte compressed form.
pub const PK_LEN: usize = 133;

/// `n - 1`, little-endian `u64` limbs. `N_LIMBS[0]` is odd (`n` is prime), so the subtraction
/// never borrows out of the low limb.
const N_MINUS_1_LIMBS: [u64; 9] = [
    N_LIMBS[0] - 1,
    N_LIMBS[1],
    N_LIMBS[2],
    N_LIMBS[3],
    N_LIMBS[4],
    N_LIMBS[5],
    N_LIMBS[6],
    N_LIMBS[7],
    N_LIMBS[8],
];

/// `2^576 mod (n-1)` (this module's accumulator is 9 limbs = 576 bits) -- the correction
/// [`reduce_wide_bits_mod_n_minus_1`] adds back in when doubling the running remainder carries out
/// of the top limb. See [`crate::extra_bits`]'s identical-in-kind constant for the derivation.
const TWO_POW_576_MOD_N_MINUS_1_LIMBS: [u64; 9] = [
    0xfc00000000000000, 0x28a2482470b763cd, 0x17e2251b23bb31dc, 0xca4019ff5b847b2d,
    0x02d73cbc3e206834, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000,
];

/// FIPS 186-5 Appendix A.4.1 steps 3-5 for P-521's `n`: reduces the big-endian bit string `bytes`
/// (any length) modulo `n-1` and adds `1`, landing in `[1, n-1]`. See [`crate::extra_bits`]'s
/// identical algorithm (there, over 4 limbs for P-256) for the full derivation and constant-time
/// reasoning; verified (not checked in) against Python's arbitrary-precision `%` the same way.
pub(crate) fn reduce_wide_bits_mod_n_minus_1(bytes: &[u8]) -> P521Scalar {
    let mut acc = [0u64; 9];
    for &byte in bytes {
        for bit_idx in (0..8).rev() {
            let bit = (byte >> bit_idx) & 1;
            let (doubled, carry) = nat::add(&acc, &acc);
            let mut with_bit = doubled;
            with_bit[0] |= bit as u64;
            let (with_carry_correction, _) = nat::add(&with_bit, &TWO_POW_576_MOD_N_MINUS_1_LIMBS);
            let mut candidate = [0u64; 9];
            ct::conditional_select(
                Condition::<u64>::from_lsb(carry),
                &with_carry_correction,
                &with_bit,
                &mut candidate,
            );
            let (reduced, borrow) = nat::sub(&candidate, &N_MINUS_1_LIMBS);
            ct::conditional_select(
                Condition::<u64>::from_lsb(borrow),
                &candidate,
                &reduced,
                &mut acc,
            );
        }
    }
    let (plus_one, _) = nat::add(&acc, &[1, 0, 0, 0, 0, 0, 0, 0, 0]);
    P521Scalar::from_limbs(plus_one)
}

/// An ECDSA P-521 private key: FIPS 186-5 §6.2's `d`, `d` in `[1, n-1]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ECDSAP521PrivateKey(P521Scalar);

impl ECDSAP521PrivateKey {
    /// The wrapped scalar, for this crate's own sign implementation to compute with.
    pub(crate) fn scalar(&self) -> &P521Scalar {
        &self.0
    }
}

impl DerivePublicKey<ECDSAP521PublicKey, PK_LEN> for ECDSAP521PrivateKey {
    fn derive_pk(&self) -> ECDSAP521PublicKey {
        let q = comb_multiply_base_point(&self.0);
        // d is in [1, n-1] by construction (every ECDSAP521PrivateKey is built that way; see
        // from_bytes and keygen_from_rng) and G has prime order n, so [d]G is never the identity.
        let (x, y) = q.to_affine().expect("[d]G is never infinity for d in [1, n-1]");
        ECDSAP521PublicKey { x, y }
    }
}

impl SignaturePrivateKey<SK_LEN> for ECDSAP521PrivateKey {
    fn encode(&self) -> [u8; SK_LEN] {
        self.0.to_be_bytes()
    }

    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        out.fill(0);
        *out = self.0.to_be_bytes();
        SK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let array: [u8; SK_LEN] = bytes.try_into().map_err(|_| {
            SignatureError::DecodingError("ECDSA P-521 private key must be 66 bytes")
        })?;
        // FIPS 186-5 §6.2: d is in [1, n-1], checked on the raw big-endian value *before* any
        // reduction. `P521Scalar::from_be_bytes` reduces mod n, so checking afterwards would accept
        // an out-of-range encoding as a different, perfectly valid key: `d = n + 1` would load as
        // `d = 1`, giving one key two encodings and silently treating malformed input as well-
        // formed. Comparing against the fixed public values 0 and n is a one-time validation of
        // caller-supplied bytes at load time, not a computation performed repeatedly on a secret
        // intermediate value, so branching on it leaks nothing beyond what the caller already knows
        // from having supplied these exact bytes.
        let limbs = p521_sec1::limbs_from_be_bytes(&array);
        let (_, borrow) = nat::sub(&limbs, &N_LIMBS);
        if limbs == [0; 9] || borrow != 1 {
            return Err(SignatureError::DecodingError(
                "ECDSA P-521 private key must be in [1, n-1]",
            ));
        }
        Ok(Self(P521Scalar::from_limbs(limbs)))
    }
}

/// An ECDSA P-521 public key: FIPS 186-5 §6.2's `Q = [d]G`, stored as affine coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ECDSAP521PublicKey {
    pub(crate) x: P521FieldElement,
    pub(crate) y: P521FieldElement,
}

impl SignaturePublicKey<PK_LEN> for ECDSAP521PublicKey {
    fn encode(&self) -> [u8; PK_LEN] {
        p521_sec1::encode_uncompressed(&self.x, &self.y)
    }

    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        out.fill(0);
        *out = self.encode();
        PK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let (x, y) = p521_sec1::decode(bytes).ok_or(SignatureError::DecodingError(
            "invalid or out-of-range SEC 1 P-521 point encoding",
        ))?;
        Ok(Self { x, y })
    }
}

impl Display for ECDSAP521PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "ECDSAP521PublicKey {{ {:x?} }}", self.encode())
    }
}

/// FIPS 186-5 Appendix A.2.1: generates an ECDSA P-521 key pair, sourcing the DRBG output from the
/// library's default OS-backed RNG.
pub fn keygen() -> Result<(ECDSAP521PublicKey, ECDSAP521PrivateKey), SignatureError> {
    keygen_from_rng(&mut DefaultRNG::default())
}

/// As [`keygen`], but sources the DRBG output from the caller-provided RNG.
pub fn keygen_from_rng(
    rng: &mut dyn RNG,
) -> Result<(ECDSAP521PublicKey, ECDSAP521PrivateKey), SignatureError> {
    // Raw DRBG output, reduced below into the private key / per-message secret: held in
    // `Secret` so it is scrubbed when this function returns rather than left on the stack.
    let mut bytes = Secret::<[u8; SK_LEN]>::new();
    rng.next_bytes_out(&mut *bytes).map_err(SignatureError::RNGError)?;
    let d = reduce_wide_bits_mod_n_minus_1(&*bytes);

    let q = comb_multiply_base_point(&d);
    // d is in [1, n-1] by construction and G has prime order n (cofactor h = 1), so [d]G is never
    // the identity for any valid d -- see crate::keys::keygen_from_rng's identical argument.
    let (x, y) = q.to_affine().expect("[d]G is never infinity for d in [1, n-1]");

    Ok((ECDSAP521PublicKey { x, y }, ECDSAP521PrivateKey(d)))
}

// `reduce_wide_bits_mod_n_minus_1` is private and, through `keygen`/`sign_randomized`, only ever
// reached on genuinely random DRBG output, so there is no fixed public-API input to pin a KAT
// against -- the QUALITY_AND_STYLE.md private-function exception applies. Expected values
// computed independently in Python via `(int.from_bytes(bytes, 'big') % (n - 1)) + 1`, not from
// this module's own reduction code; this is exactly what would have caught the wide-reduction bug
// this module's docs describe, had it existed here from the start.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answer_all_ff() {
        let input = [0xffu8; SK_LEN];
        let expected: [u64; 9] = [
            0x482470b763cdfc00, 0x251b23bb31dc28a2, 0x19ff5b847b2d17e2, 0x3cbc3e206834ca40,
            0x00000000000002d7, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
            0x0000000000000000,
        ];
        assert_eq!(reduce_wide_bits_mod_n_minus_1(&input), P521Scalar::from_limbs(expected));
    }

    #[test]
    fn known_answer_repeating_pattern() {
        let mut input = [0u8; SK_LEN];
        for (i, b) in input.iter_mut().enumerate().take(64) {
            *b = [0x01, 0x02, 0x03, 0x04][i % 4];
        }
        input[64] = 0x05;
        input[65] = 0x06;
        let expected: [u64; 9] = [
            0x0304010203040507, 0x0304010203040102, 0x0304010203040102, 0x0304010203040102,
            0x0304010203040102, 0x0304010203040102, 0x0304010203040102, 0x0304010203040102,
            0x0000000000000102,
        ];
        assert_eq!(reduce_wide_bits_mod_n_minus_1(&input), P521Scalar::from_limbs(expected));
    }

    #[test]
    fn known_answer_all_zero_yields_one() {
        let input = [0u8; SK_LEN];
        let mut expected = [0u64; 9];
        expected[0] = 1;
        assert_eq!(reduce_wide_bits_mod_n_minus_1(&input), P521Scalar::from_limbs(expected));
    }
}
