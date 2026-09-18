//! ECDSA P-521 key types (FIPS 186-5 §6.2) and key-pair generation (Appendix A.2.1). Identical in
//! shape to [`crate::keys_p384`] -- see that module's docs for the general reasoning -- with
//! P-521's types and SEC 1 encoding widths substituted.
//!
//! # DRBG output length, and why the reduction is the wide form
//!
//! FIPS 186-5 Table A.2 gives `p521` a required and recommended DRBG output of 521 bits for key
//! generation: `n` is within `2^260` of `2^521`, so the reduction's bias is negligible with no
//! headroom. But Appendix A.3.1 -- the randomised per-message secret -- requires `N + t` bits with
//! `t >= 64` regardless, so both draws are `N + 71 = 592` bits (74 bytes, the byte-aligned width
//! at or above `585`; [`EXTRA_BITS_DRBG_OUTPUT_LEN`]). An earlier version drew the 66-byte
//! `SK_LEN` (528 bits, `t = 7`) for both, which met Table A.2 but not A.3.1.
//!
//! Even at 528 bits the reduction had to handle a value far wider than `n`: 66 bytes is 7 bits more
//! than `n`'s 521 (SEC 1 octets are byte-aligned and 521 is not a multiple of 8), so a raw draw
//! reinterpreted as a 9-limb integer can be as large as `2^528 - 1`, far past the `< 2(n-1)` a
//! single conditional subtraction of `n - 1` assumes, and one subtraction silently leaves most of
//! the value unreduced (a bug this module's own tests caught: `keygen`/`sign_randomized` produced
//! keys/signatures too broken to round-trip through sign+verify, despite every fixed-input KAT --
//! which never exercises a raw, unbounded DRBG value -- passing). [`reduce_wide_bits_mod_n_minus_1`]
//! is this module's own reduction, a single fold at bit 521 -- see its docs for why P-521 gets
//! neither the other curves' Barrett reduction nor the field's Solinas fold.

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

/// Requested output length, in bytes, from the DRBG for FIPS 186-5 Appendix A.2.1 key generation
/// and Appendix A.3.1 randomised per-message secret generation: the smallest whole number of bytes
/// holding `N + t` bits with `N = 521` and `t = 64`, i.e. `ceil(585 / 8) = 74` bytes (`t = 71`).
/// See the module docs.
pub(crate) const EXTRA_BITS_DRBG_OUTPUT_LEN: usize = 74;

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

/// `2^521 mod (n-1)`, the fold constant [`reduce_wide_bits_mod_n_minus_1`] uses: `n - 1` has
/// no special form, so this is a genuine ~259-bit value, computed in Python from SP 800-186
/// §3.2.1.5's `n`.
const TWO_POW_521_MOD_N_MINUS_1_LIMBS: [u64; 9] = [
    0x449048e16ec79bf8, 0xc44a36477663b851, 0x8033feb708f65a2f, 0xae79787c40d06994,
    0x0000000000000005, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000,
];

/// FIPS 186-5 Appendix A.4.1 steps 3-5 for P-521's `n`: reduces the big-endian bit string `bytes`
/// (up to 80 bytes; the DRBG draw is 74) modulo `n-1` and adds `1`, landing in `[1, n-1]`.
///
/// P-521's `n - 1` is `2^521`-ish while the limb width is `2^576`, so neither the Solinas fold
/// the field uses nor `bouncycastle_ec::barrett` (which wants a modulus filling its top limb)
/// applies as written. What does is a single fold at bit 521: split `x = hi * 2^521 + lo`, so
/// `x = hi * (2^521 mod (n-1)) + lo (mod n-1)`. With `x < 2^640`, `hi < 2^119` and the fold
/// constant is below `2^259`, so `hi * C + lo < 2^521 + 2^378 < 2 (n-1)`, and one conditional
/// subtraction finishes the reduction. Every step is branch-free in `x`: a fixed-width
/// multiplication, an addition and a masked select. Verified (not checked in) in Python against
/// arbitrary-precision `%` over 20,000 pseudorandom inputs at widths up to 80 bytes plus the
/// all-ones extremes.
pub(crate) fn reduce_wide_bits_mod_n_minus_1(bytes: &[u8]) -> P521Scalar {
    assert!(
        bytes.len() <= 80,
        "reduce_wide_bits_mod_n_minus_1 given {} bytes, more than 80",
        bytes.len()
    );
    let x = bouncycastle_ec::barrett::limbs_from_be_bytes::<10>(bytes);

    // lo = x mod 2^521: the low 8 limbs plus the low 9 bits of limb 8.
    let mut lo = [0u64; 9];
    lo[..8].copy_from_slice(&x[..8]);
    lo[8] = x[8] & 0x1ff;
    // hi = x >> 521: bits 9..63 of limb 8 and all of limb 9, at most 119 bits.
    let mut hi = [0u64; 9];
    hi[0] = (x[8] >> 9) | (x[9] << 55);
    hi[1] = x[9] >> 9;

    let product =
        bouncycastle_ec::montgomery::widening_mul::<9, 18>(&hi, &TWO_POW_521_MOD_N_MINUS_1_LIMBS);
    debug_assert!(product[9..].iter().all(|&limb| limb == 0), "hi * C must fit in 9 limbs");
    let mut folded = [0u64; 9];
    folded.copy_from_slice(&product[..9]);
    let (sum, carry) = nat::add(&folded, &lo);
    debug_assert_eq!(carry, 0, "the fold's sum must fit in 9 limbs");

    let (reduced, borrow) = nat::sub(&sum, &N_MINUS_1_LIMBS);
    let mut acc = [0u64; 9];
    ct::conditional_select(Condition::<u64>::from_lsb(borrow), &sum, &reduced, &mut acc);

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
    let mut extra_bits = Secret::<[u8; EXTRA_BITS_DRBG_OUTPUT_LEN]>::new();
    rng.next_bytes_out(&mut *extra_bits).map_err(SignatureError::RNGError)?;
    let d = reduce_wide_bits_mod_n_minus_1(&*extra_bits);

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
    fn known_answer_all_ff_at_the_drbg_width() {
        // 74 bytes of 0xff: the width keygen and sign_randomized actually draw. Expected value is
        // Python's ((2^592 - 1) % (n - 1)) + 1.
        let input = [0xffu8; EXTRA_BITS_DRBG_OUTPUT_LEN];
        let expected: [u64; 9] = [
            0x0000000000000000, 0x482470b763cdfc00, 0x251b23bb31dc28a2, 0x19ff5b847b2d17e2,
            0x3cbc3e206834ca40, 0x00000000000002d7, 0x0000000000000000, 0x0000000000000000,
            0x0000000000000000,
        ];
        assert_eq!(reduce_wide_bits_mod_n_minus_1(&input), P521Scalar::from_limbs(expected));
    }

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
    fn known_answer_at_the_n_minus_1_boundary() {
        // n - 1 is the modulus of Appendix A.4.1 step 4 itself, so it reduces to 0 and step 5
        // makes it 1; n - 2 is the largest residue and comes out as n - 1, the top of the
        // output interval.
        let n_minus_1 = p521_sec1::be_bytes_from_limbs(&N_MINUS_1_LIMBS);
        let mut expected_one = [0u64; 9];
        expected_one[0] = 1;
        assert_eq!(
            reduce_wide_bits_mod_n_minus_1(&n_minus_1),
            P521Scalar::from_limbs(expected_one)
        );

        let mut n_minus_2 = n_minus_1;
        n_minus_2[SK_LEN - 1] -= 1; // n - 1 is even (n is prime), so this never borrows
        assert_eq!(
            reduce_wide_bits_mod_n_minus_1(&n_minus_2),
            P521Scalar::from_limbs(N_MINUS_1_LIMBS)
        );
    }

    #[test]
    fn known_answer_all_zero_yields_one() {
        let input = [0u8; SK_LEN];
        let mut expected = [0u64; 9];
        expected[0] = 1;
        assert_eq!(reduce_wide_bits_mod_n_minus_1(&input), P521Scalar::from_limbs(expected));
    }
}
