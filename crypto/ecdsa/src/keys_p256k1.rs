//! ECDSA secp256k1 key types (FIPS 186-5 §6.2) and key-pair generation (Appendix A.2.1). Identical
//! in shape to [`crate::keys`] -- see that module's docs for the full reasoning -- with
//! secp256k1's types and SEC 1 encoding widths substituted.
//!
//! # DRBG output length
//!
//! Unlike P-256 (which needs 96 bits of headroom beyond its 256-bit order for Appendix A.4.1's
//! bias bound -- FIPS 186-5 Table A.2's "Recommended" column gives 352), secp256k1 isn't a NIST
//! curve so there is no Table A.2 entry for it; applying A.4.1's own general criterion
//! directly (step 2's `2ρ(1-ρ)(n-1) > ε·N` check, `ε = 2⁻⁶⁴`) to secp256k1's `n` shows it holds
//! already at `l = 256` (no headroom at all needed): `n` is `2²⁵⁶ − 2^128`-ish, close enough to
//! `2²⁵⁶` that `N mod (n-1)` is tiny, making the bias negligible -- computed directly in Python,
//! not assumed by analogy to any NIST curve's table entry. So key generation and the randomised
//! per-message secret both request exactly 32 bytes and reduce with a single conditional
//! subtraction of `n - 1` (mirroring [`bouncycastle_ec::p256k1_scalar`]'s own `reduce_once` shape,
//! the same pattern [`crate::keys_p384`] uses for the same reason), rather than
//! [`crate::extra_bits`]'s bit-by-bit wide reduction.

use crate::keys_common::DerivePublicKey;
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{RNG, SignaturePrivateKey, SignaturePublicKey};
use bouncycastle_ec::nat;
use bouncycastle_ec::p256k1::P256K1FieldElement;
use bouncycastle_ec::p256k1_comb::comb_multiply_base_point;
use bouncycastle_ec::p256k1_scalar::{N_LIMBS, P256K1Scalar};
use bouncycastle_ec::p256k1_sec1;
use bouncycastle_rng::DefaultRNG;
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;
use bouncycastle_utils::secret::Secret;
use core::fmt;
use core::fmt::{Debug, Display, Formatter};

/// Encoded length of a secp256k1 private key: SEC 1 §2.3.7 integer-to-octet-string of `d`, 32
/// bytes.
pub const SK_LEN: usize = 32;

/// Encoded length of a secp256k1 public key in the canonical uncompressed form (SEC 1 §2.3.3,
/// `04 || X || Y`); [`ECDSASecp256K1PublicKey::from_bytes`] also accepts the 33-byte compressed
/// form.
pub const PK_LEN: usize = 65;

/// `n - 1`, little-endian `u64` limbs. `N_LIMBS[0]` is odd (`n` is prime), so the subtraction
/// never borrows out of the low limb.
const N_MINUS_1_LIMBS: [u64; 4] = [N_LIMBS[0] - 1, N_LIMBS[1], N_LIMBS[2], N_LIMBS[3]];

/// FIPS 186-5 Appendix A.4.1 steps 3-5 for secp256k1's `n`, given exactly-`n`-width input (see the
/// module docs for why no wider DRBG output is needed here): `x mod (n-1)`, then `x + 1`.
pub(crate) fn reduce_mod_n_minus_1_plus_one(limbs: [u64; 4]) -> P256K1Scalar {
    let (diff, borrow) = nat::sub(&limbs, &N_MINUS_1_LIMBS);
    let mut reduced = [0u64; 4];
    ct::conditional_select(Condition::<u64>::from_lsb(borrow), &limbs, &diff, &mut reduced);
    let (plus_one, _) = nat::add(&reduced, &[1, 0, 0, 0]);
    P256K1Scalar::from_limbs(plus_one)
}

/// An ECDSA secp256k1 private key: FIPS 186-5 §6.2's `d`, `d` in `[1, n-1]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ECDSASecp256K1PrivateKey(P256K1Scalar);

impl ECDSASecp256K1PrivateKey {
    /// The wrapped scalar, for this crate's own sign implementation to compute with.
    pub(crate) fn scalar(&self) -> &P256K1Scalar {
        &self.0
    }
}

impl DerivePublicKey<ECDSASecp256K1PublicKey, PK_LEN> for ECDSASecp256K1PrivateKey {
    fn derive_pk(&self) -> ECDSASecp256K1PublicKey {
        let q = comb_multiply_base_point(&self.0);
        // d is in [1, n-1] by construction (every ECDSASecp256K1PrivateKey is built that way; see
        // from_bytes and keygen_from_rng) and G has prime order n, so [d]G is never the identity.
        let (x, y) = q.to_affine().expect("[d]G is never infinity for d in [1, n-1]");
        ECDSASecp256K1PublicKey { x, y }
    }
}

impl SignaturePrivateKey<SK_LEN> for ECDSASecp256K1PrivateKey {
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
            SignatureError::DecodingError("ECDSA secp256k1 private key must be 32 bytes")
        })?;
        // FIPS 186-5 §6.2: d is in [1, n-1], checked on the raw big-endian value *before* any
        // reduction. `P256K1Scalar::from_be_bytes` reduces mod n, so checking afterwards would
        // accept an out-of-range encoding as a different, perfectly valid key: `d = n + 1` would
        // load as `d = 1`, giving one key two encodings and silently treating malformed input as
        // well-formed. Comparing against the fixed public values 0 and n is a one-time validation
        // of caller-supplied bytes at load time, not a computation performed repeatedly on a secret
        // intermediate value, so branching on it leaks nothing beyond what the caller already knows
        // from having supplied these exact bytes.
        let limbs = p256k1_sec1::limbs_from_be_bytes(&array);
        let (_, borrow) = nat::sub(&limbs, &N_LIMBS);
        if limbs == [0; 4] || borrow != 1 {
            return Err(SignatureError::DecodingError(
                "ECDSA secp256k1 private key must be in [1, n-1]",
            ));
        }
        Ok(Self(P256K1Scalar::from_limbs(limbs)))
    }
}

/// An ECDSA secp256k1 public key: FIPS 186-5 §6.2's `Q = [d]G`, stored as affine coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ECDSASecp256K1PublicKey {
    pub(crate) x: P256K1FieldElement,
    pub(crate) y: P256K1FieldElement,
}

impl SignaturePublicKey<PK_LEN> for ECDSASecp256K1PublicKey {
    fn encode(&self) -> [u8; PK_LEN] {
        p256k1_sec1::encode_uncompressed(&self.x, &self.y)
    }

    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        out.fill(0);
        *out = self.encode();
        PK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let (x, y) = p256k1_sec1::decode(bytes).ok_or(SignatureError::DecodingError(
            "invalid or out-of-range SEC 1 secp256k1 point encoding",
        ))?;
        Ok(Self { x, y })
    }
}

impl Display for ECDSASecp256K1PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "ECDSASecp256K1PublicKey {{ {:x?} }}", self.encode())
    }
}

/// FIPS 186-5 Appendix A.2.1: generates an ECDSA secp256k1 key pair, sourcing the DRBG output from
/// the library's default OS-backed RNG.
pub fn keygen() -> Result<(ECDSASecp256K1PublicKey, ECDSASecp256K1PrivateKey), SignatureError> {
    keygen_from_rng(&mut DefaultRNG::default())
}

/// As [`keygen`], but sources the DRBG output from the caller-provided RNG.
pub fn keygen_from_rng(
    rng: &mut dyn RNG,
) -> Result<(ECDSASecp256K1PublicKey, ECDSASecp256K1PrivateKey), SignatureError> {
    // Raw DRBG output, reduced below into the private key / per-message secret: held in
    // `Secret` so it is scrubbed when this function returns rather than left on the stack.
    let mut bytes = Secret::<[u8; SK_LEN]>::new();
    rng.next_bytes_out(&mut *bytes).map_err(SignatureError::RNGError)?;
    let d = reduce_mod_n_minus_1_plus_one(p256k1_sec1::limbs_from_be_bytes(&bytes));

    let q = comb_multiply_base_point(&d);
    // d is in [1, n-1] by construction and G has prime order n (cofactor h = 1), so [d]G is never
    // the identity for any valid d -- see crate::keys::keygen_from_rng's identical argument.
    let (x, y) = q.to_affine().expect("[d]G is never infinity for d in [1, n-1]");

    Ok((ECDSASecp256K1PublicKey { x, y }, ECDSASecp256K1PrivateKey(d)))
}

// `reduce_mod_n_minus_1_plus_one` is `pub(crate)`, not exposed outside the crate, and its numeric
// correctness (specifically, that `N_MINUS_1_LIMBS` really is `n - 1` and not `n` or `n + 1`) isn't
// independently pinned by `keygen`/`sign_randomized`'s own tests, which check validity (a produced
// key/signature works), not exact values -- see `crate::keys_p384`'s identical gap and fix. A KAT
// here, computed independently in Python, closes it.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reduce_mod_n_minus_1_plus_one_matches_kats() {
        let x: [u64; 4] =
            [0x310022084564664a, 0xb0525afa51a26b8a, 0x0b049ab71dbafb06, 0x72d50095457ed571];
        let expected = P256K1Scalar::from_limbs([
            0x310022084564664b, 0xb0525afa51a26b8a, 0x0b049ab71dbafb06, 0x72d50095457ed571,
        ]);
        assert_eq!(reduce_mod_n_minus_1_plus_one(x), expected);

        // x = n - 1: (n-1) mod (n-1) = 0, +1 = 1.
        assert_eq!(
            reduce_mod_n_minus_1_plus_one(N_MINUS_1_LIMBS),
            P256K1Scalar::from_limbs([1, 0, 0, 0])
        );

        // x = n - 2: the largest residue mod (n-1), so +1 gives n - 1, the top of the output
        // interval.
        let mut n_minus_2 = N_MINUS_1_LIMBS;
        n_minus_2[0] -= 1; // N_LIMBS[0] is odd, so n - 1 is even and this never borrows
        assert_eq!(
            reduce_mod_n_minus_1_plus_one(n_minus_2),
            P256K1Scalar::from_limbs(N_MINUS_1_LIMBS)
        );

        // x = n: n mod (n-1) = 1, +1 = 2.
        assert_eq!(reduce_mod_n_minus_1_plus_one(N_LIMBS), P256K1Scalar::from_limbs([2, 0, 0, 0]));
    }
}
