//! ECDSA P-384 key types (FIPS 186-5 §6.2) and key-pair generation (Appendix A.2.1). Identical in
//! shape to [`crate::keys`] -- see that module's docs for the full reasoning -- with P-384's
//! types and SEC 1 encoding widths substituted.
//!
//! # DRBG output length
//!
//! Unlike P-256 (which needs 96 bits of headroom beyond its 256-bit order for A.4.1's bias bound
//! -- SP 800-186 Table A.2's "Recommended" column gives 352), P-384's Table A.2 entry gives
//! **384** for both the "Required" and "Recommended" columns: no headroom beyond `n`'s own 384-bit
//! width is needed for the bias to be negligible. So key generation and the randomised
//! per-message secret both request exactly 48 bytes and reduce with a single conditional
//! subtraction of `n - 1` (mirroring [`bouncycastle_ec::p384_scalar`]'s own `reduce_once` shape),
//! rather than [`crate::extra_bits`]'s bit-by-bit wide reduction -- that machinery exists
//! specifically for the P-256 case where the DRBG output is wider than the scalar's native limb
//! width, which doesn't arise here.

use crate::keys_common::DerivePublicKey;
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{RNG, SignaturePrivateKey, SignaturePublicKey};
use bouncycastle_ec::nat;
use bouncycastle_ec::p384::P384FieldElement;
use bouncycastle_ec::p384_comb::comb_multiply_base_point;
use bouncycastle_ec::p384_scalar::{N_LIMBS, P384Scalar};
use bouncycastle_ec::p384_sec1;
use bouncycastle_rng::DefaultRNG;
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;
use core::fmt;
use core::fmt::{Debug, Display, Formatter};

/// Encoded length of a P-384 private key: SEC 1 §2.3.7 integer-to-octet-string of `d`, 48 bytes.
pub const SK_LEN: usize = 48;

/// Encoded length of a P-384 public key in the canonical uncompressed form (SEC 1 §2.3.3,
/// `04 || X || Y`); [`ECDSAP384PublicKey::from_bytes`] also accepts the 49-byte compressed form.
pub const PK_LEN: usize = 97;

/// `n - 1`, little-endian `u64` limbs. `N_LIMBS[0]` is odd (`n` is prime), so the subtraction
/// never borrows out of the low limb.
const N_MINUS_1_LIMBS: [u64; 6] =
    [N_LIMBS[0] - 1, N_LIMBS[1], N_LIMBS[2], N_LIMBS[3], N_LIMBS[4], N_LIMBS[5]];

/// FIPS 186-5 Appendix A.4.1 steps 3-5 for P-384's `n`, given exactly-`n`-width input (see the
/// module docs for why no wider DRBG output is needed here): `x mod (n-1)`, then `x + 1`.
pub(crate) fn reduce_mod_n_minus_1_plus_one(limbs: [u64; 6]) -> P384Scalar {
    let (diff, borrow) = nat::sub(&limbs, &N_MINUS_1_LIMBS);
    let mut reduced = [0u64; 6];
    ct::conditional_select(Condition::<u64>::from_lsb(borrow), &limbs, &diff, &mut reduced);
    let (plus_one, _) = nat::add(&reduced, &[1, 0, 0, 0, 0, 0]);
    P384Scalar::from_limbs(plus_one)
}

/// An ECDSA P-384 private key: FIPS 186-5 §6.2's `d`, `d` in `[1, n-1]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ECDSAP384PrivateKey(P384Scalar);

impl ECDSAP384PrivateKey {
    /// The wrapped scalar, for this crate's own sign implementation to compute with.
    pub(crate) fn scalar(&self) -> &P384Scalar {
        &self.0
    }
}

impl DerivePublicKey<ECDSAP384PublicKey, PK_LEN> for ECDSAP384PrivateKey {
    fn derive_pk(&self) -> ECDSAP384PublicKey {
        let q = comb_multiply_base_point(&self.0);
        // d is in [1, n-1] by construction (every ECDSAP384PrivateKey is built that way; see
        // from_bytes and keygen_from_rng) and G has prime order n, so [d]G is never the identity.
        let (x, y) = q.to_affine().expect("[d]G is never infinity for d in [1, n-1]");
        ECDSAP384PublicKey { x, y }
    }
}

impl SignaturePrivateKey<SK_LEN> for ECDSAP384PrivateKey {
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
            SignatureError::DecodingError("ECDSA P-384 private key must be 48 bytes")
        })?;
        let scalar = P384Scalar::from_be_bytes(&array);
        if scalar == P384Scalar::from_limbs([0, 0, 0, 0, 0, 0]) {
            return Err(SignatureError::DecodingError(
                "ECDSA P-384 private key must be in [1, n-1], got 0",
            ));
        }
        Ok(Self(scalar))
    }
}

/// An ECDSA P-384 public key: FIPS 186-5 §6.2's `Q = [d]G`, stored as affine coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ECDSAP384PublicKey {
    pub(crate) x: P384FieldElement,
    pub(crate) y: P384FieldElement,
}

impl SignaturePublicKey<PK_LEN> for ECDSAP384PublicKey {
    fn encode(&self) -> [u8; PK_LEN] {
        p384_sec1::encode_uncompressed(&self.x, &self.y)
    }

    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        out.fill(0);
        *out = self.encode();
        PK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let (x, y) = p384_sec1::decode(bytes).ok_or(SignatureError::DecodingError(
            "invalid or out-of-range SEC 1 P-384 point encoding",
        ))?;
        Ok(Self { x, y })
    }
}

impl Display for ECDSAP384PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "ECDSAP384PublicKey {{ {:x?} }}", self.encode())
    }
}

/// FIPS 186-5 Appendix A.2.1: generates an ECDSA P-384 key pair, sourcing the DRBG output from the
/// library's default OS-backed RNG.
pub fn keygen() -> Result<(ECDSAP384PublicKey, ECDSAP384PrivateKey), SignatureError> {
    keygen_from_rng(&mut DefaultRNG::default())
}

/// As [`keygen`], but sources the DRBG output from the caller-provided RNG.
pub fn keygen_from_rng(
    rng: &mut dyn RNG,
) -> Result<(ECDSAP384PublicKey, ECDSAP384PrivateKey), SignatureError> {
    let mut bytes = [0u8; SK_LEN];
    rng.next_bytes_out(&mut bytes).map_err(SignatureError::RNGError)?;
    let d = reduce_mod_n_minus_1_plus_one(p384_sec1::limbs_from_be_bytes(&bytes));

    let q = comb_multiply_base_point(&d);
    // d is in [1, n-1] by construction and G has prime order n (cofactor h = 1), so [d]G is never
    // the identity for any valid d -- see crate::keys::keygen_from_rng's identical argument.
    let (x, y) = q.to_affine().expect("[d]G is never infinity for d in [1, n-1]");

    Ok((ECDSAP384PublicKey { x, y }, ECDSAP384PrivateKey(d)))
}

// `reduce_mod_n_minus_1_plus_one` is `pub(crate)`, not exposed outside the crate, and its numeric
// correctness (specifically, that `N_MINUS_1_LIMBS` really is `n - 1` and not `n` or `n + 1`) isn't
// independently pinned by `keygen`/`sign_randomized`'s own tests, which check validity (a produced
// key/signature works), not exact values. A KAT here, computed independently in Python
// (`(x % (n-1)) + 1`), closes that gap -- the QUALITY_AND_STYLE.md private-function exception
// applies (`pub(crate)`, unreachable from an external integration test).
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reduce_mod_n_minus_1_plus_one_matches_kats() {
        let x: [u64; 6] = [
            0xe7531273ac31909b, 0xa4afd95a574e5ceb, 0x2e841ff3542270c0, 0x128fd0fd853321fe,
            0x7e4ef8d29646bba8, 0x0c479ba61fe9eb49,
        ];
        let expected = P384Scalar::from_limbs([
            0xe7531273ac31909c, 0xa4afd95a574e5ceb, 0x2e841ff3542270c0, 0x128fd0fd853321fe,
            0x7e4ef8d29646bba8, 0x0c479ba61fe9eb49,
        ]);
        assert_eq!(reduce_mod_n_minus_1_plus_one(x), expected);

        // x = n - 1: (n-1) mod (n-1) = 0, +1 = 1.
        let n_minus_1 = N_MINUS_1_LIMBS;
        assert_eq!(
            reduce_mod_n_minus_1_plus_one(n_minus_1),
            P384Scalar::from_limbs([1, 0, 0, 0, 0, 0])
        );

        // x = n: n mod (n-1) = 1, +1 = 2.
        assert_eq!(
            reduce_mod_n_minus_1_plus_one(N_LIMBS),
            P384Scalar::from_limbs([2, 0, 0, 0, 0, 0])
        );
    }
}
