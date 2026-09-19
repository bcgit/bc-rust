//! ECDSA P-384 key types (FIPS 186-5 §6.2) and key-pair generation (Appendix A.2.1). Identical in
//! shape to [`crate::keys`] -- see that module's docs for the full reasoning -- with P-384's
//! types and SEC 1 encoding widths substituted.
//!
//! # DRBG output length
//!
//! FIPS 186-5 Table A.2 gives `p384` a required and recommended DRBG output of 384 bits for key
//! generation: `n` is close enough to `2^384` that the reduction's bias is negligible with no
//! headroom at all. But Appendix A.3.1 -- the randomised per-message secret -- requires `N + t`
//! bits with `t >= 64` regardless, so both draws are 448 bits (56 bytes) and go through
//! [`crate::extra_bits_p384`]'s wide reduction; see that module's docs for the reasoning and for
//! why key generation uses the same draw.

use crate::extra_bits_p384::reduce_wide_bits_mod_n_minus_1;
use crate::keys_common::DerivePublicKey;
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{RNG, SignaturePrivateKey, SignaturePublicKey};
use bouncycastle_ec::nat;
use bouncycastle_ec::p384::P384FieldElement;
use bouncycastle_ec::p384_comb::comb_multiply_base_point;
use bouncycastle_ec::p384_scalar::{N_LIMBS, P384Scalar};
use bouncycastle_ec::p384_sec1;
use bouncycastle_rng::DefaultRNG;
use bouncycastle_utils::secret::Secret;
use core::fmt;
use core::fmt::{Debug, Display, Formatter};

/// Encoded length of a P-384 private key: SEC 1 §2.3.7 integer-to-octet-string of `d`, 48 bytes.
pub const SK_LEN: usize = 48;

/// Encoded length of a P-384 public key in the canonical uncompressed form (SEC 1 §2.3.3,
/// `04 || X || Y`); [`ECDSAP384PublicKey::from_bytes`] also accepts the 49-byte compressed form.
pub const PK_LEN: usize = 97;

/// Requested output length, in bytes, from the DRBG for FIPS 186-5 Appendix A.2.1 key generation
/// and Appendix A.3.1 randomised per-message secret generation: `N + t` with `N = 384` and
/// `t = 64`, the minimum A.3.1 step 2 accepts, giving 448 bits. See the module docs.
pub(crate) const EXTRA_BITS_DRBG_OUTPUT_LEN: usize = 56;

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
        // FIPS 186-5 §6.2: d is in [1, n-1], checked on the raw big-endian value *before* any
        // reduction. `P384Scalar::from_be_bytes` reduces mod n, so checking afterwards would accept
        // an out-of-range encoding as a different, perfectly valid key: `d = n + 1` would load as
        // `d = 1`, giving one key two encodings and silently treating malformed input as well-
        // formed. Comparing against the fixed public values 0 and n is a one-time validation of
        // caller-supplied bytes at load time, not a computation performed repeatedly on a secret
        // intermediate value, so branching on it leaks nothing beyond what the caller already knows
        // from having supplied these exact bytes.
        let limbs = p384_sec1::limbs_from_be_bytes(&array);
        let (_, borrow) = nat::sub(&limbs, &N_LIMBS);
        if limbs == [0; 6] || borrow != 1 {
            return Err(SignatureError::DecodingError(
                "ECDSA P-384 private key must be in [1, n-1]",
            ));
        }
        Ok(Self(P384Scalar::from_limbs(limbs)))
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
    // Raw DRBG output, reduced below into the private key / per-message secret: held in
    // `Secret` so it is scrubbed when this function returns rather than left on the stack.
    let mut extra_bits = Secret::<[u8; EXTRA_BITS_DRBG_OUTPUT_LEN]>::new();
    rng.next_bytes_out(&mut *extra_bits).map_err(SignatureError::RNGError)?;
    let d = reduce_wide_bits_mod_n_minus_1(&*extra_bits);

    let q = comb_multiply_base_point(&d);
    // d is in [1, n-1] by construction and G has prime order n (cofactor h = 1), so [d]G is never
    // the identity for any valid d -- see crate::keys::keygen_from_rng's identical argument.
    let (x, y) = q.to_affine().expect("[d]G is never infinity for d in [1, n-1]");

    Ok((ECDSAP384PublicKey { x, y }, ECDSAP384PrivateKey(d)))
}
