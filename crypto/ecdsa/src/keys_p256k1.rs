//! ECDSA secp256k1 key types (FIPS 186-5 §6.2) and key-pair generation (Appendix A.2.1). Identical
//! in shape to [`crate::keys`] -- see that module's docs for the full reasoning -- with
//! secp256k1's types and SEC 1 encoding widths substituted.
//!
//! # DRBG output length
//!
//! secp256k1's `n` is within `2^129` of `2^256`, so Appendix A.4.1's bias bound already holds at
//! 256 bits and key generation would need no headroom. But Appendix A.3.1 -- the randomised
//! per-message secret -- requires `N + t` bits with `t >= 64` regardless, so both draws are 320
//! bits (40 bytes) and go through [`crate::extra_bits_p256k1`]'s wide reduction; see that
//! module's docs for the reasoning and for why key generation uses the same draw.

use crate::extra_bits_p256k1::reduce_wide_bits_mod_n_minus_1;
use crate::keys_common::DerivePublicKey;
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{RNG, SignaturePrivateKey, SignaturePublicKey};
use bouncycastle_ec::nat;
use bouncycastle_ec::p256k1::P256K1FieldElement;
use bouncycastle_ec::p256k1_comb::comb_multiply_base_point;
use bouncycastle_ec::p256k1_scalar::{N_LIMBS, P256K1Scalar};
use bouncycastle_ec::p256k1_sec1;
use bouncycastle_rng::DefaultRNG;
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

/// Requested output length, in bytes, from the DRBG for FIPS 186-5 Appendix A.2.1 key generation
/// and Appendix A.3.1 randomised per-message secret generation: `N + t` with `N = 256` and
/// `t = 64`, the minimum A.3.1 step 2 accepts, giving 320 bits. See the module docs.
pub(crate) const EXTRA_BITS_DRBG_OUTPUT_LEN: usize = 40;

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
    let mut extra_bits = Secret::<[u8; EXTRA_BITS_DRBG_OUTPUT_LEN]>::new();
    rng.next_bytes_out(&mut *extra_bits).map_err(SignatureError::RNGError)?;
    let d = reduce_wide_bits_mod_n_minus_1(&*extra_bits);

    let q = comb_multiply_base_point(&d);
    // d is in [1, n-1] by construction and G has prime order n (cofactor h = 1), so [d]G is never
    // the identity for any valid d -- see crate::keys::keygen_from_rng's identical argument.
    let (x, y) = q.to_affine().expect("[d]G is never infinity for d in [1, n-1]");

    Ok((ECDSASecp256K1PublicKey { x, y }, ECDSASecp256K1PrivateKey(d)))
}
