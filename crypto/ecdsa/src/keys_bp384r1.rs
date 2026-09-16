//! ECDSA brainpoolP384r1 key types (FIPS 186-5 §6.2) and key-pair generation (Appendix A.2.1).
//! Identical in shape to [`crate::keys`] -- see that module's docs for the full reasoning -- with
//! brainpoolP384r1's types and SEC 1 encoding widths substituted, and [`crate::extra_bits_bp384r1`]
//! in place of [`crate::extra_bits`] for the wide-DRBG-output reduction this curve's `n` needs (see
//! that module's docs for why).

use crate::extra_bits_bp384r1::reduce_wide_bits_mod_n_minus_1;
use crate::keys_common::DerivePublicKey;
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{RNG, SignaturePrivateKey, SignaturePublicKey};
use bouncycastle_ec::bp384r1::Bp384r1FieldElement;
use bouncycastle_ec::bp384r1_comb::comb_multiply_base_point;
use bouncycastle_ec::bp384r1_scalar::Bp384r1Scalar;
use bouncycastle_ec::bp384r1_sec1;
use bouncycastle_rng::DefaultRNG;
use core::fmt;
use core::fmt::{Debug, Display, Formatter};

/// Encoded length of a brainpoolP384r1 private key: SEC 1 §2.3.7 integer-to-octet-string of `d`,
/// 48 bytes.
pub const SK_LEN: usize = 48;

/// Encoded length of a brainpoolP384r1 public key in the canonical uncompressed form (SEC 1
/// §2.3.3, `04 || X || Y`); [`ECDSABp384r1PublicKey::from_bytes`] also accepts the 49-byte
/// compressed form.
pub const PK_LEN: usize = 97;

/// Requested output length, in bytes, from the DRBG for FIPS 186-5 Appendix A.2.1 key generation
/// and Appendix A.3.1 randomised per-message secret generation: `448` bits (56 bytes) -- derived
/// directly from Appendix A.4.1's own bias-bound check for brainpoolP384r1's `n` (see
/// [`crate::extra_bits_bp384r1`]'s docs), not copied from any other curve's table entry.
pub(crate) const EXTRA_BITS_DRBG_OUTPUT_LEN: usize = 56;

/// An ECDSA brainpoolP384r1 private key: FIPS 186-5 §6.2's `d`, `d` in `[1, n-1]`, held in
/// [`bouncycastle_utils::secret::Secret`] via [`Bp384r1Scalar`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ECDSABp384r1PrivateKey(Bp384r1Scalar);

impl ECDSABp384r1PrivateKey {
    /// The wrapped scalar, for this crate's own sign implementation to compute with.
    pub(crate) fn scalar(&self) -> &Bp384r1Scalar {
        &self.0
    }
}

impl DerivePublicKey<ECDSABp384r1PublicKey, PK_LEN> for ECDSABp384r1PrivateKey {
    fn derive_pk(&self) -> ECDSABp384r1PublicKey {
        let q = comb_multiply_base_point(&self.0);
        // d is in [1, n-1] by construction (every ECDSABp384r1PrivateKey is built that way; see
        // from_bytes and keygen_from_rng) and G has prime order n, so [d]G is never the identity.
        let (x, y) = q.to_affine().expect("[d]G is never infinity for d in [1, n-1]");
        ECDSABp384r1PublicKey { x, y }
    }
}

impl SignaturePrivateKey<SK_LEN> for ECDSABp384r1PrivateKey {
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
            SignatureError::DecodingError("ECDSA brainpoolP384r1 private key must be 48 bytes")
        })?;
        let scalar = Bp384r1Scalar::from_be_bytes(&array);
        // FIPS 186-5 §6.2: d is in [1, n-1]. Checking equality with the fixed public value 0 is a
        // one-time validation of caller-supplied bytes at load time, not a computation performed
        // repeatedly on a secret intermediate value, so branching on it here leaks nothing beyond
        // what the caller already knows from having supplied these exact bytes.
        if scalar == Bp384r1Scalar::from_limbs([0, 0, 0, 0, 0, 0]) {
            return Err(SignatureError::DecodingError(
                "ECDSA brainpoolP384r1 private key must be in [1, n-1], got 0",
            ));
        }
        Ok(Self(scalar))
    }
}

/// An ECDSA brainpoolP384r1 public key: FIPS 186-5 §6.2's `Q = [d]G`, stored as affine
/// coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ECDSABp384r1PublicKey {
    pub(crate) x: Bp384r1FieldElement,
    pub(crate) y: Bp384r1FieldElement,
}

impl SignaturePublicKey<PK_LEN> for ECDSABp384r1PublicKey {
    fn encode(&self) -> [u8; PK_LEN] {
        bp384r1_sec1::encode_uncompressed(&self.x, &self.y)
    }

    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        out.fill(0);
        *out = self.encode();
        PK_LEN
    }

    /// Accepts both SEC 1 §2.3.3 encodings (49-byte compressed, 97-byte uncompressed), fully
    /// validated per [`bp384r1_sec1::decode`]'s docs (partial validation is full validation here:
    /// RFC 5639 §3.4 gives brainpoolP384r1 cofactor `h = 1`).
    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let (x, y) = bp384r1_sec1::decode(bytes).ok_or(SignatureError::DecodingError(
            "invalid or out-of-range SEC 1 brainpoolP384r1 point encoding",
        ))?;
        Ok(Self { x, y })
    }
}

impl Display for ECDSABp384r1PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "ECDSABp384r1PublicKey {{ {:x?} }}", self.encode())
    }
}

/// FIPS 186-5 Appendix A.2.1: generates an ECDSA brainpoolP384r1 key pair, sourcing the DRBG
/// output from the library's default OS-backed RNG.
pub fn keygen() -> Result<(ECDSABp384r1PublicKey, ECDSABp384r1PrivateKey), SignatureError> {
    keygen_from_rng(&mut DefaultRNG::default())
}

/// As [`keygen`], but sources the DRBG output from the caller-provided RNG.
pub fn keygen_from_rng(
    rng: &mut dyn RNG,
) -> Result<(ECDSABp384r1PublicKey, ECDSABp384r1PrivateKey), SignatureError> {
    let mut extra_bits = [0u8; EXTRA_BITS_DRBG_OUTPUT_LEN];
    rng.next_bytes_out(&mut extra_bits).map_err(SignatureError::RNGError)?;
    let d = reduce_wide_bits_mod_n_minus_1(&extra_bits);

    let q = comb_multiply_base_point(&d);
    // d is in [1, n-1] by construction (see reduce_wide_bits_mod_n_minus_1) and G has prime order
    // n (RFC 5639 §3.4's cofactor h = 1), so [d]G is never the identity: this holds for every
    // valid d, so branching on it here leaks nothing about which d was drawn.
    let (x, y) = q.to_affine().expect("[d]G is never infinity for d in [1, n-1]");

    Ok((ECDSABp384r1PublicKey { x, y }, ECDSABp384r1PrivateKey(d)))
}
