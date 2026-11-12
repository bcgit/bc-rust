//! ECDSA brainpoolP256r1 key types (FIPS 186-5 §6.2) and key-pair generation (Appendix A.2.1).
//! Identical in shape to [`crate::keys_p256`] -- see that module's docs for the full reasoning --
//! with brainpoolP256r1's types and SEC 1 encoding widths substituted, and
//! [`bouncycastle_ec::hazmat::bp256r1_extra_bits`] in place of
//! [`bouncycastle_ec::hazmat::p256_extra_bits`] for the wide-DRBG-output reduction this curve's `n`
//! needs (see that module's docs for why).

use crate::keys_common::{DerivePublicKey, SignatureKeyPair};
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{RNG, SignaturePrivateKey, SignaturePublicKey};
use bouncycastle_ec::Bp256r1;
use bouncycastle_ec::hazmat::bp256r1::Bp256r1FieldElement;
use bouncycastle_ec::hazmat::bp256r1_keygen;
use bouncycastle_ec::hazmat::bp256r1_scalar::{Bp256r1Scalar, N_LIMBS};
use bouncycastle_ec::hazmat::bp256r1_sec1;
use bouncycastle_ec::nat;
use core::fmt;
use core::fmt::{Debug, Display, Formatter};

/// Encoded length of a brainpoolP256r1 private key: SEC 1 §2.3.7 integer-to-octet-string of `d`,
/// 32 bytes.
pub const SK_LEN: usize = 32;

/// Encoded length of a brainpoolP256r1 public key in the canonical uncompressed form (SEC 1
/// §2.3.3, `04 || X || Y`); [`ECDSABp256r1PublicKey::from_bytes`] also accepts the 33-byte
/// compressed form.
pub const PK_LEN: usize = 65;

/// Requested output length, in bytes, from the DRBG for FIPS 186-5 Appendix A.2.1 key generation
/// and Appendix A.3.1 randomised per-message secret generation: `320` bits (40 bytes) -- derived
/// directly from Appendix A.4.1's own bias-bound check for brainpoolP256r1's `n` (see
/// [`bouncycastle_ec::hazmat::bp256r1_extra_bits`]'s docs), not copied from any other curve's table
/// entry.
pub(crate) const EXTRA_BITS_DRBG_OUTPUT_LEN: usize = 40;

/// An ECDSA brainpoolP256r1 private key: FIPS 186-5 §6.2's `d`, `d` in `[1, n-1]`, held in
/// [`bouncycastle_utils::secret::Secret`] via [`Bp256r1Scalar`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ECDSABp256r1PrivateKey(Bp256r1Scalar);

impl ECDSABp256r1PrivateKey {
    /// The wrapped scalar, for this crate's own sign implementation to compute with.
    pub(crate) fn scalar(&self) -> &Bp256r1Scalar {
        &self.0
    }
}

impl DerivePublicKey<ECDSABp256r1PublicKey, PK_LEN> for ECDSABp256r1PrivateKey {
    fn derive_pk(&self) -> ECDSABp256r1PublicKey {
        let (x, y) = bp256r1_keygen::public_point(&self.0);
        ECDSABp256r1PublicKey { x, y }
    }
}

impl SignaturePrivateKey<SK_LEN> for ECDSABp256r1PrivateKey {
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
            SignatureError::DecodingError("ECDSA brainpoolP256r1 private key must be 32 bytes")
        })?;
        // FIPS 186-5 §6.2: d is in [1, n-1], checked on the raw big-endian value *before* any
        // reduction. `Bp256r1Scalar::from_be_bytes` reduces mod n, so checking afterwards would
        // accept an out-of-range encoding as a different, perfectly valid key: `d = n + 1` would
        // load as `d = 1`, giving one key two encodings and silently treating malformed input as
        // well-formed. Comparing against the fixed public values 0 and n is a one-time validation
        // of caller-supplied bytes at load time, not a computation performed repeatedly on a secret
        // intermediate value, so branching on it leaks nothing beyond what the caller already knows
        // from having supplied these exact bytes.
        let limbs = bp256r1_sec1::limbs_from_be_bytes(&array);
        let (_, borrow) = nat::sub(&limbs, &N_LIMBS);
        if limbs == [0; 4] || borrow != 1 {
            return Err(SignatureError::DecodingError(
                "ECDSA brainpoolP256r1 private key must be in [1, n-1]",
            ));
        }
        Ok(Self(Bp256r1Scalar::from_limbs(limbs)))
    }
}

/// An ECDSA brainpoolP256r1 public key: FIPS 186-5 §6.2's `Q = [d]G`, stored as affine
/// coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ECDSABp256r1PublicKey {
    pub(crate) x: Bp256r1FieldElement,
    pub(crate) y: Bp256r1FieldElement,
}

impl SignaturePublicKey<PK_LEN> for ECDSABp256r1PublicKey {
    fn encode(&self) -> [u8; PK_LEN] {
        bp256r1_sec1::encode_uncompressed(&self.x, &self.y)
    }

    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        out.fill(0);
        *out = self.encode();
        PK_LEN
    }

    /// Accepts both SEC 1 §2.3.3 encodings (33-byte compressed, 65-byte uncompressed), fully
    /// validated per [`bp256r1_sec1::decode`]'s docs (partial validation is full validation here:
    /// RFC 5639 §3.4 gives brainpoolP256r1 cofactor `h = 1`).
    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let (x, y) = bp256r1_sec1::decode(bytes).ok_or(SignatureError::DecodingError(
            "invalid or out-of-range SEC 1 brainpoolP256r1 point encoding",
        ))?;
        Ok(Self { x, y })
    }
}

impl Display for ECDSABp256r1PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "ECDSABp256r1PublicKey {{ {:x?} }}", self.encode())
    }
}

/// As [`keygen`], but sources the DRBG output from the caller-provided RNG, which must
/// offer a security strength of at least 128 bits: FIPS 186-5 Appendix A.2.1 step 3 requires
/// a DRBG whose security strength is "not less than" the one SP 800-57 Part 1 Rev. 5's
/// Table 2 associates with brainpoolP256r1's 256-bit order (`f = 256-383` in that table's ECC column, giving
/// 128-bit security).
pub fn keygen(
    rng: &mut dyn RNG,
) -> Result<(ECDSABp256r1PublicKey, ECDSABp256r1PrivateKey), SignatureError> {
    // The pair comes from ec's generator, which checks the RNG's strength, draws
    // EXTRA_BITS_DRBG_OUTPUT_LEN bytes and reduces them; this crate names the key types.
    let (d, (x, y)) = bp256r1_keygen::keygen::<EXTRA_BITS_DRBG_OUTPUT_LEN>(rng)?;
    Ok((ECDSABp256r1PublicKey { x, y }, ECDSABp256r1PrivateKey(d)))
}

/// [`Bp256r1::generate_signature_key_pair`](SignatureKeyPair::generate_signature_key_pair) is [`keygen`].
impl SignatureKeyPair for Bp256r1 {
    type PublicKey = ECDSABp256r1PublicKey;
    type PrivateKey = ECDSABp256r1PrivateKey;

    fn generate_signature_key_pair(
        rng: &mut dyn RNG,
    ) -> Result<(ECDSABp256r1PublicKey, ECDSABp256r1PrivateKey), SignatureError> {
        keygen(rng)
    }
}
