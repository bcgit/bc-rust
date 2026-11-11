//! ECDSA P-256 key types (FIPS 186-5 §6.2) and key-pair generation (Appendix A.2.1).

use crate::keys_common::DerivePublicKey;
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{RNG, SignaturePrivateKey, SignaturePublicKey};
use bouncycastle_ec::hazmat::p256::P256FieldElement;
use bouncycastle_ec::hazmat::p256_keygen;
use bouncycastle_ec::hazmat::p256_scalar::{N_LIMBS, P256Scalar};
use bouncycastle_ec::hazmat::p256_sec1;
use bouncycastle_ec::nat;
use core::fmt;
use core::fmt::{Debug, Display, Formatter};

/// Encoded length of a P-256 private key: SEC 1 §2.3.7 integer-to-octet-string of `d`, `ceil(log2
/// n / 8)` = 32 bytes.
pub const SK_LEN: usize = 32;

/// Encoded length of a P-256 public key in the canonical form [`ECDSAP256PublicKey::encode`]
/// emits: SEC 1 §2.3.3's uncompressed `04 || X || Y`, 65 bytes.
/// [`ECDSAP256PublicKey::from_bytes`] also accepts the 33-byte compressed form.
pub const PK_LEN: usize = 65;

/// Requested output length, in bytes, from the DRBG for FIPS 186-5 Appendix A.2.1 key generation
/// and Appendix A.3.1 randomised per-message secret generation: FIPS 186-5 Table A.2 (in
/// Appendix A.2.1) gives 352 bits in its "Recommended" column for `p256`, i.e. `N + t` with `N =
/// 256` and `t = 96 >= 64`.
pub(crate) const EXTRA_BITS_DRBG_OUTPUT_LEN: usize = 44;

/// An ECDSA P-256 private key: FIPS 186-5 §6.2's `d`, `d` in `[1, n-1]`, held in
/// [`bouncycastle_utils::secret::Secret`] via [`P256Scalar`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ECDSAP256PrivateKey(P256Scalar);

impl ECDSAP256PrivateKey {
    /// The wrapped scalar, for this crate's own sign implementation to compute with.
    pub(crate) fn scalar(&self) -> &P256Scalar {
        &self.0
    }
}

impl DerivePublicKey<ECDSAP256PublicKey, PK_LEN> for ECDSAP256PrivateKey {
    fn derive_pk(&self) -> ECDSAP256PublicKey {
        let (x, y) = p256_keygen::public_point(&self.0);
        ECDSAP256PublicKey { x, y }
    }
}

impl SignaturePrivateKey<SK_LEN> for ECDSAP256PrivateKey {
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
            SignatureError::DecodingError("ECDSA P-256 private key must be 32 bytes")
        })?;
        // FIPS 186-5 §6.2: d is in [1, n-1], checked on the raw big-endian value *before* any
        // reduction. `P256Scalar::from_be_bytes` reduces mod n, so checking afterwards would accept
        // an out-of-range encoding as a different, perfectly valid key: `d = n + 1` would load as
        // `d = 1`, giving one key two encodings and silently treating malformed input as well-
        // formed. Comparing against the fixed public values 0 and n is a one-time validation of
        // caller-supplied bytes at load time, not a computation performed repeatedly on a secret
        // intermediate value, so branching on it leaks nothing beyond what the caller already knows
        // from having supplied these exact bytes.
        let limbs = p256_sec1::limbs_from_be_bytes(&array);
        let (_, borrow) = nat::sub(&limbs, &N_LIMBS);
        if limbs == [0; 4] || borrow != 1 {
            return Err(SignatureError::DecodingError(
                "ECDSA P-256 private key must be in [1, n-1]",
            ));
        }
        Ok(Self(P256Scalar::from_limbs(limbs)))
    }
}

/// An ECDSA P-256 public key: FIPS 186-5 §6.2's `Q = [d]G`, stored as affine coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ECDSAP256PublicKey {
    pub(crate) x: P256FieldElement,
    pub(crate) y: P256FieldElement,
}

impl SignaturePublicKey<PK_LEN> for ECDSAP256PublicKey {
    fn encode(&self) -> [u8; PK_LEN] {
        p256_sec1::encode_uncompressed(&self.x, &self.y)
    }

    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        out.fill(0);
        *out = self.encode();
        PK_LEN
    }

    /// Accepts both SEC 1 §2.3.3 encodings (33-byte compressed, 65-byte uncompressed), fully
    /// validated per SP 800-186 Appendix D.1.1.1 (see [`p256_sec1::decode`]'s docs).
    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let (x, y) = p256_sec1::decode(bytes).ok_or(SignatureError::DecodingError(
            "invalid or out-of-range SEC 1 P-256 point encoding",
        ))?;
        Ok(Self { x, y })
    }
}

impl Display for ECDSAP256PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "ECDSAP256PublicKey {{ {:x?} }}", self.encode())
    }
}

/// As [`keygen`], but sources the DRBG output from the caller-provided RNG, which must
/// offer a security strength of at least 128 bits: FIPS 186-5 Appendix A.2.1 step 3 requires
/// a DRBG whose security strength is "not less than" the one SP 800-57 Part 1 Rev. 5's
/// Table 2 associates with P-256's 256-bit order (`f = 256-383` in that table's ECC column, giving
/// 128-bit security).
pub fn keygen(
    rng: &mut dyn RNG,
) -> Result<(ECDSAP256PublicKey, ECDSAP256PrivateKey), SignatureError> {
    // The pair comes from ec's generator, which checks the RNG's strength, draws
    // EXTRA_BITS_DRBG_OUTPUT_LEN bytes and reduces them; this crate names the key types.
    let (d, (x, y)) = p256_keygen::keygen::<EXTRA_BITS_DRBG_OUTPUT_LEN>(rng)?;
    Ok((ECDSAP256PublicKey { x, y }, ECDSAP256PrivateKey(d)))
}
