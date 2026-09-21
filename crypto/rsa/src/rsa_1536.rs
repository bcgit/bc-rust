//! RSA-1536: verification only. `L = 24` (1536 bits). As with [`crate::rsa_1024`], there is no
//! `RSA1536PrivateKey` and no signing function -- see that module's docs and this crate's
//! `# Scope` for why.
//!
//! Only PKCS#1 v1.5 is wired up: Wycheproof has no PSS vectors at 1536 bits (nor, realistically,
//! would PSS be paired with a modulus this small in practice -- it postdates PKCS#1 v1.5 and
//! became common alongside longer keys), so there is nothing to validate a PSS pairing against at
//! this size.
//!
//! The `SignatureVerifier` types ([`RSASSA_PKCS1_v1_5_SHA256`] and siblings) are verify-only for
//! the same reason and in the same way as [`crate::rsa_1024`]'s -- see that module's docs.

use crate::keys::RsaPublicKey;
use crate::rsassa_pkcs1_v1_5::RSASSA_PKCS1_v1_5;
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::SignaturePublicKey;
use bouncycastle_sha2::{SHA256, SHA384, SHA512};

/// An RSA-1536 public key.
pub type RSA1536PublicKey = RsaPublicKey<24>;

/// Encoded length of an [`RSA1536PublicKey`] under [`SignaturePublicKey`]: 192 + 4 bytes (see
/// [`RsaPublicKey`]'s `# Encoding`).
pub const PK_LEN: usize = 196;
/// Signature length: `k`, the modulus length in octets (RFC 8017 §8.2.1 step 2.c).
pub const SIG_LEN: usize = 192;

impl SignaturePublicKey<PK_LEN> for RSA1536PublicKey {
    fn encode(&self) -> [u8; PK_LEN] {
        self.encode_raw::<192, PK_LEN>()
    }

    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        *out = self.encode_raw::<192, PK_LEN>();
        PK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let bytes: &[u8; PK_LEN] = bytes
            .try_into()
            .map_err(|_| SignatureError::DecodingError("RSA-1536 public key must be 196 bytes"))?;
        Self::from_bytes_raw::<192, PK_LEN>(bytes)
    }
}

/// RSASSA-PKCS1-v1_5/SHA-256 over RSA-1536 as a `SignatureVerifier` only -- see
/// [`crate::rsa_1024::RSASSA_PKCS1_v1_5_SHA256`] for why the signing-side widths (`HALF = 12`,
/// `SK_LEN = 480`) are named but inert.
#[allow(non_camel_case_types)]
pub type RSASSA_PKCS1_v1_5_SHA256 =
    RSASSA_PKCS1_v1_5<SHA256, 32, 51, 24, 48, 49, 12, 24, 25, 192, 480, PK_LEN>;
/// RSASSA-PKCS1-v1_5/SHA-384 over RSA-1536, verify-only; see [`RSASSA_PKCS1_v1_5_SHA256`].
#[allow(non_camel_case_types)]
pub type RSASSA_PKCS1_v1_5_SHA384 =
    RSASSA_PKCS1_v1_5<SHA384, 48, 67, 24, 48, 49, 12, 24, 25, 192, 480, PK_LEN>;
/// RSASSA-PKCS1-v1_5/SHA-512 over RSA-1536, verify-only; see [`RSASSA_PKCS1_v1_5_SHA256`].
#[allow(non_camel_case_types)]
pub type RSASSA_PKCS1_v1_5_SHA512 =
    RSASSA_PKCS1_v1_5<SHA512, 64, 83, 24, 48, 49, 12, 24, 25, 192, 480, PK_LEN>;
