//! RSA-1536: verification only. `L = 24` (1536 bits). As with [`crate::rsa_1024`], there is no
//! `Rsa1536PrivateKey` and no signing function -- see that module's docs and this crate's
//! `# Scope` for why.
//!
//! Only PKCS#1 v1.5 is wired up: Wycheproof has no PSS vectors at 1536 bits (nor, realistically,
//! would PSS be paired with a modulus this small in practice -- it postdates PKCS#1 v1.5 and
//! became common alongside longer keys), so there is nothing to validate a PSS pairing against at
//! this size.
use crate::keys::RsaPublicKey;
use crate::rsassa_pkcs1_v1_5;
use bouncycastle_core::errors::SignatureError;
use bouncycastle_sha2::{SHA256, SHA384, SHA512};

/// An RSA-1536 public key.
pub type Rsa1536PublicKey = RsaPublicKey<24>;

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) verification against a SHA-256 digest. See
/// [`rsassa_pkcs1_v1_5::verify`] for what each error means.
pub fn pkcs1_v1_5_verify_sha256(
    pk: &Rsa1536PublicKey,
    message: &[u8],
    signature: &[u8; 192],
) -> Result<(), SignatureError> {
    rsassa_pkcs1_v1_5::verify::<SHA256, 32, 24, 48, 49, 192>(pk, message, signature)
}

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) verification against a SHA-384 digest. See
/// [`rsassa_pkcs1_v1_5::verify`] for what each error means.
pub fn pkcs1_v1_5_verify_sha384(
    pk: &Rsa1536PublicKey,
    message: &[u8],
    signature: &[u8; 192],
) -> Result<(), SignatureError> {
    rsassa_pkcs1_v1_5::verify::<SHA384, 48, 24, 48, 49, 192>(pk, message, signature)
}

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) verification against a SHA-512 digest. See
/// [`rsassa_pkcs1_v1_5::verify`] for what each error means.
pub fn pkcs1_v1_5_verify_sha512(
    pk: &Rsa1536PublicKey,
    message: &[u8],
    signature: &[u8; 192],
) -> Result<(), SignatureError> {
    rsassa_pkcs1_v1_5::verify::<SHA512, 64, 24, 48, 49, 192>(pk, message, signature)
}
