//! RSA-1024: verification only. `L = 16` (1024 bits). There is no `Rsa1024PrivateKey` and no
//! signing function -- per this crate's `# Scope` (see `src/lib.rs`), a 1024-bit modulus is for
//! verifying signatures made elsewhere (legacy interoperability), not for producing new ones, and
//! that is enforced by the absent type rather than a runtime check.
//!
//! Only SHA-256 and SHA-384 PKCS#1 v1.5 are wired up: Wycheproof's own
//! `rsa_pkcs1_1024_sig_gen_test.json` has no SHA-512 group at 1024 bits (unlike every other size
//! this crate offers) and no PSS vectors at all, so there is nothing to validate a SHA-512 or PSS
//! pairing against at this size -- both remain mathematically expressible through
//! [`crate::rsassa_pkcs1_v1_5`]/[`crate::rsassa_pss`] directly if a caller ever needs them, just
//! not exposed here without real vectors behind them.

use crate::keys::RsaPublicKey;
use crate::rsassa_pkcs1_v1_5;
use bouncycastle_core::errors::SignatureError;
use bouncycastle_sha2::{SHA256, SHA384};

/// An RSA-1024 public key.
pub type Rsa1024PublicKey = RsaPublicKey<16>;

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) verification against a SHA-256 digest. See
/// [`rsassa_pkcs1_v1_5::verify`] for what each error means.
pub fn pkcs1_v1_5_verify_sha256(
    pk: &Rsa1024PublicKey,
    message: &[u8],
    signature: &[u8; 128],
) -> Result<(), SignatureError> {
    rsassa_pkcs1_v1_5::verify::<SHA256, 32, 16, 32, 33, 128>(pk, message, signature)
}

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) verification against a SHA-384 digest. See
/// [`rsassa_pkcs1_v1_5::verify`] for what each error means.
pub fn pkcs1_v1_5_verify_sha384(
    pk: &Rsa1024PublicKey,
    message: &[u8],
    signature: &[u8; 128],
) -> Result<(), SignatureError> {
    rsassa_pkcs1_v1_5::verify::<SHA384, 48, 16, 32, 33, 128>(pk, message, signature)
}
