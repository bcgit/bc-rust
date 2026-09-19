//! RSA-2048: the generic engine ([`crate::modexp`], [`crate::rsa_core`], [`crate::rsassa_pkcs1_v1_5`])
//! wired to concrete widths -- `L = 32` (2048 bits), `HALF = 16` (1024-bit CRT primes) -- so a
//! caller using this size doesn't thread six const-generic width parameters through every call.
//! One file per modulus size, matching [`crate::keys::RsaPrivateKey`]'s own `<L, HALF>` shape;
//! `rsa_1024`/`rsa_3072`/`rsa_4096`/`rsa_8192` are the same pattern at their own widths.

use crate::keys::{RsaPrivateKey, RsaPublicKey};
use crate::rsassa_pkcs1_v1_5;
use bouncycastle_core::errors::SignatureError;
use bouncycastle_sha2::SHA256;

/// An RSA-2048 private key (`p`, `q` each 1024 bits).
pub type Rsa2048PrivateKey = RsaPrivateKey<32, 16>;
/// An RSA-2048 public key.
pub type Rsa2048PublicKey = RsaPublicKey<32>;

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) signing, `s = m^d mod n` over an EMSA-PKCS1-v1_5/SHA-256
/// encoded message. See [`rsassa_pkcs1_v1_5::sign`] for what each error means.
pub fn pkcs1_v1_5_sign_sha256(
    sk: &Rsa2048PrivateKey,
    message: &[u8],
) -> Result<[u8; 256], SignatureError> {
    rsassa_pkcs1_v1_5::sign::<SHA256, 32, 51, 32, 64, 65, 16, 32, 33, 256>(sk, message)
}

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) verification against a SHA-256 digest. See
/// [`rsassa_pkcs1_v1_5::verify`] for what each error means.
pub fn pkcs1_v1_5_verify_sha256(
    pk: &Rsa2048PublicKey,
    message: &[u8],
    signature: &[u8; 256],
) -> Result<(), SignatureError> {
    rsassa_pkcs1_v1_5::verify::<SHA256, 32, 32, 64, 65, 256>(pk, message, signature)
}
