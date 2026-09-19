//! RSA-4096: `L = 64` (4096 bits), `HALF = 32` (2048-bit CRT primes). See [`crate::rsa_2048`]'s
//! docs for the pattern every concrete modulus size in this crate follows.

use crate::keys::{RsaPrivateKey, RsaPublicKey};
use crate::rsassa_pkcs1_v1_5;
use crate::rsassa_pss;
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::RNG;
use bouncycastle_sha2::{SHA256, SHA384, SHA512};

/// An RSA-4096 private key (`p`, `q` each 2048 bits).
pub type Rsa4096PrivateKey = RsaPrivateKey<64, 32>;
/// An RSA-4096 public key.
pub type Rsa4096PublicKey = RsaPublicKey<64>;

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) signing with SHA-256. See [`rsassa_pkcs1_v1_5::sign`] for
/// what each error means.
pub fn pkcs1_v1_5_sign_sha256(
    sk: &Rsa4096PrivateKey,
    message: &[u8],
) -> Result<[u8; 512], SignatureError> {
    rsassa_pkcs1_v1_5::sign::<SHA256, 32, 51, 64, 128, 129, 32, 64, 65, 512>(sk, message)
}

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) verification against a SHA-256 digest. See
/// [`rsassa_pkcs1_v1_5::verify`] for what each error means.
pub fn pkcs1_v1_5_verify_sha256(
    pk: &Rsa4096PublicKey,
    message: &[u8],
    signature: &[u8; 512],
) -> Result<(), SignatureError> {
    rsassa_pkcs1_v1_5::verify::<SHA256, 32, 64, 128, 129, 512>(pk, message, signature)
}

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) signing with SHA-384. See [`rsassa_pkcs1_v1_5::sign`] for
/// what each error means.
pub fn pkcs1_v1_5_sign_sha384(
    sk: &Rsa4096PrivateKey,
    message: &[u8],
) -> Result<[u8; 512], SignatureError> {
    rsassa_pkcs1_v1_5::sign::<SHA384, 48, 67, 64, 128, 129, 32, 64, 65, 512>(sk, message)
}

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) verification against a SHA-384 digest. See
/// [`rsassa_pkcs1_v1_5::verify`] for what each error means.
pub fn pkcs1_v1_5_verify_sha384(
    pk: &Rsa4096PublicKey,
    message: &[u8],
    signature: &[u8; 512],
) -> Result<(), SignatureError> {
    rsassa_pkcs1_v1_5::verify::<SHA384, 48, 64, 128, 129, 512>(pk, message, signature)
}

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) signing with SHA-512. See [`rsassa_pkcs1_v1_5::sign`] for
/// what each error means.
pub fn pkcs1_v1_5_sign_sha512(
    sk: &Rsa4096PrivateKey,
    message: &[u8],
) -> Result<[u8; 512], SignatureError> {
    rsassa_pkcs1_v1_5::sign::<SHA512, 64, 83, 64, 128, 129, 32, 64, 65, 512>(sk, message)
}

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) verification against a SHA-512 digest. See
/// [`rsassa_pkcs1_v1_5::verify`] for what each error means.
pub fn pkcs1_v1_5_verify_sha512(
    pk: &Rsa4096PublicKey,
    message: &[u8],
    signature: &[u8; 512],
) -> Result<(), SignatureError> {
    rsassa_pkcs1_v1_5::verify::<SHA512, 64, 64, 128, 129, 512>(pk, message, signature)
}

/// RSASSA-PSS (RFC 8017 §8.1) signing with SHA-256 and a 32-byte salt drawn fresh from `rng`. See
/// [`rsassa_pss::sign`] for what each error means.
pub fn pss_sign_sha256(
    sk: &Rsa4096PrivateKey,
    message: &[u8],
    rng: &mut dyn RNG,
) -> Result<[u8; 512], SignatureError> {
    rsassa_pss::sign::<SHA256, 32, 36, 32, 72, 479, 64, 128, 129, 32, 64, 65, 512>(sk, message, rng)
}

/// As [`pss_sign_sha256`], but with the salt supplied directly instead of drawn from an RNG.
pub fn pss_sign_sha256_with_salt(
    sk: &Rsa4096PrivateKey,
    message: &[u8],
    salt: &[u8; 32],
) -> Result<[u8; 512], SignatureError> {
    rsassa_pss::sign_with_salt::<SHA256, 32, 36, 32, 72, 479, 64, 128, 129, 32, 64, 65, 512>(
        sk, message, salt,
    )
}

/// RSASSA-PSS (RFC 8017 §8.1) verification against a SHA-256/MGF1-SHA-256/32-byte-salt encoding.
/// See [`rsassa_pss::verify`] for what each error means.
pub fn pss_verify_sha256(
    pk: &Rsa4096PublicKey,
    message: &[u8],
    signature: &[u8; 512],
) -> Result<(), SignatureError> {
    rsassa_pss::verify::<SHA256, 32, 36, 32, 72, 479, 64, 128, 129, 512>(pk, message, signature)
}

/// RSASSA-PSS (RFC 8017 §8.1) signing with SHA-384 and a 48-byte salt drawn fresh from `rng`. See
/// [`rsassa_pss::sign`] for what each error means.
pub fn pss_sign_sha384(
    sk: &Rsa4096PrivateKey,
    message: &[u8],
    rng: &mut dyn RNG,
) -> Result<[u8; 512], SignatureError> {
    rsassa_pss::sign::<SHA384, 48, 52, 48, 104, 463, 64, 128, 129, 32, 64, 65, 512>(
        sk, message, rng,
    )
}

/// As [`pss_sign_sha384`], but with the salt supplied directly instead of drawn from an RNG.
pub fn pss_sign_sha384_with_salt(
    sk: &Rsa4096PrivateKey,
    message: &[u8],
    salt: &[u8; 48],
) -> Result<[u8; 512], SignatureError> {
    rsassa_pss::sign_with_salt::<SHA384, 48, 52, 48, 104, 463, 64, 128, 129, 32, 64, 65, 512>(
        sk, message, salt,
    )
}

/// RSASSA-PSS (RFC 8017 §8.1) verification against a SHA-384/MGF1-SHA-384/48-byte-salt encoding.
/// See [`rsassa_pss::verify`] for what each error means.
pub fn pss_verify_sha384(
    pk: &Rsa4096PublicKey,
    message: &[u8],
    signature: &[u8; 512],
) -> Result<(), SignatureError> {
    rsassa_pss::verify::<SHA384, 48, 52, 48, 104, 463, 64, 128, 129, 512>(pk, message, signature)
}

/// RSASSA-PSS (RFC 8017 §8.1) signing with SHA-512 and a 64-byte salt drawn fresh from `rng`. See
/// [`rsassa_pss::sign`] for what each error means.
pub fn pss_sign_sha512(
    sk: &Rsa4096PrivateKey,
    message: &[u8],
    rng: &mut dyn RNG,
) -> Result<[u8; 512], SignatureError> {
    rsassa_pss::sign::<SHA512, 64, 68, 64, 136, 447, 64, 128, 129, 32, 64, 65, 512>(
        sk, message, rng,
    )
}

/// As [`pss_sign_sha512`], but with the salt supplied directly instead of drawn from an RNG.
pub fn pss_sign_sha512_with_salt(
    sk: &Rsa4096PrivateKey,
    message: &[u8],
    salt: &[u8; 64],
) -> Result<[u8; 512], SignatureError> {
    rsassa_pss::sign_with_salt::<SHA512, 64, 68, 64, 136, 447, 64, 128, 129, 32, 64, 65, 512>(
        sk, message, salt,
    )
}

/// RSASSA-PSS (RFC 8017 §8.1) verification against a SHA-512/MGF1-SHA-512/64-byte-salt encoding.
/// See [`rsassa_pss::verify`] for what each error means.
pub fn pss_verify_sha512(
    pk: &Rsa4096PublicKey,
    message: &[u8],
    signature: &[u8; 512],
) -> Result<(), SignatureError> {
    rsassa_pss::verify::<SHA512, 64, 68, 64, 136, 447, 64, 128, 129, 512>(pk, message, signature)
}
