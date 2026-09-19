//! RSA-3072: `L = 48` (3072 bits), `HALF = 24` (1536-bit CRT primes). See [`crate::rsa_2048`]'s
//! docs for the pattern every concrete modulus size in this crate follows.

use crate::keys::{RsaPrivateKey, RsaPublicKey};
use crate::rsassa_pkcs1_v1_5;
use crate::rsassa_pss;
use crate::rsassa_pss_shake;
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::RNG;
use bouncycastle_sha2::{SHA256, SHA384, SHA512};
use bouncycastle_sha3::SHAKE128;

/// An RSA-3072 private key (`p`, `q` each 1536 bits).
pub type Rsa3072PrivateKey = RsaPrivateKey<48, 24>;
/// An RSA-3072 public key.
pub type Rsa3072PublicKey = RsaPublicKey<48>;

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) signing with SHA-256. See [`rsassa_pkcs1_v1_5::sign`] for
/// what each error means.
pub fn pkcs1_v1_5_sign_sha256(
    sk: &Rsa3072PrivateKey,
    message: &[u8],
) -> Result<[u8; 384], SignatureError> {
    rsassa_pkcs1_v1_5::sign::<SHA256, 32, 51, 48, 96, 97, 24, 48, 49, 384>(sk, message)
}

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) verification against a SHA-256 digest. See
/// [`rsassa_pkcs1_v1_5::verify`] for what each error means.
pub fn pkcs1_v1_5_verify_sha256(
    pk: &Rsa3072PublicKey,
    message: &[u8],
    signature: &[u8; 384],
) -> Result<(), SignatureError> {
    rsassa_pkcs1_v1_5::verify::<SHA256, 32, 48, 96, 97, 384>(pk, message, signature)
}

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) signing with SHA-384. See [`rsassa_pkcs1_v1_5::sign`] for
/// what each error means.
pub fn pkcs1_v1_5_sign_sha384(
    sk: &Rsa3072PrivateKey,
    message: &[u8],
) -> Result<[u8; 384], SignatureError> {
    rsassa_pkcs1_v1_5::sign::<SHA384, 48, 67, 48, 96, 97, 24, 48, 49, 384>(sk, message)
}

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) verification against a SHA-384 digest. See
/// [`rsassa_pkcs1_v1_5::verify`] for what each error means.
pub fn pkcs1_v1_5_verify_sha384(
    pk: &Rsa3072PublicKey,
    message: &[u8],
    signature: &[u8; 384],
) -> Result<(), SignatureError> {
    rsassa_pkcs1_v1_5::verify::<SHA384, 48, 48, 96, 97, 384>(pk, message, signature)
}

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) signing with SHA-512. See [`rsassa_pkcs1_v1_5::sign`] for
/// what each error means.
pub fn pkcs1_v1_5_sign_sha512(
    sk: &Rsa3072PrivateKey,
    message: &[u8],
) -> Result<[u8; 384], SignatureError> {
    rsassa_pkcs1_v1_5::sign::<SHA512, 64, 83, 48, 96, 97, 24, 48, 49, 384>(sk, message)
}

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) verification against a SHA-512 digest. See
/// [`rsassa_pkcs1_v1_5::verify`] for what each error means.
pub fn pkcs1_v1_5_verify_sha512(
    pk: &Rsa3072PublicKey,
    message: &[u8],
    signature: &[u8; 384],
) -> Result<(), SignatureError> {
    rsassa_pkcs1_v1_5::verify::<SHA512, 64, 48, 96, 97, 384>(pk, message, signature)
}

/// RSASSA-PSS (RFC 8017 §8.1) signing with SHA-256 and a 32-byte salt drawn fresh from `rng`. See
/// [`rsassa_pss::sign`] for what each error means.
pub fn pss_sign_sha256(
    sk: &Rsa3072PrivateKey,
    message: &[u8],
    rng: &mut dyn RNG,
) -> Result<[u8; 384], SignatureError> {
    rsassa_pss::sign::<SHA256, 32, 36, 32, 72, 351, 48, 96, 97, 24, 48, 49, 384>(sk, message, rng)
}

/// As [`pss_sign_sha256`], but with the salt supplied directly instead of drawn from an RNG.
pub fn pss_sign_sha256_with_salt(
    sk: &Rsa3072PrivateKey,
    message: &[u8],
    salt: &[u8; 32],
) -> Result<[u8; 384], SignatureError> {
    rsassa_pss::sign_with_salt::<SHA256, 32, 36, 32, 72, 351, 48, 96, 97, 24, 48, 49, 384>(
        sk, message, salt,
    )
}

/// RSASSA-PSS (RFC 8017 §8.1) verification against a SHA-256/MGF1-SHA-256/32-byte-salt encoding.
/// See [`rsassa_pss::verify`] for what each error means.
pub fn pss_verify_sha256(
    pk: &Rsa3072PublicKey,
    message: &[u8],
    signature: &[u8; 384],
) -> Result<(), SignatureError> {
    rsassa_pss::verify::<SHA256, 32, 36, 32, 72, 351, 48, 96, 97, 384>(pk, message, signature)
}

/// RSASSA-PSS (RFC 8017 §8.1) signing with SHA-384 and a 48-byte salt drawn fresh from `rng`. See
/// [`rsassa_pss::sign`] for what each error means.
pub fn pss_sign_sha384(
    sk: &Rsa3072PrivateKey,
    message: &[u8],
    rng: &mut dyn RNG,
) -> Result<[u8; 384], SignatureError> {
    rsassa_pss::sign::<SHA384, 48, 52, 48, 104, 335, 48, 96, 97, 24, 48, 49, 384>(sk, message, rng)
}

/// As [`pss_sign_sha384`], but with the salt supplied directly instead of drawn from an RNG.
pub fn pss_sign_sha384_with_salt(
    sk: &Rsa3072PrivateKey,
    message: &[u8],
    salt: &[u8; 48],
) -> Result<[u8; 384], SignatureError> {
    rsassa_pss::sign_with_salt::<SHA384, 48, 52, 48, 104, 335, 48, 96, 97, 24, 48, 49, 384>(
        sk, message, salt,
    )
}

/// RSASSA-PSS (RFC 8017 §8.1) verification against a SHA-384/MGF1-SHA-384/48-byte-salt encoding.
/// See [`rsassa_pss::verify`] for what each error means.
pub fn pss_verify_sha384(
    pk: &Rsa3072PublicKey,
    message: &[u8],
    signature: &[u8; 384],
) -> Result<(), SignatureError> {
    rsassa_pss::verify::<SHA384, 48, 52, 48, 104, 335, 48, 96, 97, 384>(pk, message, signature)
}

/// RSASSA-PSS (RFC 8017 §8.1) signing with SHA-512 and a 64-byte salt drawn fresh from `rng`. See
/// [`rsassa_pss::sign`] for what each error means.
pub fn pss_sign_sha512(
    sk: &Rsa3072PrivateKey,
    message: &[u8],
    rng: &mut dyn RNG,
) -> Result<[u8; 384], SignatureError> {
    rsassa_pss::sign::<SHA512, 64, 68, 64, 136, 319, 48, 96, 97, 24, 48, 49, 384>(sk, message, rng)
}

/// As [`pss_sign_sha512`], but with the salt supplied directly instead of drawn from an RNG.
pub fn pss_sign_sha512_with_salt(
    sk: &Rsa3072PrivateKey,
    message: &[u8],
    salt: &[u8; 64],
) -> Result<[u8; 384], SignatureError> {
    rsassa_pss::sign_with_salt::<SHA512, 64, 68, 64, 136, 319, 48, 96, 97, 24, 48, 49, 384>(
        sk, message, salt,
    )
}

/// RSASSA-PSS (RFC 8017 §8.1) verification against a SHA-512/MGF1-SHA-512/64-byte-salt encoding.
/// See [`rsassa_pss::verify`] for what each error means.
pub fn pss_verify_sha512(
    pk: &Rsa3072PublicKey,
    message: &[u8],
    signature: &[u8; 384],
) -> Result<(), SignatureError> {
    rsassa_pss::verify::<SHA512, 64, 68, 64, 136, 319, 48, 96, 97, 384>(pk, message, signature)
}

/// RSASSA-PSS-SHAKE128 (`id-RSASSA-PSS-SHAKE128`, RFC 8702 §3.2.1) signing: SHAKE128 as both the
/// message hash and, natively rather than through MGF1, the mask generation function, with a
/// 32-byte salt drawn fresh from `rng`. RFC 8702 §5 recommends this pairing for a 2048- or
/// 3072-bit RSA modulus. See [`rsassa_pss_shake::sign`] for what each error means.
pub fn pss_shake128_sign(
    sk: &Rsa3072PrivateKey,
    message: &[u8],
    rng: &mut dyn RNG,
) -> Result<[u8; 384], SignatureError> {
    rsassa_pss_shake::sign::<SHAKE128, 32, 32, 72, 351, 48, 96, 97, 24, 48, 49, 384>(
        sk, message, rng,
    )
}

/// As [`pss_shake128_sign`], but with the salt supplied directly instead of drawn from an RNG.
pub fn pss_shake128_sign_with_salt(
    sk: &Rsa3072PrivateKey,
    message: &[u8],
    salt: &[u8; 32],
) -> Result<[u8; 384], SignatureError> {
    rsassa_pss_shake::sign_with_salt::<SHAKE128, 32, 32, 72, 351, 48, 96, 97, 24, 48, 49, 384>(
        sk, message, salt,
    )
}

/// RSASSA-PSS-SHAKE128 (RFC 8702 §3.2.1) verification. See [`rsassa_pss_shake::verify`] for what
/// each error means.
pub fn pss_shake128_verify(
    pk: &Rsa3072PublicKey,
    message: &[u8],
    signature: &[u8; 384],
) -> Result<(), SignatureError> {
    rsassa_pss_shake::verify::<SHAKE128, 32, 32, 72, 351, 48, 96, 97, 384>(pk, message, signature)
}
