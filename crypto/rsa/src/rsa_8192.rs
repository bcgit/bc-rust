//! RSA-8192: `L = 128` (8192 bits), `HALF = 64` (4096-bit CRT primes). See [`crate::rsa_2048`]'s
//! docs for the pattern every concrete modulus size in this crate follows.

use crate::keys::{RsaPrivateKey, RsaPublicKey};
use crate::rsassa_pkcs1_v1_5;
use crate::rsassa_pkcs1_v1_5::RSASSA_PKCS1_v1_5;
use crate::rsassa_pss;
use crate::rsassa_pss::RSASSA_PSS;
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{RNG, SignaturePrivateKey, SignaturePublicKey};
use bouncycastle_sha2::{SHA256, SHA384, SHA512};

/// An RSA-8192 private key (`p`, `q` each 4096 bits).
pub type Rsa8192PrivateKey = RsaPrivateKey<128, 64>;
/// An RSA-8192 public key.
pub type Rsa8192PublicKey = RsaPublicKey<128>;

/// Encoded length of an [`Rsa8192PrivateKey`] under [`SignaturePrivateKey`]: five 512-byte
/// values (see [`RsaPrivateKey`]'s `# Encoding`).
pub const SK_LEN: usize = 2560;
/// Encoded length of an [`Rsa8192PublicKey`] under [`SignaturePublicKey`]: 1024 + 4 bytes (see
/// [`RsaPublicKey`]'s `# Encoding`).
pub const PK_LEN: usize = 1028;
/// Signature length: `k`, the modulus length in octets (RFC 8017 §8.1.1/§8.2.1 step 2.c).
pub const SIG_LEN: usize = 1024;

impl SignaturePrivateKey<SK_LEN> for Rsa8192PrivateKey {
    fn encode(&self) -> [u8; SK_LEN] {
        self.encode_raw::<512, SK_LEN>()
    }

    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        *out = self.encode_raw::<512, SK_LEN>();
        SK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let bytes: &[u8; SK_LEN] = bytes.try_into().map_err(|_| {
            SignatureError::DecodingError("RSA-8192 private key must be 2560 bytes")
        })?;
        Self::from_bytes_raw::<512, SK_LEN>(bytes)
    }
}

impl SignaturePublicKey<PK_LEN> for Rsa8192PublicKey {
    fn encode(&self) -> [u8; PK_LEN] {
        self.encode_raw::<1024, PK_LEN>()
    }

    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        *out = self.encode_raw::<1024, PK_LEN>();
        PK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let bytes: &[u8; PK_LEN] = bytes
            .try_into()
            .map_err(|_| SignatureError::DecodingError("RSA-8192 public key must be 1028 bytes"))?;
        Self::from_bytes_raw::<1024, PK_LEN>(bytes)
    }
}

/// RSASSA-PKCS1-v1_5/SHA-256 over RSA-8192 as a `Signer`/`SignatureVerifier`; see
/// [`crate::rsa_2048::RSASSA_PKCS1_v1_5_SHA256`] for the pattern.
#[allow(non_camel_case_types)]
pub type RSASSA_PKCS1_v1_5_SHA256 =
    RSASSA_PKCS1_v1_5<SHA256, 32, 51, 128, 256, 257, 64, 128, 129, 1024, SK_LEN, PK_LEN>;
/// RSASSA-PKCS1-v1_5/SHA-384 over RSA-8192.
#[allow(non_camel_case_types)]
pub type RSASSA_PKCS1_v1_5_SHA384 =
    RSASSA_PKCS1_v1_5<SHA384, 48, 67, 128, 256, 257, 64, 128, 129, 1024, SK_LEN, PK_LEN>;
/// RSASSA-PKCS1-v1_5/SHA-512 over RSA-8192.
#[allow(non_camel_case_types)]
pub type RSASSA_PKCS1_v1_5_SHA512 =
    RSASSA_PKCS1_v1_5<SHA512, 64, 83, 128, 256, 257, 64, 128, 129, 1024, SK_LEN, PK_LEN>;

/// RSASSA-PSS/SHA-256 over RSA-8192 as a `Signer`/`SignatureVerifier`; see
/// [`crate::rsa_2048::RSASSA_PSS_SHA256`] for the pattern (including where the salt comes from).
#[allow(non_camel_case_types)]
pub type RSASSA_PSS_SHA256 =
    RSASSA_PSS<SHA256, 32, 36, 32, 72, 991, 128, 256, 257, 64, 128, 129, 1024, SK_LEN, PK_LEN>;
/// RSASSA-PSS/SHA-384 over RSA-8192.
#[allow(non_camel_case_types)]
pub type RSASSA_PSS_SHA384 =
    RSASSA_PSS<SHA384, 48, 52, 48, 104, 975, 128, 256, 257, 64, 128, 129, 1024, SK_LEN, PK_LEN>;
/// RSASSA-PSS/SHA-512 over RSA-8192.
#[allow(non_camel_case_types)]
pub type RSASSA_PSS_SHA512 =
    RSASSA_PSS<SHA512, 64, 68, 64, 136, 959, 128, 256, 257, 64, 128, 129, 1024, SK_LEN, PK_LEN>;

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) signing with SHA-256. See [`rsassa_pkcs1_v1_5::sign`] for
/// what each error means.
pub fn pkcs1_v1_5_sign_sha256(
    sk: &Rsa8192PrivateKey,
    message: &[u8],
) -> Result<[u8; 1024], SignatureError> {
    rsassa_pkcs1_v1_5::sign::<SHA256, 32, 51, 128, 256, 257, 64, 128, 129, 1024>(sk, message)
}

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) verification against a SHA-256 digest. See
/// [`rsassa_pkcs1_v1_5::verify`] for what each error means.
pub fn pkcs1_v1_5_verify_sha256(
    pk: &Rsa8192PublicKey,
    message: &[u8],
    signature: &[u8; 1024],
) -> Result<(), SignatureError> {
    rsassa_pkcs1_v1_5::verify::<SHA256, 32, 128, 256, 257, 1024>(pk, message, signature)
}

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) signing with SHA-384. See [`rsassa_pkcs1_v1_5::sign`] for
/// what each error means.
pub fn pkcs1_v1_5_sign_sha384(
    sk: &Rsa8192PrivateKey,
    message: &[u8],
) -> Result<[u8; 1024], SignatureError> {
    rsassa_pkcs1_v1_5::sign::<SHA384, 48, 67, 128, 256, 257, 64, 128, 129, 1024>(sk, message)
}

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) verification against a SHA-384 digest. See
/// [`rsassa_pkcs1_v1_5::verify`] for what each error means.
pub fn pkcs1_v1_5_verify_sha384(
    pk: &Rsa8192PublicKey,
    message: &[u8],
    signature: &[u8; 1024],
) -> Result<(), SignatureError> {
    rsassa_pkcs1_v1_5::verify::<SHA384, 48, 128, 256, 257, 1024>(pk, message, signature)
}

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) signing with SHA-512. See [`rsassa_pkcs1_v1_5::sign`] for
/// what each error means.
pub fn pkcs1_v1_5_sign_sha512(
    sk: &Rsa8192PrivateKey,
    message: &[u8],
) -> Result<[u8; 1024], SignatureError> {
    rsassa_pkcs1_v1_5::sign::<SHA512, 64, 83, 128, 256, 257, 64, 128, 129, 1024>(sk, message)
}

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) verification against a SHA-512 digest. See
/// [`rsassa_pkcs1_v1_5::verify`] for what each error means.
pub fn pkcs1_v1_5_verify_sha512(
    pk: &Rsa8192PublicKey,
    message: &[u8],
    signature: &[u8; 1024],
) -> Result<(), SignatureError> {
    rsassa_pkcs1_v1_5::verify::<SHA512, 64, 128, 256, 257, 1024>(pk, message, signature)
}

/// RSASSA-PSS (RFC 8017 §8.1) signing with SHA-256 and a 32-byte salt drawn fresh from `rng`. See
/// [`rsassa_pss::sign`] for what each error means.
pub fn pss_sign_sha256(
    sk: &Rsa8192PrivateKey,
    message: &[u8],
    rng: &mut dyn RNG,
) -> Result<[u8; 1024], SignatureError> {
    rsassa_pss::sign::<SHA256, 32, 36, 32, 72, 991, 128, 256, 257, 64, 128, 129, 1024>(
        sk, message, rng,
    )
}

/// As [`pss_sign_sha256`], but with the salt supplied directly instead of drawn from an RNG.
pub fn pss_sign_sha256_with_salt(
    sk: &Rsa8192PrivateKey,
    message: &[u8],
    salt: &[u8; 32],
) -> Result<[u8; 1024], SignatureError> {
    rsassa_pss::sign_with_salt::<SHA256, 32, 36, 32, 72, 991, 128, 256, 257, 64, 128, 129, 1024>(
        sk, message, salt,
    )
}

/// RSASSA-PSS (RFC 8017 §8.1) verification against a SHA-256/MGF1-SHA-256/32-byte-salt encoding.
/// See [`rsassa_pss::verify`] for what each error means.
pub fn pss_verify_sha256(
    pk: &Rsa8192PublicKey,
    message: &[u8],
    signature: &[u8; 1024],
) -> Result<(), SignatureError> {
    rsassa_pss::verify::<SHA256, 32, 36, 32, 72, 991, 128, 256, 257, 1024>(pk, message, signature)
}

/// RSASSA-PSS (RFC 8017 §8.1) signing with SHA-384 and a 48-byte salt drawn fresh from `rng`. See
/// [`rsassa_pss::sign`] for what each error means.
pub fn pss_sign_sha384(
    sk: &Rsa8192PrivateKey,
    message: &[u8],
    rng: &mut dyn RNG,
) -> Result<[u8; 1024], SignatureError> {
    rsassa_pss::sign::<SHA384, 48, 52, 48, 104, 975, 128, 256, 257, 64, 128, 129, 1024>(
        sk, message, rng,
    )
}

/// As [`pss_sign_sha384`], but with the salt supplied directly instead of drawn from an RNG.
pub fn pss_sign_sha384_with_salt(
    sk: &Rsa8192PrivateKey,
    message: &[u8],
    salt: &[u8; 48],
) -> Result<[u8; 1024], SignatureError> {
    rsassa_pss::sign_with_salt::<SHA384, 48, 52, 48, 104, 975, 128, 256, 257, 64, 128, 129, 1024>(
        sk, message, salt,
    )
}

/// RSASSA-PSS (RFC 8017 §8.1) verification against a SHA-384/MGF1-SHA-384/48-byte-salt encoding.
/// See [`rsassa_pss::verify`] for what each error means.
pub fn pss_verify_sha384(
    pk: &Rsa8192PublicKey,
    message: &[u8],
    signature: &[u8; 1024],
) -> Result<(), SignatureError> {
    rsassa_pss::verify::<SHA384, 48, 52, 48, 104, 975, 128, 256, 257, 1024>(pk, message, signature)
}

/// RSASSA-PSS (RFC 8017 §8.1) signing with SHA-512 and a 64-byte salt drawn fresh from `rng`. See
/// [`rsassa_pss::sign`] for what each error means.
pub fn pss_sign_sha512(
    sk: &Rsa8192PrivateKey,
    message: &[u8],
    rng: &mut dyn RNG,
) -> Result<[u8; 1024], SignatureError> {
    rsassa_pss::sign::<SHA512, 64, 68, 64, 136, 959, 128, 256, 257, 64, 128, 129, 1024>(
        sk, message, rng,
    )
}

/// As [`pss_sign_sha512`], but with the salt supplied directly instead of drawn from an RNG.
pub fn pss_sign_sha512_with_salt(
    sk: &Rsa8192PrivateKey,
    message: &[u8],
    salt: &[u8; 64],
) -> Result<[u8; 1024], SignatureError> {
    rsassa_pss::sign_with_salt::<SHA512, 64, 68, 64, 136, 959, 128, 256, 257, 64, 128, 129, 1024>(
        sk, message, salt,
    )
}

/// RSASSA-PSS (RFC 8017 §8.1) verification against a SHA-512/MGF1-SHA-512/64-byte-salt encoding.
/// See [`rsassa_pss::verify`] for what each error means.
pub fn pss_verify_sha512(
    pk: &Rsa8192PublicKey,
    message: &[u8],
    signature: &[u8; 1024],
) -> Result<(), SignatureError> {
    rsassa_pss::verify::<SHA512, 64, 68, 64, 136, 959, 128, 256, 257, 1024>(pk, message, signature)
}
