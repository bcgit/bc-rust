//! RSA-2048: the generic engine ([`crate::modexp`], [`crate::rsa_core`], [`crate::rsassa_pkcs1_v1_5`],
//! [`crate::rsassa_pss`]) wired to concrete widths -- `L = 32` (2048 bits), `HALF = 16` (1024-bit
//! CRT primes) -- so a caller using this size doesn't thread const-generic width parameters
//! through every call. One file per modulus size, matching [`crate::keys::RsaPrivateKey`]'s own
//! `<L, HALF>` shape; `rsa_1024`/`rsa_3072`/`rsa_4096`/`rsa_8192` are the same pattern at their
//! own widths. PSS's salt length is fixed to each hash's own output length (`H_LEN`) throughout,
//! matching RFC 8017 §9.1 note 4's "typical" choice and Wycheproof's own
//! `rsa_pss_2048_sha256_mgf1_32_test.json`/`..._sha384_mgf1_48_test.json`.
//!
//! Each (scheme, hash) pairing is offered two ways over the same code path: a pair of free
//! functions taking a whole message (`pkcs1_v1_5_sign_sha256`/`pkcs1_v1_5_verify_sha256`, ...),
//! and a type implementing `bouncycastle_core`'s `Signer`/`SignatureVerifier` traits
//! ([`RSASSA_PKCS1_v1_5_SHA256`], ...) for streaming use and for code written against those
//! traits. The key types implement `SignaturePrivateKey`/`SignaturePublicKey` here, at this
//! size's [`SK_LEN`]/[`PK_LEN`].

use crate::keys::{RsaPrivateKey, RsaPublicKey};
use crate::rsassa_pkcs1_v1_5;
use crate::rsassa_pkcs1_v1_5::RSASSA_PKCS1_v1_5;
use crate::rsassa_pss;
use crate::rsassa_pss::RSASSA_PSS;
use crate::rsassa_pss_shake;
use crate::rsassa_pss_shake::RSASSA_PSS_SHAKE;
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{RNG, SignaturePrivateKey, SignaturePublicKey};
use bouncycastle_sha2::{SHA256, SHA384, SHA512};
use bouncycastle_sha3::SHAKE128;

/// An RSA-2048 private key (`p`, `q` each 1024 bits).
pub type Rsa2048PrivateKey = RsaPrivateKey<32, 16>;
/// An RSA-2048 public key.
pub type Rsa2048PublicKey = RsaPublicKey<32>;

/// Encoded length of an [`Rsa2048PrivateKey`] under [`SignaturePrivateKey`]: `p || q || dP || dQ
/// || qInv`, five 128-byte values (see [`RsaPrivateKey`]'s `# Encoding`).
pub const SK_LEN: usize = 640;
/// Encoded length of an [`Rsa2048PublicKey`] under [`SignaturePublicKey`]: `n || e`, 256 + 4
/// bytes (see [`RsaPublicKey`]'s `# Encoding`).
pub const PK_LEN: usize = 260;
/// Signature length: `k`, the modulus length in octets (RFC 8017 §8.1.1/§8.2.1 step 2.c).
pub const SIG_LEN: usize = 256;

impl SignaturePrivateKey<SK_LEN> for Rsa2048PrivateKey {
    fn encode(&self) -> [u8; SK_LEN] {
        self.encode_raw::<128, SK_LEN>()
    }

    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        *out = self.encode_raw::<128, SK_LEN>();
        SK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let bytes: &[u8; SK_LEN] = bytes
            .try_into()
            .map_err(|_| SignatureError::DecodingError("RSA-2048 private key must be 640 bytes"))?;
        Self::from_bytes_raw::<128, SK_LEN>(bytes)
    }
}

impl SignaturePublicKey<PK_LEN> for Rsa2048PublicKey {
    fn encode(&self) -> [u8; PK_LEN] {
        self.encode_raw::<256, PK_LEN>()
    }

    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        *out = self.encode_raw::<256, PK_LEN>();
        PK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let bytes: &[u8; PK_LEN] = bytes
            .try_into()
            .map_err(|_| SignatureError::DecodingError("RSA-2048 public key must be 260 bytes"))?;
        Self::from_bytes_raw::<256, PK_LEN>(bytes)
    }
}

/// RSASSA-PKCS1-v1_5/SHA-256 over RSA-2048 as a `Signer`/`SignatureVerifier`: [`RSASSA_PKCS1_v1_5`]
/// at the widths [`pkcs1_v1_5_sign_sha256`] passes. Deterministic, so `Signer::sign` reproduces
/// that function's output byte for byte.
#[allow(non_camel_case_types)]
pub type RSASSA_PKCS1_v1_5_SHA256 =
    RSASSA_PKCS1_v1_5<SHA256, 32, 51, 32, 64, 65, 16, 32, 33, 256, SK_LEN, PK_LEN>;
/// RSASSA-PKCS1-v1_5/SHA-384 over RSA-2048; see [`RSASSA_PKCS1_v1_5_SHA256`].
#[allow(non_camel_case_types)]
pub type RSASSA_PKCS1_v1_5_SHA384 =
    RSASSA_PKCS1_v1_5<SHA384, 48, 67, 32, 64, 65, 16, 32, 33, 256, SK_LEN, PK_LEN>;
/// RSASSA-PKCS1-v1_5/SHA-512 over RSA-2048; see [`RSASSA_PKCS1_v1_5_SHA256`].
#[allow(non_camel_case_types)]
pub type RSASSA_PKCS1_v1_5_SHA512 =
    RSASSA_PKCS1_v1_5<SHA512, 64, 83, 32, 64, 65, 16, 32, 33, 256, SK_LEN, PK_LEN>;

/// RSASSA-PSS/SHA-256 (MGF1-SHA-256, 32-byte salt) over RSA-2048 as a `Signer`/`SignatureVerifier`:
/// [`RSASSA_PSS`] at the widths [`pss_sign_sha256`] passes, drawing its salt from the library's
/// default RNG (see that type's docs).
#[allow(non_camel_case_types)]
pub type RSASSA_PSS_SHA256 =
    RSASSA_PSS<SHA256, 32, 36, 32, 72, 223, 32, 64, 65, 16, 32, 33, 256, SK_LEN, PK_LEN>;
/// RSASSA-PSS/SHA-384 (48-byte salt) over RSA-2048; see [`RSASSA_PSS_SHA256`].
#[allow(non_camel_case_types)]
pub type RSASSA_PSS_SHA384 =
    RSASSA_PSS<SHA384, 48, 52, 48, 104, 207, 32, 64, 65, 16, 32, 33, 256, SK_LEN, PK_LEN>;
/// RSASSA-PSS/SHA-512 (64-byte salt) over RSA-2048; see [`RSASSA_PSS_SHA256`].
#[allow(non_camel_case_types)]
pub type RSASSA_PSS_SHA512 =
    RSASSA_PSS<SHA512, 64, 68, 64, 136, 191, 32, 64, 65, 16, 32, 33, 256, SK_LEN, PK_LEN>;
/// RSASSA-PSS-SHAKE128 (RFC 8702 §3.2.1) over RSA-2048 as a `Signer`/`SignatureVerifier`:
/// [`RSASSA_PSS_SHAKE`] at the widths [`pss_shake128_sign`] passes.
#[allow(non_camel_case_types)]
pub type RSASSA_PSS_SHAKE128 =
    RSASSA_PSS_SHAKE<SHAKE128, 32, 32, 72, 223, 32, 64, 65, 16, 32, 33, 256, SK_LEN, PK_LEN>;

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

/// RSASSA-PSS (RFC 8017 §8.1) signing with SHA-256 (both as the message hash and, per §8.1's own
/// recommendation, as MGF1's hash) and a 32-byte salt drawn fresh from `rng` for each signature.
/// See [`rsassa_pss::sign`] for what each error means.
pub fn pss_sign_sha256(
    sk: &Rsa2048PrivateKey,
    message: &[u8],
    rng: &mut dyn RNG,
) -> Result<[u8; 256], SignatureError> {
    rsassa_pss::sign::<SHA256, 32, 36, 32, 72, 223, 32, 64, 65, 16, 32, 33, 256>(sk, message, rng)
}

/// As [`pss_sign_sha256`], but with the salt supplied directly instead of drawn from an RNG --
/// deterministic, for testing against a known salt. See [`rsassa_pss::sign_with_salt`].
pub fn pss_sign_sha256_with_salt(
    sk: &Rsa2048PrivateKey,
    message: &[u8],
    salt: &[u8; 32],
) -> Result<[u8; 256], SignatureError> {
    rsassa_pss::sign_with_salt::<SHA256, 32, 36, 32, 72, 223, 32, 64, 65, 16, 32, 33, 256>(
        sk, message, salt,
    )
}

/// RSASSA-PSS (RFC 8017 §8.1) verification against a SHA-256/MGF1-SHA-256/32-byte-salt encoding.
/// See [`rsassa_pss::verify`] for what each error means.
pub fn pss_verify_sha256(
    pk: &Rsa2048PublicKey,
    message: &[u8],
    signature: &[u8; 256],
) -> Result<(), SignatureError> {
    rsassa_pss::verify::<SHA256, 32, 36, 32, 72, 223, 32, 64, 65, 256>(pk, message, signature)
}

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) signing with SHA-384. See [`rsassa_pkcs1_v1_5::sign`] for
/// what each error means.
pub fn pkcs1_v1_5_sign_sha384(
    sk: &Rsa2048PrivateKey,
    message: &[u8],
) -> Result<[u8; 256], SignatureError> {
    rsassa_pkcs1_v1_5::sign::<SHA384, 48, 67, 32, 64, 65, 16, 32, 33, 256>(sk, message)
}

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) verification against a SHA-384 digest. See
/// [`rsassa_pkcs1_v1_5::verify`] for what each error means.
pub fn pkcs1_v1_5_verify_sha384(
    pk: &Rsa2048PublicKey,
    message: &[u8],
    signature: &[u8; 256],
) -> Result<(), SignatureError> {
    rsassa_pkcs1_v1_5::verify::<SHA384, 48, 32, 64, 65, 256>(pk, message, signature)
}

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) signing with SHA-512. See [`rsassa_pkcs1_v1_5::sign`] for
/// what each error means.
pub fn pkcs1_v1_5_sign_sha512(
    sk: &Rsa2048PrivateKey,
    message: &[u8],
) -> Result<[u8; 256], SignatureError> {
    rsassa_pkcs1_v1_5::sign::<SHA512, 64, 83, 32, 64, 65, 16, 32, 33, 256>(sk, message)
}

/// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) verification against a SHA-512 digest. See
/// [`rsassa_pkcs1_v1_5::verify`] for what each error means.
pub fn pkcs1_v1_5_verify_sha512(
    pk: &Rsa2048PublicKey,
    message: &[u8],
    signature: &[u8; 256],
) -> Result<(), SignatureError> {
    rsassa_pkcs1_v1_5::verify::<SHA512, 64, 32, 64, 65, 256>(pk, message, signature)
}

/// RSASSA-PSS (RFC 8017 §8.1) signing with SHA-384 (as both the message hash and MGF1's hash)
/// and a 48-byte salt drawn fresh from `rng`. See [`rsassa_pss::sign`] for what each error means.
pub fn pss_sign_sha384(
    sk: &Rsa2048PrivateKey,
    message: &[u8],
    rng: &mut dyn RNG,
) -> Result<[u8; 256], SignatureError> {
    rsassa_pss::sign::<SHA384, 48, 52, 48, 104, 207, 32, 64, 65, 16, 32, 33, 256>(sk, message, rng)
}

/// As [`pss_sign_sha384`], but with the salt supplied directly instead of drawn from an RNG --
/// deterministic, for testing against a known salt. See [`rsassa_pss::sign_with_salt`].
pub fn pss_sign_sha384_with_salt(
    sk: &Rsa2048PrivateKey,
    message: &[u8],
    salt: &[u8; 48],
) -> Result<[u8; 256], SignatureError> {
    rsassa_pss::sign_with_salt::<SHA384, 48, 52, 48, 104, 207, 32, 64, 65, 16, 32, 33, 256>(
        sk, message, salt,
    )
}

/// RSASSA-PSS (RFC 8017 §8.1) verification against a SHA-384/MGF1-SHA-384/48-byte-salt encoding.
/// See [`rsassa_pss::verify`] for what each error means.
pub fn pss_verify_sha384(
    pk: &Rsa2048PublicKey,
    message: &[u8],
    signature: &[u8; 256],
) -> Result<(), SignatureError> {
    rsassa_pss::verify::<SHA384, 48, 52, 48, 104, 207, 32, 64, 65, 256>(pk, message, signature)
}

/// RSASSA-PSS (RFC 8017 §8.1) signing with SHA-512 (as both the message hash and MGF1's hash)
/// and a 64-byte salt drawn fresh from `rng`. See [`rsassa_pss::sign`] for what each error means.
pub fn pss_sign_sha512(
    sk: &Rsa2048PrivateKey,
    message: &[u8],
    rng: &mut dyn RNG,
) -> Result<[u8; 256], SignatureError> {
    rsassa_pss::sign::<SHA512, 64, 68, 64, 136, 191, 32, 64, 65, 16, 32, 33, 256>(sk, message, rng)
}

/// As [`pss_sign_sha512`], but with the salt supplied directly instead of drawn from an RNG --
/// deterministic, for testing against a known salt. See [`rsassa_pss::sign_with_salt`].
pub fn pss_sign_sha512_with_salt(
    sk: &Rsa2048PrivateKey,
    message: &[u8],
    salt: &[u8; 64],
) -> Result<[u8; 256], SignatureError> {
    rsassa_pss::sign_with_salt::<SHA512, 64, 68, 64, 136, 191, 32, 64, 65, 16, 32, 33, 256>(
        sk, message, salt,
    )
}

/// RSASSA-PSS (RFC 8017 §8.1) verification against a SHA-512/MGF1-SHA-512/64-byte-salt encoding.
/// See [`rsassa_pss::verify`] for what each error means.
pub fn pss_verify_sha512(
    pk: &Rsa2048PublicKey,
    message: &[u8],
    signature: &[u8; 256],
) -> Result<(), SignatureError> {
    rsassa_pss::verify::<SHA512, 64, 68, 64, 136, 191, 32, 64, 65, 256>(pk, message, signature)
}

/// RSASSA-PSS-SHAKE128 (`id-RSASSA-PSS-SHAKE128`, RFC 8702 §3.2.1) signing: SHAKE128 as both the
/// message hash and, natively rather than through MGF1, the mask generation function, with a
/// 32-byte salt drawn fresh from `rng` for each signature. RFC 8702 §5 recommends this pairing for
/// a 2048- or 3072-bit RSA modulus. See [`rsassa_pss_shake::sign`] for what each error means.
pub fn pss_shake128_sign(
    sk: &Rsa2048PrivateKey,
    message: &[u8],
    rng: &mut dyn RNG,
) -> Result<[u8; 256], SignatureError> {
    rsassa_pss_shake::sign::<SHAKE128, 32, 32, 72, 223, 32, 64, 65, 16, 32, 33, 256>(
        sk, message, rng,
    )
}

/// As [`pss_shake128_sign`], but with the salt supplied directly instead of drawn from an RNG --
/// deterministic, for testing against a known salt. See [`rsassa_pss_shake::sign_with_salt`].
pub fn pss_shake128_sign_with_salt(
    sk: &Rsa2048PrivateKey,
    message: &[u8],
    salt: &[u8; 32],
) -> Result<[u8; 256], SignatureError> {
    rsassa_pss_shake::sign_with_salt::<SHAKE128, 32, 32, 72, 223, 32, 64, 65, 16, 32, 33, 256>(
        sk, message, salt,
    )
}

/// RSASSA-PSS-SHAKE128 (RFC 8702 §3.2.1) verification. See [`rsassa_pss_shake::verify`] for what
/// each error means.
pub fn pss_shake128_verify(
    pk: &Rsa2048PublicKey,
    message: &[u8],
    signature: &[u8; 256],
) -> Result<(), SignatureError> {
    rsassa_pss_shake::verify::<SHAKE128, 32, 32, 72, 223, 32, 64, 65, 256>(pk, message, signature)
}
