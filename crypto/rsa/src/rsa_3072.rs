//! RSA-3072: `L = 48` (3072 bits), `HALF = 24` (1536-bit CRT primes). See [`crate::rsa_2048`]'s
//! docs for the pattern every concrete modulus size in this crate follows.

use crate::keys::{RsaPrivateKey, RsaPublicKey};
use crate::rsassa_pkcs1_v1_5::RSASSA_PKCS1_v1_5;
use crate::rsassa_pss::RSASSA_PSS;
use crate::rsassa_pss_shake::RSASSA_PSS_SHAKE;
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{SignaturePrivateKey, SignaturePublicKey};
use bouncycastle_sha2::{SHA256, SHA384, SHA512};
use bouncycastle_sha3::SHAKE128;

/// An RSA-3072 private key (`p`, `q` each 1536 bits).
pub type RSA3072PrivateKey = RsaPrivateKey<48, 24>;
/// An RSA-3072 public key.
pub type RSA3072PublicKey = RsaPublicKey<48>;

/// Encoded length of an [`RSA3072PrivateKey`] under [`SignaturePrivateKey`]: five 192-byte
/// values (see [`RsaPrivateKey`]'s `# Encoding`).
pub const SK_LEN: usize = 960;
/// Encoded length of an [`RSA3072PublicKey`] under [`SignaturePublicKey`]: 384 + 4 bytes (see
/// [`RsaPublicKey`]'s `# Encoding`).
pub const PK_LEN: usize = 388;
/// Signature length: `k`, the modulus length in octets (RFC 8017 §8.1.1/§8.2.1 step 2.c).
pub const SIG_LEN: usize = 384;

impl SignaturePrivateKey<SK_LEN> for RSA3072PrivateKey {
    fn encode(&self) -> [u8; SK_LEN] {
        self.encode_raw::<192, SK_LEN>()
    }

    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        *out = self.encode_raw::<192, SK_LEN>();
        SK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let bytes: &[u8; SK_LEN] = bytes
            .try_into()
            .map_err(|_| SignatureError::DecodingError("RSA-3072 private key must be 960 bytes"))?;
        Self::from_bytes_raw::<192, SK_LEN>(bytes)
    }
}

impl SignaturePublicKey<PK_LEN> for RSA3072PublicKey {
    fn encode(&self) -> [u8; PK_LEN] {
        self.encode_raw::<384, PK_LEN>()
    }

    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        *out = self.encode_raw::<384, PK_LEN>();
        PK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let bytes: &[u8; PK_LEN] = bytes
            .try_into()
            .map_err(|_| SignatureError::DecodingError("RSA-3072 public key must be 388 bytes"))?;
        Self::from_bytes_raw::<384, PK_LEN>(bytes)
    }
}

/// RSASSA-PKCS1-v1_5/SHA-256 over RSA-3072 as a `Signer`/`SignatureVerifier`; see
/// [`crate::rsa_2048::RSASSA_PKCS1_v1_5_SHA256`] for the pattern.
#[allow(non_camel_case_types)]
pub type RSASSA_PKCS1_v1_5_SHA256 =
    RSASSA_PKCS1_v1_5<SHA256, 32, 51, 48, 96, 97, 24, 48, 49, 384, SK_LEN, PK_LEN>;
/// RSASSA-PKCS1-v1_5/SHA-384 over RSA-3072.
#[allow(non_camel_case_types)]
pub type RSASSA_PKCS1_v1_5_SHA384 =
    RSASSA_PKCS1_v1_5<SHA384, 48, 67, 48, 96, 97, 24, 48, 49, 384, SK_LEN, PK_LEN>;
/// RSASSA-PKCS1-v1_5/SHA-512 over RSA-3072.
#[allow(non_camel_case_types)]
pub type RSASSA_PKCS1_v1_5_SHA512 =
    RSASSA_PKCS1_v1_5<SHA512, 64, 83, 48, 96, 97, 24, 48, 49, 384, SK_LEN, PK_LEN>;

/// RSASSA-PSS/SHA-256 over RSA-3072 as a `Signer`/`SignatureVerifier`; see
/// [`crate::rsa_2048::RSASSA_PSS_SHA256`] for the pattern (including where the salt comes from).
#[allow(non_camel_case_types)]
pub type RSASSA_PSS_SHA256 =
    RSASSA_PSS<SHA256, 32, 36, 32, 72, 351, 48, 96, 97, 24, 48, 49, 384, SK_LEN, PK_LEN>;
/// RSASSA-PSS/SHA-384 over RSA-3072.
#[allow(non_camel_case_types)]
pub type RSASSA_PSS_SHA384 =
    RSASSA_PSS<SHA384, 48, 52, 48, 104, 335, 48, 96, 97, 24, 48, 49, 384, SK_LEN, PK_LEN>;
/// RSASSA-PSS/SHA-512 over RSA-3072.
#[allow(non_camel_case_types)]
pub type RSASSA_PSS_SHA512 =
    RSASSA_PSS<SHA512, 64, 68, 64, 136, 319, 48, 96, 97, 24, 48, 49, 384, SK_LEN, PK_LEN>;
/// RSASSA-PSS-SHAKE128 (RFC 8702 §3.2.1) over RSA-3072 as a `Signer`/`SignatureVerifier`.
#[allow(non_camel_case_types)]
pub type RSASSA_PSS_SHAKE128 =
    RSASSA_PSS_SHAKE<SHAKE128, 32, 32, 72, 351, 48, 96, 97, 24, 48, 49, 384, SK_LEN, PK_LEN>;
