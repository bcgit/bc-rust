//! RSA-2048: the generic engine ([`crate::modexp`], [`crate::rsa_core`], [`crate::rsassa_pkcs1_v1_5`],
//! [`crate::rsassa_pss`]) wired to concrete widths -- `L = 32` (2048 bits), `HALF = 16` (1024-bit
//! CRT primes) -- so a caller using this size doesn't thread const-generic width parameters
//! through every call. One file per modulus size, matching [`crate::keys::RsaPrivateKey`]'s own
//! `<L, HALF>` shape; `rsa_1024`/`rsa_3072`/`rsa_4096`/`rsa_8192` are the same pattern at their
//! own widths. PSS's salt length is fixed to each hash's own output length (`H_LEN`) throughout,
//! matching RFC 8017 §9.1 note 4's "typical" choice and Wycheproof's own
//! `rsa_pss_2048_sha256_mgf1_32_test.json`/`..._sha384_mgf1_48_test.json`.
//!
//! Each (scheme, hash) pairing is a type implementing `bouncycastle_core`'s
//! `Signer`/`SignatureVerifier` traits ([`RSASSA_PKCS1_v1_5_SHA256`], [`RSASSA_PSS_SHA256`],
//! [`RSASSA_PSS_SHAKE128`], ...): one-shot or streaming, with PSS's salt from the default RNG or
//! under the caller's control via `sign_randomized`/`set_signer_salt`. The key types implement
//! `SignaturePrivateKey`/`SignaturePublicKey` here, at this size's [`SK_LEN`]/[`PK_LEN`].

use crate::keys::{RsaPrivateKey, RsaPublicKey};
use crate::rsassa_pkcs1_v1_5::RSASSA_PKCS1_v1_5;
use crate::rsassa_pss::RSASSA_PSS;
use crate::rsassa_pss_shake::RSASSA_PSS_SHAKE;
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{SignaturePrivateKey, SignaturePublicKey};
use bouncycastle_sha2::{SHA256, SHA384, SHA512};
use bouncycastle_sha3::SHAKE128;

/// An RSA-2048 private key (`p`, `q` each 1024 bits).
pub type RSA2048PrivateKey = RsaPrivateKey<32, 16>;
/// An RSA-2048 public key.
pub type RSA2048PublicKey = RsaPublicKey<32>;

/// Encoded length of an [`RSA2048PrivateKey`] under [`SignaturePrivateKey`]: `p || q || dP || dQ
/// || qInv`, five 128-byte values (see [`RsaPrivateKey`]'s `# Encoding`).
pub const SK_LEN: usize = 640;
/// Encoded length of an [`RSA2048PublicKey`] under [`SignaturePublicKey`]: `n || e`, 256 + 4
/// bytes (see [`RsaPublicKey`]'s `# Encoding`).
pub const PK_LEN: usize = 260;
/// Signature length: `k`, the modulus length in octets (RFC 8017 §8.1.1/§8.2.1 step 2.c).
pub const SIG_LEN: usize = 256;

impl SignaturePrivateKey<SK_LEN> for RSA2048PrivateKey {
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

impl SignaturePublicKey<PK_LEN> for RSA2048PublicKey {
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
/// at this size's widths. Deterministic: PKCS#1 v1.5 has no randomness, so `Signer::sign`
/// always reproduces the same signature.
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
/// [`RSASSA_PSS`] at this size's widths, drawing its salt from the library's default RNG unless
/// `sign_randomized`/`set_signer_salt` supply it (see that type's docs).
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
/// [`RSASSA_PSS_SHAKE`] at this size's widths.
#[allow(non_camel_case_types)]
pub type RSASSA_PSS_SHAKE128 =
    RSASSA_PSS_SHAKE<SHAKE128, 32, 32, 72, 223, 32, 64, 65, 16, 32, 33, 256, SK_LEN, PK_LEN>;
