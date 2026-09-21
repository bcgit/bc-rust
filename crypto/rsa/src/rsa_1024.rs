//! RSA-1024: verification only. `L = 16` (1024 bits). There is no `RSA1024PrivateKey` and no
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
//!
//! The same verification-only scope holds for the `bouncycastle_core` trait types
//! ([`RSASSA_PKCS1_v1_5_SHA256`], [`RSASSA_PKCS1_v1_5_SHA384`]): they implement
//! `SignatureVerifier` but not `Signer`, because `Signer` is only implemented where the private
//! key type implements `SignaturePrivateKey`, and `RsaPrivateKey<16, 8>` does not (no size module
//! declares it). Enforced by the compiler, as this doctest pins:
//!
//! ```compile_fail
//! use bouncycastle_core::traits::Signer;
//! use bouncycastle_rsa::keys::RsaPrivateKey;
//! use bouncycastle_rsa::rsa_1024::RSASSA_PKCS1_v1_5_SHA256;
//!
//! fn sign_1024(sk: &RsaPrivateKey<16, 8>) {
//!     // error: no function or associated item named `sign` -- there is no `Signer` impl.
//!     let _ = RSASSA_PKCS1_v1_5_SHA256::sign(sk, b"", None);
//! }
//! ```

use crate::keys::RsaPublicKey;
use crate::rsassa_pkcs1_v1_5::RSASSA_PKCS1_v1_5;
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::SignaturePublicKey;
use bouncycastle_sha2::{SHA256, SHA384};

/// An RSA-1024 public key.
pub type RSA1024PublicKey = RsaPublicKey<16>;

/// Encoded length of an [`RSA1024PublicKey`] under [`SignaturePublicKey`]: 128 + 4 bytes (see
/// [`RsaPublicKey`]'s `# Encoding`).
pub const PK_LEN: usize = 132;
/// Signature length: `k`, the modulus length in octets (RFC 8017 §8.2.1 step 2.c).
pub const SIG_LEN: usize = 128;

impl SignaturePublicKey<PK_LEN> for RSA1024PublicKey {
    fn encode(&self) -> [u8; PK_LEN] {
        self.encode_raw::<128, PK_LEN>()
    }

    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        *out = self.encode_raw::<128, PK_LEN>();
        PK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let bytes: &[u8; PK_LEN] = bytes
            .try_into()
            .map_err(|_| SignatureError::DecodingError("RSA-1024 public key must be 132 bytes"))?;
        Self::from_bytes_raw::<128, PK_LEN>(bytes)
    }
}

/// RSASSA-PKCS1-v1_5/SHA-256 over RSA-1024 as a `SignatureVerifier` only (see the module docs):
/// [`RSASSA_PKCS1_v1_5`] at this size's widths. The signing-side
/// widths the generic type also needs (`HALF = 8`, `HALF2 = 16`, `HALF21 = 17`, `SK_LEN = 320`)
/// are what an RSA-1024 CRT key would have if one existed; they name the type but nothing uses
/// them, since the `Signer` impl they would feed does not exist for `RsaPrivateKey<16, 8>`.
#[allow(non_camel_case_types)]
pub type RSASSA_PKCS1_v1_5_SHA256 =
    RSASSA_PKCS1_v1_5<SHA256, 32, 51, 16, 32, 33, 8, 16, 17, 128, 320, PK_LEN>;
/// RSASSA-PKCS1-v1_5/SHA-384 over RSA-1024, verify-only; see [`RSASSA_PKCS1_v1_5_SHA256`].
#[allow(non_camel_case_types)]
pub type RSASSA_PKCS1_v1_5_SHA384 =
    RSASSA_PKCS1_v1_5<SHA384, 48, 67, 16, 32, 33, 8, 16, 17, 128, 320, PK_LEN>;
