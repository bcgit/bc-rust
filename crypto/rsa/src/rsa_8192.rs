//! RSA-8192: `L = 128` (8192 bits), `HALF = 64` (4096-bit CRT primes). See [`crate::rsa_2048`]'s
//! docs for the pattern every concrete modulus size in this crate follows.

use crate::keys::{RsaPrivateKey, RsaPublicKey};
use crate::rsassa_pkcs1_v1_5::RSASSA_PKCS1_v1_5;
use crate::rsassa_pss::RSASSA_PSS;
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{RNG, SecurityStrength, SignaturePrivateKey, SignaturePublicKey};
use bouncycastle_rng::DefaultRNG;
use bouncycastle_sha2::{SHA256, SHA384, SHA512};
use core::num::NonZeroUsize;

/// An RSA-8192 private key (`p`, `q` each 4096 bits).
pub type RSA8192PrivateKey = RsaPrivateKey<128, 64>;
/// An RSA-8192 public key.
pub type RSA8192PublicKey = RsaPublicKey<128>;

/// Encoded length of an [`RSA8192PrivateKey`] under [`SignaturePrivateKey`]: five 512-byte
/// values (see [`RsaPrivateKey`]'s `# Encoding`).
pub const SK_LEN: usize = 2560;
/// Encoded length of an [`RSA8192PublicKey`] under [`SignaturePublicKey`]: 1024 + 4 bytes (see
/// [`RsaPublicKey`]'s `# Encoding`).
pub const PK_LEN: usize = 1028;
/// Signature length: `k`, the modulus length in octets (RFC 8017 §8.1.1/§8.2.1 step 2.c).
pub const SIG_LEN: usize = 1024;

/// FIPS 186-5 Appendix A.1.3 key pair generation for RSA-8192 (see [`crate::keygen`]), sourcing
/// the candidates from the library's default OS-backed RNG. `e` is [`crate::keygen::PUBLIC_EXPONENT`].
pub fn keygen() -> Result<(RSA8192PublicKey, RSA8192PrivateKey), SignatureError> {
    keygen_from_rng(&mut DefaultRNG::default())
}

/// As [`keygen`], but sourcing the candidates from the caller-provided RNG, which must offer a
/// security strength of at least 192 bits (SP 800-57 Part 1 Rev. 5, Table 2: `k = 7680` gives 192, and 8192 exceeds it). Each
/// candidate prime gets 4 Miller-Rabin rounds: FIPS 186-5 Table B.1 stops at 2048-bit primes; Appendix C.1's formula (2), which reproduces every entry of that table, gives 3 rounds for 4096-bit primes at `2^-192` (RSA-8192 exceeds SP 800-57's 7680-bit/192-bit row) and 5 at `2^-256`, so 4 is taken, matching the table's last row with margin.
pub fn keygen_from_rng(
    rng: &mut dyn RNG,
) -> Result<(RSA8192PublicKey, RSA8192PrivateKey), SignatureError> {
    crate::keygen::keygen_from_rng::<64, 128, 129>(
        rng,
        NonZeroUsize::new(4).expect("nonzero literal"),
        SecurityStrength::_192bit,
    )
}

impl SignaturePrivateKey<SK_LEN> for RSA8192PrivateKey {
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

impl SignaturePublicKey<PK_LEN> for RSA8192PublicKey {
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
