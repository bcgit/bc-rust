//! RSA-4096: `L = 64` (4096 bits), `HALF = 32` (2048-bit CRT primes). See [`crate::rsa_2048`]'s
//! docs for the pattern every concrete modulus size in this crate follows.

use crate::keys::{RsaPrivateKey, RsaPublicKey};
use crate::rsassa_pkcs1_v1_5::RSASSA_PKCS1_v1_5;
use crate::rsassa_pss::RSASSA_PSS;
use crate::rsassa_pss_shake::RSASSA_PSS_SHAKE;
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{RNG, SecurityStrength, SignaturePrivateKey, SignaturePublicKey};
use bouncycastle_rng::DefaultRNG;
use bouncycastle_sha2::{SHA256, SHA384, SHA512};
use bouncycastle_sha3::SHAKE256;
use core::num::NonZeroUsize;

/// An RSA-4096 private key (`p`, `q` each 2048 bits).
pub type RSA4096PrivateKey = RsaPrivateKey<64, 32>;
/// An RSA-4096 public key.
pub type RSA4096PublicKey = RsaPublicKey<64>;

/// Encoded length of an [`RSA4096PrivateKey`] under [`SignaturePrivateKey`]: five 256-byte
/// values (see [`RsaPrivateKey`]'s `# Encoding`).
pub const SK_LEN: usize = 1280;
/// Encoded length of an [`RSA4096PublicKey`] under [`SignaturePublicKey`]: 512 + 4 bytes (see
/// [`RsaPublicKey`]'s `# Encoding`).
pub const PK_LEN: usize = 516;
/// Signature length: `k`, the modulus length in octets (RFC 8017 §8.1.1/§8.2.1 step 2.c).
pub const SIG_LEN: usize = 512;

/// FIPS 186-5 Appendix A.1.3 key pair generation for RSA-4096 (see [`crate::keygen`]), sourcing
/// the candidates from the library's default OS-backed RNG. `e` is [`crate::keygen::PUBLIC_EXPONENT`].
pub fn keygen() -> Result<(RSA4096PublicKey, RSA4096PrivateKey), SignatureError> {
    keygen_from_rng(&mut DefaultRNG::default())
}

/// As [`keygen`], but sourcing the candidates from the caller-provided RNG, which must offer a
/// security strength of at least 128 bits: SP 800-57 Part 1 Rev. 5, Table 2 lists 128 for `k = 3072` and 192 for `k = 7680`, so 4096 is at least 128. Each
/// candidate prime gets 4 Miller-Rabin rounds: FIPS 186-5 Table B.1's row for 2048-bit `p` and `q` at an error probability of `2^-144` (the strength Table B.1 itself pairs with this size).
pub fn keygen_from_rng(
    rng: &mut dyn RNG,
) -> Result<(RSA4096PublicKey, RSA4096PrivateKey), SignatureError> {
    crate::keygen::keygen_from_rng::<32, 64, 65>(
        rng,
        NonZeroUsize::new(4).expect("nonzero literal"),
        SecurityStrength::_128bit,
    )
}

impl SignaturePrivateKey<SK_LEN> for RSA4096PrivateKey {
    fn encode(&self) -> [u8; SK_LEN] {
        self.encode_raw::<256, SK_LEN>()
    }

    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        *out = self.encode_raw::<256, SK_LEN>();
        SK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let bytes: &[u8; SK_LEN] = bytes.try_into().map_err(|_| {
            SignatureError::DecodingError("RSA-4096 private key must be 1280 bytes")
        })?;
        Self::from_bytes_raw::<256, SK_LEN>(bytes)
    }
}

impl SignaturePublicKey<PK_LEN> for RSA4096PublicKey {
    fn encode(&self) -> [u8; PK_LEN] {
        self.encode_raw::<512, PK_LEN>()
    }

    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        *out = self.encode_raw::<512, PK_LEN>();
        PK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let bytes: &[u8; PK_LEN] = bytes
            .try_into()
            .map_err(|_| SignatureError::DecodingError("RSA-4096 public key must be 516 bytes"))?;
        Self::from_bytes_raw::<512, PK_LEN>(bytes)
    }
}

/// RSASSA-PKCS1-v1_5/SHA-256 over RSA-4096 as a `Signer`/`SignatureVerifier`; see
/// [`crate::rsa_2048::RSASSA_PKCS1_v1_5_SHA256`] for the pattern.
#[allow(non_camel_case_types)]
pub type RSASSA_PKCS1_v1_5_SHA256 =
    RSASSA_PKCS1_v1_5<SHA256, 32, 51, 64, 128, 129, 32, 64, 65, 512, SK_LEN, PK_LEN>;
/// RSASSA-PKCS1-v1_5/SHA-384 over RSA-4096.
#[allow(non_camel_case_types)]
pub type RSASSA_PKCS1_v1_5_SHA384 =
    RSASSA_PKCS1_v1_5<SHA384, 48, 67, 64, 128, 129, 32, 64, 65, 512, SK_LEN, PK_LEN>;
/// RSASSA-PKCS1-v1_5/SHA-512 over RSA-4096.
#[allow(non_camel_case_types)]
pub type RSASSA_PKCS1_v1_5_SHA512 =
    RSASSA_PKCS1_v1_5<SHA512, 64, 83, 64, 128, 129, 32, 64, 65, 512, SK_LEN, PK_LEN>;

/// RSASSA-PSS/SHA-256 over RSA-4096 as a `Signer`/`SignatureVerifier`; see
/// [`crate::rsa_2048::RSASSA_PSS_SHA256`] for the pattern (including where the salt comes from).
#[allow(non_camel_case_types)]
pub type RSASSA_PSS_SHA256 =
    RSASSA_PSS<SHA256, 32, 36, 32, 72, 479, 64, 128, 129, 32, 64, 65, 512, SK_LEN, PK_LEN>;
/// RSASSA-PSS/SHA-384 over RSA-4096.
#[allow(non_camel_case_types)]
pub type RSASSA_PSS_SHA384 =
    RSASSA_PSS<SHA384, 48, 52, 48, 104, 463, 64, 128, 129, 32, 64, 65, 512, SK_LEN, PK_LEN>;
/// RSASSA-PSS/SHA-512 over RSA-4096.
#[allow(non_camel_case_types)]
pub type RSASSA_PSS_SHA512 =
    RSASSA_PSS<SHA512, 64, 68, 64, 136, 447, 64, 128, 129, 32, 64, 65, 512, SK_LEN, PK_LEN>;
/// RSASSA-PSS-SHAKE256 (RFC 8702 §3.2.1) over RSA-4096 as a `Signer`/`SignatureVerifier`.
#[allow(non_camel_case_types)]
pub type RSASSA_PSS_SHAKE256 =
    RSASSA_PSS_SHAKE<SHAKE256, 64, 64, 136, 447, 64, 128, 129, 32, 64, 65, 512, SK_LEN, PK_LEN>;
