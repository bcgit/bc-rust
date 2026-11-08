//! RSA-2048: the generic engine ([`crate::modexp`], [`crate::rsa_core`], [`crate::rsassa_pkcs1_v1_5`],
//! [`crate::rsassa_pss`]) wired to concrete widths -- `L = 32` (2048 bits), `HALF = 16` (1024-bit
//! CRT primes) -- so a caller using this size doesn't thread const-generic width parameters
//! through every call. One file per modulus size, matching [`crate::keys::RsaPrivateKey`]'s own
//! `<L, HALF>` shape; `rsa_1024`/`rsa_3072`/`rsa_4096`/`rsa_8192` are the same pattern at their
//! own widths. PSS's salt length is fixed to each hash's own output length (`H_LEN`) throughout,
//! matching RFC 8017 §9.1 note 4's "typical" choice and Wycheproof's own
//! `rsa_pss_2048_sha256_mgf1_32_test.json`/`..._sha384_mgf1_48_test.json`.
//!
//! Each (scheme, hash) pairing is an algorithm marker the key role traits are implemented over
//! ([`RSASSA_PKCS1_v1_5_SHA256`], [`RSASSA_PSS_SHA256`], [`RSASSA_PSS_SHAKE128`], ...): one-shot
//! or streaming, with PSS's salt from the RNG handed to `create_signer` or fixed through `set_salt`
//! on the signer. The key types implement
//! `SignaturePrivateKey`/`SignaturePublicKey` here, at this size's [`SK_LEN`]/[`PK_LEN`].

use crate::keys::{RsaPrivateKey, RsaPublicKey};
use crate::rsassa_pkcs1_v1_5::RSASSA_PKCS1_v1_5;
use crate::rsassa_pss::RSASSA_PSS;
use crate::rsassa_pss_shake::RSASSA_PSS_SHAKE;
use crate::rsasve::{RsaKEMPrivateKey, RsaKEMPublicKey, RsasveDecapsulator, RsasveEncapsulator};
use bouncycastle_core::errors::{KEMError, SignatureError};
use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    KEMPrivateKey, KEMPublicKey, RNG, SignaturePrivateKey, SignaturePublicKey,
};
use bouncycastle_sha2::{SHA256, SHA384, SHA512};
use bouncycastle_sha3::SHAKE128;
use core::num::NonZeroUsize;

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

/// As [`keygen`], but sourcing the candidates from the caller-provided RNG, which must offer a
/// security strength of at least 112 bits (SP 800-57 Part 1 Rev. 5, Table 2, `k = 2048`). Each
/// candidate prime gets 5 Miller-Rabin rounds: FIPS 186-5 Table B.1's row for 1024-bit `p` and `q` at an error probability of `2^-112`, RSA-2048's security strength (SP 800-57 Part 1 Rev. 5, Table 2).
pub fn keygen(rng: &mut dyn RNG) -> Result<(RSA2048PublicKey, RSA2048PrivateKey), SignatureError> {
    crate::keygen::keygen_from_rng::<16, 32, 33>(
        rng,
        NonZeroUsize::new(5).expect("nonzero literal"),
        SecurityStrength::_112bit,
    )
}

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

/// RSASSA-PKCS1-v1_5/SHA-256 over RSA-2048 through the key role traits: [`RSASSA_PKCS1_v1_5`]
/// at this size's widths. Deterministic: PKCS#1 v1.5 has no randomness, so it is the
/// `DeterministicSigningKey` role and always reproduces the same signature.
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

/// RSASSA-PSS/SHA-256 (MGF1-SHA-256, 32-byte salt) over RSA-2048 through the key role traits:
/// [`RSASSA_PSS`] at this size's widths, drawing its salt from the RNG handed to `SigningKey::create_signer`
/// unless `set_salt` on the signer replaces it (see that type's docs).
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
/// RSASSA-PSS-SHAKE128 (RFC 8702 §3.2.1) over RSA-2048 through the key role traits:
/// [`RSASSA_PSS_SHAKE`] at this size's widths.
#[allow(non_camel_case_types)]
pub type RSASSA_PSS_SHAKE128 =
    RSASSA_PSS_SHAKE<SHAKE128, 32, 32, 72, 223, 32, 64, 65, 16, 32, 33, 256, SK_LEN, PK_LEN>;

/// An RSA-2048 private key-establishment key for [`RSASVE`], kept apart from the signing key type
/// [`RSA2048PrivateKey`] (see [`crate::rsasve`]'s `# Key separation`). It uses the same `SK_LEN`-byte
/// encoding.
pub type RSA2048KEMPrivateKey = RsaKEMPrivateKey<32, 16>;
/// An RSA-2048 public key-establishment key for [`RSASVE`]; see [`RSA2048KEMPrivateKey`]. It uses
/// the same `PK_LEN`-byte encoding.
pub type RSA2048KEMPublicKey = RsaKEMPublicKey<32>;

/// [`RSASVE`] ciphertext length: `nLen`, the modulus length in octets (SP 800-56B Rev. 2
/// §7.2.1.2's output `C`).
pub const CT_LEN: usize = 256;
/// [`RSASVE`] shared-secret length: also `nLen` (§7.2.1.2's output `Z`). This is the raw secret
/// value, not a derived key: see [`crate::rsasve`].
pub const SS_LEN: usize = 256;

/// RSASVE (SP 800-56B Rev. 2 §7.2.1) over RSA-2048, the algorithm the KEM roles of
/// [`RSA2048KEMPublicKey`] and [`RSA2048KEMPrivateKey`] name:
/// [`crate::rsasve::RSASVE`] at this size's widths and its 112-bit security strength.
pub type RSASVE = crate::rsasve::RSASVE<32, 64, 65, 16, 32, 33, 256, 112>;

impl RSASVE {
    /// As [`Self::keygen`], but sourcing the candidates from the caller-provided RNG, with the
    /// same RNG requirements as [`keygen`].
    pub fn keygen(
        rng: &mut dyn RNG,
    ) -> Result<(RSA2048KEMPublicKey, RSA2048KEMPrivateKey), KEMError> {
        crate::rsasve::keygen_from(keygen(rng))
    }
}

impl EncapsulatingKey<(), CT_LEN, SS_LEN> for RSA2048KEMPublicKey {
    type Algorithm = RSASVE;
    type Encapsulator<'k> = RsasveEncapsulator<'k, 32, 64, 65, 256, 112>;

    /// The raw KEM takes nothing beyond the key, so this never fails.
    fn create_encapsulator<'k>(&'k self, _params: ()) -> Result<Self::Encapsulator<'k>, KEMError> {
        Ok(RsasveEncapsulator::new(self))
    }
}

impl DecapsulatingKey<(), CT_LEN, SS_LEN> for RSA2048KEMPrivateKey {
    type Algorithm = RSASVE;
    type Decapsulator<'k> = RsasveDecapsulator<'k, 32, 64, 65, 16, 32, 33, 256, 112>;

    /// The raw KEM takes nothing beyond the key, so this never fails.
    fn create_decapsulator<'k>(&'k self, _params: ()) -> Result<Self::Decapsulator<'k>, KEMError> {
        Ok(RsasveDecapsulator::new(self))
    }
}

impl KEMPrivateKey<SK_LEN> for RSA2048KEMPrivateKey {
    fn encode(&self) -> [u8; SK_LEN] {
        self.0.encode_raw::<128, SK_LEN>()
    }

    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        *out = self.0.encode_raw::<128, SK_LEN>();
        SK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, KEMError> {
        let bytes: &[u8; SK_LEN] = bytes
            .try_into()
            .map_err(|_| KEMError::DecodingError("RSA-2048 private key must be 640 bytes"))?;
        crate::rsasve::private_key_from_bytes::<32, 16, 128, SK_LEN>(bytes)
    }
}

impl KEMPublicKey<PK_LEN> for RSA2048KEMPublicKey {
    fn encode(&self) -> [u8; PK_LEN] {
        self.0.encode_raw::<256, PK_LEN>()
    }

    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        *out = self.0.encode_raw::<256, PK_LEN>();
        PK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, KEMError> {
        let bytes: &[u8; PK_LEN] = bytes
            .try_into()
            .map_err(|_| KEMError::DecodingError("RSA-2048 public key must be 260 bytes"))?;
        crate::rsasve::public_key_from_bytes::<32, 256, PK_LEN>(bytes)
    }
}
