//! RSA-3072: the generic types at this size, as aliases over the marker [`RSA3072`]:
//! the key types, `keygen`, every (scheme, hash) pairing offered at this size, and RSASVE.
//! Every (scheme, hash) pairing is an algorithm marker the key role traits are implemented over.
//! PSS's salt length is the hash's own output length throughout, RFC 8017 §9.1 note 4's
//! "typical" choice and Wycheproof's own `rsa_pss_*_mgf1_<hLen>_test.json`.

use crate::keys::{RsaPrivateKey, RsaPublicKey};
use crate::rsassa_pkcs1_v1_5::RSASSA_PKCS1_v1_5;
use crate::rsassa_pss::RSASSA_PSS;
use crate::rsassa_pss_shake::RSASSA_PSS_SHAKE;
use crate::rsasve::{RsaKEMPrivateKey, RsaKEMPublicKey};
pub use crate::size::RSA3072;
use crate::size::{RsaSigningSize, RsaSize};
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::RNG;
use bouncycastle_sha2::{SHA256, SHA384, SHA512};
use bouncycastle_sha3::SHAKE128;

/// An RSA-3072 public key.
pub type RSA3072PublicKey = RsaPublicKey<RSA3072>;
/// Encoded length of an RSA-3072 public key: `n || e`.
pub const PK_LEN: usize = RSA3072::PK_LEN;
/// Length of an RSA-3072 signature: the modulus's.
pub const SIG_LEN: usize = RSA3072::K_LEN;
/// An RSA-3072 private key.
pub type RSA3072PrivateKey = RsaPrivateKey<RSA3072>;
/// Encoded length of an RSA-3072 private key: `p || q || dP || dQ || qInv`.
pub const SK_LEN: usize = RSA3072::SK_LEN;

/// FIPS 186-5 Appendix A.1.3 key generation at RSA-3072: [`RsaSigningSize::keygen`].
///
/// # Errors
/// As [`RsaSigningSize::keygen`].
pub fn keygen(rng: &mut dyn RNG) -> Result<(RSA3072PublicKey, RSA3072PrivateKey), SignatureError> {
    RSA3072::keygen(rng)
}

/// RSASSA-PKCS1-v1_5 with SHA-256 at RSA-3072.
#[allow(non_camel_case_types)]
pub type RSASSA_PKCS1_v1_5_SHA256 = RSASSA_PKCS1_v1_5<RSA3072, SHA256>;
/// RSASSA-PKCS1-v1_5 with SHA-384 at RSA-3072.
#[allow(non_camel_case_types)]
pub type RSASSA_PKCS1_v1_5_SHA384 = RSASSA_PKCS1_v1_5<RSA3072, SHA384>;
/// RSASSA-PKCS1-v1_5 with SHA-512 at RSA-3072.
#[allow(non_camel_case_types)]
pub type RSASSA_PKCS1_v1_5_SHA512 = RSASSA_PKCS1_v1_5<RSA3072, SHA512>;
/// RSASSA-PSS with SHA-256 (and MGF1 over it) at RSA-3072.
#[allow(non_camel_case_types)]
pub type RSASSA_PSS_SHA256 = RSASSA_PSS<RSA3072, SHA256>;
/// RSASSA-PSS with SHA-384 (and MGF1 over it) at RSA-3072.
#[allow(non_camel_case_types)]
pub type RSASSA_PSS_SHA384 = RSASSA_PSS<RSA3072, SHA384>;
/// RSASSA-PSS with SHA-512 (and MGF1 over it) at RSA-3072.
#[allow(non_camel_case_types)]
pub type RSASSA_PSS_SHA512 = RSASSA_PSS<RSA3072, SHA512>;
/// RSASSA-PSS with SHAKE128 as hash and mask (RFC 8702 §3.2.1, §5's pairing for this size) at RSA-3072.
#[allow(non_camel_case_types)]
pub type RSASSA_PSS_SHAKE128 = RSASSA_PSS_SHAKE<RSA3072, SHAKE128>;

/// An RSA-3072 key-establishment private key.
pub type RSA3072KEMPrivateKey = RsaKEMPrivateKey<RSA3072>;
/// An RSA-3072 key-establishment public key.
pub type RSA3072KEMPublicKey = RsaKEMPublicKey<RSA3072>;
/// Length of an RSASVE-3072 ciphertext: `nLen`.
pub const CT_LEN: usize = RSA3072::K_LEN;
/// Length of an RSASVE-3072 shared secret, the secret value `Z`: `nLen`.
pub const SS_LEN: usize = RSA3072::K_LEN;
/// RSASVE at RSA-3072; `RSASVE::keygen` gives the KEM pair.
pub type RSASVE = crate::rsasve::RSASVE<RSA3072>;
