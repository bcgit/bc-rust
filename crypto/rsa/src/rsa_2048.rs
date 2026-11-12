//! RSA-2048: the generic types at this size, as aliases over the marker [`RSA2048`]:
//! the key types, `keygen`, every (scheme, hash) pairing offered at this size, and RSASVE.
//! Every (scheme, hash) pairing is an algorithm marker the key role traits are implemented over.
//! PSS's salt length is the hash's own output length throughout, RFC 8017 §9.1 note 4's
//! "typical" choice and Wycheproof's own `rsa_pss_*_mgf1_<hLen>_test.json`.

use crate::keys::{RsaPrivateKey, RsaPublicKey};
use crate::rsassa_pkcs1_v1_5::RSASSA_PKCS1_v1_5;
use crate::rsassa_pss::RSASSA_PSS;
use crate::rsassa_pss_shake::RSASSA_PSS_SHAKE;
use crate::rsasve::{RsaKEMPrivateKey, RsaKEMPublicKey};
pub use crate::size::RSA2048;
use crate::size::{RsaSigningSize, RsaSize};
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::RNG;
use bouncycastle_sha2::{SHA256, SHA384, SHA512};
use bouncycastle_sha3::SHAKE128;

/// An RSA-2048 public key.
pub type RSA2048PublicKey = RsaPublicKey<RSA2048>;
/// Encoded length of an RSA-2048 public key: `n || e`.
pub const PK_LEN: usize = RSA2048::PK_LEN;
/// Length of an RSA-2048 signature: the modulus's.
pub const SIG_LEN: usize = RSA2048::K_LEN;
/// An RSA-2048 private key.
pub type RSA2048PrivateKey = RsaPrivateKey<RSA2048>;
/// Encoded length of an RSA-2048 private key: `p || q || dP || dQ || qInv`.
pub const SK_LEN: usize = RSA2048::SK_LEN;

/// FIPS 186-5 Appendix A.1.3 key generation at RSA-2048: [`RsaSigningSize::keygen`].
///
/// # Errors
/// As [`RsaSigningSize::keygen`].
pub fn keygen(rng: &mut dyn RNG) -> Result<(RSA2048PublicKey, RSA2048PrivateKey), SignatureError> {
    RSA2048::keygen(rng)
}

/// RSASSA-PKCS1-v1_5 with SHA-256 at RSA-2048.
#[allow(non_camel_case_types)]
pub type RSASSA_PKCS1_v1_5_SHA256 = RSASSA_PKCS1_v1_5<RSA2048, SHA256>;
/// RSASSA-PKCS1-v1_5 with SHA-384 at RSA-2048.
#[allow(non_camel_case_types)]
pub type RSASSA_PKCS1_v1_5_SHA384 = RSASSA_PKCS1_v1_5<RSA2048, SHA384>;
/// RSASSA-PKCS1-v1_5 with SHA-512 at RSA-2048.
#[allow(non_camel_case_types)]
pub type RSASSA_PKCS1_v1_5_SHA512 = RSASSA_PKCS1_v1_5<RSA2048, SHA512>;
/// RSASSA-PSS with SHA-256 (and MGF1 over it) at RSA-2048.
#[allow(non_camel_case_types)]
pub type RSASSA_PSS_SHA256 = RSASSA_PSS<RSA2048, SHA256>;
/// RSASSA-PSS with SHA-384 (and MGF1 over it) at RSA-2048.
#[allow(non_camel_case_types)]
pub type RSASSA_PSS_SHA384 = RSASSA_PSS<RSA2048, SHA384>;
/// RSASSA-PSS with SHA-512 (and MGF1 over it) at RSA-2048.
#[allow(non_camel_case_types)]
pub type RSASSA_PSS_SHA512 = RSASSA_PSS<RSA2048, SHA512>;
/// RSASSA-PSS with SHAKE128 as hash and mask (RFC 8702 §3.2.1, §5's pairing for this size) at RSA-2048.
#[allow(non_camel_case_types)]
pub type RSASSA_PSS_SHAKE128 = RSASSA_PSS_SHAKE<RSA2048, SHAKE128>;

/// An RSA-2048 key-establishment private key.
pub type RSA2048KEMPrivateKey = RsaKEMPrivateKey<RSA2048>;
/// An RSA-2048 key-establishment public key.
pub type RSA2048KEMPublicKey = RsaKEMPublicKey<RSA2048>;
/// Length of an RSASVE-2048 ciphertext: `nLen`.
pub const CT_LEN: usize = RSA2048::K_LEN;
/// Length of an RSASVE-2048 shared secret, the secret value `Z`: `nLen`.
pub const SS_LEN: usize = RSA2048::K_LEN;
/// RSASVE at RSA-2048; `RSASVE::keygen` gives the KEM pair.
pub type RSASVE = crate::rsasve::RSASVE<RSA2048>;
