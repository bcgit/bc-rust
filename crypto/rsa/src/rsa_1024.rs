//! RSA-1024: the generic types at this size, as aliases over the marker [`RSA1024`]:
//! the public key and the PKCS#1 v1.5 verifiers (this size is verification only; see the crate's `# Scope`).
//! Every (scheme, hash) pairing is an algorithm marker the key role traits are implemented over.

use crate::keys::RsaPublicKey;
use crate::rsassa_pkcs1_v1_5::RSASSA_PKCS1_v1_5;
pub use crate::size::RSA1024;
use crate::size::RsaSize;
use bouncycastle_sha2::{SHA256, SHA384};

/// An RSA-1024 public key.
pub type RSA1024PublicKey = RsaPublicKey<RSA1024>;
/// Encoded length of an RSA-1024 public key: `n || e`.
pub const PK_LEN: usize = RSA1024::PK_LEN;
/// Length of an RSA-1024 signature: the modulus's.
pub const SIG_LEN: usize = RSA1024::K_LEN;

/// RSASSA-PKCS1-v1_5 with SHA-256 at RSA-1024.
#[allow(non_camel_case_types)]
pub type RSASSA_PKCS1_v1_5_SHA256 = RSASSA_PKCS1_v1_5<RSA1024, SHA256>;
/// RSASSA-PKCS1-v1_5 with SHA-384 at RSA-1024.
#[allow(non_camel_case_types)]
pub type RSASSA_PKCS1_v1_5_SHA384 = RSASSA_PKCS1_v1_5<RSA1024, SHA384>;
