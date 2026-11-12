//! RSA-1536: the generic types at this size, as aliases over the marker [`RSA1536`]:
//! the public key and the PKCS#1 v1.5 verifiers (this size is verification only; see the crate's `# Scope`).
//! Every (scheme, hash) pairing is an algorithm marker the key role traits are implemented over.

use crate::keys::RsaPublicKey;
use crate::rsassa_pkcs1_v1_5::RSASSA_PKCS1_v1_5;
pub use crate::size::RSA1536;
use crate::size::RsaSize;
use bouncycastle_sha2::{SHA256, SHA384, SHA512};

/// An RSA-1536 public key.
pub type RSA1536PublicKey = RsaPublicKey<RSA1536>;
/// Encoded length of an RSA-1536 public key: `n || e`.
pub const PK_LEN: usize = RSA1536::PK_LEN;
/// Length of an RSA-1536 signature: the modulus's.
pub const SIG_LEN: usize = RSA1536::K_LEN;

/// RSASSA-PKCS1-v1_5 with SHA-256 at RSA-1536.
#[allow(non_camel_case_types)]
pub type RSASSA_PKCS1_v1_5_SHA256 = RSASSA_PKCS1_v1_5<RSA1536, SHA256>;
/// RSASSA-PKCS1-v1_5 with SHA-384 at RSA-1536.
#[allow(non_camel_case_types)]
pub type RSASSA_PKCS1_v1_5_SHA384 = RSASSA_PKCS1_v1_5<RSA1536, SHA384>;
/// RSASSA-PKCS1-v1_5 with SHA-512 at RSA-1536.
#[allow(non_camel_case_types)]
pub type RSASSA_PKCS1_v1_5_SHA512 = RSASSA_PKCS1_v1_5<RSA1536, SHA512>;
