//! HMAC-based Extract-and-Expand Key Derivation Function (HKDF) over SM3, as per RFC 5869.
//!
//! Uses [`bouncycastle_hkdf`] to provide the HKDF-SM3 instantiation: [`HKDF_SM3`]. HKDF itself is
//! implemented generically in [`bouncycastle_hkdf`]; this module pins its const parameters to SM3
//! and publishes the resulting type alias. See [`bouncycastle_hkdf`] for the extract and expand
//! phases, entropy tracking and suspend/resume, all of which apply here unchanged.
//!
//! # Usage Examples
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial, KeyMaterial256, KeyType};
//! use bouncycastle_sm3::hkdf::HKDF_SM3;
//!
//! let salt = KeyMaterial256::from_bytes_as_type(&[0x5a; 32], KeyType::MACKey).unwrap();
//! let ikm = KeyMaterial256::from_bytes_as_type(&[0xa5; 32], KeyType::MACKey).unwrap();
//!
//! let mut okm = KeyMaterial::<64>::new();
//! HKDF_SM3::extract_and_expand_out(&salt, &ikm, b"context info", 64, &mut okm).unwrap();
//! ```
//!
//! # Memory Usage
//!
//! | Object                     | Size (bytes) |
//! |----------------------------|--------------|
//! | `HKDF_SM3`                 | 368          |
//! | Suspended `HKDF_SM3` state | 122          |
//!
//! The suspended state is the inner HMAC's (which is SM3's) plus 14 bytes; the salt is not part of
//! it and must be re-supplied on resume.
//!
//! # 🚨 Security Considerations 🚨
//!
//! * Resuming a suspended HKDF with a different salt cannot be detected and silently produces a
//!   different PRK.
//! * The output key inherits the security strength of the inputs, at most SM3's 128 bits; HKDF
//!   stretches key material but does not create entropy.

use crate::hmac::SUSPENDED_HMAC_SM3_STATE_LEN;
use crate::{SM3, SUSPENDED_SM3_STATE_LEN};
use bouncycastle_hkdf::HKDF;

/// Algorithm name string for HKDF-SM3, as used by the factories and CLI.
pub const HKDF_SM3_NAME: &str = "HKDF-SM3";

/// Length in bytes of the serialized state of [`HKDF_SM3`]: the inner HMAC's, plus the 14 bytes
/// of HKDF's own bookkeeping (see the `SuspendableKeyed` impl in `bouncycastle-hkdf`).
pub const SUSPENDED_HKDF_SM3_STATE_LEN: usize = SUSPENDED_HMAC_SM3_STATE_LEN + 14;

/// Public type for HKDF using SM3.
#[allow(non_camel_case_types)]
pub type HKDF_SM3 = HKDF<SM3, SUSPENDED_SM3_STATE_LEN, SUSPENDED_HKDF_SM3_STATE_LEN>;
