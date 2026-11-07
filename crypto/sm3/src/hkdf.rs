//! HMAC-based Extract-and-Expand Key Derivation Function (HKDF) over SM3, as per RFC 5869.
//!
//! Uses [`bouncycastle_hkdf`] to provide the HKDF-SM3 instantiation: [`HKDF_SM3`]. HKDF itself is
//! implemented generically in [`bouncycastle_hkdf`]; this module publishes the type alias over SM3.
//! See [`bouncycastle_hkdf`] for the extract and expand phases and entropy tracking, all of which
//! apply here unchanged.
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
//! | Object     | Size (bytes) |
//! |------------|--------------|
//! | `HKDF_SM3` | 368          |
//!
//! # 🚨 Security Considerations 🚨
//!
//! * The output key inherits the security strength of the inputs, at most SM3's 128 bits; HKDF
//!   stretches key material but does not create entropy.

use crate::SM3;
use bouncycastle_hkdf::HKDF;

/// Algorithm name string for HKDF-SM3, as used by the factories and CLI.
pub const HKDF_SM3_NAME: &str = "HKDF-SM3";

/// Public type for HKDF using SM3.
#[allow(non_camel_case_types)]
pub type HKDF_SM3 = HKDF<SM3>;
