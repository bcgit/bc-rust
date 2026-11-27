//! HMAC-based Extract-and-Expand Key Derivation Function (HKDF) over RIPEMD-160, as per RFC 5869.
//!
//! Publishes the HKDF-RIPEMD160 instantiation, [`HKDF_RIPEMD160`]; HKDF itself is implemented
//! generically in [`crate::hkdf`], whose extract and expand phases and entropy tracking apply
//! here unchanged.
//!
//! # Usage Examples
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial, KeyMaterial256, KeyType};
//! use bouncycastle_digest::ripemd::hkdf::HKDF_RIPEMD160;
//!
//! let salt = KeyMaterial256::from_bytes_as_type(&[0x5a; 32], KeyType::MACKey).unwrap();
//! let ikm = KeyMaterial256::from_bytes_as_type(&[0xa5; 32], KeyType::MACKey).unwrap();
//!
//! let mut okm = KeyMaterial::<64>::new();
//! HKDF_RIPEMD160::extract_and_expand_out(&salt, &ikm, b"context info", 64, &mut okm).unwrap();
//! ```
//!
//! # Memory Usage
//!
//! | Object           | Size (bytes) |
//! |------------------|--------------|
//! | `HKDF_RIPEMD160` | 344          |
//!
//! # 🚨 Security Considerations 🚨
//!
//! * A legacy construction, for the protocols that require it: RIPEMD-160 claims no security
//!   strength in this library (see [`crate::ripemd`]), so neither does HKDF over it, and a seeded
//!   output is typed `CryptographicRandom` with no strength (see [`crate::hkdf`]).

use crate::hkdf::HKDF;
use crate::ripemd::RIPEMD160;

/// Algorithm name string for HKDF-RIPEMD160, as used by the CLI.
pub const HKDF_RIPEMD160_NAME: &str = "HKDF-RIPEMD160";

/// Public type for HKDF using RIPEMD-160.
#[allow(non_camel_case_types)]
pub type HKDF_RIPEMD160 = HKDF<RIPEMD160>;
