//! This crate defines the core traits and types used by the rest of the bc-rust.test library.

// todo -- this is the goal, but first need to remove all the Vec in favour of compile-time array sizing.
// #![no_std]

#![forbid(unsafe_code)]
#![forbid(missing_docs)]

pub mod agreement_key;
// Every function in it returns a `String` or a `Vec`.
#[cfg(feature = "std")]
pub mod base64;
pub mod direction;
pub mod errors;
pub mod hazmat;
pub mod kdf_params;
pub mod kem_key;
pub mod key_material;
mod provided;
pub mod security_strength;
pub mod signature_key;
pub mod symmetric_key;
// Its docs link to the allocating one-shots, which a build without `std` does not have.
#[cfg_attr(not(feature = "std"), allow(rustdoc::broken_intra_doc_links))]
pub mod traits;
