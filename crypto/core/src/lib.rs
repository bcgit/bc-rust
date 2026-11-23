//! This crate defines the core traits and types used by the rest of the bc-rust.test library.
//!
//! # Features
//!
//! * `alloc` gates everything that needs a heap: the one-shots that return a `Vec`, a `String`
//!   or a `Box<dyn KeyMaterialTrait>`, and the `_boxed` finals of the worker traits, which finish
//!   a worker held as `Box<dyn ..>`.
//! * `std`, on by default, implies `alloc` and gates nothing of its own: the crate uses nothing
//!   from `std`.
//!
//! With neither (`default-features = false`) the crate links no allocator and keeps everything
//! that writes into a caller's buffer.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod agreement_key;
// Its docs link to the allocating one-shots, which a build without `alloc` does not have.
#[cfg_attr(not(feature = "alloc"), allow(rustdoc::broken_intra_doc_links))]
pub mod base64;
pub mod direction;
pub mod errors;
pub mod hazmat;
// Its docs link to the allocating one-shots, which a build without `alloc` does not have.
#[cfg_attr(not(feature = "alloc"), allow(rustdoc::broken_intra_doc_links))]
pub mod hex;
pub mod kdf_params;
pub mod kem_key;
pub mod key_material;
pub mod key_transport_key;
mod provided;
pub mod security_strength;
pub mod signature_key;
pub mod symmetric_key;
// Its docs link to the allocating one-shots, which a build without `alloc` does not have.
#[cfg_attr(not(feature = "alloc"), allow(rustdoc::broken_intra_doc_links))]
pub mod traits;
