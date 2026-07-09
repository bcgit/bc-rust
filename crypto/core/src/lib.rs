//! This crate defines the core traits and types used by the rest of the bc-rust.test library.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

// The `Vec`/`Box`-returning convenience APIs live behind the (default-on) `alloc` feature.
// When it is enabled we pull in the `alloc` crate; `no_std` users who disable it get the
// allocation-free `*_out(&mut [u8])` and `*_array::<N>()` APIs only.
#[cfg(feature = "alloc")]
extern crate alloc;

pub mod errors;
pub mod key_material;
pub mod suspendable_state;
pub mod traits;
