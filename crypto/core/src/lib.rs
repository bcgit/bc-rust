//! This crate defines the core traits and types used by the rest of the bc-rust.test library.

// todo -- this is the goal, but first need to remove all the Vec in favour of compile-time array sizing.
// #![no_std]

#![feature(adt_const_params)]
#![forbid(unsafe_code)]

pub mod errors;
pub mod key_material;
pub mod traits;
