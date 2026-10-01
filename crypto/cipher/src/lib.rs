//! A utility crate for holding common building blocks for constructing symmetric ciphers on top of
//! different permutation functions, such as modes of operation and padding.
//!
//! * [`modes`] — block cipher modes of operation (NIST SP 800-38A, SP 800-38C and SP 800-38D).
//! * [`padding`] — block padding schemes, and the adapters that apply them to a block cipher mode.

#![forbid(unsafe_code)]
#![forbid(missing_docs)]
#![no_std]

pub mod modes;
pub mod padding;
