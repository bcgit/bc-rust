//! Basic utilities for the crypto crates.
//!
//! The functions contained here are not really intended to be used by end users, but you
//! are welcome to do so if you wish.
//!
//! That said, beware that this crate is not necessarily documented to the same standard as other crates.
//! Since many of the contained helpers are security-critical (such as the constant time module),
//! we will prioritize fixing security bugs over maintaining a stable API for this crate.
//!
//! This crate intentionally does not have `#![forbid(unsafe_code)]` because some of the constant-time
//! and zeroization techniques require unsafe code in order to force the compiler into specific
//! assembly-level behaviours. The idea is to contain the unsafe code in a central location rather
//! so that the higher-level primitives can stick to safe rust.
//!
//! Within the crate it is confined to two modules, [`ct`] and [`secret`]: the crate denies
//! `unsafe_code`, those two allow it, and every other module forbids it, so the compiler holds
//! the line.

#![no_std]
#![forbid(missing_docs)]
#![deny(unsafe_code)]
#![allow(private_bounds)]

#[forbid(unsafe_code)]
pub mod bitslice;
#[forbid(unsafe_code)]
pub mod const_str;
#[allow(unsafe_code)]
pub mod ct;
#[allow(unsafe_code)]
pub mod secret;
#[forbid(unsafe_code)]
pub mod suspendable_state;

/// Basic max function. If they are equal, it returns the first one.
pub fn max<'a, T: PartialOrd>(x: &'a T, y: &'a T) -> &'a T {
    if x >= y { x } else { y }
}

/// Basic min function. If they are equal, it returns the first one.
pub fn min<'a, T: PartialOrd>(x: &'a T, y: &'a T) -> &'a T {
    if x <= y { x } else { y }
}
