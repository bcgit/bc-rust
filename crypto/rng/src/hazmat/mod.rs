//! Raw DRBG operations whose safe use is the caller's responsibility; see
//! [`bouncycastle_core::hazmat`] for what the path means and the supported uses.
//!
//! [`NewUninitialized`] constructs a DRBG with no seed at all; `HashDRBG80090A::new` seeds from
//! the OS and is the constructor to use where the `std` feature provides it.

mod new_uninitialized;

pub use new_uninitialized::NewUninitialized;
