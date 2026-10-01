//! Raw DRBG operations whose safe use is the caller's responsibility; see
//! [`bouncycastle_core::hazmat`] for what the path means and the supported uses.
//!
//! [`NewUninitialized`] constructs a DRBG with no seed at all; [`HashDRBG80090A::new`]
//! seeds from the OS and is the constructor to use.
//!
//! [`HashDRBG80090A::new`]: crate::hash_drbg80090a::HashDRBG80090A::new

mod new_uninitialized;

pub use new_uninitialized::NewUninitialized;
