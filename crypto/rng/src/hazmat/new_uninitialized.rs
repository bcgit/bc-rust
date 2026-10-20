//! [`NewUninitialized`]: a DRBG constructed with no entropy, to be seeded by the caller.

// Imports needed for docs
#[allow(unused_imports)]
use crate::Sp80090ADrbg;
#[allow(unused_imports)]
use crate::hash_drbg80090a::HashDRBG80090A;
// end of imports needed for docs

/// Constructs a DRBG with no seed at all.
///
/// # 🚨 Security Considerations 🚨
/// The value is unusable until [`Sp80090ADrbg::instantiate`] has been called, and everything
/// built on its output is only as strong as the seed material that call is given. Nothing here
/// checks that material. [`HashDRBG80090A::new`] seeds from the OS and is the constructor to use;
/// this exists for the SP 800-90A known-answer tests and for environments that must supply their
/// own entropy.
///
/// A trait rather than an inherent constructor so that it is only reachable with this module's
/// path in scope; see [`bouncycastle_core::hazmat`].
pub trait NewUninitialized: Sized {
    /// Creates an uninstantiated instance; call [`Sp80090ADrbg::instantiate`] before use.
    fn new_uninitialized() -> Self;
}
