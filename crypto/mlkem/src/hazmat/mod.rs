//! Raw ML-KEM operations whose safe use is the caller's responsibility; see
//! [`bouncycastle_core::hazmat`] for what the path means and the supported uses.
//!
//! [`EncapsWithRandomness`] takes the encapsulation randomness from the caller; the
//! [`KEMEncapsulator`](bouncycastle_core::traits::KEMEncapsulator) methods draw it from the DRBG
//! and are the ones to use.

mod encaps_with_randomness;

pub use encaps_with_randomness::EncapsWithRandomness;
