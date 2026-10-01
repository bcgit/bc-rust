//! The raw Camellia permutation, [`Camellia`] and its three key-length aliases; see
//! [`bouncycastle_core::hazmat`] for what the path means and the supported uses.
//!
//! [`Camellia_128`] and its siblings transform exactly one block and are the primitive under the
//! modes in this crate, not a cipher for data; use [`Camellia_CBC_128`](crate::Camellia_CBC_128)
//! and the other mode aliases at the crate root.

pub(crate) mod camellia;

pub use camellia::{Camellia, Camellia_128, Camellia_192, Camellia_256};
