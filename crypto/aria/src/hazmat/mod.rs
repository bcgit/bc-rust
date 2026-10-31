//! The raw ARIA permutation, [`ARIAInternal`] and its three key-length aliases; see
//! [`bouncycastle_core::hazmat`] for what the path means and the supported uses.
//!
//! [`ARIA128Internal`] and its siblings transform exactly one block and are the primitive under the modes
//! in this crate, not a cipher for data; use [`ARIA_CBC_128`](crate::ARIA_CBC_128) and the other
//! mode aliases at the crate root.

pub(crate) mod aria;

pub use aria::{ARIA128Internal, ARIA192Internal, ARIA256Internal, ARIAInternal};
