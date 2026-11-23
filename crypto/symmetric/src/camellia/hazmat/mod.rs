//! The raw Camellia permutation, [`CamelliaInternal`] and its three key-length aliases; see
//! [`bouncycastle_core::hazmat`] for what the path means and the supported uses.
//!
//! [`Camellia128Internal`] and its siblings transform exactly one block and are the primitive
//! under the modes in this module, not a cipher for data; use
//! [`Camellia_CBC_128`](crate::camellia::Camellia_CBC_128) and the other mode aliases at the module root.

pub(in crate::camellia) mod camellia;

pub use camellia::{
    Camellia128Internal, Camellia192Internal, Camellia256Internal, CamelliaInternal,
};
