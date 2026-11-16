//! The raw TDEA permutations and the ECB aliases; see [`bouncycastle_core::hazmat`] for what the
//! path means and the supported uses.
//!
//! [`TDESInternal`] and the decryption-only [`TDES2Internal`] transform exactly one block and are
//! the engines under the keys at the crate root, not a cipher for data. [`TDES_ECB`] and
//! [`TDES2_ECB`] are that operation block by block with padding: equal plaintext blocks give equal
//! ciphertext blocks, so they are here for interoperability and test vectors. Use
//! [`TDES3Key`](crate::TDES3Key) under [`TDES_CBC`](crate::TDES_CBC) and the other modes at the
//! crate root.

pub(crate) mod ecb;
pub(crate) mod tdes;
pub(crate) mod tdes2;

pub use ecb::{TDES_ECB, TDES2_ECB};
pub use tdes::TDESInternal;
pub use tdes2::TDES2Internal;
