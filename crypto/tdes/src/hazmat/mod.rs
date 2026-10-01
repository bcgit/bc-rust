//! The raw TDEA permutations and the ECB aliases; see [`bouncycastle_core::hazmat`] for what the
//! path means and the supported uses.
//!
//! [`TDES`] and the decryption-only [`TDES2Key`] transform exactly one block and are the primitive
//! under the modes in this crate, not a cipher for data. [`TDES_ECB`] and [`TDES2_ECB`] are that
//! operation block by block with padding: equal plaintext blocks give equal ciphertext blocks, so
//! they are here for interoperability and test vectors. Use [`TDES_CBC`](crate::TDES_CBC) and the
//! other mode aliases at the crate root.

pub(crate) mod ecb;
pub(crate) mod tdes;
pub(crate) mod tdes2;

pub use ecb::{TDES_ECB, TDES2_ECB};
pub use tdes::TDES;
pub use tdes2::TDES2Key;
