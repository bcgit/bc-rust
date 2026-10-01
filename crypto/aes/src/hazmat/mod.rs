//! Raw AES items whose safe use is the caller's responsibility; see [`bouncycastle_core::hazmat`]
//! for what the path means and the supported uses.
//!
//! [`AESInternal`] is the keyed permutation: it transforms exactly one block and is the primitive
//! under every mode in this crate, not a cipher for data. [`AES_ECB_128`] and friends are that
//! permutation applied block by block, with padding; equal plaintext blocks give equal ciphertext
//! blocks, so they are here for interoperability and test vectors.

mod aes_internal;
mod ecb;

pub use aes_internal::{AES128Internal, AES192Internal, AES256Internal, AESInternal};
pub use ecb::{AES_ECB_128, AES_ECB_192, AES_ECB_256};
