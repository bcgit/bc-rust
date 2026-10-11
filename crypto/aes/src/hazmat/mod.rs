//! Raw primitives whose safe use is the caller's responsibility.
//!
//! An item lives under a `hazmat` module when it is a correct, tested primitive whose
//! *composition* is the caller's responsibility, or that otherwise carry non-trivial
//! Security Considerations which are the caller's responsibility.
//!
//! Part of the design intention is to allow static code analyzers to easily find and flag
//! such uses with a simple search such as
//!
//! ```text
//! grep -rnE --include='*.rs' 'use .*::hazmat::'
//! ```
//!
//! [`AESInternal`] is the keyed permutation: it transforms exactly one block and is the primitive
//! under every mode in this crate, not a cipher for data. [`AES_ECB_128`] and friends are that
//! permutation applied block by block, with padding; equal plaintext blocks give equal ciphertext
//! blocks, so they are here for interoperability and test vectors.

mod aes_internal;
mod ecb;

pub use aes_internal::{AES128Internal, AES192Internal, AES256Internal, AESInternal};
pub use ecb::{AES_ECB_128, AES_ECB_192, AES_ECB_256};
