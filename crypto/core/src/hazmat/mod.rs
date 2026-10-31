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

mod ecb_key;
mod electronic_code_book;
mod hazardous_operations;
mod key_stream;
mod mode;

pub use ecb_key::{EcbDecryptionKey, EcbEncryptionKey};
pub use electronic_code_book::{BlockPermutation, ElectronicCodeBook};
pub use hazardous_operations::do_hazardous_operations;
pub use key_stream::KeyStream;
pub use mode::{
    AeadDeclaredDecryptMode, AeadDeclaredEncryptMode, AeadDecryptMode, AeadEncryptMode,
    BlockDecryptMode, BlockEncryptMode, EcbDecryptMode, EcbEncryptMode, MacMode, Mode, ModeKey,
    NonceMacMode, SymmetricDecryptMode, SymmetricEncryptMode,
};
