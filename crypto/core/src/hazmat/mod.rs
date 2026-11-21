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
mod finish_token;
mod hazardous_operations;
mod kdf_output;
mod key_stream;
mod mode;
mod pre_hash_strength;
mod without_collision_resistance;

pub use ecb_key::{EcbDecryptionKey, EcbEncryptionKey};
pub use electronic_code_book::{BlockPermutation, ElectronicCodeBook, KeyExpansion};
pub use finish_token::finish_token;
pub use hazardous_operations::do_hazardous_operations;
pub use kdf_output::label_kdf_output;
pub use key_stream::KeyStream;
pub use mode::{
    AeadDeclaredDecryptMode, AeadDeclaredEncryptMode, AeadDecryptMode, AeadEncryptMode,
    AeadInPlaceDecryptMode, AeadInPlaceEncryptMode, BlockDecryptMode, BlockEncryptMode,
    EcbDecryptMode, EcbEncryptMode, KeyUnwrapMode, KeyWrapMode, MacMode, Mode, NonceMacMode,
    SymmetricDecryptMode, SymmetricEncryptMode,
};
pub use pre_hash_strength::waive_pre_hash_strength_rule;
pub use without_collision_resistance::WithoutCollisionResistance;
