//! Raw primitives whose safe use is the caller's responsibility.
//!
//! An item lives under a `hazmat` module when it is a correct, tested primitive whose
//! *composition* is the caller's job, and a wrong composition fails silently: the code compiles,
//! runs and produces output, and the output is insecure. Nothing here is a cipher for data. The
//! supported uses are:
//!
//! 1. implementing a mode or construction that is generic over the trait, as `bouncycastle_cipher::modes`
//!    does;
//! 2. known-answer tests and vector harnesses;
//! 3. a specification that mandates the raw operation: SP 800-38F key wrap, CMAC subkey
//!    generation, a protocol that fixes the nonce.
//!
//! Everything outside a `hazmat` module keeps the library's "if it compiles, then it's safe"
//! contract. `hazmat` is the one place where that contract is suspended, and the path is the
//! notice: `grep -rn hazmat` finds every raw-primitive use in a downstream, and a project that
//! wants to forbid one outright can name it in clippy's `disallowed-types`.
//!
//! [`do_hazardous_operations`] is a different kind of hazard: not a raw primitive but the one way to
//! switch off the checks a [`KeyMaterial`](crate::key_material::KeyMaterial) makes on its own
//! contents. It is here so that an audit for `hazmat` finds it too.
//!
//! Each crate that has hazmat items keeps them under its own `hazmat` module, never at the crate
//! root: this crate holds the traits, and `bouncycastle-aes` and `bouncycastle_cipher::modes` hold their
//! implementors. The safe adapters that wrap them -- `bouncycastle_cipher::stream::StreamCipher`
//! over a [`KeyStream`], the modes over an [`ElectronicCodeBook`] -- are not hazmat and stay where
//! they are.

mod electronic_code_book;
mod hazardous_operations;
mod key_stream;

pub use electronic_code_book::ElectronicCodeBook;
pub use hazardous_operations::do_hazardous_operations;
pub use key_stream::KeyStream;
