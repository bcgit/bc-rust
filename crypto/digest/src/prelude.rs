//! The traits a caller needs in scope to call this crate's methods, for a glob import:
//! `use bouncycastle_digest::prelude::*;`. The hashes, XOFs, MACs and KDFs here add none to
//! [`bouncycastle_core::prelude`], which this re-exports.

pub use bouncycastle_core::prelude::*;
