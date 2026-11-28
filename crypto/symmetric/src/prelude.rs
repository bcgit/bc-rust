//! The traits a caller needs in scope to call this crate's methods, for a glob import:
//! `use bouncycastle_symmetric::prelude::*;`. The keys and workers here add none to
//! [`bouncycastle_core::prelude`], which this re-exports.

pub use bouncycastle_core::prelude::*;
