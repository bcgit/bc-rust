//! The traits a caller needs in scope to call this crate's methods, for a glob import:
//! `use bouncycastle_rng::prelude::*;`. It is [`bouncycastle_core::prelude`] and
//! [`Sp80090ADrbg`](crate::Sp80090ADrbg), imported as `_`.

pub use bouncycastle_core::prelude::*;

pub use crate::Sp80090ADrbg as _;
