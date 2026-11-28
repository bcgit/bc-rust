//! The traits a caller needs in scope to call this crate's methods, for a glob import:
//! `use bouncycastle_modexp::prelude::*;`. It is [`bouncycastle_core::prelude`] and the RSA size
//! markers' scheme-bound key generation, imported as `_`. The size traits, whose methods are
//! limb conversions and the scheme-less `keygen`, are left out.

pub use bouncycastle_core::prelude::*;

pub use crate::rsa::size::{KemKeyPair as _, SignatureKeyPair as _};
