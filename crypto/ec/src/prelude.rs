//! The traits a caller needs in scope to call this crate's methods, for a glob import:
//! `use bouncycastle_ec::prelude::*;`. It is [`bouncycastle_core::prelude`] and this crate's
//! key-pair generation on a curve marker and DHKEM's Auth mode, all
//! imported as `_`. The curve arithmetic traits are left out.

pub use bouncycastle_core::prelude::*;

pub use crate::dhkem::{AuthDecapsulatingKey as _, AuthEncapsulatingKey as _};
pub use crate::eccdh::keys_common::AgreementKeyPair as _;
pub use crate::ecdsa::keys_common::SignatureKeyPair as _;
