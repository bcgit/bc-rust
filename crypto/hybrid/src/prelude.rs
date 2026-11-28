//! The traits a caller needs in scope to call this crate's methods, for a glob import:
//! `use bouncycastle_hybrid::prelude::*;`. It is [`bouncycastle_core::prelude`] and HPKE's
//! setups and single-shot operations on a key, all imported as `_`.

pub use bouncycastle_core::prelude::*;

pub use crate::hpke::{
    HpkeAuthRecipient as _, HpkeAuthSender as _, HpkeRecipient as _, HpkeSender as _,
};
