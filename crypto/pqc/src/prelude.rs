//! The traits a caller needs in scope to call this crate's methods, for a glob import:
//! `use bouncycastle_pqc::prelude::*;`. It is [`bouncycastle_core::prelude`] and the ML-DSA and
//! ML-KEM key generation and key traits, of both forms, all imported as `_`.

pub use bouncycastle_core::prelude::*;

pub use crate::mldsa::{MLDSAPrivateKeyTrait as _, MLDSAPublicKeyTrait as _, MLDSATrait as _};
pub use crate::mldsa_lowmemory::{
    MLDSAPrivateKeyTrait as _, MLDSAPublicKeyTrait as _, MLDSATrait as _,
};
pub use crate::mlkem::{MLKEMPrivateKeyTrait as _, MLKEMPublicKeyTrait as _, MLKEMTrait as _};
pub use crate::mlkem_lowmemory::{
    MLKEMPrivateKeyTrait as _, MLKEMPublicKeyTrait as _, MLKEMTrait as _,
};
