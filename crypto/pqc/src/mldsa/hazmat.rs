//! What a caller must name on purpose; see [`bouncycastle_core::hazmat`] for what the path means.
//!
//! # 🚨 Security Considerations 🚨
//!
//! [`AnyStrength`] lets HashML-DSA sign and verify over a hash weaker than the parameter set,
//! which lowers the signature's strength to the hash's. It does not let a hash without
//! `CollisionResistantHash` sign.

#[doc(inline)]
pub use crate::mldsa_common::hazmat::AnyStrength;
