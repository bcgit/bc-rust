//! The raw SM4 permutation, [`SM4Internal`]; see [`bouncycastle_core::hazmat`] for what the path
//! means and the supported uses.
//!
//! [`SM4Internal`] transforms exactly one block and is the primitive under the modes in this
//! crate, not a cipher for data; use [`SM4Key`](crate::SM4Key) under [`SM4_CBC`](crate::SM4_CBC),
//! [`SM4_CFB`](crate::SM4_CFB), [`SM4_CFB8`](crate::SM4_CFB8) or [`SM4_CTR`](crate::SM4_CTR).

pub(crate) mod sm4;

pub use sm4::SM4Internal;
