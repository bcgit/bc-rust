//! The raw SM4 permutation, [`SM4Internal`]; see [`bouncycastle_core::hazmat`] for what the path
//! means and the supported uses.
//!
//! [`SM4Internal`] transforms exactly one block and is the primitive under the modes in this
//! module, not a cipher for data; use [`SM4Key`](crate::sm4::SM4Key) under [`SM4_CBC`](crate::sm4::SM4_CBC),
//! [`SM4_CFB`](crate::sm4::SM4_CFB), [`SM4_CFB8`](crate::sm4::SM4_CFB8), [`SM4_OFB`](crate::sm4::SM4_OFB) or
//! [`SM4_CTR`](crate::sm4::SM4_CTR).

pub(in crate::sm4) mod sm4;

pub use sm4::SM4Internal;
