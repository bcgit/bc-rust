//! The mode, padding, stream and key machinery every cipher module is built on, re-exported at
//! the crate root as [`modes`], [`padding`], [`stream`] and [`BlockCipherKey`]. It is one private
//! module so that its internals are `pub(in crate::framework)`: a cipher module reaches the
//! public items and nothing else.

mod key;
pub mod modes;
pub mod padding;
pub mod stream;

pub use key::BlockCipherKey;

pub(in crate::framework) mod sealed {
    /// Private supertrait of [`KeyStreamPolicy`](crate::stream::KeyStreamPolicy): only the
    /// keystream types of [`modes`](crate::modes) implement it, beside their definitions.
    pub trait Sealed {}
}
