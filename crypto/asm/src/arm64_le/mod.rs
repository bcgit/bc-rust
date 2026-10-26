//! The AArch64 back end: the Crypto Extensions kernels for AES ([`aes`]) and the GHASH multiply
//! ([`ghash`]), the vector wrappers they share ([`intrinsics`]), and [`Aes`], the proof that the
//! CPU has the instructions, whose methods are the safe way into the kernels. The crate docs say
//! when this module exists and what makes the kernels safe to call.

pub mod aes;
pub mod ghash;
pub mod intrinsics;

mod cpu;
pub use cpu::Aes;
