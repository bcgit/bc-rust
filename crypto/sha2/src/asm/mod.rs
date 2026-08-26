//! Hardware-accelerated compression backends.
//!
//! One submodule per algorithm; each algorithm submodule dispatches further
//! by `(target_arch, target_endian)` — see [`sha256`] for the shape every
//! backend follows.
//!
//! This is the one place in the crate that grants itself an exception from
//! the `sha256`/`sha512` modules' `#![forbid(unsafe_code)]`: every backend
//! under here is gated on its own `(feature = "asm", target_arch,
//! target_endian)` cfg and carries a `// SAFETY:` comment at its unsafe
//! block, but none of it can compile unless this crate's `asm` feature is
//! explicitly opted into.
#![allow(unsafe_code)]

pub(crate) mod sha256;
