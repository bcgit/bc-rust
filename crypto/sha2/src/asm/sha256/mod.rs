//! Hardware SHA-256 compression dispatch.
//!
//! Each backend module below is gated on its own `(target_arch,
//! target_endian)` pair at the `mod` declaration and exposes
//! `try_compress(h: &mut [u32; 8], blocks: &[[u8; 64]]) -> bool`, always
//! available regardless of target or the `asm` feature — the fallback below
//! returns `false` unconditionally when no backend module applies, so
//! callers never need their own `#[cfg]`.

#[cfg(all(feature = "asm", target_arch = "aarch64", target_endian = "little"))]
mod aarch64_le;

#[cfg(all(feature = "asm", target_arch = "aarch64", target_endian = "little"))]
pub(crate) use aarch64_le::try_compress;

#[cfg(not(all(feature = "asm", target_arch = "aarch64", target_endian = "little")))]
pub(crate) fn try_compress(_h: &mut [u32; 8], _blocks: &[[u8; 64]]) -> bool {
    false
}
