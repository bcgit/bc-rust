//! Internal little-endian load/store helpers.
//!
//! These replace the external `arrayref` crate so that this crate carries no third-party runtime
//! dependencies (per the project's QUALITY_AND_STYLE rules). All callers pass slices that are at
//! least 8 bytes long at the given offset, so `copy_from_slice` is infallible by construction and
//! no fallible conversion is involved.

/// Load the 8 bytes at `src[off..off + 8]` as a little-endian `u64`.
#[inline(always)]
pub(crate) fn load_u64_le(src: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&src[off..off + 8]);
    u64::from_le_bytes(b)
}

/// Store `val` as little-endian into `dst[off..off + 8]`.
#[inline(always)]
pub(crate) fn store_u64_le(dst: &mut [u8], off: usize, val: u64) {
    dst[off..off + 8].copy_from_slice(&val.to_le_bytes());
}
