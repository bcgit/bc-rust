//! The two bodies of `PlaneWord::splat` from `crypto/aes/src/bitslice.rs`, with the barrier the
//! crate applies off x86-64 and aarch64 and without it, each out of line so that it lands in the
//! assembly as one symbol. `../check_aes_ct_asm.sh` builds this for the Cortex-M0 and RISC-V 32I
//! targets and checks that the barriered bodies hold no multiply, call or branch, and that the
//! plain ones do show the multiply LLVM folds the shifts and ORs into, which is what the check
//! exists to catch. Keep the bodies the same as the crate's.
#![no_std]
#![forbid(unsafe_code)]

use bouncycastle_utils::ct;

/// `u32::splat` as the crate compiles it off the fixed-latency targets.
#[inline(never)]
pub fn splat32_barrier(pattern: u16) -> u32 {
    let x = ct::value_barrier(u32::from(pattern));
    x | (x << 16)
}

/// `u64::splat` as the crate compiles it off the fixed-latency targets.
#[inline(never)]
pub fn splat64_barrier(pattern: u16) -> u64 {
    let x = ct::value_barrier(u64::from(pattern));
    x | (x << 16) | (x << 32) | (x << 48)
}

/// The same without the barrier: the positive control, which LLVM may fold into a multiply.
#[inline(never)]
pub fn splat32_plain(pattern: u16) -> u32 {
    let x = u32::from(pattern);
    x | (x << 16)
}

/// The same without the barrier: the positive control, which LLVM may fold into a multiply.
#[inline(never)]
pub fn splat64_plain(pattern: u16) -> u64 {
    let x = u64::from(pattern);
    x | (x << 16) | (x << 32) | (x << 48)
}
