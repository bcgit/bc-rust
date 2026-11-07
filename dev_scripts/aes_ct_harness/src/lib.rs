//! The two bodies of `PlaneWord::splat` from `crypto/aes/src/bitslice.rs`, with the barrier the
//! crate applies off x86-64 and aarch64 and without it, each out of line so that it lands in the
//! assembly as one symbol; and the TDES round function, whose `spread` carries the same guard,
//! compiled from the crate's own `des.rs` and `sbox.rs` (included by path, unmodified), with a
//! plain-shift `spread` beside it as the control. `../check_aes_ct_asm.sh` builds this for the
//! Cortex-M0 and RISC-V 32I targets and checks that the barriered bodies hold no multiply, call
//! or branch, and that the plain ones do show the multiply LLVM folds the shifts and ORs into,
//! which is what the check exists to catch. Keep the `splat` bodies the same as the crate's.
#![no_std]
#![forbid(unsafe_code)]
#![allow(dead_code)]

use bouncycastle_utils::ct;

#[path = "../../../crypto/tdes/src/des.rs"]
mod des;
#[path = "../../../crypto/tdes/src/sbox.rs"]
mod sbox;

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

/// The TDES round function as the crate compiles it: sixteen DEA rounds over a schedule, with
/// `spread` going through the barrier off the fixed-latency targets.
#[inline(never)]
pub fn tdes_rounds(l: u32, r: u32, sk: &des::Subkeys) -> (u32, u32) {
    des::rounds(l, r, sk, false)
}

/// The crate's `spread` without the barrier: the positive control, which LLVM folds into a
/// multiply by 15 on Cortex-M0.
#[inline(never)]
pub fn spread_plain(v: u32) -> u32 {
    let v = v & 0x1111_1111;
    v | (v << 1) | (v << 2) | (v << 3)
}
