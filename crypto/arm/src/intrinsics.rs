//! Safe wrappers over the AArch64 NEON and Crypto Extension intrinsics the kernels use.
//!
//! This is the only module in bc-rust outside `bouncycastle-utils` that contains `unsafe`.
//! Every function here is a one-line wrapper around one intrinsic from
//! [`core::arch::aarch64`], and nothing else in this crate may write `unsafe` (the crate root is
//! `#![deny(unsafe_code)]`).
//!
//! # Why the calls are `unsafe` at all
//!
//! The intrinsics are declared with `#[target_feature(enable = "aes")]` or `"neon"`. The
//! compiler lets a function call them without `unsafe` only when the *calling function* carries
//! the same attribute; a target feature enabled for the whole build does not count, and a trait
//! method cannot carry the attribute. The kernels are ordinary functions behind ordinary traits,
//! so the one place the feature requirement can be discharged is here.
//!
//! # SAFETY
//!
//! Calling a `#[target_feature]` function is undefined behaviour if the CPU lacks the feature.
//! This module is compiled only under `cfg(all(target_arch = "aarch64", target_endian =
//! "little", target_feature = "aes", target_feature = "neon"))`: the build has declared that
//! every CPU the binary may run on has `FEAT_AES` (which includes `PMULL`) and NEON, so the
//! instructions are present wherever this code executes. That declaration is the whole safety
//! argument, and every `SAFETY:` comment below refers back to it. The two load/store wrappers
//! add one more condition, that the pointer they pass is derived from a `&[u8; 16]` /
//! `&mut [u8; 16]` and so is valid for exactly sixteen bytes.
//!
//! Nothing in this module or crate uses `#[target_feature]` itself, so the only `unsafe` call
//! sites are the ones in this file.

#![allow(unsafe_code)]

use core::arch::aarch64::{
    uint8x16_t, vaddq_u32, vaesdq_u8, vaeseq_u8, vaesimcq_u8, vaesmcq_u8, vcombine_u64,
    vcreate_u64, vdupq_n_u8, vdupq_n_u32, veorq_u8, vextq_u8, vgetq_lane_u32, vgetq_lane_u64,
    vld1q_u8, vmull_high_p64, vmull_p64, vorrq_u8, vreinterpretq_p64_u8, vreinterpretq_u8_p128,
    vreinterpretq_u8_u32, vreinterpretq_u8_u64, vreinterpretq_u32_u8, vreinterpretq_u64_u8,
    vrev64q_u8, vshlq_n_u32, vshrq_n_u32, vst1q_u8,
};

/// One 128-bit NEON register, viewed as sixteen bytes in memory order.
///
/// Lane numbering follows the little-endian target: byte 0 is the lowest address, 32-bit lane
/// `i` is bytes `4i..4i+4` read little-endian, and 64-bit lane `i` is bytes `8i..8i+8`. Which
/// view a method takes is in its name.
///
/// Deliberately neither `Debug` nor `PartialEq`: a value is usually key material or GHASH
/// state, and the kernels compare nothing. Tests go through [`V128::to_bytes`].
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct V128(uint8x16_t);

impl V128 {
    /// Loads sixteen bytes.
    #[inline(always)]
    pub fn from_bytes(bytes: &[u8; 16]) -> V128 {
        // SAFETY: the module-level argument, and `bytes` is a `&[u8; 16]`, valid for sixteen
        // bytes of reads.
        V128(unsafe { vld1q_u8(bytes.as_ptr()) })
    }

    /// Stores the sixteen bytes.
    #[inline(always)]
    pub fn to_bytes(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        // SAFETY: the module-level argument, and `out` is a `[u8; 16]`, valid for sixteen bytes
        // of writes.
        unsafe { vst1q_u8(out.as_mut_ptr(), self.0) };
        out
    }

    /// All zero.
    #[inline(always)]
    pub fn zero() -> V128 {
        // SAFETY: the module-level argument.
        V128(unsafe { vdupq_n_u8(0) })
    }

    /// The same 32-bit word in all four lanes; its four bytes appear in memory order in each.
    #[inline(always)]
    pub fn splat_u32(word: u32) -> V128 {
        // SAFETY: the module-level argument.
        V128(unsafe { vreinterpretq_u8_u32(vdupq_n_u32(word)) })
    }

    /// 32-bit lane `L`.
    #[inline(always)]
    pub fn lane_u32<const L: i32>(self) -> u32 {
        // SAFETY: the module-level argument; `L` is checked at compile time by the intrinsic.
        unsafe { vgetq_lane_u32::<L>(vreinterpretq_u32_u8(self.0)) }
    }

    /// 64-bit lanes `lo` (bytes 0..8) and `hi` (bytes 8..16).
    #[inline(always)]
    pub fn from_u64x2(lo: u64, hi: u64) -> V128 {
        // SAFETY: the module-level argument.
        V128(unsafe { vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(lo), vcreate_u64(hi))) })
    }

    /// 64-bit lane `L`.
    #[inline(always)]
    pub fn lane_u64<const L: i32>(self) -> u64 {
        // SAFETY: the module-level argument; `L` is checked at compile time by the intrinsic.
        unsafe { vgetq_lane_u64::<L>(vreinterpretq_u64_u8(self.0)) }
    }

    /// Bitwise XOR.
    #[inline(always)]
    pub fn eor(self, other: V128) -> V128 {
        // SAFETY: the module-level argument.
        V128(unsafe { veorq_u8(self.0, other.0) })
    }

    /// Bitwise OR.
    #[inline(always)]
    pub fn orr(self, other: V128) -> V128 {
        // SAFETY: the module-level argument.
        V128(unsafe { vorrq_u8(self.0, other.0) })
    }

    /// `AESE`: one AES encryption round without the column mixing, i.e.
    /// `SHIFTROWS(SUBBYTES(self XOR round_key))` in FIPS 197's terms (Sec 5.1.1, 5.1.2, 5.1.4).
    #[inline(always)]
    pub fn aese(self, round_key: V128) -> V128 {
        // SAFETY: the module-level argument.
        V128(unsafe { vaeseq_u8(self.0, round_key.0) })
    }

    /// `AESMC`: `MIXCOLUMNS(self)` (FIPS 197 Sec 5.1.3).
    #[inline(always)]
    pub fn aesmc(self) -> V128 {
        // SAFETY: the module-level argument.
        V128(unsafe { vaesmcq_u8(self.0) })
    }

    /// `AESD`: one AES decryption round without the column mixing, i.e.
    /// `INVSHIFTROWS(INVSUBBYTES(self XOR round_key))` (FIPS 197 Sec 5.3.1, 5.3.2, 5.3.4).
    #[inline(always)]
    pub fn aesd(self, round_key: V128) -> V128 {
        // SAFETY: the module-level argument.
        V128(unsafe { vaesdq_u8(self.0, round_key.0) })
    }

    /// `AESIMC`: `INVMIXCOLUMNS(self)` (FIPS 197 Sec 5.3.3).
    #[inline(always)]
    pub fn aesimc(self) -> V128 {
        // SAFETY: the module-level argument.
        V128(unsafe { vaesimcq_u8(self.0) })
    }

    /// Reverses the byte order within each 64-bit lane.
    #[inline(always)]
    pub fn rev64(self) -> V128 {
        // SAFETY: the module-level argument.
        V128(unsafe { vrev64q_u8(self.0) })
    }

    /// `EXT`: bytes `N..16` of `self` followed by bytes `0..N` of `other`, so that
    /// `a.ext::<N>(b)` is a window of width sixteen slid `N` bytes into the concatenation
    /// `a || b`. `self.ext::<N>(zero)` shifts `self` down by `N` bytes; `zero.ext::<N>(self)`
    /// shifts it up by `16 - N`.
    #[inline(always)]
    pub fn ext<const N: i32>(self, other: V128) -> V128 {
        // SAFETY: the module-level argument; `N` is checked at compile time by the intrinsic.
        V128(unsafe { vextq_u8::<N>(self.0, other.0) })
    }

    /// Logical right shift of each 32-bit lane by `N` bits, zero-filled.
    #[inline(always)]
    pub fn shr32<const N: i32>(self) -> V128 {
        // SAFETY: the module-level argument; `N` is checked at compile time by the intrinsic.
        V128(unsafe { vreinterpretq_u8_u32(vshrq_n_u32::<N>(vreinterpretq_u32_u8(self.0))) })
    }

    /// Left shift of each 32-bit lane by `N` bits, zero-filled.
    #[inline(always)]
    pub fn shl32<const N: i32>(self) -> V128 {
        // SAFETY: the module-level argument; `N` is checked at compile time by the intrinsic.
        V128(unsafe { vreinterpretq_u8_u32(vshlq_n_u32::<N>(vreinterpretq_u32_u8(self.0))) })
    }

    /// Wrapping addition of each 32-bit lane; carries never cross a lane.
    #[inline(always)]
    pub fn add32(self, other: V128) -> V128 {
        // SAFETY: the module-level argument.
        V128(unsafe {
            vreinterpretq_u8_u32(vaddq_u32(
                vreinterpretq_u32_u8(self.0),
                vreinterpretq_u32_u8(other.0),
            ))
        })
    }

    /// `PMULL`: the 128-bit carry-less product of the low 64-bit lanes of `self` and `other`.
    #[inline(always)]
    pub fn pmull_ll(self, other: V128) -> V128 {
        // SAFETY: the module-level argument.
        V128(unsafe {
            vreinterpretq_u8_p128(vmull_p64(
                vgetq_lane_u64::<0>(vreinterpretq_u64_u8(self.0)),
                vgetq_lane_u64::<0>(vreinterpretq_u64_u8(other.0)),
            ))
        })
    }

    /// `PMULL`: the carry-less product of the high lane of `self` and the low lane of `other`.
    #[inline(always)]
    pub fn pmull_hl(self, other: V128) -> V128 {
        // SAFETY: the module-level argument.
        V128(unsafe {
            vreinterpretq_u8_p128(vmull_p64(
                vgetq_lane_u64::<1>(vreinterpretq_u64_u8(self.0)),
                vgetq_lane_u64::<0>(vreinterpretq_u64_u8(other.0)),
            ))
        })
    }

    /// `PMULL`: the carry-less product of the low lane of `self` and the high lane of `other`.
    #[inline(always)]
    pub fn pmull_lh(self, other: V128) -> V128 {
        // SAFETY: the module-level argument.
        V128(unsafe {
            vreinterpretq_u8_p128(vmull_p64(
                vgetq_lane_u64::<0>(vreinterpretq_u64_u8(self.0)),
                vgetq_lane_u64::<1>(vreinterpretq_u64_u8(other.0)),
            ))
        })
    }

    /// `PMULL2`: the 128-bit carry-less product of the high 64-bit lanes of `self` and `other`.
    #[inline(always)]
    pub fn pmull_hh(self, other: V128) -> V128 {
        // SAFETY: the module-level argument.
        V128(unsafe {
            vreinterpretq_u8_p128(vmull_high_p64(
                vreinterpretq_p64_u8(self.0),
                vreinterpretq_p64_u8(other.0),
            ))
        })
    }
}
