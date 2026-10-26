//! Wrappers over the AArch64 NEON and Crypto Extension intrinsics the kernels use.
//!
//! Every method of [`V128`] is a one-line wrapper around one intrinsic from
//! [`core::arch::aarch64`], declared `#[target_feature(enable = "aes,neon")]` like the
//! intrinsics themselves. Inside such a function the compiler accepts the intrinsic calls as
//! safe, and in exchange calling one from code without the attribute is `unsafe`: the compiler
//! will not let the precondition, that the CPU has the instructions, be forgotten. The kernels in
//! [`super::aes`] and [`super::ghash`] carry the same attribute; [`super::Aes`] is
//! the one place that precondition is discharged.
//!
//! # SAFETY
//!
//! The only `unsafe` here is in [`V128::from_bytes`] and [`V128::to_bytes`], because the
//! load/store intrinsics take a raw pointer. Each pointer is derived from a `&[u8; 16]` /
//! `&mut [u8; 16]` and so is valid for exactly sixteen bytes.

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
    ///
    /// # Safety
    ///
    /// Callable only from a kernel with the same `#[target_feature]`, reached through an
    /// [`Aes`](super::Aes) proof, whose existence is the precondition.
    #[target_feature(enable = "aes,neon")]
    #[inline]
    pub fn from_bytes(bytes: &[u8; 16]) -> V128 {
        // SAFETY: `bytes` is a `&[u8; 16]`, valid for sixteen bytes of reads.
        V128(unsafe { vld1q_u8(bytes.as_ptr()) })
    }

    /// Stores the sixteen bytes.
    ///
    /// # Safety
    ///
    /// Callable only from a kernel with the same `#[target_feature]`, reached through an
    /// [`Aes`](super::Aes) proof, whose existence is the precondition.
    #[target_feature(enable = "aes,neon")]
    #[inline]
    pub fn to_bytes(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        // SAFETY: `out` is a `[u8; 16]`, valid for sixteen bytes of writes.
        unsafe { vst1q_u8(out.as_mut_ptr(), self.0) };
        out
    }

    /// All zero.
    ///
    /// # Safety
    ///
    /// Callable only from a kernel with the same `#[target_feature]`, reached through an
    /// [`Aes`](super::Aes) proof, whose existence is the precondition.
    #[target_feature(enable = "aes,neon")]
    #[inline]
    pub fn zero() -> V128 {
        V128(vdupq_n_u8(0))
    }

    /// The same 32-bit word in all four lanes; its four bytes appear in memory order in each.
    ///
    /// # Safety
    ///
    /// Callable only from a kernel with the same `#[target_feature]`, reached through an
    /// [`Aes`](super::Aes) proof, whose existence is the precondition.
    #[target_feature(enable = "aes,neon")]
    #[inline]
    pub fn splat_u32(word: u32) -> V128 {
        V128(vreinterpretq_u8_u32(vdupq_n_u32(word)))
    }

    /// 32-bit lane `L`.
    ///
    /// # Safety
    ///
    /// Callable only from a kernel with the same `#[target_feature]`, reached through an
    /// [`Aes`](super::Aes) proof, whose existence is the precondition.
    #[target_feature(enable = "aes,neon")]
    #[inline]
    pub fn lane_u32<const L: i32>(self) -> u32 {
        vgetq_lane_u32::<L>(vreinterpretq_u32_u8(self.0))
    }

    /// 64-bit lanes `lo` (bytes 0..8) and `hi` (bytes 8..16).
    ///
    /// # Safety
    ///
    /// Callable only from a kernel with the same `#[target_feature]`, reached through an
    /// [`Aes`](super::Aes) proof, whose existence is the precondition.
    #[target_feature(enable = "aes,neon")]
    #[inline]
    pub fn from_u64x2(lo: u64, hi: u64) -> V128 {
        V128(vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(lo), vcreate_u64(hi))))
    }

    /// 64-bit lane `L`.
    ///
    /// # Safety
    ///
    /// Callable only from a kernel with the same `#[target_feature]`, reached through an
    /// [`Aes`](super::Aes) proof, whose existence is the precondition.
    #[target_feature(enable = "aes,neon")]
    #[inline]
    pub fn lane_u64<const L: i32>(self) -> u64 {
        vgetq_lane_u64::<L>(vreinterpretq_u64_u8(self.0))
    }

    /// Bitwise XOR.
    ///
    /// # Safety
    ///
    /// Callable only from a kernel with the same `#[target_feature]`, reached through an
    /// [`Aes`](super::Aes) proof, whose existence is the precondition.
    #[target_feature(enable = "aes,neon")]
    #[inline]
    pub fn eor(self, other: V128) -> V128 {
        V128(veorq_u8(self.0, other.0))
    }

    /// Bitwise OR.
    ///
    /// # Safety
    ///
    /// Callable only from a kernel with the same `#[target_feature]`, reached through an
    /// [`Aes`](super::Aes) proof, whose existence is the precondition.
    #[target_feature(enable = "aes,neon")]
    #[inline]
    pub fn orr(self, other: V128) -> V128 {
        V128(vorrq_u8(self.0, other.0))
    }

    /// `AESE`: one AES encryption round without the column mixing, i.e.
    /// `SHIFTROWS(SUBBYTES(self XOR round_key))` in FIPS 197's terms (Sec 5.1.1, 5.1.2, 5.1.4).
    ///
    /// # Safety
    ///
    /// Callable only from a kernel with the same `#[target_feature]`, reached through an
    /// [`Aes`](super::Aes) proof, whose existence is the precondition.
    #[target_feature(enable = "aes,neon")]
    #[inline]
    pub fn aese(self, round_key: V128) -> V128 {
        V128(vaeseq_u8(self.0, round_key.0))
    }

    /// `AESMC`: `MIXCOLUMNS(self)` (FIPS 197 Sec 5.1.3).
    ///
    /// # Safety
    ///
    /// Callable only from a kernel with the same `#[target_feature]`, reached through an
    /// [`Aes`](super::Aes) proof, whose existence is the precondition.
    #[target_feature(enable = "aes,neon")]
    #[inline]
    pub fn aesmc(self) -> V128 {
        V128(vaesmcq_u8(self.0))
    }

    /// `AESD`: one AES decryption round without the column mixing, i.e.
    /// `INVSHIFTROWS(INVSUBBYTES(self XOR round_key))` (FIPS 197 Sec 5.3.1, 5.3.2, 5.3.4).
    ///
    /// # Safety
    ///
    /// Callable only from a kernel with the same `#[target_feature]`, reached through an
    /// [`Aes`](super::Aes) proof, whose existence is the precondition.
    #[target_feature(enable = "aes,neon")]
    #[inline]
    pub fn aesd(self, round_key: V128) -> V128 {
        V128(vaesdq_u8(self.0, round_key.0))
    }

    /// `AESIMC`: `INVMIXCOLUMNS(self)` (FIPS 197 Sec 5.3.3).
    ///
    /// # Safety
    ///
    /// Callable only from a kernel with the same `#[target_feature]`, reached through an
    /// [`Aes`](super::Aes) proof, whose existence is the precondition.
    #[target_feature(enable = "aes,neon")]
    #[inline]
    pub fn aesimc(self) -> V128 {
        V128(vaesimcq_u8(self.0))
    }

    /// Reverses the byte order within each 64-bit lane.
    ///
    /// # Safety
    ///
    /// Callable only from a kernel with the same `#[target_feature]`, reached through an
    /// [`Aes`](super::Aes) proof, whose existence is the precondition.
    #[target_feature(enable = "aes,neon")]
    #[inline]
    pub fn rev64(self) -> V128 {
        V128(vrev64q_u8(self.0))
    }

    /// `EXT`: bytes `N..16` of `self` followed by bytes `0..N` of `other`, so that
    /// `a.ext::<N>(b)` is a window of width sixteen slid `N` bytes into the concatenation
    /// `a || b`. `self.ext::<N>(zero)` shifts `self` down by `N` bytes; `zero.ext::<N>(self)`
    /// shifts it up by `16 - N`.
    ///
    /// # Safety
    ///
    /// Callable only from a kernel with the same `#[target_feature]`, reached through an
    /// [`Aes`](super::Aes) proof, whose existence is the precondition.
    #[target_feature(enable = "aes,neon")]
    #[inline]
    pub fn ext<const N: i32>(self, other: V128) -> V128 {
        V128(vextq_u8::<N>(self.0, other.0))
    }

    /// Logical right shift of each 32-bit lane by `N` bits, zero-filled.
    ///
    /// # Safety
    ///
    /// Callable only from a kernel with the same `#[target_feature]`, reached through an
    /// [`Aes`](super::Aes) proof, whose existence is the precondition.
    #[target_feature(enable = "aes,neon")]
    #[inline]
    pub fn shr32<const N: i32>(self) -> V128 {
        V128(vreinterpretq_u8_u32(vshrq_n_u32::<N>(vreinterpretq_u32_u8(self.0))))
    }

    /// Left shift of each 32-bit lane by `N` bits, zero-filled.
    ///
    /// # Safety
    ///
    /// Callable only from a kernel with the same `#[target_feature]`, reached through an
    /// [`Aes`](super::Aes) proof, whose existence is the precondition.
    #[target_feature(enable = "aes,neon")]
    #[inline]
    pub fn shl32<const N: i32>(self) -> V128 {
        V128(vreinterpretq_u8_u32(vshlq_n_u32::<N>(vreinterpretq_u32_u8(self.0))))
    }

    /// Wrapping addition of each 32-bit lane; carries never cross a lane.
    ///
    /// # Safety
    ///
    /// Callable only from a kernel with the same `#[target_feature]`, reached through an
    /// [`Aes`](super::Aes) proof, whose existence is the precondition.
    #[target_feature(enable = "aes,neon")]
    #[inline]
    pub fn add32(self, other: V128) -> V128 {
        V128(vreinterpretq_u8_u32(vaddq_u32(
            vreinterpretq_u32_u8(self.0),
            vreinterpretq_u32_u8(other.0),
        )))
    }

    /// `PMULL`: the 128-bit carry-less product of the low 64-bit lanes of `self` and `other`.
    ///
    /// # Safety
    ///
    /// Callable only from a kernel with the same `#[target_feature]`, reached through an
    /// [`Aes`](super::Aes) proof, whose existence is the precondition.
    #[target_feature(enable = "aes,neon")]
    #[inline]
    pub fn pmull_ll(self, other: V128) -> V128 {
        V128(vreinterpretq_u8_p128(vmull_p64(
            vgetq_lane_u64::<0>(vreinterpretq_u64_u8(self.0)),
            vgetq_lane_u64::<0>(vreinterpretq_u64_u8(other.0)),
        )))
    }

    /// `PMULL`: the carry-less product of the high lane of `self` and the low lane of `other`.
    ///
    /// # Safety
    ///
    /// Callable only from a kernel with the same `#[target_feature]`, reached through an
    /// [`Aes`](super::Aes) proof, whose existence is the precondition.
    #[target_feature(enable = "aes,neon")]
    #[inline]
    pub fn pmull_hl(self, other: V128) -> V128 {
        V128(vreinterpretq_u8_p128(vmull_p64(
            vgetq_lane_u64::<1>(vreinterpretq_u64_u8(self.0)),
            vgetq_lane_u64::<0>(vreinterpretq_u64_u8(other.0)),
        )))
    }

    /// `PMULL`: the carry-less product of the low lane of `self` and the high lane of `other`.
    ///
    /// # Safety
    ///
    /// Callable only from a kernel with the same `#[target_feature]`, reached through an
    /// [`Aes`](super::Aes) proof, whose existence is the precondition.
    #[target_feature(enable = "aes,neon")]
    #[inline]
    pub fn pmull_lh(self, other: V128) -> V128 {
        V128(vreinterpretq_u8_p128(vmull_p64(
            vgetq_lane_u64::<0>(vreinterpretq_u64_u8(self.0)),
            vgetq_lane_u64::<1>(vreinterpretq_u64_u8(other.0)),
        )))
    }

    /// `PMULL2`: the 128-bit carry-less product of the high 64-bit lanes of `self` and `other`.
    ///
    /// # Safety
    ///
    /// Callable only from a kernel with the same `#[target_feature]`, reached through an
    /// [`Aes`](super::Aes) proof, whose existence is the precondition.
    #[target_feature(enable = "aes,neon")]
    #[inline]
    pub fn pmull_hh(self, other: V128) -> V128 {
        V128(vreinterpretq_u8_p128(vmull_high_p64(
            vreinterpretq_p64_u8(self.0),
            vreinterpretq_p64_u8(other.0),
        )))
    }
}
