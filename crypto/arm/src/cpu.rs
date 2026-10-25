//! [`Aes`]: the proof that the CPU has the instructions, and the safe way into the
//! kernels.

#![allow(unsafe_code)]

use crate::aes::{self, Block, RoundKeys128, RoundKeys192, RoundKeys256};
use crate::ghash::{self, Element};

/// Proof that the CPU running this code has `FEAT_AES`, `FEAT_PMULL` and NEON.
///
/// A value exists only if [`detect`](Self::detect) found the instructions or the build declared
/// them, so holding one is what makes the `#[target_feature]` kernels in [`aes`] and [`ghash`]
/// safe to call; its methods are those kernels. It is zero-sized and `Copy`: check once and
/// keep it beside the data it will be used on.
#[derive(Clone, Copy, Debug)]
pub struct Aes(());

impl Aes {
    /// `Some` if the CPU has the instructions.
    ///
    /// When the build declares them (`target_feature = "aes"`) this is always `Some` and costs
    /// nothing. Otherwise, with the `std` feature, it asks the operating system through
    /// `std::arch::is_aarch64_feature_detected!`, which caches the answer after the first call.
    #[inline]
    pub fn detect() -> Option<Self> {
        #[cfg(target_feature = "aes")]
        return Some(Self(()));
        // The kernels' `aes` target feature covers `FEAT_PMULL` as well as `FEAT_AES`, but the
        // run-time `"aes"` query does not: std_detect sets it on Linux from the kernel's `aes` and
        // `asimd` hwcaps alone. So `PMULL`, which the GHASH kernels execute, is asked for itself.
        #[cfg(not(target_feature = "aes"))]
        return (std::arch::is_aarch64_feature_detected!("aes")
            && std::arch::is_aarch64_feature_detected!("pmull")
            && std::arch::is_aarch64_feature_detected!("neon"))
        .then_some(Self(()));
    }

    /// The proof, without a check: the build declares the instructions, so every CPU it may run
    /// on has them.
    #[cfg(target_feature = "aes")]
    #[inline]
    pub const fn declared() -> Self {
        Self(())
    }

    /// [`aes::expand_128`].
    #[inline]
    pub fn expand_128(self, key: &[u8; 16]) -> RoundKeys128 {
        // SAFETY: `self` exists, so the CPU has what the callee's `#[target_feature]` names.
        unsafe { aes::expand_128(key) }
    }

    /// [`aes::expand_192`].
    #[inline]
    pub fn expand_192(self, key: &[u8; 24]) -> RoundKeys192 {
        // SAFETY: `self` exists, so the CPU has what the callee's `#[target_feature]` names.
        unsafe { aes::expand_192(key) }
    }

    /// [`aes::expand_256`].
    #[inline]
    pub fn expand_256(self, key: &[u8; 32]) -> RoundKeys256 {
        // SAFETY: `self` exists, so the CPU has what the callee's `#[target_feature]` names.
        unsafe { aes::expand_256(key) }
    }

    /// [`aes::equivalent_inverse_round_keys`].
    #[inline]
    pub fn equivalent_inverse_round_keys<const N: usize>(self, w: &[Block; N]) -> [Block; N] {
        // SAFETY: `self` exists, so the CPU has what the callee's `#[target_feature]` names.
        unsafe { aes::equivalent_inverse_round_keys(w) }
    }

    /// [`aes::encrypt_blocks`].
    #[inline]
    pub fn encrypt_blocks<const N: usize, const B: usize>(
        self,
        w: &[Block; N],
        blocks: &mut [Block; B],
    ) {
        // SAFETY: `self` exists, so the CPU has what the callee's `#[target_feature]` names.
        unsafe { aes::encrypt_blocks(w, blocks) }
    }

    /// [`aes::decrypt_blocks`].
    #[inline]
    pub fn decrypt_blocks<const N: usize, const B: usize>(
        self,
        dw: &[Block; N],
        blocks: &mut [Block; B],
    ) {
        // SAFETY: `self` exists, so the CPU has what the callee's `#[target_feature]` names.
        unsafe { aes::decrypt_blocks(dw, blocks) }
    }

    /// [`ghash::mul`].
    #[inline]
    pub fn ghash_mul(self, x: &Element, y: &Element) -> Element {
        // SAFETY: `self` exists, so the CPU has what the callee's `#[target_feature]` names.
        unsafe { ghash::mul(x, y) }
    }

    /// [`ghash::mul4`].
    #[inline]
    pub fn ghash_mul4(self, x: &[Element; 4], y: &[Element; 4]) -> Element {
        // SAFETY: `self` exists, so the CPU has what the callee's `#[target_feature]` names.
        unsafe { ghash::mul4(x, y) }
    }
}
