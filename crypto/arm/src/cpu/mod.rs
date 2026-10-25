//! [`Aes`]: the proof that the CPU has the instructions, and the safe way into the
//! kernels.
//!
//! In a build that does not declare `aes`, [`Aes::detect`] reads a feature word that the
//! library works out itself, without the standard library: `probe` makes one call to the
//! operating system, `parse` turns the answer into the word, and [`features`] caches it.
//!
//! # What each proof requires
//!
//! A kernel's `#[target_feature]` attribute says what the compiler may emit; the proof's query
//! set says what the CPU is known to have. The query set must cover the attribute set, and may
//! be longer: the compiler's `aes` implies `PMULL`, but Linux reports `PMULL` as a bit of its
//! own, so the proof asks for it.
//!
//! | Proof | Kernel attribute | `declared()` | Linux, Android (`AT_HWCAP`) | macOS, iOS (`hw.optional.*`) | Windows (`PF_*`) | Bare metal (ID registers) |
//! |---|---|---|---|---|---|---|
//! | [`Aes`] | `aes,neon` | `target_feature = "aes"` | `ASIMD` 1, `AES` 3, `PMULL` 4 | `neon`, `arm.FEAT_AES`, `arm.FEAT_PMULL` | 19, 30 | `PFR0.AdvSIMD != 0b1111`, `ISAR0.AES >= 0b0010` |
//!
//! A later proof adds a row, a bit in the feature word and one line in each parser.
//!
//! # Audit of the `unsafe` sites
//!
//! Rows 11-13 are one per operating system, so a given build compiles eleven.
//!
//! | # | Site | Value reaching it | Preconditions | Guarantee | Pinned by |
//! |---|---|---|---|---|---|
//! | 1 | `V128::from_bytes`: `vld1q_u8` | `&[u8; 16]` | pointer valid for 16 bytes of reads; NEON | the type; the function's `#[target_feature]`, reached only through a proof | `tests/intrinsics_tests.rs` |
//! | 2 | `V128::to_bytes`: `vst1q_u8` | local `[u8; 16]` | pointer valid for 16 bytes of writes; NEON | the same | the same |
//! | 3 | `Aes::expand_128` | `&[u8; 16]` | FEAT_AES, FEAT_PMULL, NEON | `self` exists: only `detect()`, which queries all three, or `declared()` under `cfg(target_feature = "aes")` builds one | `tests/aes_tests.rs`, FIPS 197 Appendix A |
//! | 4 | `Aes::expand_192` | `&[u8; 24]` | the same | the same | Appendix A |
//! | 5 | `Aes::expand_256` | `&[u8; 32]` | the same | the same | Appendix A |
//! | 6 | `Aes::equivalent_inverse_round_keys` | `&[Block; N]` | the same; `N` in {11, 13, 15} | the proof; a const assert on `N` | Appendix C |
//! | 7 | `Aes::encrypt_blocks` | `&[Block; N]`, `&mut [Block; B]` | the same; `B` in {1, 2, 4} | the proof; const asserts on `N` and `B` | Appendices B and C, SP 800-38A F.1, the aes crate's agreement tests |
//! | 8 | `Aes::decrypt_blocks` | the same | the same | the same | the same |
//! | 9 | `Aes::ghash_mul` | two `&[u64; 2]` | FEAT_PMULL, NEON | the proof | `tests/ghash_tests.rs`, against Algorithm 1 |
//! | 10 | `Aes::ghash_mul4` | two `&[[u64; 2]; 4]` | the same | the proof | `tests/ghash_tests.rs`, against four `mul`s |
//! | 11 | `probe` on Linux, Android: `getauxval` twice | the named constants `AT_HWCAP`, `AT_HWCAP2` | the symbol is in the C library the target links | integers in and out; glibc >= 2.16, musl and bionic have it | `tests/detect_matches_std.rs`; the parser tests |
//! | 12 | `probe` on macOS, iOS: `sysctlbyname` | a `c"..."` literal, a local `i32`, `len = size_of::<i32>()` | NUL-terminated name; buffer valid for `len` bytes | the literal; the typed local; accepted only if `rc == 0 && len == 4` | `probe`'s unit test of a known and an unknown name; `tests/detect_matches_std.rs`; the parser tests |
//! | 13 | `probe` on Windows: `IsProcessorFeaturePresent` | a `PfFeature` | the symbol is in kernel32 | `#[link(name = "kernel32")]`; the enum holds only constants from `winnt.h` | `tests/detect_matches_std.rs` on Windows; the parser tests |

#![allow(unsafe_code)]

// A build that declares `aes` proves `Aes` at compile time and never probes; the detector stays
// compiled so that build type-checks its back end and runs the parser tests.
#[cfg_attr(target_feature = "aes", allow(dead_code, reason = "a declared build never probes"))]
mod parse;
#[cfg_attr(target_feature = "aes", allow(dead_code, reason = "a declared build never probes"))]
mod probe;

use core::sync::atomic::{AtomicU32, Ordering};

use crate::aes::{self, Block, RoundKeys128, RoundKeys192, RoundKeys256};
use crate::ghash::{self, Element};

/// The feature word, with [`INIT`] set once it has been probed.
#[cfg_attr(target_feature = "aes", allow(dead_code, reason = "a declared build never probes"))]
static FEATURES: AtomicU32 = AtomicU32::new(0);

/// Set in [`FEATURES`] once the probe has run, so a CPU with no features is not probed again.
#[cfg_attr(target_feature = "aes", allow(dead_code, reason = "a declared build never probes"))]
const INIT: u32 = 1 << 31;

/// The CPU's feature word, probed on the first call and cached.
#[cfg_attr(target_feature = "aes", allow(dead_code, reason = "a declared build never probes"))]
fn features() -> u32 {
    // Two first callers may both probe. Both compute the same word, since what the operating
    // system reports does not change while the process runs, and an aligned atomic store cannot
    // tear, so the cache ends up holding that word. `Relaxed` is enough because nothing else is
    // published through it.
    let cached = FEATURES.load(Ordering::Relaxed);
    if cached & INIT != 0 {
        return cached;
    }
    let probed = probe::probe() | INIT;
    FEATURES.store(probed, Ordering::Relaxed);
    probed
}

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
    /// nothing. Otherwise it asks the operating system on the first call and caches the answer;
    /// on an operating system the library cannot ask, it is `None`.
    #[inline]
    pub fn detect() -> Option<Self> {
        #[cfg(target_feature = "aes")]
        return Some(Self(()));
        #[cfg(not(target_feature = "aes"))]
        return (features() & parse::AES != 0).then_some(Self(()));
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

#[cfg(test)]
mod tests {
    //! A unit test because the cache is private: it is the only way to pin that the probe runs
    //! once and its word is kept.

    use super::*;

    #[test]
    fn the_cached_word_is_marked_and_kept() {
        let first = features();
        assert_ne!(first & INIT, 0, "INIT set after the first read: {first:#x}");
        assert_eq!(FEATURES.load(Ordering::Relaxed), first);
        assert_eq!(features(), first);
    }
}
