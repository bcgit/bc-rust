//! Windows: `IsProcessorFeaturePresent`, one call per constant, and the parser that turns the
//! answers into the feature word.

#![deny(unsafe_code)]

use super::AES;

#[cfg(target_os = "windows")]
mod ffi {
    //! The one call, and the only code in this file allowed `unsafe`.

    #![allow(unsafe_code)]

    use super::PfFeature;

    #[link(name = "kernel32")] // a `no_std` crate names the import library itself
    unsafe extern "system" {
        /// `BOOL IsProcessorFeaturePresent(DWORD ProcessorFeature)`.
        fn IsProcessorFeaturePresent(feature: u32) -> i32;
    }

    /// Whether `IsProcessorFeaturePresent` reports `feature`.
    pub(super) fn is_present(feature: PfFeature) -> bool {
        // SAFETY: the declaration matches kernel32's; an integer goes in and one comes out, and
        // `feature` is one of the documented constants. An unknown one returns 0.
        unsafe { IsProcessorFeaturePresent(feature as u32) != 0 }
    }
}

/// `IsProcessorFeaturePresent`, one call per constant.
#[cfg(target_os = "windows")]
pub(in super::super) fn probe() -> u32 {
    features_from_pf(ffi::is_present)
}

/// The `IsProcessorFeaturePresent` constants the proofs use, from `winnt.h` (Microsoft's
/// `windows-sys` crate carries the same values).
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub(super) enum PfFeature {
    /// `PF_ARM_NEON_INSTRUCTIONS_AVAILABLE`.
    Neon = 19,
    /// `PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE`: "the Arm v8 extra cryptographic instructions
    /// (for example, AES, SHA1 and SHA2)".
    V8Crypto = 30,
}

/// Windows: `has(feature)` is whether `IsProcessorFeaturePresent` reports it.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(super) fn features_from_pf(mut has: impl FnMut(PfFeature) -> bool) -> u32 {
    let mut features = 0;
    if has(PfFeature::Neon) && has(PfFeature::V8Crypto) {
        features |= AES;
    }
    features
}

#[cfg(test)]
mod tests {
    //! Unit tests, because these functions are private and pure, with answers known from the
    //! headers; the words are synthetic, one per class of CPU.

    use super::*;

    #[test]
    fn pf_needs_neon_and_crypto() {
        assert_eq!(features_from_pf(|_| true), AES);
        assert_eq!(features_from_pf(|f| f == PfFeature::Neon), 0);
        assert_eq!(features_from_pf(|f| f == PfFeature::V8Crypto), 0);
        assert_eq!(features_from_pf(|_| false), 0);
    }

    // 19 is in `winnt.h` and Microsoft's `windows-sys` 0.61.2, though the Microsoft Learn page
    // for `IsProcessorFeaturePresent` does not list it; 30 is on that page.
    #[test]
    fn pf_constants_are_the_documented_values() {
        assert_eq!(PfFeature::Neon as u32, 19);
        assert_eq!(PfFeature::V8Crypto as u32, 30);
    }
}
