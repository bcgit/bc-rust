//! What each operating system reports, turned into the feature word: one bit per proof. Each
//! function is one column of the table in the `cpu` module docs. Every target compiles all of
//! them, so their tests run on any host; each target calls only its own.

#![deny(unsafe_code)]

use core::ffi::CStr;

/// The bit for [`Aes`](super::Aes) in the feature word.
pub(super) const AES: u32 = 1 << 0;

/// `AT_HWCAP` bits, from the kernel's `arch/arm64/include/uapi/asm/hwcap.h`. Those for the
/// proofs still to come are named now, so each adds one line to [`features_from_hwcap`].
#[allow(dead_code, reason = "bits for the proofs still to come")]
mod hwcap {
    pub const ASIMD: u64 = 1 << 1;
    pub const AES: u64 = 1 << 3;
    pub const PMULL: u64 = 1 << 4;
    pub const SHA1: u64 = 1 << 5;
    pub const SHA2: u64 = 1 << 6;
    pub const SHA3: u64 = 1 << 17;
    pub const SM3: u64 = 1 << 18;
    pub const SM4: u64 = 1 << 19;
    pub const SHA512: u64 = 1 << 21;
    pub const SVE: u64 = 1 << 22;
}

/// `AT_HWCAP2` bits, from the same header.
#[allow(dead_code, reason = "bits for the proofs still to come")]
mod hwcap2 {
    pub const SVE2: u64 = 1 << 1;
    pub const SVEAES: u64 = 1 << 2;
    pub const SVEPMULL: u64 = 1 << 3;
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

/// Linux and Android: the `AT_HWCAP` and `AT_HWCAP2` words of the auxiliary vector.
#[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
pub(super) fn features_from_hwcap(hwcap: u64, _hwcap2: u64) -> u32 {
    let has = |bits: u64| hwcap & bits == bits;
    let mut features = 0;
    // `AES` does not imply `PMULL` here, though the compiler's `aes` does, and the GHASH
    // kernels execute `PMULL`.
    if has(hwcap::ASIMD | hwcap::AES | hwcap::PMULL) {
        features |= AES;
    }
    features
}

/// macOS and iOS: `has(name)` is whether the `hw.optional` sysctl `name` exists and is non-zero.
#[cfg_attr(not(any(target_os = "macos", target_os = "ios")), allow(dead_code))]
pub(super) fn features_from_sysctl(mut has: impl FnMut(&CStr) -> bool) -> u32 {
    let mut features = 0;
    if has(c"hw.optional.neon")
        && has(c"hw.optional.arm.FEAT_AES")
        && has(c"hw.optional.arm.FEAT_PMULL")
    {
        features |= AES;
    }
    features
}

/// Whether one `sysctlbyname` answer for an `i32` sysctl says "present": the call succeeded
/// (`rc` is -1 for an unknown name), wrote exactly an `i32`, and the value is non-zero.
#[cfg_attr(not(any(target_os = "macos", target_os = "ios")), allow(dead_code))]
pub(super) fn sysctl_present(rc: i32, len: usize, value: i32) -> bool {
    rc == 0 && len == size_of::<i32>() && value != 0
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

/// Bare metal at EL1 or higher: `ID_AA64PFR0_EL1`, `ID_AA64ISAR0_EL1` and `ID_AA64ZFR0_EL1`,
/// with the field positions of the kernel's `arch/arm64/tools/sysreg`.
#[allow(dead_code, reason = "for the bare-metal opt-in, which reads the registers")]
pub(super) fn features_from_id_registers(pfr0: u64, isar0: u64, _zfr0: u64) -> u32 {
    // PFR0.AdvSIMD [23:20] is signed: 0b1111 is "not implemented", every other value has it.
    let adv_simd = (pfr0 >> 20) & 0xf;
    // ISAR0.AES [7:4]: 0b0001 is AES alone, 0b0010 AES and PMULL.
    let aes = (isar0 >> 4) & 0xf;
    let mut features = 0;
    if adv_simd != 0b1111 && aes >= 0b0010 {
        features |= AES;
    }
    features
}

#[cfg(test)]
mod tests {
    //! Unit tests, because these functions are private and pure, with answers known from the
    //! headers; the words are synthetic, one per class of CPU.

    use super::*;

    /// A Graviton2-like (Neoverse N1) word: bits 0-12 (`FP` through `ASIMDRDM`, which include
    /// `AES` and `PMULL`), `LRCPC` 15, `DCPOP` 16, `ASIMDDP` 20 and `SSBS` 28; no `SHA3` or `SVE`.
    const GRAVITON2_HWCAP: u64 = 0x1fff | 1 << 15 | 1 << 16 | 1 << 20 | 1 << 28;

    #[test]
    fn hwcap_with_asimd_aes_and_pmull_gives_aes() {
        assert_eq!(features_from_hwcap(hwcap::ASIMD | hwcap::AES | hwcap::PMULL, 0), AES);
        assert_eq!(features_from_hwcap(GRAVITON2_HWCAP, 0), AES);
    }

    #[test]
    fn hwcap_missing_any_of_the_three_gives_nothing() {
        // NEON alone, as on a Cortex-A53 sold without the Cryptographic Extension.
        assert_eq!(features_from_hwcap(hwcap::ASIMD, 0), 0);
        // AES without PMULL: what std's "aes" alone accepts on Linux.
        assert_eq!(features_from_hwcap(hwcap::ASIMD | hwcap::AES, 0), 0);
        assert_eq!(features_from_hwcap(hwcap::ASIMD | hwcap::PMULL, 0), 0);
        assert_eq!(features_from_hwcap(hwcap::AES | hwcap::PMULL, 0), 0);
    }

    #[test]
    fn hwcap_all_zero_and_all_ones() {
        assert_eq!(features_from_hwcap(0, 0), 0);
        assert_eq!(features_from_hwcap(0, u64::MAX), 0);
        assert_eq!(features_from_hwcap(u64::MAX, u64::MAX), AES);
    }

    #[test]
    fn sysctl_needs_all_three_names() {
        let names =
            [c"hw.optional.neon", c"hw.optional.arm.FEAT_AES", c"hw.optional.arm.FEAT_PMULL"];
        assert_eq!(features_from_sysctl(|n| names.contains(&n)), AES);
        for missing in names {
            assert_eq!(
                features_from_sysctl(|n| n != missing && names.contains(&n)),
                0,
                "{missing:?}"
            );
        }
        assert_eq!(features_from_sysctl(|_| false), 0);
        assert_eq!(features_from_sysctl(|_| true), AES);
    }

    #[test]
    fn pf_needs_neon_and_crypto() {
        assert_eq!(features_from_pf(|_| true), AES);
        assert_eq!(features_from_pf(|f| f == PfFeature::Neon), 0);
        assert_eq!(features_from_pf(|f| f == PfFeature::V8Crypto), 0);
        assert_eq!(features_from_pf(|_| false), 0);
    }

    #[test]
    fn sysctl_present_only_for_a_whole_nonzero_answer() {
        assert!(sysctl_present(0, 4, 1));
        // An unknown name, such as `hw.optional.AdvSIMD` on macOS 26.
        assert!(!sysctl_present(-1, 4, 1));
        assert!(!sysctl_present(0, 8, 1));
        assert!(!sysctl_present(0, 0, 1));
        assert!(!sysctl_present(0, 4, 0));
    }

    // 19 is in `winnt.h` and Microsoft's `windows-sys` 0.61.2, though the Microsoft Learn page
    // for `IsProcessorFeaturePresent` does not list it; 30 is on that page.
    #[test]
    fn pf_constants_are_the_documented_values() {
        assert_eq!(PfFeature::Neon as u32, 19);
        assert_eq!(PfFeature::V8Crypto as u32, 30);
    }

    #[test]
    fn id_registers_need_pmull_and_advsimd() {
        let aes_only = 0b0001 << 4;
        let aes_pmull = 0b0010 << 4;
        let advsimd_ni = 0b1111 << 20;
        let advsimd_fp16 = 0b0001 << 20;
        assert_eq!(features_from_id_registers(0, aes_pmull, 0), AES);
        assert_eq!(features_from_id_registers(advsimd_fp16, aes_pmull, 0), AES);
        assert_eq!(features_from_id_registers(0, aes_only, 0), 0);
        assert_eq!(features_from_id_registers(advsimd_ni, aes_pmull, 0), 0);
        // A reserved value above PMULL still has it, as the "at least" reading of the field says.
        assert_eq!(features_from_id_registers(0, 0b1111 << 4, 0), AES);
    }

    #[test]
    fn id_registers_all_zero_and_all_ones() {
        assert_eq!(features_from_id_registers(0, 0, 0), 0);
        // All ones has AdvSIMD = 0b1111, not implemented.
        assert_eq!(features_from_id_registers(u64::MAX, u64::MAX, u64::MAX), 0);
        assert_eq!(features_from_id_registers(0, u64::MAX, u64::MAX), AES);
    }

    #[test]
    fn id_registers_read_only_their_fields() {
        // Every bit outside PFR0.AdvSIMD and ISAR0.AES set, those two fields at "absent".
        let pfr0 = !(0xf << 20) | (0b1111 << 20);
        let isar0 = !(0xf << 4);
        assert_eq!(features_from_id_registers(pfr0, isar0, u64::MAX), 0);
    }
}
