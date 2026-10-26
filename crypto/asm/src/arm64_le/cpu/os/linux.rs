//! Linux and Android: the auxiliary vector's `AT_HWCAP` and `AT_HWCAP2` words, read with
//! `getauxval`, and the parser that turns them into the feature word.

#![deny(unsafe_code)]

use super::AES;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod ffi {
    //! The one call, and the only code in this file allowed `unsafe`.

    #![allow(unsafe_code)]

    unsafe extern "C" {
        /// `unsigned long getauxval(unsigned long type)`: glibc >= 2.16, musl and bionic, one of
        /// which every Rust Linux and Android target links.
        fn getauxval(t: core::ffi::c_ulong) -> core::ffi::c_ulong;
    }

    /// The `AT_HWCAP` and `AT_HWCAP2` words.
    pub(super) fn auxv_words() -> (core::ffi::c_ulong, core::ffi::c_ulong) {
        use core::ffi::c_ulong;
        // The kernel's `include/uapi/linux/auxvec.h`.
        const AT_HWCAP: c_ulong = 16;
        const AT_HWCAP2: c_ulong = 26;
        // SAFETY: the declaration matches the C library's; an integer goes in and one comes out,
        // so no pointer crosses, and a key the kernel does not supply returns 0.
        unsafe { (getauxval(AT_HWCAP), getauxval(AT_HWCAP2)) }
    }
}

/// The auxiliary vector's `AT_HWCAP` and `AT_HWCAP2` words.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(in super::super) fn probe() -> u32 {
    let (hwcap, hwcap2) = ffi::auxv_words();
    features_from_hwcap(hwcap, hwcap2)
}

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
}
