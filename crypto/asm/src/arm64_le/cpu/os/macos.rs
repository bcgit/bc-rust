//! macOS and iOS: the `hw.optional` sysctls, read with `sysctlbyname`, and the parser that turns
//! them into the feature word.
//!
//! On Darwin NEON is read as `hw.optional.neon`. xnu's `bsd/kern/kern_mib.c` defines it from
//! `gARM_AdvSIMD` in every release from xnu-8792 (macOS 13, line 1056) to main (macOS 26,
//! `LEGACY_ARM_SYSCTL(neon, AdvSIMD)`, line 1154, pinned equal by its test at line 1292),
//! while the top-level `hw.optional.AdvSIMD` that std 1.94.1 reads (`darwin/aarch64.rs:39`) is
//! gone from main, so on macOS 26 std reports no `asimd`.

#![deny(unsafe_code)]

use super::AES;
use core::ffi::CStr;

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod ffi {
    //! The one call, and the only code in this file allowed `unsafe`.

    #![allow(unsafe_code)]

    unsafe extern "C" {
        /// `int sysctlbyname(const char *, void *, size_t *, void *, size_t)`, in libSystem, which
        /// every Darwin binary links.
        fn sysctlbyname(
            name: *const core::ffi::c_char,
            oldp: *mut core::ffi::c_void,
            oldlenp: *mut usize,
            newp: *mut core::ffi::c_void,
            newlen: usize,
        ) -> core::ffi::c_int;
    }

    /// Whether the integer sysctl `name` exists and is non-zero; anything else, an unknown name
    /// included, is "not present".
    pub(super) fn sysctl_flag(name: &core::ffi::CStr) -> bool {
        let mut value: i32 = 0;
        let mut len = size_of::<i32>();
        // SAFETY: `name` is a `CStr`, so NUL-terminated; `value` is a live local of `len` bytes, so
        // the kernel writes at most that many and stores the length it wrote in `len`; nothing is
        // set, since the new value is null with length 0.
        let rc = unsafe {
            sysctlbyname(name.as_ptr(), (&raw mut value).cast(), &mut len, core::ptr::null_mut(), 0)
        };
        super::sysctl_present(rc, len, value)
    }
}

/// The `hw.optional` sysctls.
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(in super::super) fn probe() -> u32 {
    features_from_sysctl(ffi::sysctl_flag)
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

#[cfg(test)]
mod tests {
    //! Unit tests, because these functions are private and pure, with answers known from the
    //! headers; the words are synthetic, one per class of CPU.

    use super::*;

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
    fn sysctl_present_only_for_a_whole_nonzero_answer() {
        assert!(sysctl_present(0, 4, 1));
        // An unknown name, such as `hw.optional.AdvSIMD` on macOS 26.
        assert!(!sysctl_present(-1, 4, 1));
        assert!(!sysctl_present(0, 8, 1));
        assert!(!sysctl_present(0, 0, 1));
        assert!(!sysctl_present(0, 4, 0));
    }

    /// The real call, on a known name and an unknown one.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[test]
    fn sysctl_flag_reads_a_known_name_and_rejects_an_unknown_one() {
        // `hw.optional.neon` is 1 on every Apple aarch64 device.
        assert!(ffi::sysctl_flag(c"hw.optional.neon"));
        assert!(!ffi::sysctl_flag(c"hw.optional.bouncycastle.no_such_name"));
    }
}
