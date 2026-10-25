//! The one call per operating system that asks what the CPU has, and the crate's only `unsafe`
//! outside `intrinsics` and the proof methods. One back end is compiled per target; elsewhere
//! [`probe`] reports nothing and the portable engines run.
//!
//! On Darwin NEON is read as `hw.optional.neon`. xnu's `bsd/kern/kern_mib.c` defines it from
//! `gARM_AdvSIMD` in every release from xnu-8792 (macOS 13, line 1056) to main (macOS 26,
//! `LEGACY_ARM_SYSCTL(neon, AdvSIMD)`, line 1154, pinned equal by its test at line 1292),
//! while the top-level `hw.optional.AdvSIMD` that std 1.94.1 reads (`darwin/aarch64.rs:39`) is
//! gone from main, so on macOS 26 std reports no `asimd`.

#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe extern "C" {
    /// `unsigned long getauxval(unsigned long type)`: glibc >= 2.16, musl and bionic, one of
    /// which every Rust Linux and Android target links.
    fn getauxval(t: core::ffi::c_ulong) -> core::ffi::c_ulong;
}

/// The auxiliary vector's `AT_HWCAP` and `AT_HWCAP2` words.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(super) fn probe() -> u32 {
    use core::ffi::c_ulong;
    // The kernel's `include/uapi/linux/auxvec.h`.
    const AT_HWCAP: c_ulong = 16;
    const AT_HWCAP2: c_ulong = 26;
    // SAFETY: the declaration matches the C library's; an integer goes in and one comes out,
    // so no pointer crosses, and a key the kernel does not supply returns 0.
    let (hwcap, hwcap2) = unsafe { (getauxval(AT_HWCAP), getauxval(AT_HWCAP2)) };
    super::parse::features_from_hwcap(hwcap, hwcap2)
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
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

/// The `hw.optional` sysctls.
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(super) fn probe() -> u32 {
    super::parse::features_from_sysctl(sysctl_flag)
}

/// Whether the integer sysctl `name` exists and is non-zero; anything else, an unknown name
/// included, is "not present".
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn sysctl_flag(name: &core::ffi::CStr) -> bool {
    let mut value: i32 = 0;
    let mut len = size_of::<i32>();
    // SAFETY: `name` is a `CStr`, so NUL-terminated; `value` is a live local of `len` bytes, so
    // the kernel writes at most that many and stores the length it wrote in `len`; nothing is
    // set, since the new value is null with length 0.
    let rc = unsafe {
        sysctlbyname(name.as_ptr(), (&raw mut value).cast(), &mut len, core::ptr::null_mut(), 0)
    };
    super::parse::sysctl_present(rc, len, value)
}

#[cfg(target_os = "windows")]
#[link(name = "kernel32")] // a `no_std` crate names the import library itself
unsafe extern "system" {
    /// `BOOL IsProcessorFeaturePresent(DWORD ProcessorFeature)`.
    fn IsProcessorFeaturePresent(feature: u32) -> i32;
}

/// `IsProcessorFeaturePresent`, one call per constant.
#[cfg(target_os = "windows")]
pub(super) fn probe() -> u32 {
    super::parse::features_from_pf(|feature| {
        // SAFETY: the declaration matches kernel32's; an integer goes in and one comes out, and
        // `feature` is one of the documented constants. An unknown one returns 0.
        unsafe { IsProcessorFeaturePresent(feature as u32) != 0 }
    })
}

/// No back end: nothing is detected, so only a build that declares a feature uses its kernels.
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "windows"
)))]
pub(super) fn probe() -> u32 {
    0
}

#[cfg(all(test, any(target_os = "macos", target_os = "ios")))]
mod tests {
    //! A unit test because `sysctl_flag` is private: the real call, on a known name and an
    //! unknown one.

    use super::sysctl_flag;

    #[test]
    fn sysctl_flag_reads_a_known_name_and_rejects_an_unknown_one() {
        // `hw.optional.neon` is 1 on every Apple aarch64 device.
        assert!(sysctl_flag(c"hw.optional.neon"));
        assert!(!sysctl_flag(c"hw.optional.bouncycastle.no_such_name"));
    }
}
