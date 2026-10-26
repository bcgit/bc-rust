//! What each operating system reports, turned into the feature word: one bit per proof. Each
//! file here is one column of the table in the `cpu` module docs: its parser, and on its own
//! targets the one call that asks. Every target compiles every parser, so their tests run on any
//! host; each target calls only its own.

#![deny(unsafe_code)]

mod bare_metal;
mod linux;
mod macos;
mod windows;

/// The bit for [`Aes`](super::Aes) in the feature word.
pub(super) const AES: u32 = 1 << 0;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(super) use linux::probe;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(super) use macos::probe;
#[cfg(target_os = "windows")]
pub(super) use windows::probe;

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
