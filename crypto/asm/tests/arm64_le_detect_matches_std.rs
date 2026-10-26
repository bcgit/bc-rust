//! The crate's own detector against the standard library's, on whatever machine runs the tests,
//! and its cache under repeated and concurrent calls. The library uses no std; a test may.

#![cfg(all(
    target_arch = "aarch64",
    target_endian = "little",
    target_feature = "neon",
    any(
        target_feature = "aes",
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "windows"
    )
))]

use bouncycastle_asm::arm64_le::Aes;
use std::arch::is_aarch64_feature_detected;

#[test]
fn aes_detect_matches_std() {
    // Only these three: std 1.94.1 reads `hw.optional.AdvSIMD` (`darwin/aarch64.rs:39`), gone
    // from macOS 26, so its run-time `asimd`, `sha2` and `sha3` are false there.
    let std_says = is_aarch64_feature_detected!("aes")
        && is_aarch64_feature_detected!("pmull")
        && is_aarch64_feature_detected!("neon");
    assert_eq!(Aes::detect().is_some(), std_says);
}

#[test]
fn a_thousand_calls_agree() {
    let first = Aes::detect().is_some();
    for _ in 0..1000 {
        assert_eq!(Aes::detect().is_some(), first);
    }
}

#[test]
fn eight_threads_agree() {
    let answers: Vec<bool> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..8).map(|_| s.spawn(|| Aes::detect().is_some())).collect();
        handles.into_iter().map(|h| h.join().expect("a detecting thread")).collect()
    });
    assert!(answers.iter().all(|&a| a == answers[0]), "{answers:?}");
    assert_eq!(answers[0], Aes::detect().is_some());
}
