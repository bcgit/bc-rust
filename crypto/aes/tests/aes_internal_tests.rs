//! The contract of the three `AESInternal` engines that is neither a known-answer value nor a
//! trait conformance property: their size, name and strength.
//!
//! The "Memory Usage" table in the crate docs quotes the sizes, and the whole point of the crate
//! is that they are this small: `4 * (Nr + 1)` words of schedule (FIPS 197 Sec 5.2) per
//! schedule held, nothing else, and no tables anywhere. The bit-sliced engine holds one
//! schedule; the `Arm` engine, the default on an AArch64 build with the Crypto Extensions,
//! holds two (`w` and `dw`), and `Detected` holds one of those two behind a variant tag. A size that matches the schedules exactly also shows there is no
//! round counter, direction flag or initialised marker alongside them. If the representation
//! grows, the docs are wrong -- fix both.

use bouncycastle_aes::hazmat::engine::Bitsliced;
use bouncycastle_aes::hazmat::{AES128Internal, AES192Internal, AES256Internal, AESInternal};
use bouncycastle_aes::{AES128Params, AES192Params, AES256Params};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::Algorithm;

/// How many schedules the default engine holds on this target, and what it holds besides: two
/// where the default is `Arm` or `Detected` (an AArch64 build that declares the Crypto
/// Extensions or targets an operating system the arm crate can ask), one everywhere else, and
/// for `Detected` a 4-byte variant tag (the enum takes `Bitsliced`'s `u32` alignment).
#[cfg(all(
    target_arch = "aarch64",
    target_endian = "little",
    target_feature = "aes",
    target_feature = "neon"
))]
const DEFAULT_ENGINE: (usize, usize) = (2, 0);
#[cfg(all(
    target_arch = "aarch64",
    target_endian = "little",
    target_feature = "neon",
    not(target_feature = "aes"),
    any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "windows"
    )
))]
const DEFAULT_ENGINE: (usize, usize) = (2, 4);
#[cfg(not(all(
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
)))]
const DEFAULT_ENGINE: (usize, usize) = (1, 0);

/// One check per engine: the size is exactly its schedules, the name is the FIPS 197 name, and
/// the strength is the key length (FIPS 197 Sec 6.1 ties the three key lengths to 128, 192 and
/// 256 bits).
fn check_engine<A: Algorithm>(
    nr: usize,
    key_len: usize,
    name: &str,
    (schedules, tag): (usize, usize),
) {
    assert_eq!(
        size_of::<A>(),
        schedules * 4 * (nr + 1) * 4 + tag,
        "{name}: {schedules} x 4 * (Nr + 1) words and a {tag}-byte tag, nothing else"
    );
    assert_eq!(A::ALG_NAME, name);
    assert_eq!(A::MAX_SECURITY_STRENGTH, SecurityStrength::from_bytes(key_len));
}

#[test]
fn the_engines_match_the_documented_memory_table_names_and_strengths() {
    check_engine::<AES128Internal>(10, 16, "AES-128", DEFAULT_ENGINE);
    check_engine::<AES192Internal>(12, 24, "AES-192", DEFAULT_ENGINE);
    check_engine::<AES256Internal>(14, 32, "AES-256", DEFAULT_ENGINE);
    check_engine::<AESInternal<AES128Params, Bitsliced<AES128Params>>>(10, 16, "AES-128", (1, 0));
    check_engine::<AESInternal<AES192Params, Bitsliced<AES192Params>>>(12, 24, "AES-192", (1, 0));
    check_engine::<AESInternal<AES256Params, Bitsliced<AES256Params>>>(14, 32, "AES-256", (1, 0));

    // The literal figures the crate docs' table quotes, so a wrong `nr` above cannot hide one:
    // the bit-sliced engine on every target, and the default engine on this one.
    assert_eq!(size_of::<AESInternal<AES128Params, Bitsliced<AES128Params>>>(), 176);
    assert_eq!(size_of::<AESInternal<AES192Params, Bitsliced<AES192Params>>>(), 208);
    assert_eq!(size_of::<AESInternal<AES256Params, Bitsliced<AES256Params>>>(), 240);
    assert_eq!(size_of::<AES128Internal>(), 176 * DEFAULT_ENGINE.0 + DEFAULT_ENGINE.1);
    assert_eq!(size_of::<AES192Internal>(), 208 * DEFAULT_ENGINE.0 + DEFAULT_ENGINE.1);
    assert_eq!(size_of::<AES256Internal>(), 240 * DEFAULT_ENGINE.0 + DEFAULT_ENGINE.1);
}
