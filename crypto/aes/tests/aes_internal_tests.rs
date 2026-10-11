//! The contract of the three `AESInternal` engines that is neither a known-answer value nor a
//! trait conformance property: their size, name and strength.
//!
//! The "Memory Usage" table in the crate docs quotes the sizes, and the whole point of the crate
//! is that they are this small: `4 * (Nr + 1)` words of schedule (FIPS 197 Sec 5.2), nothing
//! else, and no tables anywhere. A size that matches `4 * (Nr + 1) * 4` bytes exactly also shows
//! there is no round counter, direction flag or initialised marker alongside the schedule, which
//! is what lets both directions run from one value. If the representation grows, the docs are
//! wrong -- fix both.

use bouncycastle_aes::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::Algorithm;

/// One check per engine: the size is exactly the schedule, the name is the FIPS 197 name, and
/// the strength is the key length (FIPS 197 Sec 6.1 ties the three key lengths to 128, 192 and
/// 256 bits).
fn check_engine<A: Algorithm>(nr: usize, key_len: usize, name: &str) {
    assert_eq!(size_of::<A>(), 4 * (nr + 1) * 4, "{name}: 4 * (Nr + 1) words, nothing else");
    assert_eq!(A::ALG_NAME, name);
    assert_eq!(A::MAX_SECURITY_STRENGTH, SecurityStrength::from_bytes(key_len));
}

#[test]
fn the_engines_match_the_documented_memory_table_names_and_strengths() {
    check_engine::<AES128Internal>(10, 16, "AES-128");
    check_engine::<AES192Internal>(12, 24, "AES-192");
    check_engine::<AES256Internal>(14, 32, "AES-256");
    // The literal figures the crate docs' table quotes, so a wrong `nr` above cannot hide one.
    assert_eq!(size_of::<AES128Internal>(), 176);
    assert_eq!(size_of::<AES192Internal>(), 208);
    assert_eq!(size_of::<AES256Internal>(), 240);
}
