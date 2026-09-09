//! FIPS 180-4 s. 5.3.6 known-answer tests for the SHA-512/t IV Generation Function.
//!
//! The initial hash value H(0) for SHA-512/224 and SHA-512/256 is not stored as a literal in this
//! crate: it is produced by the IV Generation Function (FIPS 180-4 s. 5.3.6), evaluated at compile
//! time. These tests pin what that function produces against the words the standard lists in
//! s. 5.3.6.1 and s. 5.3.6.2.
//!
//! H(0) is read back through the public suspend API rather than from a crate-private constant. A
//! freshly-constructed hash has processed no message, so the chaining value in its serialized state
//! is still H(0). The layout is a 3-byte library version tag (written by
//! `bouncycastle_core::suspendable_state::add_lib_ver`) followed by the eight 64-bit chaining
//! words, little-endian.
//!
//! Note that a wrong H(0) is also caught end-to-end by the CAVP vectors in `cavp_tests.rs`, since
//! every SHA-512/224 and SHA-512/256 digest would then differ. These tests localize such a failure
//! to the IV Generation Function itself.

use bouncycastle_core::traits::Suspendable;
use bouncycastle_sha2::{SHA512_224, SHA512_256, SUSPENDED_SHA512_STATE_LEN};

/// Bytes occupied by the library version tag at the front of a suspended state.
const LIB_VER_TAG_LEN: usize = 3;

/// FIPS 180-4 s. 5.3.6.1: the eight 64-bit words H(0) shall consist of for SHA-512/224, "obtained
/// by executing the SHA-512/t IV Generation Function with t = 224".
const SHA512_224_H0: [u64; 8] = [
    0x8C3D37C819544DA2, 0x73E1996689DCD4D6, 0x1DFAB7AE32FF9C82, 0x679DD514582F9FCF,
    0x0F6D2B697BD44DA8, 0x77E36F7304C48942, 0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1,
];

/// FIPS 180-4 s. 5.3.6.2: the eight 64-bit words H(0) shall consist of for SHA-512/256, "obtained
/// by executing the SHA-512/t IV Generation Function with t = 256".
const SHA512_256_H0: [u64; 8] = [
    0x22312194FC2BF72C, 0x9F555FA3C84C64C2, 0x2393B86B6F53B151, 0x963877195940EABD,
    0x96283EE2A88EFFE3, 0xBE5E1E2553863992, 0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2,
];

/// Recovers the eight chaining words of a freshly-constructed SHA-512-family hash, which has had no
/// message applied and so still holds H(0).
fn h0_of<H: Default + Suspendable<SUSPENDED_SHA512_STATE_LEN>>() -> [u64; 8] {
    let state = H::default().suspend();

    let mut h0 = [0u64; 8];
    for (i, word) in h0.iter_mut().enumerate() {
        let offset = LIB_VER_TAG_LEN + (i * 8);
        // infallible: the slice is 8 bytes, and offset + 8 <= 3 + 64 < SUSPENDED_SHA512_STATE_LEN.
        *word = u64::from_le_bytes(state[offset..offset + 8].try_into().unwrap());
    }
    h0
}

/// FIPS 180-4 s. 6.6 exception 1 / s. 5.3.6.1: SHA-512/224 uses the H(0) listed in s. 5.3.6.1.
#[test]
fn sha512_224_h0_matches_the_listed_words() {
    assert_eq!(h0_of::<SHA512_224>(), SHA512_224_H0);
}

/// FIPS 180-4 s. 6.7 exception 1 / s. 5.3.6.2: SHA-512/256 uses the H(0) listed in s. 5.3.6.2.
#[test]
fn sha512_256_h0_matches_the_listed_words() {
    assert_eq!(h0_of::<SHA512_256>(), SHA512_256_H0);
}
