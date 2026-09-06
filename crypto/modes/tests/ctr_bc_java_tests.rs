//! Cross-implementation tests for CTR against **BC Java's `SICBlockCipher`**.
//!
//! # Why this is the closest comparison available
//!
//! `ctr_vector_tests.rs` checks against OpenSSL, but OpenSSL's `-aes-*-ctr` takes the whole 16-byte
//! initial counter block as its IV: it has no notion of a nonce, and its counter is always the full
//! block. It can therefore only ever agree with this type at the one width where the two coincide,
//! and it cannot exercise a **narrow** counter at all.
//!
//! BC Java's `SICBlockCipher` (Segmented Integer Counter, its name for CTR) is built the same way
//! this type is. Given an IV shorter than the block it
//!
//! * copies the IV into the leading bytes and **zero-fills the rest**, so the counter starts at 0
//!   (`reset()`);
//! * increments the trailing bytes big-endian with carry (`incrementCounter()`);
//! * and **throws** `IllegalStateException("Counter in CTR/SIC mode out of range.")` once the carry
//!   would reach the IV, which `checkCounter()` detects by comparing the leading bytes back against
//!   the IV.
//!
//! That is the same construction, the same starting value and the same overflow rule, so it can
//! check the counter widths OpenSSL cannot reach. The one difference is the cap: BC Java allows a
//! counter up to `min(8, blockSize / 2)` bytes, which is 8 for AES, where this type stops at 4. Ours
//! is a subset, and on the overlap (nonce 12 to 15 bytes) the two agree exactly.
//!
//! # Provenance
//!
//! The blocks below are the **keystream**, i.e. `Oj = CIPH_K(N | j)`, obtained by encrypting zeros
//! with `SICBlockCipher.newInstance(AESEngine.newInstance())` under AES-128 key
//! `2b7e151628aed2a6abf7158809cf4f3c`, from the working tree of `bc-java` at
//! `core/src/main/java/org/bouncycastle/crypto/modes/SICBlockCipher.java`. Encrypting zeros is used
//! so the values are the keystream itself rather than a keystream XORed with something, which makes
//! a mismatch point straight at the counter block that produced it.
//!
//! Whole-message agreement with BC Java was also checked while these were generated -- the 69-byte
//! vectors of `ctr_vector_tests.rs` and a 5000-byte message across the 255-to-256 carry, at all
//! three key lengths -- and it is exact. Those cases are covered there and by the ACVP suite, so
//! what is pinned here is specifically the part neither of them reaches: the narrow counters.

use bouncycastle_aes_lowmemory::Aes128;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::StreamCipherEncryptor;
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_hex as hex;
use bouncycastle_modes::{Ctr, Encrypting};

/// The AES-128 key used for every vector in this file: SP 800-38A Appendix F's first key.
const KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";

fn key() -> KeyMaterial<16> {
    let raw = hex::decode(KEY).expect("valid hex");
    KeyMaterial::<16>::from_bytes_as_type(&raw, KeyType::SymmetricCipherKey).expect("a valid key")
}

/// Produces `blocks` blocks of keystream by encrypting zeros under the given nonce.
fn keystream<const NONCE_LEN: usize>(nonce_hex: &str, blocks: usize) -> Vec<u8> {
    let nonce: [u8; NONCE_LEN] =
        hex::decode(nonce_hex).expect("valid hex").try_into().expect("nonce length");
    let (mut enc, got) = Ctr::<Aes128, Encrypting, 16, 16, NONCE_LEN>::do_encrypt_init_rng(
        &key(),
        &mut FixedSeedRNG::<NONCE_LEN>::new(nonce),
    )
    .expect("encrypt init");
    assert_eq!(got, nonce, "the pinned RNG should reproduce the nonce");

    let mut data = vec![0u8; blocks * 16];
    enc.do_encrypt(&mut data).expect("encryption");
    data
}

/// Checks the numbered keystream blocks against BC Java's.
fn check(name: &str, keystream: &[u8], expected: &[(usize, &str)]) {
    for (j, want) in expected {
        let got = &keystream[j * 16..(j + 1) * 16];
        let got_hex: String = got.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            &got_hex, want,
            "{name}: keystream block {j} must match BC Java's SICBlockCipher"
        );
    }
}

/// A **1-byte** counter (15-byte nonce): the narrowest this type allows, and a width OpenSSL cannot
/// express at all. Blocks 254 and 255 are the last two the counter can produce, so this pins the top
/// of the range as well as the bottom.
#[test]
fn one_byte_counter_matches_bc_java() {
    const NONCE: &str = "5a5b5c5d5e5f606162636465666768";
    let ks = keystream::<15>(NONCE, 256);
    check(
        "1-byte counter",
        &ks,
        &[
            (0, "419c915d236c793736311df5d96395aa"),
            (1, "23af650ed9d051ac2d5ed6365ff36b1e"),
            (2, "1e1723bab8f7a67f152ae5bf5e0a6156"),
            (254, "da78aa259930654dec5fd7b1bd194ee9"),
            (255, "3e0caa53956c10ee5c3959d588b79cf3"),
        ],
    );
}

/// A **2-byte** counter (14-byte nonce), spanning the 255-to-256 boundary.
///
/// That boundary is the carry from one counter byte into the next, and it is the case a per-byte
/// increment that forgot to carry, or one that wrote the counter little-endian, would get wrong.
/// BC Java carries the same way, so agreement across blocks 255 and 256 pins it.
#[test]
fn two_byte_counter_matches_bc_java_across_the_carry() {
    const NONCE: &str = "3c3d3e3f40414243444546474849";
    let ks = keystream::<14>(NONCE, 260);
    check(
        "2-byte counter",
        &ks,
        &[
            (0, "2f79f802e5baf1eea03e079c55fa43ff"),
            (254, "7ef19c2ab2e750a19741a653edabd4e2"),
            (255, "a30a0d0c6c2c58bb04befb8aa32675ee"),
            (256, "580080107847864b8589e21a9fb3cdff"),
            (257, "fd85537add6a73476e13928f49eba5ee"),
        ],
    );
}

/// A **3-byte** counter (13-byte nonce), the remaining width between the two above and the 4-byte
/// counter the ACVP and OpenSSL suites cover.
#[test]
fn three_byte_counter_matches_bc_java() {
    const NONCE: &str = "0102030405060708090a0b0c0d";
    let ks = keystream::<13>(NONCE, 3);
    check(
        "3-byte counter",
        &ks,
        &[
            (0, "e24be69cfe7c13dd7a94807fb91f95a7"),
            (1, "234790f73eb542c18dbfc2a6f7a06795"),
            (2, "95e5a3963bcdf6183357da61878861bc"),
        ],
    );
}

/// The counter limit falls in the same place as BC Java's.
///
/// BC Java throws `IllegalStateException("Counter in CTR/SIC mode out of range.")` on the byte after
/// the counter's last value; this type returns `SymmetricCipherError::StateError` on the same byte.
/// Checked here at the same 15-byte nonce as above, where the boundary is 256 blocks -- 4096 bytes
/// exactly -- and confirmed against BC Java at the 14-byte nonce too, where it is 1 MiB.
#[test]
fn the_counter_limit_falls_where_bc_java_throws() {
    let nonce: [u8; 15] =
        hex::decode("5a5b5c5d5e5f606162636465666768").unwrap().try_into().unwrap();
    let (mut enc, _) = Ctr::<Aes128, Encrypting, 16, 16, 15>::do_encrypt_init_rng(
        &key(),
        &mut FixedSeedRNG::<15>::new(nonce),
    )
    .unwrap();

    // BC Java encrypts 4096 bytes under this IV without complaint.
    let mut data = vec![0u8; 4096];
    enc.do_encrypt(&mut data).expect("4096 bytes must be accepted, as BC Java accepts them");

    // ...and throws on the next byte.
    let mut one = [0u8; 1];
    assert!(
        enc.do_encrypt(&mut one).is_err(),
        "byte 4097 must be refused, where BC Java throws IllegalStateException"
    );
}
