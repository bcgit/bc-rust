//! The test vectors of Bouncy Castle Java's SM4 tests, run against this port.
//!
//! Two files in bc-java carry SM4 known answers, and both are reproduced here exactly as written
//! there:
//!
//! * `core/src/test/java/org/bouncycastle/crypto/test/SM4Test.java` -- a `BlockCipherVectorTest`
//!   (key, plaintext, ciphertext, checked in both directions by `CipherTest`), and
//!   `test1000000()`, which encrypts the plaintext 1,000,000 times in place, checks the result,
//!   then decrypts it 1,000,000 times and checks the plaintext comes back. Its header credits the
//!   vectors to <http://eprint.iacr.org/2008/329.pdf>, the Diffie-Ledin translation of the
//!   standard.
//! * `prov/src/test/java/org/bouncycastle/jce/provider/test/SM4Test.java` -- the `cipherTests`
//!   array `{ "128", key, plaintext, ciphertext }`, the same vector driven through the JCE
//!   provider as `SM4/ECB/NoPadding`.
//!
//! These are GB/T 32907-2016's own Example 1 and Example 2, so they coincide with Appendix A.1.1
//! through A.1.3 of draft-ribose-cfrg-sm4-10 in `gbt32907_tests.rs`. They are kept as a separate
//! file so that agreement with the source implementation is asserted in its own terms, including
//! the decryption half of `test1000000()`, which the draft does not print. That test is ignored in
//! unoptimised builds (see its attribute) and runs under `cargo test --release`.

use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_hex as hex;
use bouncycastle_sm4::{Block, SM4};

/// `SM4Test.tests[0]` and the provider `cipherTests`: `KeyParameter(Hex.decode(..))`.
const KEY: &str = "0123456789abcdeffedcba9876543210";
/// The `BlockCipherVectorTest` input.
const PLAINTEXT: &str = "0123456789abcdeffedcba9876543210";
/// The `BlockCipherVectorTest` output.
const CIPHERTEXT: &str = "681edf34d206965e86b3e94f536e4246";
/// `test1000000()`: `cipher`.
const CIPHERTEXT_1000000: &str = "595298c7c6fd271f0402f804c33d3f66";

fn block(hex_str: &str) -> Block {
    hex::decode(hex_str).expect("valid hex").try_into().expect("16 bytes")
}

fn engine() -> SM4 {
    let key = KeyMaterial::<16>::from_bytes_as_type(&block(KEY), KeyType::SymmetricCipherKey)
        .expect("a valid symmetric cipher key");
    SM4::new(&key).expect("a valid SM4 key")
}

/// `BlockCipherVectorTest`, encryption half: `engine.init(true, param)` then `processBlock`.
#[test]
fn block_cipher_vector_test_encrypts() {
    let mut buf = block(PLAINTEXT);
    engine().encrypt_block(&mut buf);
    assert_eq!(buf, block(CIPHERTEXT), "SM4 failed encryption");
}

/// `BlockCipherVectorTest`, decryption half: `engine.init(false, param)` then `processBlock`.
#[test]
fn block_cipher_vector_test_decrypts() {
    let mut buf = block(CIPHERTEXT);
    engine().decrypt_block(&mut buf);
    assert_eq!(buf, block(PLAINTEXT), "SM4 failed reversal");
}

/// The provider test's `cipherTests` entry is the same vector at "128" bits, through
/// `SM4/ECB/NoPadding`; ECB on one block is the bare permutation.
#[test]
fn provider_cipher_tests_entry() {
    let mut buf = block(PLAINTEXT);
    engine().encrypt_block(&mut buf);
    assert_eq!(buf, block(CIPHERTEXT), "SM4 failed encryption");
    engine().decrypt_block(&mut buf);
    assert_eq!(buf, block(PLAINTEXT), "SM4 failed decryption");
}

/// `test1000000()`, both halves: 1,000,000 encryptions in place must give `cipher`, and
/// 1,000,000 decryptions of that must give `plain` back.
///
/// The decryption half is the part not printed in the specification, and it is the strongest
/// check of the reversed-round-key decryption path: one wrong `rk_{31-i}` would derail a million
/// chained blocks.
/// Gated to optimised builds: a million single-block calls through the four-lane circuit take
/// over a minute unoptimised. `cargo test --release -p bouncycastle-sm4` runs it.
#[cfg_attr(debug_assertions, ignore = "1,000,000 iterations; run with `cargo test --release`")]
#[test]
fn test_1000000() {
    let engine = engine();
    let mut buf = block(PLAINTEXT);

    for _ in 0..1_000_000 {
        engine.encrypt_block(&mut buf);
    }
    assert_eq!(buf, block(CIPHERTEXT_1000000), "1000000 encryption test failed");

    for _ in 0..1_000_000 {
        engine.decrypt_block(&mut buf);
    }
    assert_eq!(buf, block(PLAINTEXT), "1000000 decryption test failed");
}
