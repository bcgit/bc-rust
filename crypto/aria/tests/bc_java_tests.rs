//! The checks of Bouncy Castle Java's `ARIATest`
//! (`core/src/test/java/org/bouncycastle/crypto/test/ARIATest.java`), run against this port.
//!
//! `ARIATest` does three things: `checkTestVectors_RFC5794()` runs the three Appendix A vectors in
//! both directions through `processBlock`; `checkRandomRoundtrips()` encrypts and decrypts a
//! chain of 100 random blocks for each key length; and `MyARIAEngine.checkImplementation()` checks
//! that `A` is an involution on 100 random inputs and that `SB3`/`SB4` invert `SB1`/`SB2` on all
//! 256 bytes. The first and second are reproduced here in the same terms (with a fixed
//! pseudo-random source in place of `SecureRandom`); the third is pinned inside the crate, where
//! `A` and the S-box circuits are visible (`round::tests` and `sbox::tests`), and its S-box half is
//! repeated here against the reference tables.

mod common;

use bouncycastle_aria::{ARIA_128, ARIA_192, ARIA_256, BLOCK_LEN};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::ElectronicCodeBook;
use common::{SB1, SB2, bytes, sb3, sb4};

/// `TEST_VECTORS_RFC5794`: `(name, key, plaintext, ciphertext)`.
const TEST_VECTORS_RFC5794: [(&str, &str, &str, &str); 3] = [
    (
        "128-Bit Key",
        "000102030405060708090a0b0c0d0e0f",
        "00112233445566778899aabbccddeeff",
        "d718fbd6ab644c739da95f3be6451778",
    ),
    (
        "192-Bit Key",
        "000102030405060708090a0b0c0d0e0f1011121314151617",
        "00112233445566778899aabbccddeeff",
        "26449c1805dbe7aa25a468ce263a9e79",
    ),
    (
        "256-Bit Key",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "00112233445566778899aabbccddeeff",
        "f92bd7c79fb72e2f2b8f80c1972d24fc",
    ),
];

fn engine<const KEY_LEN: usize, P: ElectronicCodeBook<KEY_LEN, 16>>(key: &[u8; KEY_LEN]) -> P {
    <P as ElectronicCodeBook<KEY_LEN, 16>>::new(
        &KeyMaterial::<KEY_LEN>::from_bytes_as_type(key, KeyType::SymmetricCipherKey)
            .expect("a valid symmetric cipher key"),
    )
    .expect("a valid key")
}

/// `checkTestVector_RFC5794(tv)`: `init(true, key)`, `processBlock`, compare ("Incorrect
/// ciphertext computed"); `init(false, key)`, `processBlock`, compare ("Incorrect plaintext").
fn check_test_vector<const KEY_LEN: usize, P: ElectronicCodeBook<KEY_LEN, 16>>(
    name: &str,
    key: &str,
    plaintext: &str,
    ciphertext: &str,
) {
    let c: P = engine(&bytes::<KEY_LEN>(key));
    let plaintext: [u8; BLOCK_LEN] = bytes(plaintext);
    let ciphertext: [u8; BLOCK_LEN] = bytes(ciphertext);
    let mut actual = plaintext;
    c.encrypt_block(&mut actual);
    assert_eq!(actual, ciphertext, "Incorrect ciphertext computed for '{name}'");
    c.decrypt_block(&mut actual);
    assert_eq!(actual, plaintext, "Incorrect plaintext computed for '{name}'");
}

#[test]
fn check_test_vectors_rfc5794() {
    let [v128, v192, v256] = TEST_VECTORS_RFC5794;
    check_test_vector::<16, ARIA_128>(v128.0, v128.1, v128.2, v128.3);
    check_test_vector::<24, ARIA_192>(v192.0, v192.1, v192.2, v192.3);
    check_test_vector::<32, ARIA_256>(v256.0, v256.1, v256.2, v256.3);
}

/// `checkRandomRoundtrips()`: for each key length, a random key and block; 100 times, encrypt,
/// decrypt, compare, and feed the ciphertext back in as the next plaintext. Run for 100 keys as
/// `performTest()` does.
fn random_roundtrips<const KEY_LEN: usize, P: ElectronicCodeBook<KEY_LEN, 16>>(seed: &mut u32) {
    let key: [u8; KEY_LEN] = common::pseudo_random(seed);
    let ce: P = engine(&key);
    let mut txt: [u8; BLOCK_LEN] = common::pseudo_random(seed);
    for _ in 0..100 {
        let mut enc = txt;
        ce.encrypt_block(&mut enc);
        let mut dec = enc;
        ce.decrypt_block(&mut dec);
        assert_eq!(txt, dec);
        txt = enc;
    }
}

#[test]
fn check_random_roundtrips() {
    let mut seed = 0xA51A_0001;
    for _ in 0..100 {
        random_roundtrips::<16, ARIA_128>(&mut seed);
        random_roundtrips::<24, ARIA_192>(&mut seed);
        random_roundtrips::<32, ARIA_256>(&mut seed);
    }
}

/// `checkSBoxes()`: `x == SB1(SB3(x))`, `x == SB3(SB1(x))`, `x == SB2(SB4(x))`, `x == SB4(SB2(x))`
/// for every byte, on the reference tables.
#[test]
fn check_sboxes() {
    let (s3, s4) = (sb3(), sb4());
    for x in 0..=255u8 {
        assert_eq!(SB1[s3[x as usize] as usize], x);
        assert_eq!(s3[SB1[x as usize] as usize], x);
        assert_eq!(SB2[s4[x as usize] as usize], x);
        assert_eq!(s4[SB2[x as usize] as usize], x);
    }
}
