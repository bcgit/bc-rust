//! The test vectors of Bouncy Castle Java's Camellia tests, run against this port.
//!
//! `core/src/test/java/org/bouncycastle/crypto/test/CamelliaTest.java` (and the identical
//! `CamelliaLightTest.java`) is a `CipherTest` over nine `BlockCipherVectorTest`s -- key, plaintext,
//! ciphertext, checked in both directions -- whose header credits them to the NESSIE test vectors
//! (<https://www.cosic.esat.kuleuven.be/nessie/testvectors/>) and RFC 3713. Vectors 2, 3 and 6 are
//! the three of RFC 3713 Appendix A (also in `rfc3713_tests.rs`); the others are NESSIE's, and
//! coincide with entries in NTT's file (`ntt_cryptrec_tests.rs`). They are kept as a separate file
//! so that agreement with the source implementation's own test suite is asserted in its own terms.

mod common;

use bouncycastle_camellia::{BLOCK_LEN, Camellia_128, Camellia_192, Camellia_256};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::ElectronicCodeBook;
use common::bytes;

/// `CamelliaTest.tests`: `(index, key, input, output)`.
const TESTS: [(usize, &str, &str, &str); 9] = [
    (
        0,
        "00000000000000000000000000000000",
        "80000000000000000000000000000000",
        "07923A39EB0A817D1C4D87BDB82D1F1C",
    ),
    (
        1,
        "80000000000000000000000000000000",
        "00000000000000000000000000000000",
        "6C227F749319A3AA7DA235A9BBA05A2C",
    ),
    (
        2,
        "0123456789abcdeffedcba9876543210",
        "0123456789abcdeffedcba9876543210",
        "67673138549669730857065648eabe43",
    ),
    // 192 bit
    (
        3,
        "0123456789abcdeffedcba98765432100011223344556677",
        "0123456789abcdeffedcba9876543210",
        "b4993401b3e996f84ee5cee7d79b09b9",
    ),
    (
        4,
        "000000000000000000000000000000000000000000000000",
        "00040000000000000000000000000000",
        "9BCA6C88B928C1B0F57F99866583A9BC",
    ),
    (
        5,
        "949494949494949494949494949494949494949494949494",
        "636EB22D84B006381235641BCF0308D2",
        "94949494949494949494949494949494",
    ),
    // 256 bit
    (
        6,
        "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
        "0123456789abcdeffedcba9876543210",
        "9acc237dff16d76c20ef7c919e3a7509",
    ),
    (
        7,
        "4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A",
        "057764FE3A500EDBD988C5C3B56CBA9A",
        "4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A",
    ),
    (
        8,
        "0303030303030303030303030303030303030303030303030303030303030303",
        "7968B08ABA92193F2295121EF8D75C8A",
        "03030303030303030303030303030303",
    ),
];

/// `BlockCipherVectorTest`: `engine.init(true, param)`, `processBlock`, compare; then
/// `engine.init(false, param)`, `processBlock`, compare ("failed reversal").
fn block_cipher_vector_test<const KEY_LEN: usize, P: ElectronicCodeBook<KEY_LEN, 16>>(
    id: usize,
    key: &str,
    input: &[u8; BLOCK_LEN],
    output: &[u8; BLOCK_LEN],
) {
    // The Java `KeyParameter` takes any bytes; an all-zero key would be tagged `Zeroized` by
    // `from_bytes_as_type`, so the tag and strength are set explicitly, as the CLI does.
    let key_bytes: [u8; KEY_LEN] = bytes(key);
    let mut km =
        KeyMaterial::<KEY_LEN>::from_bytes_as_type(&key_bytes, KeyType::SymmetricCipherKey)
            .expect("a key");
    bouncycastle_core::key_material::do_hazardous_operations(&mut km, |k| {
        k.set_key_type(KeyType::SymmetricCipherKey)?;
        k.set_security_strength(bouncycastle_core::traits::SecurityStrength::from_bytes(KEY_LEN))
    })
    .expect("retagging the key");
    let engine = P::new(&km).expect("a valid key");

    let mut buf = *input;
    engine.encrypt_block(&mut buf);
    assert_eq!(&buf, output, "Camellia test {id} failed encryption");

    engine.decrypt_block(&mut buf);
    assert_eq!(&buf, input, "Camellia test {id} failed reversal");
}

#[test]
fn camellia_test_vectors() {
    for (id, key, input, output) in TESTS {
        let input: [u8; BLOCK_LEN] = bytes(input);
        let output: [u8; BLOCK_LEN] = bytes(output);
        match key.len() / 2 {
            16 => block_cipher_vector_test::<16, Camellia_128>(id, key, &input, &output),
            24 => block_cipher_vector_test::<24, Camellia_192>(id, key, &input, &output),
            32 => block_cipher_vector_test::<32, Camellia_256>(id, key, &input, &output),
            n => panic!("unexpected key length {n}"),
        }
    }
}
