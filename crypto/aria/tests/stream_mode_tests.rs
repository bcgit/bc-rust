//! Known-answer tests for the stream modes of operation over ARIA: the `ARIA-*-CFB`,
//! `ARIA-*-CFB8` and `ARIA-*-CTR` entries of OpenSSL's
//! `test/recipes/30-test_evp_data/evpciph_aria.txt` (OpenSSL 3.6.2), which attributes them to
//! `ARIA-testvector-e.pdf` from the ARIA site. Transcribed from the OpenSSL file.
//!
//! RFC 5794 itself publishes only single-block values (Appendix A), so these KISA vectors are the
//! only published mode answers for ARIA -- and unlike Camellia's and SM4's they line up with these
//! aliases exactly, in all three modes:
//!
//! * The CFB128 and CFB8 vectors share the IV `0f1e2d3c..f0` that the CBC vectors use, and are
//!   driven through [`StreamCipherEncryptor::do_encrypt_init_rng`] with a [`FixedSeedRNG`] whose
//!   stream is that IV (there is no API for supplying one); the test asserts the returned init data
//!   really is the vector's IV before comparing any ciphertext. Decryption takes the IV directly.
//! * The CTR vectors start from an **all-zero counter block** and their `NextIV` is `..0a` after
//!   the 160-byte, ten-block message, so the counter runs 0, 1, ... 9. That is exactly what the
//!   nonce/counter split of `Ctr` produces from a twelve-byte zero nonce (see the [`ARIA_CTR_128`]
//!   docs), so they are straight known-answer tests through the alias too.
//!
//! The same 160-byte plaintext runs through all three modes, and it is the one the ECB and CBC
//! vectors in `kisa_vectors_tests.rs` use.

mod common;

use bouncycastle_aria::{
    ARIA_CFB_128, ARIA_CFB_192, ARIA_CFB_256, ARIA_CFB8_128, ARIA_CFB8_192, ARIA_CFB8_256,
    ARIA_CTR_128, ARIA_CTR_192, ARIA_CTR_256, BLOCK_LEN, CTR_NONCE_LEN,
};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{StreamCipherDecryptor, StreamCipherEncryptor};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_modes::{Decrypting, Encrypting};
use common::bytes;

/// The 160-byte plaintext shared by all nine vectors.
const PLAINTEXT: &str = "11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd";

/// The number of bytes in that plaintext: ten whole blocks.
const LEN: usize = 160;

/// The IV shared by the CFB128 and CFB8 vectors -- the same one the CBC vectors use.
const IV: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";

const KEY_128: &str = "00112233445566778899aabbccddeeff";
const KEY_192: &str = "00112233445566778899aabbccddeeff0011223344556677";
const KEY_256: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

/// `ARIA-128-CFB` ciphertext (CFB128).
const CFB_CT_128: &str = concat!(
    "3720e53ba7d615383406b09f0a05a200",
    "c07c21e6370f413a5d132500a6828501",
    "7c61b434c7b7ca9685a51071861e4d4b",
    "b873b599b479e2d573dddeafba89f812",
    "ac6a9e44d554078eb3be94839db4b33d",
    "a3f59c063123a7ef6f20e10579fa4fd2",
    "39100ca73b52d4fcafeadee73f139f78",
    "f9b7614c2b3b9dbe010f87db06a89a94",
    "35f79ce8121431371f4e87b984e0230c",
    "22a6dacb32fc42dcc6accef33285bf11",
);
/// `ARIA-192-CFB` ciphertext (CFB128).
const CFB_CT_192: &str = concat!(
    "4171f7192bf4495494d2736129640f5c",
    "4d87a9a213664c9448477c6ecc201359",
    "8d9766952dd8c3868f17e36ef66fd84b",
    "fa45d1593d2d6ee3ea2115047d710d4f",
    "b66187caa3a315b3c8ea2d313962edcf",
    "e5a3e2028d5ba9a09fd5c65c19d3440e",
    "477f0cab0628ec6902c73ee02f1afee9",
    "f80115be7b9df82d1e28228e28581a20",
    "560e195cbb9e2b327bf56fd2d0ae5502",
    "e42c13e9b4015d4da42dc859252e7da4",
);
/// `ARIA-256-CFB` ciphertext (CFB128).
const CFB_CT_256: &str = concat!(
    "26834705b0f2c0e2588d4a7f09009635",
    "f28bb93d8c31f870ec1e0bdb082b66fa",
    "402dd9c202be300c4517d196b14d4ce1",
    "1dce97f7aaba54341b0d872cc9b63753",
    "a3e8556a14be6f7b3e27e3cfc39caf80",
    "f2a355aa50dc83c09c7b11828694f8e4",
    "aa726c528976b53f2c877f4991a3a8d2",
    "8adb63bd751846ffb2350265e179d499",
    "0753ae8485ff9b4133ddad5875b84a90",
    "cbcfa62a045d726df71b6bda0eeca0be",
);
/// `ARIA-128-CFB8` ciphertext.
const CFB8_CT_128: &str = concat!(
    "373c8f6a965599ec785cc8f8149f6c81",
    "b632ccb8e0c6eb6a9707ae52c59257a4",
    "1f94701c1096933127a90195ed0c8e98",
    "690547572423bb45c3d70e4a18ee56b9",
    "67c10e000ba4df5fba7c404134a343d8",
    "375d04b151d161ef83417fe1748447d3",
    "0a6723c406733df7d18aa39a20752d23",
    "81942e244811bb97f72eae446b1815aa",
    "690cd1b1adcbd007c0088ecdc91cb2e2",
    "caf0e11e72459878137eea64ac62a9a1",
);
/// `ARIA-192-CFB8` ciphertext.
const CFB8_CT_192: &str = concat!(
    "411d3b4f57f705aa4d13c46e2cf426af",
    "7c8c916ed7923d889f0047bbf11471b6",
    "d54f8757ef519339105be3cb69babb97",
    "6a57d5631fc23cc3051fe9d36e8b8e27",
    "a2b2c0c4d31928ccbf30ea8239b46ba1",
    "b77f6198e7ecd2ce27b35958148e826f",
    "06aaf385bd30362ff141583e7c1d8924",
    "d44d36a1133094074631e18adafa9d2e",
    "55de98f6895c89d4266ebd33f3d4be51",
    "53a96fa12132ece2e81e66e55baa7ade",
);
/// `ARIA-256-CFB8` ciphertext.
const CFB8_CT_256: &str = concat!(
    "26baa33651e1f66434fec88ef27fd2b9",
    "a79e246dd89a3ffa00e8bdb37155433e",
    "6c24bd0b87d9a85baa9f485ccb984f5e",
    "c24d6a3ef5e3c81396177f039cf580df",
    "db55d6e1c47a28921dfe369e12fd357b",
    "289ad3a5544e1c1bd616d454db9c5f91",
    "f603373f29d5b2ed1b4b51de80f28537",
    "bbd43d5e3b5dd071dc91153cbbe732df",
    "c325821b06ed8acaae656dcf2da9f13e",
    "4f29db671476f1e644ff06d9b67d6bd4",
);
/// `ARIA-128-CTR` ciphertext.
const CTR_CT_128: &str = concat!(
    "ac5d7de805a0bf1c57c854501af60fa1",
    "1497e2a34519dea1569e91e5b5ccae2f",
    "f3bfa1bf975f4571f48be191613546c3",
    "911163c085f871f0e7ae5f2a085b8185",
    "1c2a3ddf20ecb8fa51901aec8ee4ba32",
    "a35dab67bb72cd9140ad188a967ac0fb",
    "bdfa94ea6cce47dcf8525ab5a814cfeb",
    "2bb60ee2b126e2d9d847c1a9e96f9019",
    "e3e6a7fe40d3829afb73db1cc245646a",
    "ddb62d9b907baaafbe46a73dbc131d3d",
);
/// `ARIA-192-CTR` ciphertext.
const CTR_CT_192: &str = concat!(
    "08625ca8fe569c19ba7af3760a6ed1ce",
    "f4d199263e999dde14082dbba7560b79",
    "a4c6b456b8707dce751f9854f18893df",
    "db3f4e5afa539733e6f1e70b98ba3789",
    "1f8f81e95df8efc26c7ce043504cb189",
    "58b865e4e316cd2aa1c97f31bf23dc04",
    "6ef326b95a692a191ba0f2a41c5fe9ae",
    "070f236ff7078e703b42666caafbdd20",
    "bad74ac4c20c0f46c7ca24c151716575",
    "c947da16c90cfe1bf217a41cfebe7531",
);
/// `ARIA-256-CTR` ciphertext.
const CTR_CT_256: &str = concat!(
    "30026c329666141721178b99c0a1f1b2",
    "f06940253f7b3089e2a30ea86aa3c88f",
    "5940f05ad7ee41d71347bb7261e348f1",
    "8360473fdf7d4e7723bffb4411cc13f6",
    "cdd89f3bc7b9c768145022c7a74f14d7",
    "c305cd012a10f16050c23f1ae5c23f45",
    "998d13fbaa041e51619577e077276489",
    "6a5d4516d8ffceb3bf7e05f613edd9a6",
    "0cdcedaff9cfcaf4e00d445a54334f73",
    "ab2cad944e51d266548e61c6eb0aa1cd",
);

fn key_material<const N: usize>(hex_str: &str) -> KeyMaterial<N> {
    KeyMaterial::<N>::from_bytes_as_type(&bytes::<N>(hex_str), KeyType::SymmetricCipherKey)
        .expect("a valid symmetric cipher key")
}

/// One vector, through the alias: encrypted under the vector's own init data, in one call and then
/// in pieces, and decrypted back both ways.
///
/// `init` is the IV for the CFB modes and the nonce for CTR; the only difference between the three
/// modes here is its length, which is why one function covers all nine vectors.
fn check<const KEY_LEN: usize, const INIT_DATA_LEN: usize, Enc, Dec>(
    name: &str,
    key_hex: &str,
    init: [u8; INIT_DATA_LEN],
    expected: &str,
) where
    Enc: StreamCipherEncryptor<KEY_LEN, INIT_DATA_LEN>,
    Dec: StreamCipherDecryptor<KEY_LEN, INIT_DATA_LEN>,
{
    let key = key_material::<KEY_LEN>(key_hex);
    let pt = bytes::<LEN>(PLAINTEXT);
    let ct = bytes::<LEN>(expected);

    // There is no API for supplying init data, so pin the RNG to the vector's and check it came
    // back before trusting any ciphertext.
    let (mut enc, got) =
        Enc::do_encrypt_init_rng(&key, &mut FixedSeedRNG::<INIT_DATA_LEN>::new(init))
            .expect("encryption init");
    assert_eq!(got, init, "{name}: the pinned RNG should produce the vector's init data");
    let mut data = pt;
    let written = enc.do_encrypt(&mut data).expect("encryption");
    assert_eq!(written, LEN, "{name}: a stream cipher writes exactly what it was given");
    assert_eq!(data, ct, "{name} encrypt, one call");

    // Block by block: the answer must not depend on where the call boundaries fall.
    let (mut enc, _) =
        Enc::do_encrypt_init_rng(&key, &mut FixedSeedRNG::<INIT_DATA_LEN>::new(init))
            .expect("encryption init");
    let mut data = pt;
    for block in data.chunks_mut(BLOCK_LEN) {
        enc.do_encrypt(block).expect("encryption");
    }
    assert_eq!(data, ct, "{name} encrypt, one block at a time");

    let mut data = ct;
    let read = Dec::decrypt(&key, &init, &mut data).expect("decryption");
    assert_eq!(read, LEN, "{name}: bytes read");
    assert_eq!(data, pt, "{name} decrypt, one shot");

    // Seven bytes at a time, which crosses no boundary the mode cares about and every boundary it
    // must not.
    let mut dec = Dec::do_decrypt_init(&key, &init).expect("decryption init");
    let mut data = ct;
    for piece in data.chunks_mut(7) {
        dec.do_decrypt(piece).expect("decryption");
    }
    assert_eq!(data, pt, "{name} decrypt, seven bytes at a time");
}

// ---- CFB128 --------------------------------------------------------------------------------

#[test]
fn aria_128_cfb_vectors() {
    check::<16, BLOCK_LEN, ARIA_CFB_128<Encrypting>, ARIA_CFB_128<Decrypting>>(
        "ARIA-128-CFB",
        KEY_128,
        bytes::<BLOCK_LEN>(IV),
        CFB_CT_128,
    );
}

#[test]
fn aria_192_cfb_vectors() {
    check::<24, BLOCK_LEN, ARIA_CFB_192<Encrypting>, ARIA_CFB_192<Decrypting>>(
        "ARIA-192-CFB",
        KEY_192,
        bytes::<BLOCK_LEN>(IV),
        CFB_CT_192,
    );
}

#[test]
fn aria_256_cfb_vectors() {
    check::<32, BLOCK_LEN, ARIA_CFB_256<Encrypting>, ARIA_CFB_256<Decrypting>>(
        "ARIA-256-CFB",
        KEY_256,
        bytes::<BLOCK_LEN>(IV),
        CFB_CT_256,
    );
}

// ---- CFB8 ----------------------------------------------------------------------------------

#[test]
fn aria_128_cfb8_vectors() {
    check::<16, BLOCK_LEN, ARIA_CFB8_128<Encrypting>, ARIA_CFB8_128<Decrypting>>(
        "ARIA-128-CFB8",
        KEY_128,
        bytes::<BLOCK_LEN>(IV),
        CFB8_CT_128,
    );
}

#[test]
fn aria_192_cfb8_vectors() {
    check::<24, BLOCK_LEN, ARIA_CFB8_192<Encrypting>, ARIA_CFB8_192<Decrypting>>(
        "ARIA-192-CFB8",
        KEY_192,
        bytes::<BLOCK_LEN>(IV),
        CFB8_CT_192,
    );
}

#[test]
fn aria_256_cfb8_vectors() {
    check::<32, BLOCK_LEN, ARIA_CFB8_256<Encrypting>, ARIA_CFB8_256<Decrypting>>(
        "ARIA-256-CFB8",
        KEY_256,
        bytes::<BLOCK_LEN>(IV),
        CFB8_CT_256,
    );
}

// ---- CTR -----------------------------------------------------------------------------------

/// The vectors' counter block is all zeros, so the nonce these aliases split off it is twelve zero
/// bytes and the counter starts at zero -- which is what `Ctr` does anyway.
const CTR_NONCE: [u8; CTR_NONCE_LEN] = [0u8; CTR_NONCE_LEN];

#[test]
fn aria_128_ctr_vectors() {
    check::<16, CTR_NONCE_LEN, ARIA_CTR_128<Encrypting>, ARIA_CTR_128<Decrypting>>(
        "ARIA-128-CTR", KEY_128, CTR_NONCE, CTR_CT_128,
    );
}

#[test]
fn aria_192_ctr_vectors() {
    check::<24, CTR_NONCE_LEN, ARIA_CTR_192<Encrypting>, ARIA_CTR_192<Decrypting>>(
        "ARIA-192-CTR", KEY_192, CTR_NONCE, CTR_CT_192,
    );
}

#[test]
fn aria_256_ctr_vectors() {
    check::<32, CTR_NONCE_LEN, ARIA_CTR_256<Encrypting>, ARIA_CTR_256<Decrypting>>(
        "ARIA-256-CTR", KEY_256, CTR_NONCE, CTR_CT_256,
    );
}

/// CFB128 and CFB8 are different modes, and the vectors say so: under the same key and IV the two
/// published ciphertexts agree on their first byte -- both are `P_1 XOR MSB_8(O_1)` of the same
/// first output block -- and differ everywhere after it.
#[test]
fn the_published_cfb128_and_cfb8_vectors_differ_after_the_first_byte() {
    for (name, cfb, cfb8) in [
        ("ARIA-128", CFB_CT_128, CFB8_CT_128),
        ("ARIA-192", CFB_CT_192, CFB8_CT_192),
        ("ARIA-256", CFB_CT_256, CFB8_CT_256),
    ] {
        let cfb = bytes::<LEN>(cfb);
        let cfb8 = bytes::<LEN>(cfb8);
        assert_eq!(cfb[0], cfb8[0], "{name}: the first byte comes from the same output block");
        assert_ne!(cfb[1..], cfb8[1..], "{name}: and the rest must not agree");
    }
}
