//! HMAC-RIPEMD160 known-answer tests.
//!
//! Two published sources: RFC 2286, "Test Cases for HMAC-RIPEMD160 and HMAC-RIPEMD128" (the
//! seven cases of Sec 2, transcribed from the downloaded text), and the designers' HMAC table on
//! <https://homes.esat.kuleuven.be/~bosselae/ripemd160.html> ("HMAC-RIPEMD-160: test vectors"):
//! the nine standard RIPEMD messages under two keys.

mod common;

use bouncycastle_core::direction::{Decrypting, Encrypting};
use bouncycastle_core::errors::{KeyMaterialError, MACError};
use bouncycastle_core::hex;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey, MacVerificationKey};
use bouncycastle_core::traits::{
    Algorithm, AlgorithmInfo, AlgorithmOID, HashAlgParams, MACGenerator,
};
use bouncycastle_core_test_framework::DUMMY_SEED;
use bouncycastle_digest::ripemd::RIPEMD160;
use bouncycastle_digest::ripemd::hmac::*;
use bouncycastle_hmac::{HMACParams, HmacKey};
use bouncycastle_rng::HashDRBG_SHA256;
use common::{arr, test_hmac};

fn key<const N: usize>(bytes: &[u8]) -> KeyMaterial<N> {
    KeyMaterial::<N>::from_bytes_as_type(bytes, KeyType::MACKey).expect("a MAC key")
}

/// One RFC 2286 case: `(key, data, digest)`; `key` and `data` as bytes.
struct Case {
    key: Vec<u8>,
    data: Vec<u8>,
    digest: &'static str,
}

/// RFC 2286 Sec 2 (HMAC-RIPEMD160); the keys of cases 1, 3 and 5 are 20 bytes.
fn rfc2286_cases() -> Vec<Case> {
    vec![
        Case {
            key: vec![0x0b; 20],
            data: b"Hi There".to_vec(),
            digest: "24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668",
        },
        Case {
            key: b"Jefe".to_vec(),
            data: b"what do ya want for nothing?".to_vec(),
            digest: "dda6c0213a485a9e24f4742064a7f033b43c4069",
        },
        Case {
            key: vec![0xaa; 20],
            data: vec![0xdd; 50],
            digest: "b0b105360de759960ab4f35298e116e295d8e7c1",
        },
        Case {
            key: hex::decode("0102030405060708090a0b0c0d0e0f10111213141516171819").unwrap(),
            data: vec![0xcd; 50],
            digest: "d5ca862f4d21d5e610e18b4cf1beb97a4365ecf4",
        },
        Case {
            key: vec![0x0c; 20],
            data: b"Test With Truncation".to_vec(),
            digest: "7619693978f91d90539ae786500ff3d8e0518e39",
        },
        Case {
            key: vec![0xaa; 80],
            data: b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
            digest: "6466ca07ac5eac29e1bd523e5ada7605b791fd8b",
        },
        Case {
            key: vec![0xaa; 80],
            data: b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
                .to_vec(),
            digest: "69ea60798d71616cce5fd0871e23754cd75d5a0a",
        },
    ]
}

/// Each case through the MAC framework's key suite (one-shots, workers, every bit flip refused)
/// and the construction suite, and streamed in pieces. The key is built with the weak form, since
/// RFC 2286's short keys carry no security strength.
#[test]
fn rfc2286_hmac_ripemd160() {
    let cases = rfc2286_cases();
    for (i, c) in cases.iter().enumerate() {
        let material = key::<80>(&c.key);
        let expected = arr::<20>(c.digest);
        test_hmac::<20, RIPEMD160>(&material, &c.data, &expected);
        let hmac_key = HmacKey::<RIPEMD160>::from_key_material_allow_weak(&material).unwrap();
        let mut m = hmac_key.create_generator();
        for chunk in c.data.chunks(5) {
            m.do_update(chunk);
        }
        assert_eq!(m.do_final(), expected, "test_case {} streamed", i + 1);
    }
    // test_case 5's digest-96: the first 12 bytes of the tag.
    let k = HmacKey::<RIPEMD160>::from_key_material(&key::<80>(&cases[4].key)).unwrap();
    assert_eq!(k.mac(&cases[4].data)[..12], arr::<12>("7619693978f91d90539ae786"));
}

/// The designers' eight short messages; the ninth is one million times "a".
const MESSAGES: [&[u8]; 8] = [
    b"",
    b"a",
    b"abc",
    b"message digest",
    b"abcdefghijklmnopqrstuvwxyz",
    b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
];

fn check_designers_table(key_hex: &str, digests: [&str; 8], million_a: &str) {
    let k = HmacKey::<RIPEMD160>::from_key_material(&key::<32>(&hex::decode(key_hex).unwrap()))
        .unwrap();
    for (msg, digest) in MESSAGES.iter().zip(digests.iter()) {
        assert_eq!(k.mac(msg), arr::<20>(digest), "key {key_hex}");
        assert_eq!(k.verify(msg, &arr::<20>(digest)), Ok(()), "key {key_hex}");
    }
    let mut m = k.create_generator();
    for _ in 0..1000 {
        m.do_update(&[b'a'; 1000]);
    }
    assert_eq!(m.do_final(), arr::<20>(million_a), "million a, key {key_hex}");
}

/// "HMAC-RIPEMD-160: test vectors", keys `00112233445566778899aabbccddeeff01234567` and
/// `0123456789abcdeffedcba987654321000112233`.
#[test]
fn designers_hmac_ripemd160() {
    check_designers_table(
        "00112233445566778899aabbccddeeff01234567",
        [
            "cf387677bfda8483e63b57e06c3b5ecd8b7fc055",
            "0d351d71b78e36dbb7391c810a0d2b6240ddbafc",
            "f7ef288cb1bbcc6160d76507e0a3bbf712fb67d6",
            "f83662cc8d339c227e600fcd636c57d2571b1c34",
            "843d1c4eb880ac8ac0c9c95696507957d0155ddb",
            "60f5ef198a2dd5745545c1f0c47aa3fb5776f881",
            "e49c136a9e5627e0681b808a3b97e6a6e661ae79",
            "31be3cc98cee37b79b0619e3e1c2be4f1aa56e6c",
        ],
        "c2aa88c6405658dc225e485488371fb2433fa735",
    );
    check_designers_table(
        "0123456789abcdeffedcba987654321000112233",
        [
            "fe69a66c7423eea9c8fa2eff8d9dafb4f17a62f5",
            "85743e899bc82dbfa36faaa7a25b7cfd372432cd",
            "6e4afd501fa6b4a1823ca3b10bd9aa0ba97ba182",
            "2e066e624badb76a184c8f90fba053330e650e92",
            "07e942aa4e3cd7c04dedc1d46e2e8cc4c741b3d9",
            "b6582318ddcfb67a53a67d676b8ad869aded629a",
            "f1be3ee877703140d34f97ea1ab3a07c141333e2",
            "85f164703e61a63131be7e45958e0794123904f9",
        ],
        "82a504a002ba6e6c67f3cd67cedb66dc169bab7a",
    );
}

#[test]
fn names_strengths_and_oids() {
    assert_eq!(HMAC_RIPEMD160::<Encrypting>::ALG_NAME, HMAC_RIPEMD160_NAME);
    assert_eq!(HMAC_RIPEMD160_NAME, "HMAC-RIPEMD160");
    assert_eq!(<RIPEMD160 as HMACParams>::HKDF_ALG_NAME, "HKDF-RIPEMD160");
    // The strength is half the hash's output length in bits, 80, which below 112 is None.
    assert_eq!(HMAC_RIPEMD160::<Encrypting>::MAX_SECURITY_STRENGTH, SecurityStrength::None);
    assert_eq!(HMAC_RIPEMD160::<Decrypting>::MAX_SECURITY_STRENGTH, SecurityStrength::None);
    assert_eq!(RIPEMD160::OUTPUT_LEN * 8 / 2, 80);
    assert_eq!(
        <RIPEMD160 as HMACParams>::HMAC_MAX_SECURITY_STRENGTH,
        SecurityStrength::from_bits(RIPEMD160::OUTPUT_LEN * 8 / 2)
    );
    // IANA isakmpOakley arc 1.3.6.1.5.5.8.1, HMAC-RIPEMD160 = 4.
    assert_eq!(HMAC_RIPEMD160::<Encrypting>::OID, &[1, 3, 6, 1, 5, 5, 8, 1, 4]);
    assert_eq!(
        HMAC_RIPEMD160::<Encrypting>::OID_DER,
        &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x08, 0x01, 0x04]
    );

    let k = HmacKey::<RIPEMD160>::from_key_material_allow_weak(&key::<32>(b"Jefe")).unwrap();
    let generator: HMAC_RIPEMD160<Encrypting> = k.create_generator();
    assert_eq!(generator.max_security_strength(), SecurityStrength::None);
    let _: HMAC_RIPEMD160<Decrypting> = k.create_verifier();
}

/// The key policy of an HMAC that claims no security strength: `from_key_material` still refuses
/// a key that carries none (a short key, a key tagged at none, zero-length material), which
/// `from_key_material_allow_weak` accepts; a key of any real strength is accepted; and
/// `keygen_from_rng` / `generate` draw a key of the hash's output length.
#[test]
fn key_policy() {
    let refused = |k: &dyn KeyMaterialTrait| {
        matches!(
            HmacKey::<RIPEMD160>::from_key_material(k),
            Err(MACError::KeyMaterialError(KeyMaterialError::SecurityStrength(_)))
        )
    };

    // tagged at none, whatever its length
    let mut no_strength =
        KeyMaterial::<64>::from_bytes_as_type(&DUMMY_SEED[..64], KeyType::MACKey).unwrap();
    no_strength.set_security_strength(SecurityStrength::None).unwrap();
    assert!(refused(&no_strength));
    // too short to carry any: 1 byte, and RFC 2286's 4-byte "Jefe"
    assert!(refused(&key::<32>(&[0x0b])));
    assert!(refused(&key::<32>(b"Jefe")));
    // zero-length material
    assert!(refused(&KeyMaterial::<32>::default()));
    for weak in [&no_strength as &dyn KeyMaterialTrait, &key::<32>(b"Jefe"), &key::<32>(&[0x0b])] {
        let k = HmacKey::<RIPEMD160>::from_key_material_allow_weak(weak).unwrap();
        assert_eq!(k.verify(b"abc", &k.mac(b"abc")), Ok(()));
    }

    // 14 bytes is the shortest key with a strength (112 bits), and is accepted
    assert!(refused(&key::<32>(&[0x0b; 13])));
    assert_eq!(key::<32>(&[0x0b; 14]).security_strength(), SecurityStrength::_112bit);
    assert!(HmacKey::<RIPEMD160>::from_key_material(&key::<32>(&[0x0b; 14])).is_ok());

    let mut rng = HashDRBG_SHA256::new_from_os();
    let generated = HmacKey::<RIPEMD160>::keygen_from_rng(&mut rng).unwrap();
    assert_eq!(generated.key_len(), 20);
    assert_eq!(generated.key_type(), KeyType::MACKey);
    let k = HmacKey::<RIPEMD160>::from_key_material(&generated).unwrap();
    assert_eq!(k.verify(b"abc", &k.mac(b"abc")), Ok(()));
    let k = HmacKey::<RIPEMD160>::generate(&mut rng).unwrap();
    assert_eq!(k.verify(b"abc", &k.mac(b"abc")), Ok(()));
}

/// `HMACParams` for `hazmat::WithoutCollisionResistance<H>` is `H`'s in every item, so the HMAC
/// over the wrapper is the HMAC over `H`: the same name, strength, OID, key type and tag.
#[test]
fn hmac_over_the_collision_resistance_wrapper_is_hmac_over_the_hash() {
    use bouncycastle_core::hazmat::WithoutCollisionResistance;
    type W = WithoutCollisionResistance<RIPEMD160>;

    assert_eq!(<W as HMACParams>::HMAC_ALG_NAME, "HMAC-RIPEMD160");
    assert_eq!(<W as HMACParams>::HKDF_ALG_NAME, "HKDF-RIPEMD160");
    assert_eq!(<W as HMACParams>::HMAC_MAX_SECURITY_STRENGTH, SecurityStrength::None);
    assert_eq!(<W as HMACParams>::HMAC_OID, <RIPEMD160 as HMACParams>::HMAC_OID);
    assert_eq!(<W as HMACParams>::HMAC_OID_DER, <RIPEMD160 as HMACParams>::HMAC_OID_DER);

    // RFC 2286 Sec 2, test case 2
    let k = key::<20>(b"Jefe");
    let wrapped = HmacKey::<W>::from_key_material_allow_weak(&k).unwrap();
    let tag: [u8; 20] = wrapped.mac(b"what do ya want for nothing?");
    assert_eq!(hex::encode(tag), "dda6c0213a485a9e24f4742064a7f033b43c4069");
    let bare = HmacKey::<RIPEMD160>::from_key_material_allow_weak(&k).unwrap();
    bare.verify(b"what do ya want for nothing?", &tag).unwrap();
}
