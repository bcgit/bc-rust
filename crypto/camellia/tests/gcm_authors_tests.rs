//! The Camellia authors' GCM-Camellia test vectors, run against the keys.
//!
//! No standard publishes a Camellia-GCM vector and OpenSSL has no Camellia-GCM at all, but
//! nettle's `testsuite/gcm-test.c` carries a set it credits as "GCM-Camellia Test Vectors
//! obtained from the authors": the AES-GCM specification's test inputs (zero key, the
//! `feffe992...` key, the `d9313225...` message, the `feedface...` AAD, the `cafebabe...` IV)
//! under Camellia-128 and Camellia-256. The cases with a 12-byte IV are here, numbered as in
//! that file: 1, 3 and 4 at 128 bits and 13 to 16 at 256 bits. Its cases 5, 6, 17 and 18 use
//! 8- and 60-byte IVs, which [`GCM`] does not take (the nonce is fixed at 96 bits), so they are
//! not run. Camellia-192 has no case in the set; `gcm_bc_java_tests.rs` covers it.

mod common;

use bouncycastle_camellia::{Camellia128Key, Camellia256Key};
use bouncycastle_cipher::modes::{GCM, GMAC};
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{
    AeadDecryptionKey, AeadEncryptionKey, FromKeyMaterial, NonceMacGenerationKey,
};
use common::bytes;

/// (case, key, IV, AAD, plaintext, ciphertext, tag).
type Case =
    (u8, &'static str, &'static str, &'static str, &'static str, &'static str, &'static str);

const MSG_64: &str = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                      1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
const MSG_60: &str = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                      1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
const AAD_20: &str = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
const IV: &str = "cafebabefacedbaddecaf888";
const ZERO_IV: &str = "000000000000000000000000";

const CAMELLIA_128: [Case; 3] = [
    (
        1,
        "00000000000000000000000000000000",
        ZERO_IV,
        "",
        "",
        "",
        "f5574acc3148dfcb9015200631024df9",
    ),
    (
        3,
        "feffe9928665731c6d6a8f9467308308",
        IV,
        "",
        MSG_64,
        "d0d94a13b632f337a0cc9955b94fa020c815f903aab12f1efaf2fe9d90f729a6\
         cccbfa986ef2ff2c33de418d9a2529091cf18fe652c1cfde13f8260614bab815",
        "86e318012dd8329dc9dae6a170f61b24",
    ),
    (
        4,
        "feffe9928665731c6d6a8f9467308308",
        IV,
        AAD_20,
        MSG_60,
        "d0d94a13b632f337a0cc9955b94fa020c815f903aab12f1efaf2fe9d90f729a6\
         cccbfa986ef2ff2c33de418d9a2529091cf18fe652c1cfde13f82606",
        "9f458869431576ea6a095456ec6b8101",
    ),
];

const CAMELLIA_256: [Case; 4] = [
    (
        13,
        "0000000000000000000000000000000000000000000000000000000000000000",
        ZERO_IV,
        "",
        "",
        "",
        "9cdb269b5d293bc5db9c55b057d9b591",
    ),
    (
        14,
        "0000000000000000000000000000000000000000000000000000000000000000",
        ZERO_IV,
        "",
        "00000000000000000000000000000000",
        "3d4b2cde666761ba5dfb305178e667fb",
        "284b63bb143c40ce100fb4dea6bb617b",
    ),
    (
        15,
        "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        IV,
        "",
        MSG_64,
        "ad142c11579dd95e41f3c1f324dabc255864d920f1b65759d8f560d4948d4477\
         58dfdcf77aa9f62581c7ff572a037f810cb1a9c4b3ca6ed638179b776549e092",
        "c912686270a2b9966415fca3be75c468",
    ),
    (
        16,
        "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        IV,
        AAD_20,
        MSG_60,
        "ad142c11579dd95e41f3c1f324dabc255864d920f1b65759d8f560d4948d4477\
         58dfdcf77aa9f62581c7ff572a037f810cb1a9c4b3ca6ed638179b77",
        "4e4b178d8fe26fdc95e2e7246dd94bec",
    ),
];

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("valid hex"))
        .collect()
}

fn key<const KEY_LEN: usize, K: FromKeyMaterial<KEY_LEN>>(hex: &str) -> K {
    let mut material = KeyMaterial::<KEY_LEN>::from_bytes_as_type(
        &bytes::<KEY_LEN>(hex),
        KeyType::SymmetricCipherKey,
    )
    .expect("a valid key");
    // `KeyMaterial` tags an all-zero buffer as `KeyType::Zeroized` whatever type is asked for,
    // and promotes it only inside `do_hazardous_operations`; cases 1, 13 and 14 need that, as
    // the AES suites' zero-key cases do.
    if material.key_type() != KeyType::SymmetricCipherKey {
        do_hazardous_operations(&mut material, |k| {
            k.set_key_type(KeyType::SymmetricCipherKey)?;
            k.set_security_strength(SecurityStrength::from_bytes(KEY_LEN))
        })
        .expect("promoting a zero test key");
    }
    K::from_key_material(&material).expect("a valid key")
}

/// The case's ciphertext and tag both ways, and a flipped tag bit refused.
fn check<const KEY_LEN: usize, K>(case: Case)
where
    K: FromKeyMaterial<KEY_LEN>
        + AeadEncryptionKey<KEY_LEN, 12, 16, 16>
        + AeadDecryptionKey<KEY_LEN, 12, 16, 16>,
{
    let (n, key_hex, iv, aad, pt, ct, tag) = case;
    let key: K = key::<KEY_LEN, K>(key_hex);
    let iv: [u8; 12] = bytes(iv);
    let (aad, pt) = (unhex(aad), unhex(pt));
    let mut expected = unhex(ct);
    expected.extend_from_slice(&unhex(tag));
    assert_eq!(key.encrypt_with_aad_nonce(&iv, &aad, &pt).unwrap(), expected, "case {n}: encrypt");
    assert_eq!(key.decrypt_with_aad(&iv, &aad, &expected).unwrap(), pt, "case {n}: decrypt");
    let last = expected.len() - 1;
    expected[last] ^= 1;
    assert!(key.decrypt_with_aad(&iv, &aad, &expected).is_err(), "case {n}: tag check");
}

#[test]
fn camellia_128_gcm_matches_the_authors_vectors() {
    for case in CAMELLIA_128 {
        check::<16, Camellia128Key<GCM>>(case);
    }
}

#[test]
fn camellia_256_gcm_matches_the_authors_vectors() {
    for case in CAMELLIA_256 {
        check::<32, Camellia256Key<GCM>>(case);
    }
}

/// Cases 1 and 13 have no message and no AAD, so their tags are GMAC of nothing under the zero
/// key: the one published Camellia-GMAC answer, run through `Camellia*Key<GMAC>`.
#[test]
fn the_empty_cases_are_gmac_known_answers() {
    fn mac_key<const KEY_LEN: usize>(hex: &str) -> KeyMaterial<KEY_LEN> {
        let mut material =
            KeyMaterial::<KEY_LEN>::from_bytes_as_type(&bytes::<KEY_LEN>(hex), KeyType::MACKey)
                .expect("a valid key");
        do_hazardous_operations(&mut material, |k| {
            k.set_key_type(KeyType::MACKey)?;
            k.set_security_strength(SecurityStrength::from_bytes(KEY_LEN))
        })
        .expect("promoting a zero test key");
        material
    }
    for (case, iv, tag) in [
        (&CAMELLIA_128[0], ZERO_IV, CAMELLIA_128[0].6),
        (&CAMELLIA_256[0], ZERO_IV, CAMELLIA_256[0].6),
    ] {
        assert!(case.3.is_empty() && case.4.is_empty(), "case {} is not the empty case", case.0);
        let iv: [u8; 12] = bytes(iv);
        let expected: [u8; 16] = bytes(tag);
        let got = match case.1.len() {
            32 => Camellia128Key::<GMAC>::from_key_material(&mac_key::<16>(case.1))
                .unwrap()
                .mac_nonce(&iv, &[]),
            _ => Camellia256Key::<GMAC>::from_key_material(&mac_key::<32>(case.1))
                .unwrap()
                .mac_nonce(&iv, &[]),
        };
        assert_eq!(got, expected, "case {}", case.0);
    }
}
