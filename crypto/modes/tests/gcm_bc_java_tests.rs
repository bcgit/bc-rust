//! Cross-implementation tests against BC Java's `GCMTest.java` `TEST_VECTORS` table
//! (`core/src/test/java/org/bouncycastle/crypto/test/GCMTest.java`), which is itself a transcription
//! of the McGrew/Viega "The Galois/Counter Mode of Operation (GCM)" Appendix B test vectors.
//!
//! Only the cases whose IV is 96 bits are usable here (D2 / the implementation plan): of the 18
//! vectors, cases 5, 11 and 17 use a 64-bit IV and cases 6, 12 and 18 use a 480-bit IV, both of
//! which exercise the `len(IV) != 96` GHASH-derived-`J0` branch of Algorithm 4 step 2 that this
//! crate does not implement. The remaining twelve (1, 2, 3, 4, 7, 8, 9, 10, 13, 14, 15, 16) are
//! transcribed below, verified against the bc-java source read this session, with all-zero fields
//! built programmatically rather than typed out (a zero key or plaintext cannot be mistyped).

use bouncycastle_aes::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{AEADCipherDecryptor, AEADCipherEncryptor};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_hex as hex;
use bouncycastle_modes::{Decrypting, Encrypting, Gcm};

fn zeros(byte_len: usize) -> String {
    "00".repeat(byte_len)
}

/// One BC Java `TEST_VECTORS` row: (name, key, plaintext, aad, iv, expected ciphertext, expected
/// tag), all as hex strings.
struct Case {
    name: &'static str,
    key: String,
    pt: String,
    aad: &'static str,
    iv: &'static str,
    ct: String,
    tag: &'static str,
}

fn cases() -> Vec<Case> {
    let k128 = "feffe9928665731c6d6a8f9467308308".to_string();
    let k192 = format!("{k128}feffe9928665731c");
    let k256 = format!("{k128}{k128}");

    let p_full = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                  1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
        .to_string();
    let p_partial = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
        .to_string();
    let aad = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
    let iv_zero = "000000000000000000000000";
    let iv_cafe = "cafebabefacedbaddecaf888";

    let c3_full = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
                   21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985"
        .to_string();
    let c4_partial = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
                      21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
        .to_string();
    let c9_full = "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c\
                   7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256"
        .to_string();
    let c10_partial = "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c\
                       7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710"
        .to_string();
    let c15_full = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
                    8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad"
        .to_string();
    let c16_partial = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
                       8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
        .to_string();

    vec![
        Case {
            name: "Test Case 1",
            key: zeros(16),
            pt: String::new(),
            aad: "",
            iv: iv_zero,
            ct: String::new(),
            tag: "58e2fccefa7e3061367f1d57a4e7455a",
        },
        Case {
            name: "Test Case 2",
            key: zeros(16),
            pt: zeros(16),
            aad: "",
            iv: iv_zero,
            ct: "0388dace60b6a392f328c2b971b2fe78".to_string(),
            tag: "ab6e47d42cec13bdf53a67b21257bddf",
        },
        Case {
            name: "Test Case 3",
            key: k128.clone(),
            pt: p_full.clone(),
            aad: "",
            iv: iv_cafe,
            ct: c3_full,
            tag: "4d5c2af327cd64a62cf35abd2ba6fab4",
        },
        Case {
            name: "Test Case 4",
            key: k128.clone(),
            pt: p_partial.clone(),
            aad,
            iv: iv_cafe,
            ct: c4_partial,
            tag: "5bc94fbc3221a5db94fae95ae7121a47",
        },
        Case {
            name: "Test Case 7",
            key: zeros(24),
            pt: String::new(),
            aad: "",
            iv: iv_zero,
            ct: String::new(),
            tag: "cd33b28ac773f74ba00ed1f312572435",
        },
        Case {
            name: "Test Case 8",
            key: zeros(24),
            pt: zeros(16),
            aad: "",
            iv: iv_zero,
            ct: "98e7247c07f0fe411c267e4384b0f600".to_string(),
            tag: "2ff58d80033927ab8ef4d4587514f0fb",
        },
        Case {
            name: "Test Case 9",
            key: k192.clone(),
            pt: p_full.clone(),
            aad: "",
            iv: iv_cafe,
            ct: c9_full,
            tag: "9924a7c8587336bfb118024db8674a14",
        },
        Case {
            name: "Test Case 10",
            key: k192.clone(),
            pt: p_partial.clone(),
            aad,
            iv: iv_cafe,
            ct: c10_partial,
            tag: "2519498e80f1478f37ba55bd6d27618c",
        },
        Case {
            name: "Test Case 13",
            key: zeros(32),
            pt: String::new(),
            aad: "",
            iv: iv_zero,
            ct: String::new(),
            tag: "530f8afbc74536b9a963b4f1c4cb738b",
        },
        Case {
            name: "Test Case 14",
            key: zeros(32),
            pt: zeros(16),
            aad: "",
            iv: iv_zero,
            ct: "cea7403d4d606b6e074ec5d3baf39d18".to_string(),
            tag: "d0d1c8a799996bf0265b98b5d48ab919",
        },
        Case {
            name: "Test Case 15",
            key: k256.clone(),
            pt: p_full,
            aad: "",
            iv: iv_cafe,
            ct: c15_full,
            tag: "b094dac5d93471bdec1a502270e3cc6c",
        },
        Case {
            name: "Test Case 16",
            key: k256,
            pt: p_partial,
            aad,
            iv: iv_cafe,
            ct: c16_partial,
            tag: "76fc6ece0f4e1768cddf8853bb2d551b",
        },
    ]
}

fn run<P, const KEY_LEN: usize>(case: &Case)
where
    P: bouncycastle_core::traits::ElectronicCodeBook<KEY_LEN, 16>,
{
    let key_bytes = hex::decode(&case.key).expect("valid hex key");
    // `KeyMaterial` tags an all-zero buffer as `KeyType::Zeroized` regardless of the type
    // requested, and will not promote it outside a `do_hazardous_operations` closure. The
    // zero-key cases (1, 2, 7, 8, 13, 14) need that opt-in, same as the ACVP suites' `cipher_key`.
    let mut key =
        KeyMaterial::<KEY_LEN>::from_bytes_as_type(&key_bytes, KeyType::SymmetricCipherKey)
            .expect("key bytes fit the buffer");
    if key.key_type() != KeyType::SymmetricCipherKey {
        bouncycastle_core::key_material::do_hazardous_operations(&mut key, |k| {
            k.set_key_type(KeyType::SymmetricCipherKey)?;
            k.set_security_strength(bouncycastle_core::traits::SecurityStrength::from_bytes(
                KEY_LEN,
            ))
        })
        .expect("promoting a known-zero test key");
    }

    let aad = hex::decode(case.aad).expect("valid hex aad");
    let pt = hex::decode(&case.pt).expect("valid hex pt");
    let iv_bytes = hex::decode(case.iv).expect("valid hex iv");
    let iv: [u8; 12] = iv_bytes.try_into().expect("a 96-bit IV");
    let expected_ct = hex::decode(&case.ct).expect("valid hex ct");
    let expected_tag = hex::decode(case.tag).expect("valid hex tag");

    let mut data = vec![0u8; pt.len()];
    let (got_iv, _, tag) = Gcm::<P, Encrypting, KEY_LEN, 16>::encrypt_out_rng_detached(
        &key,
        &mut FixedSeedRNG::<12>::new(iv),
        &aad,
        &pt,
        &mut data,
    )
    .expect("encrypt");
    assert_eq!(got_iv, iv, "{}: the pinned RNG should reproduce the vector's IV", case.name);

    assert_eq!(data, expected_ct, "{}: ciphertext mismatch", case.name);
    assert_eq!(&tag[..], &expected_tag[..], "{}: tag mismatch", case.name);

    let tag_arr: [u8; 16] = expected_tag.try_into().expect("16-byte tag");
    let mut recovered = vec![0u8; data.len()];
    Gcm::<P, Decrypting, KEY_LEN, 16>::decrypt_out_detached(
        &key, &iv, &aad, &data, &tag_arr, &mut recovered,
    )
    .unwrap_or_else(|e| panic!("{}: decrypt should have verified, got {e:?}", case.name));
    assert_eq!(recovered, pt, "{}: decrypted plaintext mismatch", case.name);
}

#[test]
fn bc_java_test_vectors_with_a_96_bit_iv() {
    let mut checked = 0usize;
    for case in cases() {
        let key_len_bytes = case.key.len() / 2;
        match key_len_bytes {
            16 => run::<AES128Internal, 16>(&case),
            24 => run::<AES192Internal, 24>(&case),
            32 => run::<AES256Internal, 32>(&case),
            other => panic!("{}: unexpected key length {other} bytes", case.name),
        }
        checked += 1;
    }
    println!("bc-java GCMTest 96-bit-IV vectors: {checked} cases checked");
    assert_eq!(checked, 12, "expected the twelve 96-bit-IV McGrew/Viega vectors");
}
