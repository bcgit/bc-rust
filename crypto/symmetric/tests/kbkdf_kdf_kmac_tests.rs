//! The KDF Using KMAC (SP 800-108r1 Section 4.4): NIST's ACVP vectors, the function against
//! the library's fixed-length KMAC, and the [`KDF`] trait's shared suite and limits.
//!
//! The vectors are ACVP-Server's `gen-val/json-files/KDF-KMAC-Sp800-108r1`, in
//! `bc-test-data/crypto/acvp`: 50 cases each for KMAC-128 and KMAC-256, with keys, contexts,
//! labels and outputs of up to 512 bytes. A missing `bc-test-data` checkout fails the test
//! rather than skipping it.

#[path = "kbkdf_common/mod.rs"]
mod common;

use bouncycastle_core::errors::KDFError;
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::kdf_params::KdfDescription;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::MacGenerationKey;
use bouncycastle_core::traits::{Algorithm, KDF};
use bouncycastle_sha3::kmac::{KMAC128Key, KMAC256Key};
use bouncycastle_symmetric::kbkdf::{KDF_KMAC128, KDF_KMAC256, MAX_KMAC_KDK_LEN};
use common::{hex_value, random};
use std::collections::HashMap;

#[test]
fn acvp_kdf_kmac() {
    let prompt = common::acvp_json("KDF-KMAC-Sp800-108r1", "prompt.json");
    let expected = common::acvp_json("KDF-KMAC-Sp800-108r1", "expectedResults.json");
    let mut answers = HashMap::new();
    for group in expected["testGroups"].as_array().unwrap() {
        for test in group["tests"].as_array().unwrap() {
            answers.insert(test["tcId"].as_u64().unwrap(), hex_value(&test["derivedKey"]));
        }
    }

    let (mut kmac128, mut kmac256) = (0usize, 0usize);
    for group in prompt["testGroups"].as_array().unwrap() {
        assert_eq!(group["testType"], "AFT");
        let mac_mode = group["macMode"].as_str().unwrap();
        for test in group["tests"].as_array().unwrap() {
            let tc_id = test["tcId"].as_u64().unwrap();
            let k_in = random(&hex_value(&test["keyDerivationKey"]));
            let (context, label) = (hex_value(&test["context"]), hex_value(&test["label"]));
            let bits = test["derivedKeyLength"].as_u64().unwrap() as usize;
            assert_eq!(bits % 8, 0, "tcId {tc_id}: L is a whole number of bytes in this set");
            let mut out = KeyMaterial::<512>::new();
            let written = match mac_mode {
                "KMAC-128" => {
                    kmac128 += 1;
                    KDF_KMAC128::new(&label).derive_key_out(&k_in, &context, bits / 8, &mut out)
                }
                "KMAC-256" => {
                    kmac256 += 1;
                    KDF_KMAC256::new(&label).derive_key_out(&k_in, &context, bits / 8, &mut out)
                }
                other => panic!("unexpected macMode {other}"),
            }
            .unwrap_or_else(|e| panic!("tcId {tc_id}: {e:?}"));
            assert_eq!(written, bits / 8, "tcId {tc_id}");
            assert_eq!(out.ref_to_bytes(), answers[&tc_id].as_slice(), "tcId {tc_id}");
        }
    }
    assert_eq!((kmac128, kmac256), (50, 50));
}

/// Section 4.4 step 2, `K_OUT = KMAC#(K_IN, Context, L, Label)`, against the library's
/// fixed-length KMAC, whose length is part of its type: the same key, the Context as the
/// message, the Label as the customization string, and `L` bound.
#[test]
fn is_kmac_of_the_context_at_the_length() {
    let key = [0x5Au8; 32];
    let mac_key = KeyMaterial::<32>::from_bytes_as_type(&key, KeyType::MACKey).unwrap();
    let k_in = random(&key);
    let (context, label) = (b"the context".as_slice(), b"KDF4X".as_slice());

    let kdf = KDF_KMAC128::new(label);
    assert_eq!(kdf.label(), label);
    assert_eq!(
        kdf.derive_key(&k_in, context, 32).unwrap().ref_to_bytes(),
        &KMAC128Key::<32>::with_params_allow_weak(&mac_key, label).unwrap().mac(context)[..]
    );
    assert_eq!(
        kdf.derive_key(&k_in, context, 48).unwrap().ref_to_bytes(),
        &KMAC128Key::<48>::with_params_allow_weak(&mac_key, label).unwrap().mac(context)[..]
    );
    let kdf = KDF_KMAC256::new(label);
    assert_eq!(
        kdf.derive_key(&k_in, context, 64).unwrap().ref_to_bytes(),
        &KMAC256Key::<64>::with_params(&mac_key, label).unwrap().mac(context)[..]
    );
    // The default has the empty Label.
    assert_eq!(KDF_KMAC256::default().label(), b"");
    assert_eq!(
        KDF_KMAC256::default().derive_key(&k_in, context, 64).unwrap().ref_to_bytes(),
        &KMAC256Key::<64>::with_params(&mac_key, b"").unwrap().mac(context)[..]
    );

    // L is bound: a shorter output is not a prefix of a longer one, and the Label and the
    // variant both change it.
    let kdf = KDF_KMAC128::new(label);
    let long = kdf.derive_key(&k_in, context, 48).unwrap();
    let short = kdf.derive_key(&k_in, context, 32).unwrap();
    assert_ne!(short.ref_to_bytes(), &long.ref_to_bytes()[..32]);
    assert_ne!(
        KDF_KMAC128::new(b"KDF").derive_key(&k_in, context, 32).unwrap().ref_to_bytes(),
        short.ref_to_bytes()
    );
    assert_ne!(
        KDF_KMAC256::new(label).derive_key(&k_in, context, 32).unwrap().ref_to_bytes(),
        short.ref_to_bytes()
    );

    // K_IN as two keys is their concatenation, and the description's engine is the same KDF.
    let (a, b) = (random(&key[..5]), random(&key[5..]));
    assert_eq!(
        kdf.derive_key_from_multiple(&[&a, &b], context, 32).unwrap().ref_to_bytes(),
        short.ref_to_bytes()
    );
    let engine = kdf.engine().unwrap();
    assert_eq!(engine.label(), label);
    assert_eq!(engine.derive_key(&k_in, context, 32).unwrap().ref_to_bytes(), short.ref_to_bytes());
}

/// The trait's suite cannot run as it is: it checks that a shorter output is a prefix, which
/// Section 4.4 rules out. Its other checks, by hand.
#[test]
fn kdf_trait_behaviour() {
    let k_in = random(&[0x5A; 32]);
    let kdf = KDF_KMAC128::new(b"label");
    let dyn_kdf: &dyn KDF = &kdf;
    assert_eq!(dyn_kdf.alg_name(), "KDF-KMAC128");
    assert_eq!(
        dyn_kdf.derive_key(&k_in, b"context", 40).unwrap().ref_to_bytes(),
        kdf.derive_key(&k_in, b"context", 40).unwrap().ref_to_bytes()
    );
    assert_ne!(
        kdf.derive_key(&k_in, b"", 40).unwrap().ref_to_bytes(),
        kdf.derive_key(&k_in, b"context", 40).unwrap().ref_to_bytes()
    );
    // K_IN as two keys is their concatenation.
    let expected = kdf.derive_key(&k_in, b"context", 40).unwrap();
    let (a, b) = (random(&[0x5A; 10]), random(&[0x5A; 22]));
    let mut out = KeyMaterial::<64>::new();
    assert_eq!(kdf.derive_key_from_multiple_out(&[&a, &b], b"context", 40, &mut out), Ok(40));
    assert_eq!(out.ref_to_bytes(), expected.ref_to_bytes());

    // Refusals, with the buffer cleared.
    let stale = || {
        let mut out = KeyMaterial::<32>::new();
        out.set_bytes_as_type(&[0xAA; 32], KeyType::CryptographicRandom).unwrap();
        out
    };
    let refused = |r: Result<usize, KDFError>, out: &KeyMaterial<32>, what: &str| {
        assert!(matches!(r, Err(KDFError::InvalidLength(_))), "{what}");
        assert_eq!((out.key_type(), out.key_len()), (KeyType::Zeroized, 0), "{what}");
    };
    let mut out = stale();
    refused(kdf.derive_key_out(&k_in, b"c", 0, &mut out), &out, "a zero length");
    let mut out = stale();
    refused(kdf.derive_key_out(&k_in, b"c", 33, &mut out), &out, "more than the buffer holds");
    let mut out = stale();
    refused(kdf.derive_key_from_multiple_out(&[], b"c", 16, &mut out), &out, "no keys");
    let mut out = stale();
    assert_eq!(kdf.derive_key_out(&k_in, b"c", 32, &mut out), Ok(32));
    // A one-byte output is allowed: the KDF has no minimum of its own.
    let mut out = stale();
    assert_eq!(kdf.derive_key_out(&k_in, b"c", 1, &mut out), Ok(1));

    // The key-derivation key's length limit.
    assert_eq!(MAX_KMAC_KDK_LEN, 512);
    let whole =
        KeyMaterial::<600>::from_bytes_as_type(&[0x11; 512], KeyType::CryptographicRandom).unwrap();
    let mut out = stale();
    assert_eq!(kdf.derive_key_out(&whole, b"c", 32, &mut out), Ok(32));
    let over =
        KeyMaterial::<600>::from_bytes_as_type(&[0x11; 513], KeyType::CryptographicRandom).unwrap();
    refused(kdf.derive_key_out(&over, b"c", 32, &mut out), &out, "a key of 513 bytes");
    let one = random(&[0x11; 1]);
    let mut out = stale();
    refused(
        kdf.derive_key_from_multiple_out(&[&whole, &one], b"c", 32, &mut out),
        &out,
        "513 bytes in two keys",
    );
}

/// The output's type and strength: `CryptographicRandom` once the full-entropy keys carry the
/// KMAC's strength in bytes, at the least of the key's, the KMAC's and the length's.
#[test]
fn the_output_is_typed_from_the_key() {
    let typed = |len: usize, strength: SecurityStrength| {
        let mut k =
            KeyMaterial::<64>::from_bytes_as_type(&[0x33; 64][..len], KeyType::SharedSecret)
                .unwrap();
        do_hazardous_operations(&mut k, |k| k.set_security_strength(strength)).unwrap();
        k
    };
    let label = |kdf: &dyn KDF, keys: &[&dyn KeyMaterialTrait], len: usize| {
        let out = kdf.derive_key_from_multiple(keys, b"c", len).unwrap();
        (out.key_type(), out.security_strength())
    };
    let random = KeyType::CryptographicRandom;
    let unknown = (KeyType::Unknown, SecurityStrength::None);
    let (k128, k256) = (KDF_KMAC128::new(b""), KDF_KMAC256::new(b""));

    assert_eq!(KDF_KMAC128::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);
    assert_eq!(KDF_KMAC256::MAX_SECURITY_STRENGTH, SecurityStrength::_256bit);
    assert_eq!((KDF_KMAC128::ALG_NAME, KDF_KMAC256::ALG_NAME), ("KDF-KMAC128", "KDF-KMAC256"));

    let strong = typed(64, SecurityStrength::_256bit);
    assert_eq!(label(&k128, &[&strong], 64), (random, SecurityStrength::_128bit));
    assert_eq!(label(&k256, &[&strong], 64), (random, SecurityStrength::_256bit));
    assert_eq!(label(&k256, &[&strong], 16), (random, SecurityStrength::_128bit));
    let weak = typed(64, SecurityStrength::_112bit);
    assert_eq!(label(&k256, &[&weak], 64), (random, SecurityStrength::_112bit));

    // The seed lengths: 16 bytes for KMAC128, 32 for KMAC256.
    assert_eq!(
        label(&k128, &[&typed(16, SecurityStrength::_128bit)], 32),
        (random, SecurityStrength::_128bit)
    );
    assert_eq!(label(&k128, &[&typed(15, SecurityStrength::_112bit)], 32), unknown);
    assert_eq!(
        label(&k256, &[&typed(32, SecurityStrength::_256bit)], 32),
        (random, SecurityStrength::_256bit)
    );
    assert_eq!(label(&k256, &[&typed(31, SecurityStrength::_192bit)], 32), unknown);
    // Two keys are credited together, at the stronger's strength; untyped bytes credit nothing.
    let (a, b) = (typed(14, SecurityStrength::_112bit), typed(16, SecurityStrength::_128bit));
    assert_eq!(label(&k256, &[&a, &b], 32), unknown);
    assert_eq!(label(&k128, &[&a, &b], 32), (random, SecurityStrength::_128bit));
    let untyped = KeyMaterial::<64>::from_bytes_as_type(&[0x33; 64], KeyType::Unknown).unwrap();
    assert_eq!(label(&k128, &[&untyped], 32), unknown);
    assert_eq!(label(&k128, &[&KeyMaterial::<64>::new()], 32), unknown);
}

/// A copy keeps its Label, and nothing is written past `L` bytes.
#[test]
fn a_copy_and_the_buffer_past_the_length() {
    let kdf = KDF_KMAC256::new(b"a label");
    #[allow(clippy::clone_on_copy)]
    let copy = kdf.clone();
    assert_eq!(copy.label(), b"a label");

    let k_in = random(&[0x5A; 32]);
    let expected = kdf.derive_key(&k_in, b"context", 40).unwrap();
    let mut exact = KeyMaterial::<40>::new();
    assert_eq!(kdf.derive_key_out(&k_in, b"context", 40, &mut exact), Ok(40));
    assert_eq!(exact.ref_to_bytes(), expected.ref_to_bytes());
    let mut roomy = KeyMaterial::<128>::new();
    assert_eq!(kdf.derive_key_out(&k_in, b"context", 40, &mut roomy), Ok(40));
    let mut capacity = Vec::new();
    do_hazardous_operations(&mut roomy, |k| {
        capacity = k.ref_to_bytes_mut()?.to_vec();
        Ok(())
    })
    .unwrap();
    assert_eq!(&capacity[..40], expected.ref_to_bytes());
    assert_eq!(&capacity[40..], &[0u8; 88]);

    // Full-entropy material whose producer stated no strength credits nothing.
    let unstated =
        KeyMaterial::<64>::from_bytes_as_type(&[0x33; 64], KeyType::SharedSecret).unwrap();
    assert_eq!(unstated.security_strength(), SecurityStrength::None);
    let out = kdf.derive_key(&unstated, b"context", 32).unwrap();
    assert_eq!(
        (out.key_type(), out.security_strength()),
        (KeyType::Unknown, SecurityStrength::None)
    );
}
