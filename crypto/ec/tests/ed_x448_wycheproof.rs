//! Known-answer tests against Project Wycheproof's `testvectors_v1/x448_test.json`.
//!
//! Requires the Wycheproof repository (https://github.com/C2SP/wycheproof) to be cloned alongside
//! this repository, i.e. at `../wycheproof` relative to the root of this git project. If it is
//! absent the test prints a warning and passes, matching the convention used by the other vector
//! suites.
//!
//! Every case is run. A `valid` or `acceptable` case has an expected shared secret and is
//! checked for exact output: the `acceptable` ones are twist, low-order and non-canonical
//! public keys, which RFC 7748 Section 5 requires to be processed rather than rejected. The
//! exception is the cases flagged `ZeroSharedSecret`, which the agreement refuses as
//! `KeyAgreementError::AgreementFailed`; a case is refused that way exactly when it carries
//! the flag. The `invalid` cases are public keys of 57 bytes (`PublicKeyTooLong`), which do
//! not decode. A result class or a flag this test does not know fails it.

use bouncycastle_core::agreement_key::AgreementKey;
use bouncycastle_core::errors::KeyAgreementError;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::PublicKey;
use bouncycastle_core_test_framework::test_data_loaders::{Value, hex_field, wycheproof_json};
use bouncycastle_ec::ed::x448::{
    POINT_LEN, SCALAR_LEN, X448PrivateKey, X448PublicKey, keygen_from_seed,
};

/// Every flag the file uses at the pinned commit.
const KNOWN_FLAGS: [&str; 12] = [
    "EdgeCaseMultiplication", "EdgeCasePrivateKey", "EdgeCaseShared", "Ktv", "LowOrderPublic",
    "NonCanonicalPublic", "Normal", "PublicKeyTooLong", "SmallPublicKey", "SpecialPublicKey",
    "Twist", "ZeroSharedSecret",
];

/// The flags that make a case `acceptable`: each names a public key RFC 7748 defines the result
/// for and some libraries reject.
const ACCEPTABLE_FLAGS: [&str; 5] =
    ["LowOrderPublic", "NonCanonicalPublic", "SmallPublicKey", "Twist", "ZeroSharedSecret"];

#[test]
fn wycheproof_x448() {
    let filename = "x448_test.json";
    let Some(doc) = wycheproof_json(filename) else { return };

    assert_eq!(doc.get("algorithm").and_then(Value::as_str), Some("XDH"), "{filename}");

    let (mut valid, mut acceptable, mut invalid) = (0usize, 0usize, 0usize);
    let (mut zero_shared, mut twist, mut non_canonical) = (0usize, 0usize, 0usize);
    for group in doc.get("testGroups").and_then(Value::as_array).expect("testGroups") {
        assert_eq!(group.get("curve").and_then(Value::as_str), Some("curve448"), "{filename}");

        for test in group.get("tests").and_then(Value::as_array).expect("tests") {
            let tc_id = test.get("tcId").and_then(Value::as_u64).expect("tcId");
            let ctx = format!("{filename} tcId {tc_id}");
            let flags: Vec<&str> = test
                .get("flags")
                .and_then(Value::as_array)
                .expect("flags")
                .iter()
                .map(|f| f.as_str().expect("a flag is a string"))
                .collect();
            for flag in &flags {
                assert!(KNOWN_FLAGS.contains(flag), "{ctx}: unknown flag {flag}");
            }
            let flagged = |flag: &str| flags.contains(&flag);

            let k: [u8; SCALAR_LEN] =
                hex_field(test, "private", tc_id).try_into().expect("a 56-byte private key");
            let k = sk_from_bytes(&k);
            let public = hex_field(test, "public", tc_id);
            let shared = hex_field(test, "shared", tc_id);

            match test.get("result").and_then(Value::as_str).expect("result") {
                "valid" => {
                    valid += 1;
                    for flag in ACCEPTABLE_FLAGS {
                        assert!(!flagged(flag), "{ctx}: a valid case flagged {flag}");
                    }
                }
                "acceptable" => {
                    acceptable += 1;
                    assert!(
                        ACCEPTABLE_FLAGS.iter().any(|flag| flagged(flag)),
                        "{ctx}: acceptable for a reason this test does not know"
                    );
                }
                "invalid" => {
                    invalid += 1;
                    // The only invalid cases are public keys of the wrong length, which the
                    // key type refuses; there is no shared secret to compare.
                    assert!(flagged("PublicKeyTooLong"), "{ctx}: invalid for an unknown reason");
                    assert_ne!(public.len(), POINT_LEN, "{ctx}");
                    assert!(shared.is_empty(), "{ctx}");
                    assert!(X448PublicKey::from_bytes(&public).is_err(), "{ctx}: decoded");
                    continue;
                }
                other => panic!("{ctx}: unexpected result {other}"),
            }
            assert!(!flagged("PublicKeyTooLong"), "{ctx}");
            twist += usize::from(flagged("Twist"));
            non_canonical += usize::from(flagged("NonCanonicalPublic"));

            assert_eq!(shared.len(), POINT_LEN, "{ctx}: shared secret length");
            let u = X448PublicKey::from_bytes(&public).expect("a 56-byte public key");
            match k.agree(&u, ()) {
                Ok(r) => {
                    assert_eq!(r.ref_to_bytes(), shared.as_slice(), "{ctx}: shared secret");
                    assert!(!flagged("ZeroSharedSecret"), "{ctx}: flagged zero, not refused");
                }
                Err(KeyAgreementError::AgreementFailed) => {
                    assert!(shared.iter().all(|&b| b == 0), "{ctx}: rejected a non-zero secret");
                    assert!(flagged("ZeroSharedSecret"), "{ctx}: refused without the flag");
                    zero_shared += 1;
                }
                Err(e) => panic!("{ctx}: unexpected error {e:?}"),
            }
        }
    }

    println!(
        "Wycheproof X448: {} cases: {valid} valid and {acceptable} acceptable computed \
         ({twist} on the twist, {non_canonical} non-canonical), of which {zero_shared} refused \
         for an all-zero shared secret; {invalid} invalid refused at key decode",
        valid + acceptable + invalid
    );
    assert_eq!(
        doc.get("numberOfTests").and_then(Value::as_u64),
        Some((valid + acceptable + invalid) as u64),
        "{filename}: every case was run"
    );
    assert!(
        valid > 0 && acceptable > 0 && invalid > 0 && zero_shared > 0 && twist > 0,
        "{filename}: expected every kind of case"
    );
    assert!(non_canonical > 0, "{filename}: expected every kind of case");
}

/// A private key from its 56 bytes, via [`keygen_from_seed`].
fn sk_from_bytes(bytes: &[u8]) -> X448PrivateKey {
    let seed = KeyMaterial::<SCALAR_LEN>::from_bytes_as_type(bytes, KeyType::Seed).unwrap();
    keygen_from_seed(&seed).unwrap().1
}
