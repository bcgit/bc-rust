//! Known-answer tests against Project Wycheproof's `testvectors_v1/ed25519_test.json`.
//!
//! Requires the Wycheproof repository (https://github.com/C2SP/wycheproof) to be cloned alongside
//! this repository, i.e. at `../wycheproof` relative to the root of this git project. If it is
//! absent the test prints a warning and passes, matching the convention used by the other vector
//! suites.
//!
//! Every group and every case is run: a `valid` case must verify and every other case must
//! not. This crate validates a public key in full when it is decoded, so a case whose key is
//! outside the prime-order subgroup would be refused at the key and never reach verification.
//! That is the expected rejection of an `invalid` case, and it would fail the test for a
//! `valid` one; the test counts both, and the file has neither.

use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::signature_key::OneShotVerifyingKey;
use bouncycastle_core::traits::PublicKey;
use bouncycastle_core_test_framework::test_data_loaders::{Value, hex_field, wycheproof_json};
use bouncycastle_ed::ed25519::{Ed25519, Ed25519PublicKey, SIGNATURE_LEN};

#[test]
fn wycheproof_ed25519() {
    let filename = "ed25519_test.json";
    let Some(doc) = wycheproof_json(filename) else { return };

    assert_eq!(doc.get("algorithm").and_then(Value::as_str), Some("EDDSA"), "{filename}");

    let (mut groups, mut valid, mut invalid) = (0usize, 0usize, 0usize);
    // How the invalid cases were refused.
    let (mut at_key_decode, mut at_length, mut at_verify) = (0usize, 0usize, 0usize);
    for group in doc.get("testGroups").and_then(Value::as_array).expect("testGroups") {
        groups += 1;
        let key = group.get("publicKey").expect("publicKey");
        assert_eq!(key.get("curve").and_then(Value::as_str), Some("edwards25519"), "{filename}");
        let pk = Ed25519PublicKey::from_bytes(&hex_field(key, "pk", 0));

        for test in group.get("tests").and_then(Value::as_array).expect("tests") {
            let tc_id = test.get("tcId").and_then(Value::as_u64).expect("tcId");
            let ctx = format!("{filename} tcId {tc_id}");
            let msg = hex_field(test, "msg", tc_id);
            let sig = hex_field(test, "sig", tc_id);
            let verdict = pk.as_ref().map_err(|_| "key decode").and_then(|pk| {
                match OneShotVerifyingKey::<Ed25519, _>::verify(pk, &msg, None, &sig) {
                    Ok(()) => Ok(()),
                    Err(SignatureError::LengthError(_)) => Err("length"),
                    Err(SignatureError::SignatureVerificationFailed) => Err("verify"),
                    Err(e) => panic!("{ctx}: unexpected error {e:?}"),
                }
            });

            match test.get("result").and_then(Value::as_str).expect("result") {
                "valid" => {
                    valid += 1;
                    assert_eq!(verdict, Ok(()), "{ctx}: a valid signature was refused");
                }
                "invalid" => {
                    invalid += 1;
                    match verdict {
                        Ok(()) => panic!("{ctx}: an invalid signature was accepted"),
                        Err("key decode") => at_key_decode += 1,
                        Err("length") => {
                            assert_ne!(sig.len(), SIGNATURE_LEN, "{ctx}");
                            at_length += 1;
                        }
                        Err(_) => {
                            assert_eq!(sig.len(), SIGNATURE_LEN, "{ctx}");
                            at_verify += 1;
                        }
                    }
                }
                other => panic!("{ctx}: unexpected result {other}"),
            }
        }
    }

    println!(
        "Wycheproof Ed25519: {groups} groups, {} cases: {valid} valid accepted; {invalid} \
         invalid refused ({at_verify} by verification, {at_length} for their length, \
         {at_key_decode} at key decode)",
        valid + invalid
    );
    assert_eq!(
        doc.get("numberOfTests").and_then(Value::as_u64),
        Some((valid + invalid) as u64),
        "{filename}: every case was run"
    );
    assert!(valid > 0 && at_verify > 0 && at_length > 0, "{filename}: expected every kind of case");
    // No key in the file is outside the prime-order subgroup.
    assert_eq!(at_key_decode, 0, "{filename}");
}
