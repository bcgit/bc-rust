//! Known-answer tests against Project Wycheproof's `testvectors_v1/ed448_test.json`.
//!
//! Requires the Wycheproof repository (https://github.com/C2SP/wycheproof) to be cloned alongside
//! this repository, i.e. at `../wycheproof` relative to the root of this git project. If it is
//! absent the test prints a warning and passes, matching the convention used by the other vector
//! suites.
//!
//! Every group and every case is run, as Ed448 with the empty context, which is all the file
//! has: a `valid` case must verify and an `invalid` one must not. Unlike the Ed25519 file,
//! this one has no `acceptable` cases and flags no key as outside the prime-order subgroup, so
//! every key must decode under the `ed448` module's full validation. A result class or a flag the
//! test does not know fails it.

use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::signature_key::OneShotVerifyingKey;
use bouncycastle_core::traits::PublicKey;
use bouncycastle_core_test_framework::test_data_loaders::{Value, hex_field, wycheproof_json};
use bouncycastle_ec::ed::ed448::{Ed448PublicKey, SIGNATURE_LEN};

/// The flags of the file, with whether a case that carries one is a signature of the right
/// length.
const FLAGS: &[(&str, bool)] = &[
    ("Valid", true),
    ("Ktv", true),
    ("InvalidKtv", true),
    ("InvalidSignature", true),
    ("InvalidEncoding", true),
    ("SignatureMalleability", true),
    ("SignatureWithGarbage", false),
    ("CompressedSignature", false),
    ("TruncatedSignature", false),
];

#[test]
fn wycheproof_ed448() {
    let filename = "ed448_test.json";
    let Some(doc) = wycheproof_json(filename) else { return };

    assert_eq!(doc.get("algorithm").and_then(Value::as_str), Some("EDDSA"), "{filename}");

    let (mut groups, mut valid, mut invalid) = (0usize, 0usize, 0usize);
    // How the invalid cases were refused, and how many cases carried each flag.
    let (mut at_length, mut at_verify) = (0usize, 0usize);
    let mut by_flag = [0usize; FLAGS.len()];
    for group in doc.get("testGroups").and_then(Value::as_array).expect("testGroups") {
        groups += 1;
        let key = group.get("publicKey").expect("publicKey");
        assert_eq!(key.get("curve").and_then(Value::as_str), Some("edwards448"), "{filename}");
        let pk = Ed448PublicKey::from_bytes(&hex_field(key, "pk", 0))
            .unwrap_or_else(|e| panic!("{filename} group {groups}: the key was refused: {e:?}"));

        for test in group.get("tests").and_then(Value::as_array).expect("tests") {
            let tc_id = test.get("tcId").and_then(Value::as_u64).expect("tcId");
            let ctx = format!("{filename} tcId {tc_id}");
            let msg = hex_field(test, "msg", tc_id);
            let sig = hex_field(test, "sig", tc_id);
            let result = test.get("result").and_then(Value::as_str).expect("result");

            let flags = test.get("flags").and_then(Value::as_array).expect("flags");
            assert_eq!(flags.len(), 1, "{ctx}: one flag a case");
            let flag = flags[0].as_str().expect("flag");
            let index = FLAGS
                .iter()
                .position(|(known, _)| *known == flag)
                .unwrap_or_else(|| panic!("{ctx}: unknown flag {flag}"));
            by_flag[index] += 1;
            assert_eq!(sig.len() == SIGNATURE_LEN, FLAGS[index].1, "{ctx}: length under {flag}");
            assert_eq!(result == "valid", matches!(flag, "Valid" | "Ktv"), "{ctx}: {flag}");

            let verdict = match pk.verify(&msg, None, &sig) {
                Ok(()) => Ok(()),
                Err(SignatureError::LengthError(_)) => Err("length"),
                Err(SignatureError::SignatureVerificationFailed) => Err("verify"),
                Err(e) => panic!("{ctx}: unexpected error {e:?}"),
            };
            match result {
                "valid" => {
                    valid += 1;
                    assert_eq!(verdict, Ok(()), "{ctx}: a valid signature was refused");
                    // The empty context is the absent one, and no other.
                    let verify = |c| pk.verify(&msg, c, &sig);
                    assert_eq!(verify(Some(&[][..])), Ok(()), "{ctx}");
                    assert!(verify(Some(&b"c"[..])).is_err(), "{ctx}");
                }
                "invalid" => {
                    invalid += 1;
                    match verdict {
                        Ok(()) => panic!("{ctx}: an invalid signature was accepted"),
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
        "Wycheproof Ed448: {groups} groups, {} cases: {valid} valid accepted; {invalid} invalid \
         refused ({at_verify} by verification, {at_length} for their length)",
        valid + invalid
    );
    for ((flag, _), count) in FLAGS.iter().zip(by_flag) {
        println!("  {flag}: {count}");
    }
    assert_eq!(
        doc.get("numberOfTests").and_then(Value::as_u64),
        Some((valid + invalid) as u64),
        "{filename}: every case was run"
    );
    // The file at the pinned commit 65ca4947.
    assert_eq!((groups, valid, invalid, at_verify, at_length), (15, 17, 70, 58, 12), "{filename}");
    assert_eq!(by_flag, [9, 8, 1, 20, 29, 8, 5, 4, 3], "{filename}");
}
