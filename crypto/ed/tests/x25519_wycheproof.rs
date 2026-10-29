//! Known-answer tests against Project Wycheproof's `testvectors_v1/x25519_test.json`.
//!
//! Requires the Wycheproof repository (https://github.com/C2SP/wycheproof) to be cloned alongside
//! this repository, i.e. at `../wycheproof` relative to the root of this git project. If it is
//! absent the tests print a warning and pass, matching the convention used by the other vector
//! suites.
//!
//! Every case is either `valid` or `acceptable`, and every case has an expected shared secret, so
//! each one is checked for exact output. The `acceptable` cases are low-order, twist and
//! non-canonical public keys, which RFC 7748 Section 5 requires to be processed rather than
//! rejected. Those whose shared secret is all zeros (flag `ZeroSharedSecret`) are also where
//! `calculate_agreement` returns `false`.

use bouncycastle_core_test_framework::test_data_loaders::{Value, hex_field, wycheproof_json};
use bouncycastle_ed::x25519::{POINT_SIZE, SCALAR_SIZE, calculate_agreement};

#[test]
fn wycheproof_x25519() {
    let filename = "x25519_test.json";
    let Some(doc) = wycheproof_json(filename) else { return };

    assert_eq!(doc.get("algorithm").and_then(Value::as_str), Some("XDH"), "{filename}");

    let (mut valid, mut acceptable, mut zero_shared) = (0usize, 0usize, 0usize);
    for group in doc.get("testGroups").and_then(Value::as_array).expect("testGroups") {
        assert_eq!(group.get("curve").and_then(Value::as_str), Some("curve25519"), "{filename}");

        for test in group.get("tests").and_then(Value::as_array).expect("tests") {
            let tc_id = test.get("tcId").and_then(Value::as_u64).expect("tcId");
            let ctx = format!("{filename} tcId {tc_id}");
            match test.get("result").and_then(Value::as_str).expect("result") {
                "valid" => valid += 1,
                "acceptable" => acceptable += 1,
                other => panic!("{ctx}: unexpected result {other}"),
            }

            let k: [u8; SCALAR_SIZE] =
                hex_field(test, "private", tc_id).try_into().expect("a 32-byte private key");
            let u: [u8; POINT_SIZE] =
                hex_field(test, "public", tc_id).try_into().expect("a 32-byte public key");
            let shared = hex_field(test, "shared", tc_id);

            let mut out = [0u8; POINT_SIZE];
            let nonzero = calculate_agreement(&k, &u, &mut out);
            assert_eq!(out.as_slice(), shared.as_slice(), "{ctx}: shared secret");
            assert_eq!(nonzero, shared.iter().any(|&b| b != 0), "{ctx}: return value");
            zero_shared += usize::from(!nonzero);
        }
    }

    println!(
        "Wycheproof X25519: {} cases ({valid} valid, {acceptable} acceptable; \
         {zero_shared} with an all-zero shared secret)",
        valid + acceptable
    );
    assert!(
        valid > 0 && acceptable > 0 && zero_shared > 0,
        "{filename}: expected every kind of case"
    );
}
