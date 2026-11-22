//! NIST ACVP vectors for the three iterated modes: ACVP-Server's `gen-val/json-files/KDF-1.0`,
//! in `bc-test-data/crypto/acvp`. The prompt gives each case's key (and IV); the expected
//! results give the fixed input data the generator chose, where it broke it for a counter in
//! the middle, and the output.
//!
//! Run: every group over HMAC with SHA-224, -256, -384, -512 and the four SHA-3 hashes, and
//! over CMAC with AES-128, -192 and -256, whose output length is a whole number of bytes. Counted
//! and not run, so that a change in what is skipped is noticed: the MACs this crate or the
//! library's release does not have (HMAC-SHA-1, HMAC-SHA2-512/224 and -512/256, CMAC-TDES), the
//! groups whose output length is not a whole number of bytes, and the cases whose counter sits
//! at a bit offset inside the fixed input data. A missing `bc-test-data` checkout fails the test
//! rather than skipping it.

#[path = "kbkdf_common/mod.rs"]
mod common;

use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::KDF;
use bouncycastle_core_test_framework::test_data_loaders::Value;
use bouncycastle_sha2::{SHA224, SHA256, SHA384, SHA512};
use bouncycastle_sha3::{SHA3_224, SHA3_256, SHA3_384, SHA3_512};
use bouncycastle_symmetric::kbkdf::{
    CounterPosition, CounterSize, IterationCounterPosition, KDF_Counter, KDF_DoublePipeline,
    KDF_Feedback, PRF_CMAC_AES128, PRF_CMAC_AES192, PRF_CMAC_AES256, PRF_HMAC, Prf,
};
use common::hex_value;
use std::collections::HashMap;

struct Case<'a> {
    mode: &'a str,
    /// ACVP names the counter's place by the fixed data: `before fixed data`, `after fixed
    /// data`, `middle fixed data`, `before iterator`, or `none`.
    location: &'a str,
    r: Option<CounterSize>,
    key_in: Vec<u8>,
    iv: Vec<u8>,
    fixed: Vec<u8>,
    /// The byte offset of a counter in the middle of the fixed data.
    break_at: usize,
    key_out: Vec<u8>,
}

fn run<P: Prf>(c: &Case) -> Vec<u8> {
    let k_in =
        KeyMaterial::<64>::from_bytes_as_type(&c.key_in, KeyType::CryptographicRandom).unwrap();
    let len = c.key_out.len();
    let mut out = KeyMaterial::<128>::new();
    let iterated = |r: CounterSize| {
        let position = match c.location {
            "before iterator" => IterationCounterPosition::BeforeIterationVariable,
            "before fixed data" => IterationCounterPosition::AfterIterationVariable,
            "after fixed data" => IterationCounterPosition::AfterFixedInput,
            other => panic!("unexpected counter location {other}"),
        };
        (r, position)
    };
    let written = match (c.mode, c.r) {
        ("counter", Some(r)) => {
            let position = match c.location {
                "before fixed data" => CounterPosition::BeforeFixedInput,
                "after fixed data" => CounterPosition::AfterFixedInput,
                "middle fixed data" => CounterPosition::InFixedInput(c.break_at),
                other => panic!("unexpected counter location {other}"),
            };
            KDF_Counter::<P>::with_counter(r, position)
                .derive_key_out(&k_in, &c.fixed, len, &mut out)
        }
        ("feedback", None) => {
            KDF_Feedback::<P>::new(&c.iv).derive_key_out(&k_in, &c.fixed, len, &mut out)
        }
        ("feedback", Some(r)) => {
            let (r, position) = iterated(r);
            KDF_Feedback::<P>::with_counter(&c.iv, r, position)
                .derive_key_out(&k_in, &c.fixed, len, &mut out)
        }
        ("double pipeline iteration", None) => {
            KDF_DoublePipeline::<P>::new().derive_key_out(&k_in, &c.fixed, len, &mut out)
        }
        ("double pipeline iteration", Some(r)) => {
            let (r, position) = iterated(r);
            KDF_DoublePipeline::<P>::with_counter(r, position)
                .derive_key_out(&k_in, &c.fixed, len, &mut out)
        }
        other => panic!("unexpected mode {other:?}"),
    }
    .unwrap();
    assert_eq!(written, len);
    out.ref_to_bytes().to_vec()
}

#[test]
fn acvp_kdf_1_0() {
    let prompt = common::acvp_json("KDF-1.0", "prompt.json");
    let expected = common::acvp_json("KDF-1.0", "expectedResults.json");
    let mut answers = HashMap::new();
    for group in expected["testGroups"].as_array().unwrap() {
        for test in group["tests"].as_array().unwrap() {
            answers.insert(test["tcId"].as_u64().unwrap(), test);
        }
    }

    let mut run_by_mode: HashMap<&str, usize> = HashMap::new();
    let (mut other_mac, mut odd_length, mut odd_break) = (0usize, 0usize, 0usize);
    for group in prompt["testGroups"].as_array().unwrap() {
        assert_eq!(group["testType"], "AFT");
        let tests = group["tests"].as_array().unwrap();
        let mac = group["macMode"].as_str().unwrap();
        if matches!(mac, "HMAC-SHA-1" | "HMAC-SHA2-512/224" | "HMAC-SHA2-512/256" | "CMAC-TDES") {
            other_mac += tests.len();
            continue;
        }
        let bits = group["keyOutLength"].as_u64().unwrap() as usize;
        if !bits.is_multiple_of(8) {
            odd_length += tests.len();
            continue;
        }
        let mode = group["kdfMode"].as_str().unwrap();
        let location = group["counterLocation"].as_str().unwrap();
        let r = group["counterLength"].as_u64().map(|bits| {
            u32::try_from(bits)
                .ok()
                .and_then(CounterSize::from_bits)
                .unwrap_or_else(|| panic!("unexpected counter length {bits}"))
        });
        assert_eq!(r.is_none(), location == "none");
        for test in tests {
            let tc_id = test["tcId"].as_u64().unwrap();
            let answer = answers[&tc_id];
            let break_bits =
                answer.get("breakLocation").and_then(Value::as_u64).unwrap_or(0) as usize;
            if !break_bits.is_multiple_of(8) {
                odd_break += 1;
                continue;
            }
            let case = Case {
                mode,
                location,
                r,
                key_in: hex_value(&test["keyIn"]),
                iv: test.get("iv").map(hex_value).unwrap_or_default(),
                fixed: hex_value(&answer["fixedData"]),
                break_at: break_bits / 8,
                key_out: hex_value(&answer["keyOut"]),
            };
            assert_eq!(case.key_out.len(), bits / 8, "tcId {tc_id}");
            let got = match mac {
                "HMAC-SHA2-224" => run::<PRF_HMAC<SHA224>>(&case),
                "HMAC-SHA2-256" => run::<PRF_HMAC<SHA256>>(&case),
                "HMAC-SHA2-384" => run::<PRF_HMAC<SHA384>>(&case),
                "HMAC-SHA2-512" => run::<PRF_HMAC<SHA512>>(&case),
                "HMAC-SHA3-224" => run::<PRF_HMAC<SHA3_224>>(&case),
                "HMAC-SHA3-256" => run::<PRF_HMAC<SHA3_256>>(&case),
                "HMAC-SHA3-384" => run::<PRF_HMAC<SHA3_384>>(&case),
                "HMAC-SHA3-512" => run::<PRF_HMAC<SHA3_512>>(&case),
                "CMAC-AES128" => run::<PRF_CMAC_AES128>(&case),
                "CMAC-AES192" => run::<PRF_CMAC_AES192>(&case),
                "CMAC-AES256" => run::<PRF_CMAC_AES256>(&case),
                other => panic!("unexpected macMode {other}"),
            };
            assert_eq!(got, case.key_out, "tcId {tc_id}: {mode}, {mac}, counter {location}");
            *run_by_mode.entry(mode).or_default() += 1;
        }
    }
    // 11756 cases in all.
    assert_eq!(
        (run_by_mode["counter"], run_by_mode["feedback"], run_by_mode["double pipeline iteration"]),
        (755, 2320, 1168)
    );
    assert_eq!((other_mac, odd_length, odd_break), (3194, 3994, 325));
}
