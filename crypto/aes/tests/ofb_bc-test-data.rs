//! Known-answer tests against the NIST ACVP `ACVP-AES-OFB` vectors from the `bc-test-data` repo.
//!
//! Requires `bc-test-data` to be cloned alongside this repository, i.e. at `../bc-test-data`
//! relative to the root of this git project; see `cfb_bc-test-data.rs`, whose structure this
//! file follows, for what happens when it is absent and how the request and response files are
//! joined on `tcId`.
//!
//! # Coverage
//!
//! 2138 AFT (Algorithm Functional Test) cases across all three key lengths and both directions,
//! including 54 whose payload spans 2 to 10 blocks. Every case is run three times: block by
//! block, as one call over the whole payload, and in 5-byte calls that never line up with a
//! block, so the pending keystream is carried between calls. OFB has no pair or four-block path
//! to exercise (SP 800-38A Sec 6.4: the forward cipher calls cannot run in parallel). Every ACVP
//! OFB payload is a whole number of blocks, so the partial final block is not covered here;
//! `crypto/cipher/tests/modes/ofb_tests.rs` pins it against the raw permutation.
//!
//! The 6 MCT (Monte Carlo Test) groups are **not** implemented, as for CFB: their expected output
//! is a `resultsArray` produced by a chained update rule defined in the ACVP AES specification
//! rather than in SP 800-38A. The test reports how many it skipped so the gap stays visible.

use bouncycastle_aes::{AES128Key, AES192Key, AES256Key};
use bouncycastle_cipher::modes::OFB;
use bouncycastle_core::hazmat::FixedSeedRNG;
use bouncycastle_core::symmetric_key::{
    FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle_core::traits::{StreamCipherDecryptor, StreamCipherEncryptor};
use bouncycastle_core_test_framework::test_data_loaders::{Value, bc_test_data_json, hex_field};
use std::collections::BTreeMap;

#[path = "common/acvp_helpers.rs"]
mod acvp_helpers;
use acvp_helpers::cipher_key;

const BLOCK_LEN: usize = 16;

const TEST_DATA_DIR: &str = "crypto/aes_tdes_vectors/AES";
const REQUEST_FILE: &str = "ACVP-AES-OFB.4014531.req.json";
const RESPONSE_FILE: &str = "ACVP-AES-OFB.4014531.rsp.json";

/// How to walk the bytes of one case.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Grouping {
    /// One block per call.
    Single,
    /// The whole payload in one call.
    Whole,
    /// Five bytes per call, so every call but the first starts mid-block and none is a whole
    /// block: the unused keystream is carried between calls.
    Bytes,
}

impl Grouping {
    fn chunk_len(self, payload_len: usize) -> usize {
        match self {
            Grouping::Single => BLOCK_LEN,
            Grouping::Whole => payload_len.max(1),
            Grouping::Bytes => 5,
        }
    }
}

/// Runs one OFB case in one direction, for a given key type, under the given grouping.
///
/// Encryption is driven through the key's `create_encryptor` with a `FixedSeedRNG` emitting the
/// vector's IV, and the returned init data is checked against that IV before any ciphertext is
/// compared -- so a change that ignored the RNG could not pass silently.
fn run_case<K, const KEY_LEN: usize>(
    key_bytes: &[u8],
    iv: [u8; BLOCK_LEN],
    input: &[u8],
    encrypt: bool,
    grouping: Grouping,
) -> Vec<u8>
where
    K: 'static,
    K: FromKeyMaterial<KEY_LEN>
        + SymmetricEncryptionKey<KEY_LEN, BLOCK_LEN, 0>
        + SymmetricDecryptionKey<KEY_LEN, BLOCK_LEN, 0>,
    for<'k> K::Encryptor<'k>: StreamCipherEncryptor<BLOCK_LEN>,
    for<'k> K::Decryptor<'k>: StreamCipherDecryptor<BLOCK_LEN>,
{
    let key = K::from_key_material(&cipher_key::<KEY_LEN>(key_bytes)).expect("a valid key");
    let mut data = input.to_vec();
    let chunk = grouping.chunk_len(data.len());

    if encrypt {
        let (mut enc, got_iv) =
            key.create_encryptor(&mut FixedSeedRNG::new(iv)).expect("encrypt init");
        assert_eq!(got_iv, iv, "the pinned RNG should reproduce the vector's IV");
        for piece in data.chunks_mut(chunk) {
            enc.do_encrypt_inplace(piece).unwrap();
        }
    } else {
        let mut dec = key.create_decryptor(&iv);
        for piece in data.chunks_mut(chunk) {
            dec.do_decrypt_inplace(piece).unwrap();
        }
    }

    data
}

/// Dispatches on key length, which is what selects the AES parameter set.
fn run_case_for_key_len(
    key_bytes: &[u8],
    iv: [u8; BLOCK_LEN],
    input: &[u8],
    encrypt: bool,
    grouping: Grouping,
) -> Vec<u8> {
    match key_bytes.len() {
        16 => run_case::<AES128Key<OFB>, 16>(key_bytes, iv, input, encrypt, grouping),
        24 => run_case::<AES192Key<OFB>, 24>(key_bytes, iv, input, encrypt, grouping),
        32 => run_case::<AES256Key<OFB>, 32>(key_bytes, iv, input, encrypt, grouping),
        other => panic!("ACVP AES vectors should only use 16, 24 or 32 byte keys, got {other}"),
    }
}

#[test]
fn acvp_aes_ofb_known_answer_tests() {
    let (Some(req), Some(rsp)) = (
        bc_test_data_json(TEST_DATA_DIR, REQUEST_FILE),
        bc_test_data_json(TEST_DATA_DIR, RESPONSE_FILE),
    ) else {
        return;
    };

    // The response file carries only the answer, against a tcId. Index it.
    let mut answers: BTreeMap<u64, Value> = BTreeMap::new();
    for group in rsp
        .get(1)
        .and_then(|s| s.get("testGroups"))
        .and_then(Value::as_array)
        .expect("response testGroups")
    {
        for test in group.get("tests").and_then(Value::as_array).expect("response tests") {
            let tc_id = test.get("tcId").and_then(Value::as_u64).expect("tcId");
            answers.insert(tc_id, test.clone());
        }
    }

    let groups = req
        .get(1)
        .and_then(|s| s.get("testGroups"))
        .and_then(Value::as_array)
        .expect("request testGroups");

    let mut checked = 0usize;
    let mut multi_block = 0usize;
    let mut skipped_mct = 0usize;
    let mut per_kind: BTreeMap<String, usize> = BTreeMap::new();

    for group in groups {
        let test_type = group.get("testType").and_then(Value::as_str).expect("testType");
        let direction = group.get("direction").and_then(Value::as_str).expect("direction");
        let encrypt = match direction {
            "encrypt" => true,
            "decrypt" => false,
            other => panic!("unexpected direction {other}"),
        };

        for test in group.get("tests").and_then(Value::as_array).expect("tests") {
            let tc_id = test.get("tcId").and_then(Value::as_u64).expect("tcId");

            if test_type == "MCT" {
                skipped_mct += 1;
                continue;
            }

            let answer = answers.get(&tc_id).unwrap_or_else(|| panic!("tcId {tc_id}: no answer"));
            if answer.get("resultsArray").is_some() {
                skipped_mct += 1;
                continue;
            }

            let key_bytes = hex_field(test, "key", tc_id);
            let iv: [u8; BLOCK_LEN] =
                hex_field(test, "iv", tc_id).try_into().expect("a 16-byte IV");

            // Input comes from the request, expected output from the response.
            let (input_field, output_field) = if encrypt { ("pt", "ct") } else { ("ct", "pt") };
            let input = hex_field(test, input_field, tc_id);
            let expected = hex_field(answer, output_field, tc_id);

            assert_eq!(input.len(), expected.len(), "tcId {tc_id}: length mismatch");
            assert_eq!(
                input.len() % BLOCK_LEN,
                0,
                "tcId {tc_id}: ACVP OFB payloads are block-aligned"
            );
            if input.len() > BLOCK_LEN {
                multi_block += 1;
            }

            for grouping in [Grouping::Single, Grouping::Whole, Grouping::Bytes] {
                let got = run_case_for_key_len(&key_bytes, iv, &input, encrypt, grouping);
                assert_eq!(
                    got,
                    expected,
                    "tcId {tc_id}: AES-{} OFB {direction}, {} blocks, {grouping:?} grouping",
                    key_bytes.len() * 8,
                    input.len() / BLOCK_LEN
                );
            }

            *per_kind.entry(format!("AES-{} {direction}", key_bytes.len() * 8)).or_default() += 1;
            checked += 1;
        }
    }

    for (kind, n) in &per_kind {
        println!("ACVP AES-OFB {kind}: {n} cases");
    }
    println!(
        "ACVP AES-OFB: {checked} AFT cases checked in three groupings each \
         ({multi_block} of them multi-block); {skipped_mct} MCT cases skipped"
    );

    // Guard against a silently-empty or partial run.
    assert!(checked > 2000, "expected the full ACVP AFT set, only checked {checked}");
    assert!(multi_block >= 50, "expected the multi-block cases, found {multi_block}");
    assert_eq!(per_kind.len(), 6, "expected all three key lengths in both directions");
}
