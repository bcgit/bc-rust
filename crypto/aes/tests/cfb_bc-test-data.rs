//! Known-answer tests against the NIST ACVP `ACVP-AES-CFB128` vectors from the `bc-test-data` repo.
//!
//! Requires `bc-test-data` to be cloned alongside this repository, i.e. at `../bc-test-data`
//! relative to the root of this git project. If it is absent the test prints a warning and passes,
//! matching the convention used by the ML-KEM, ML-DSA, `aes` and AES-CBC suites --
//! `cargo test` must stay green for someone who has only cloned this repository.
//!
//! This is the CFB128 counterpart to `cbc_bc-test-data.rs` (AES-CBC) and to
//! `ecb_bc-test-data.rs` (AES-ECB, the raw permutation). The `CFB128` file is
//! the one that matches [`Cfb`]; `ACVP-AES-CFB8` matches `Cfb8` and is read by
//! `cfb8_bc-test-data.rs`. `ACVP-AES-CFB1` is the one segment size this crate does not implement,
//! and is deliberately not read.
//!
//! # Joining the request and response files
//!
//! As with CBC, the response file carries **only the answer** (`ct` for an encrypt group, `pt` for a
//! decrypt group) against a `tcId`. The key, IV and input live in the request file, and the group
//! metadata that says which direction a case is -- `direction` and `keyLen` -- lives only there too.
//! So both files are read and joined on `tcId`.
//!
//! # Coverage
//!
//! 2138 AFT (Algorithm Functional Test) cases across all three key lengths and both directions,
//! including 54 whose payload spans 2 to 10 blocks. Every case is run **four times**: block by
//! block, in pairs with a one-block remainder for odd lengths, as one call over the whole payload,
//! and in 5-byte calls that never line up with a block. The second and third passes are what put
//! the multi-block cases through the pair and four-block paths -- which for CFB are
//! [`ElectronicCodeBook::encrypt_2blocks`] and [`ElectronicCodeBook::encrypt_4blocks`], the
//! *forward* function, even on the decrypt side -- and the fourth is what puts them through the
//! byte path with segments left open between calls. So all of that is exercised against real
//! vectors and not only against the toys in `cfb_tests.rs`. Every ACVP CFB128 payload is a whole
//! number of blocks, so the short final segment is not covered here (it is not covered by any
//! official vector); `cfb_tests.rs` pins it against the raw permutation.
//!
//! The 6 MCT (Monte Carlo Test) groups are **not** implemented: their expected output is a
//! `resultsArray` produced by a chained update rule defined in the ACVP AES specification rather
//! than in SP 800-38A, and implementing it from anything else would be guesswork. The test reports
//! how many it skipped so the gap stays visible.

use bouncycastle_aes::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_cipher::modes::Cfb;
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::hazmat::ElectronicCodeBook;
use bouncycastle_core::traits::{
    StreamCipherDecryptor, StreamCipherEncryptor, SymmetricCipherDecryptor,
    SymmetricCipherEncryptor,
};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_core_test_framework::test_data_loaders::{Value, bc_test_data_json, hex_field};
use std::collections::BTreeMap;

#[path = "common/acvp_helpers.rs"]
mod acvp_helpers;
use acvp_helpers::cipher_key;

const BLOCK_LEN: usize = 16;

const TEST_DATA_DIR: &str = "crypto/aes_tdes_vectors/AES";
const REQUEST_FILE: &str = "ACVP-AES-CFB128.4014530.req.json";
const RESPONSE_FILE: &str = "ACVP-AES-CFB128.4014530.rsp.json";

/// How to walk the bytes of one case.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Grouping {
    /// One block per call. Never forms a pair.
    Single,
    /// Two blocks per call, with a one-block remainder for odd lengths. Uses the pair path.
    Pairs,
    /// The whole payload in one call: fours, then pairs, then the remaining block. The cases
    /// of four or more blocks are the ones that reach `encrypt_4blocks`.
    Whole,
    /// Five bytes per call, so every call but the first starts mid-segment and none is a whole
    /// block: the byte path, with the unused keystream carried between calls.
    Bytes,
}

impl Grouping {
    fn chunk_len(self, payload_len: usize) -> usize {
        match self {
            Grouping::Single => BLOCK_LEN,
            Grouping::Pairs => 2 * BLOCK_LEN,
            Grouping::Whole => payload_len.max(1),
            Grouping::Bytes => 5,
        }
    }
}

/// Runs one CFB128 case in one direction, for a given permutation, under the given grouping.
///
/// Encryption is driven through `do_encrypt_init_rng` with a `FixedSeedRNG` emitting the vector's
/// IV, and the returned init data is checked against that IV before any ciphertext is compared --
/// so a change that ignored the RNG could not pass silently.
fn run_case<P, const KEY_LEN: usize>(
    key_bytes: &[u8],
    iv: [u8; BLOCK_LEN],
    input: &[u8],
    encrypt: bool,
    grouping: Grouping,
) -> Vec<u8>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    let key = cipher_key::<KEY_LEN>(key_bytes);
    let mut data = input.to_vec();
    let chunk = grouping.chunk_len(data.len());

    if encrypt {
        let (mut enc, got_iv) = Cfb::<P, Encrypting, KEY_LEN, BLOCK_LEN>::do_encrypt_init_rng(
            &key,
            &mut FixedSeedRNG::<BLOCK_LEN>::new(iv),
        )
        .expect("encrypt init");
        assert_eq!(got_iv, iv, "the pinned RNG should reproduce the vector's IV");
        for piece in data.chunks_mut(chunk) {
            enc.do_encrypt_inplace(piece).unwrap();
        }
    } else {
        let mut dec =
            Cfb::<P, Decrypting, KEY_LEN, BLOCK_LEN>::do_decrypt_init(&key, &iv).expect("dec init");
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
        16 => run_case::<AES128Internal, 16>(key_bytes, iv, input, encrypt, grouping),
        24 => run_case::<AES192Internal, 24>(key_bytes, iv, input, encrypt, grouping),
        32 => run_case::<AES256Internal, 32>(key_bytes, iv, input, encrypt, grouping),
        other => panic!("ACVP AES vectors should only use 16, 24 or 32 byte keys, got {other}"),
    }
}

#[test]
fn acvp_aes_cfb128_known_answer_tests() {
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
                "tcId {tc_id}: ACVP CFB128 payloads are block-aligned"
            );
            if input.len() > BLOCK_LEN {
                multi_block += 1;
            }

            for grouping in [Grouping::Single, Grouping::Pairs, Grouping::Whole, Grouping::Bytes] {
                let got = run_case_for_key_len(&key_bytes, iv, &input, encrypt, grouping);
                assert_eq!(
                    got,
                    expected,
                    "tcId {tc_id}: AES-{} CFB128 {direction}, {} blocks, {grouping:?} grouping",
                    key_bytes.len() * 8,
                    input.len() / BLOCK_LEN
                );
            }

            *per_kind.entry(format!("AES-{} {direction}", key_bytes.len() * 8)).or_default() += 1;
            checked += 1;
        }
    }

    for (kind, n) in &per_kind {
        println!("ACVP AES-CFB128 {kind}: {n} cases");
    }
    println!(
        "ACVP AES-CFB128: {checked} AFT cases checked in four groupings each \
         ({multi_block} of them multi-block); {skipped_mct} MCT cases skipped"
    );

    // Guard against a silently-empty or partial run.
    assert!(checked > 2000, "expected the full ACVP AFT set, only checked {checked}");
    assert!(multi_block >= 50, "expected the multi-block cases, found {multi_block}");
    assert_eq!(per_kind.len(), 6, "expected all three key lengths in both directions");
}
