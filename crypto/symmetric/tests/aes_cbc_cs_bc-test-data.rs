//! Known-answer tests against the NIST ACVP `ACVP-AES-CBC-CS1`, `-CS2` and `-CS3` vectors in the
//! `bc-test-data` repo, from both of its sets:
//!
//! * `crypto/aes_tdes_vectors/CBC/ACVP-AES-CBC-CS{1,2,3}-1.0.{req,rsp}.json` (vsId 42), whose
//!   payloads run from one block to 8192 bytes, with bit lengths among them;
//! * `crypto/aes_tdes_vectors/AES/ACVP-AES-CBC-CS{1,2,3}.401453{4,5,6}.{req,rsp}.json`, of 24- and
//!   40-byte payloads.
//!
//! As in `aes_cbc_bc-test-data.rs`, the request file holds the key, IV, input and direction and the
//! response file only the answer, so the two are joined on `tcId`. A case whose `payloadLen` (in
//! bits) is not a whole number of bytes is skipped and counted: the modes take octets, the
//! restriction the Addendum's Sec 1 allows an implementation. There are no MCT groups in these
//! files.
//!
//! Every case runs through the key's one-shots -- the drawing one, under a `FixedSeedRNG` that
//! emits the vector's IV, which is checked to come back as the init data, and the `_nonce` one --
//! and through the streaming workers in pieces of 7, 16 and 17 bytes, and of 1 byte for payloads up
//! to 1 KiB. The one-block cases, which every variant encrypts as plain CBC, are counted.
//!
//! Requires `bc-test-data` beside this repository; see
//! `bouncycastle_core_test_framework::test_data_loaders`.

use bouncycastle_core::hazmat::FixedSeedRNG;
use bouncycastle_core::symmetric_key::{
    FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};
use bouncycastle_core_test_framework::test_data_loaders::{Value, bc_test_data_json, hex_field};
use bouncycastle_symmetric::aes::{AES128Key, AES192Key, AES256Key};
use bouncycastle_symmetric::modes::{CBC_CS_FINAL_LEN, CBC_CS1, CBC_CS2, CBC_CS3};
use std::collections::BTreeMap;

#[path = "aes_common/acvp_helpers.rs"]
mod acvp_helpers;
use acvp_helpers::cipher_key;

const BLOCK_LEN: usize = 16;
const FINAL_LEN: usize = CBC_CS_FINAL_LEN;

/// The variant a file is for, which selects the key type.
#[derive(Clone, Copy, Debug)]
enum Variant {
    CS1,
    CS2,
    CS3,
}

/// The streaming piece sizes: across a block boundary, at it, and past it, and byte by byte for
/// the shorter payloads.
fn chunkings(len: usize) -> Vec<usize> {
    let mut sizes = vec![7, 16, 17];
    if len <= 1024 {
        sizes.push(1);
    }
    sizes
}

fn stream_encrypt<K, const KEY_LEN: usize>(
    key: &K,
    iv: &[u8; BLOCK_LEN],
    input: &[u8],
    chunk: usize,
) -> Vec<u8>
where
    K: SymmetricEncryptionKey<KEY_LEN, BLOCK_LEN, FINAL_LEN>,
{
    let mut enc = key.create_encryptor_nonce(iv);
    let mut out = Vec::with_capacity(input.len());
    for piece in input.chunks(chunk) {
        let mut buf = vec![0u8; enc.do_encrypt_out_len(piece.len())];
        let n = enc.do_encrypt_out(piece, &mut buf).expect("streaming encryption");
        assert_eq!(n, buf.len(), "do_encrypt_out_len must be exact");
        out.extend_from_slice(&buf);
    }
    let (last, last_len) = enc.do_encrypt_final().expect("a payload of at least one block");
    out.extend_from_slice(&last[..last_len]);
    out
}

fn stream_decrypt<K, const KEY_LEN: usize>(
    key: &K,
    iv: &[u8; BLOCK_LEN],
    input: &[u8],
    chunk: usize,
) -> Vec<u8>
where
    K: SymmetricDecryptionKey<KEY_LEN, BLOCK_LEN, FINAL_LEN>,
{
    let mut dec = key.create_decryptor(iv);
    let mut out = Vec::with_capacity(input.len());
    for piece in input.chunks(chunk) {
        let mut buf = vec![0u8; dec.do_decrypt_out_len(piece.len())];
        let n = dec.do_decrypt_out(piece, &mut buf).expect("streaming decryption");
        assert_eq!(n, buf.len(), "do_decrypt_out_len must be exact");
        out.extend_from_slice(&buf);
    }
    let mut last = [0u8; FINAL_LEN];
    let last_len = dec.do_decrypt_final_out(&mut last).expect("a payload of at least one block");
    out.extend_from_slice(&last[..last_len]);
    out
}

/// Runs one case in one direction through every API, checking that they agree, and returns the
/// output.
fn run_case<K, const KEY_LEN: usize>(
    key_bytes: &[u8],
    iv: [u8; BLOCK_LEN],
    input: &[u8],
    encrypt: bool,
) -> Vec<u8>
where
    K: FromKeyMaterial<KEY_LEN>
        + SymmetricEncryptionKey<KEY_LEN, BLOCK_LEN, FINAL_LEN>
        + SymmetricDecryptionKey<KEY_LEN, BLOCK_LEN, FINAL_LEN>,
{
    let key = K::from_key_material(&cipher_key::<KEY_LEN>(key_bytes)).expect("a valid key");
    let mut out = vec![0u8; input.len()];
    if encrypt {
        let (n, drawn) =
            key.encrypt_out(&mut FixedSeedRNG::new(iv), input, &mut out).expect("encrypt_out");
        assert_eq!(drawn, iv, "the pinned RNG should reproduce the vector's IV");
        assert_eq!(n, input.len(), "the ciphertext is as long as the plaintext");
        let mut supplied = vec![0u8; input.len()];
        key.encrypt_nonce_out(&iv, input, &mut supplied).expect("encrypt_nonce_out");
        assert_eq!(supplied, out, "encrypt_nonce_out must agree with encrypt_out");
        for chunk in chunkings(input.len()) {
            assert_eq!(
                stream_encrypt(&key, &iv, input, chunk),
                out,
                "streamed in {chunk}-byte pieces"
            );
        }
    } else {
        let n = key.decrypt_out(&iv, input, &mut out).expect("decrypt_out");
        assert_eq!(n, input.len(), "the plaintext is as long as the ciphertext");
        for chunk in chunkings(input.len()) {
            assert_eq!(
                stream_decrypt(&key, &iv, input, chunk),
                out,
                "streamed in {chunk}-byte pieces"
            );
        }
    }
    out
}

/// Dispatches on the variant and the key length, which together select the key type.
fn run(
    variant: Variant,
    key_bytes: &[u8],
    iv: [u8; BLOCK_LEN],
    input: &[u8],
    encrypt: bool,
) -> Vec<u8> {
    match (variant, key_bytes.len()) {
        (Variant::CS1, 16) => run_case::<AES128Key<CBC_CS1>, 16>(key_bytes, iv, input, encrypt),
        (Variant::CS1, 24) => run_case::<AES192Key<CBC_CS1>, 24>(key_bytes, iv, input, encrypt),
        (Variant::CS1, 32) => run_case::<AES256Key<CBC_CS1>, 32>(key_bytes, iv, input, encrypt),
        (Variant::CS2, 16) => run_case::<AES128Key<CBC_CS2>, 16>(key_bytes, iv, input, encrypt),
        (Variant::CS2, 24) => run_case::<AES192Key<CBC_CS2>, 24>(key_bytes, iv, input, encrypt),
        (Variant::CS2, 32) => run_case::<AES256Key<CBC_CS2>, 32>(key_bytes, iv, input, encrypt),
        (Variant::CS3, 16) => run_case::<AES128Key<CBC_CS3>, 16>(key_bytes, iv, input, encrypt),
        (Variant::CS3, 24) => run_case::<AES192Key<CBC_CS3>, 24>(key_bytes, iv, input, encrypt),
        (Variant::CS3, 32) => run_case::<AES256Key<CBC_CS3>, 32>(key_bytes, iv, input, encrypt),
        (_, other) => panic!("ACVP AES vectors use 16, 24 or 32 byte keys, got {other}"),
    }
}

/// The `testGroups` of an ACVP file, which is `[{acvVersion}, {vsId, .., testGroups}]`.
fn test_groups(file: &Value) -> &Vec<Value> {
    file.get(1).and_then(|s| s.get("testGroups")).and_then(Value::as_array).expect("testGroups")
}

/// What one file's run covered.
#[derive(Default, Debug)]
struct Counts {
    checked: usize,
    one_block: usize,
    multi_block: usize,
    partial_last_block: usize,
    skipped_bit_lengths: usize,
    per_kind: BTreeMap<String, usize>,
}

/// Runs every octet-length case of one request/response pair, or returns `None` if bc-test-data
/// is not there.
fn run_file(dir: &str, req_file: &str, rsp_file: &str, variant: Variant) -> Option<Counts> {
    let (Some(req), Some(rsp)) =
        (bc_test_data_json(dir, req_file), bc_test_data_json(dir, rsp_file))
    else {
        return None;
    };

    let mut answers: BTreeMap<u64, &Value> = BTreeMap::new();
    for group in test_groups(&rsp) {
        for test in group.get("tests").and_then(Value::as_array).expect("response tests") {
            answers.insert(test.get("tcId").and_then(Value::as_u64).expect("tcId"), test);
        }
    }

    let mut counts = Counts::default();
    for group in test_groups(&req) {
        assert_eq!(group.get("testType").and_then(Value::as_str), Some("AFT"), "only AFT groups");
        let encrypt = match group.get("direction").and_then(Value::as_str).expect("direction") {
            "encrypt" => true,
            "decrypt" => false,
            other => panic!("unexpected direction {other}"),
        };
        for test in group.get("tests").and_then(Value::as_array).expect("tests") {
            let tc_id = test.get("tcId").and_then(Value::as_u64).expect("tcId");
            let bits = test.get("payloadLen").and_then(Value::as_u64).expect("payloadLen");
            if bits % 8 != 0 {
                counts.skipped_bit_lengths += 1;
                continue;
            }
            let answer = answers.get(&tc_id).unwrap_or_else(|| panic!("tcId {tc_id}: no answer"));

            let key = hex_field(test, "key", tc_id);
            let iv: [u8; BLOCK_LEN] =
                hex_field(test, "iv", tc_id).try_into().expect("a 16-byte IV");
            let (input_field, output_field) = if encrypt { ("pt", "ct") } else { ("ct", "pt") };
            let input = hex_field(test, input_field, tc_id);
            let expected = hex_field(answer, output_field, tc_id);
            assert_eq!(input.len() as u64 * 8, bits, "tcId {tc_id}: payloadLen");

            let got = run(variant, &key, iv, &input, encrypt);
            assert_eq!(
                got,
                expected,
                "tcId {tc_id}: AES-{} {variant:?} {}, {} bytes",
                key.len() * 8,
                if encrypt { "encrypt" } else { "decrypt" },
                input.len()
            );

            match input.len() {
                BLOCK_LEN => counts.one_block += 1,
                n if n % BLOCK_LEN == 0 => counts.multi_block += 1,
                _ => counts.partial_last_block += 1,
            }
            *counts
                .per_kind
                .entry(format!(
                    "AES-{} {}",
                    key.len() * 8,
                    if encrypt { "encrypt" } else { "decrypt" }
                ))
                .or_default() += 1;
            counts.checked += 1;
        }
    }
    println!("{dir}/{req_file}: {counts:?}");
    Some(counts)
}

/// The vsId 42 set: every key length in both directions, one-block cases, whole-block cases and
/// partial last blocks, up to 8192 bytes. `expected` is the file's (checked, one-block,
/// whole-block, partial-last-block) counts, which guard against a silently partial run.
fn run_vsid42(variant: Variant, req_file: &str, rsp_file: &str, expected: [usize; 4]) {
    let Some(counts) = run_file("crypto/aes_tdes_vectors/CBC", req_file, rsp_file, variant) else {
        return;
    };
    assert_eq!(
        [counts.checked, counts.one_block, counts.multi_block, counts.partial_last_block],
        expected,
        "(checked, one block, whole blocks, partial last block) cases of the full set"
    );
    assert_eq!(counts.per_kind.len(), 6, "expected all three key lengths in both directions");
}

/// The second set: 24- and 40-byte payloads, every key length in both directions.
fn run_second_set(variant: Variant, req_file: &str, rsp_file: &str) {
    let Some(counts) = run_file("crypto/aes_tdes_vectors/AES", req_file, rsp_file, variant) else {
        return;
    };
    assert_eq!(counts.checked, 2228, "expected the full set");
    assert_eq!(counts.skipped_bit_lengths, 0, "the set has only octet lengths");
    assert_eq!(counts.per_kind.len(), 6, "expected all three key lengths in both directions");
}

#[test]
fn acvp_cbc_cs1_vsid42() {
    run_vsid42(
        Variant::CS1,
        "ACVP-AES-CBC-CS1-1.0.req.json",
        "ACVP-AES-CBC-CS1-1.0.rsp.json",
        [2631, 2075, 149, 407],
    );
}

#[test]
fn acvp_cbc_cs2_vsid42() {
    run_vsid42(
        Variant::CS2,
        "ACVP-AES-CBC-CS2-1.0.req.json",
        "ACVP-AES-CBC-CS2-1.0.rsp.json",
        [2379, 2072, 150, 157],
    );
}

#[test]
fn acvp_cbc_cs3_vsid42() {
    run_vsid42(
        Variant::CS3,
        "ACVP-AES-CBC-CS3-1.0.req.json",
        "ACVP-AES-CBC-CS3-1.0.rsp.json",
        [2464, 2066, 149, 249],
    );
}

#[test]
fn acvp_cbc_cs1_second_set() {
    run_second_set(
        Variant::CS1,
        "ACVP-AES-CBC-CS1.4014534.req.json",
        "ACVP-AES-CBC-CS1.4014534.rsp.json",
    );
}

#[test]
fn acvp_cbc_cs2_second_set() {
    run_second_set(
        Variant::CS2,
        "ACVP-AES-CBC-CS2.4014535.req.json",
        "ACVP-AES-CBC-CS2.4014535.rsp.json",
    );
}

#[test]
fn acvp_cbc_cs3_second_set() {
    run_second_set(
        Variant::CS3,
        "ACVP-AES-CBC-CS3.4014536.req.json",
        "ACVP-AES-CBC-CS3.4014536.rsp.json",
    );
}
