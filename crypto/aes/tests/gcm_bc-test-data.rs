//! Known-answer tests against the NIST ACVP and CAVP AES-GCM vectors from the `bc-test-data` repo.
//!
//! Requires `bc-test-data` to be cloned alongside this repository, i.e. at `../bc-test-data`
//! relative to the root of this git project. If it is absent the test prints a warning and passes,
//! matching the convention used by the other ACVP suites in this crate.
//!
//! # ACVP
//!
//! The set (`ACVP-AES-GCM.4014542`) covers all three AES key lengths, a 96-bit IV throughout,
//! 96- and 128-bit tags, payload lengths of 64/128/192 bits and AAD lengths of 128/256 bits, in
//! both directions -- 270 cases total. Not every decrypt case in this particular set is a
//! forgery, but the ones that are all report `testPassed: false`; the valid-decrypt path is
//! additionally exercised by round-tripping every encrypt case through both the detached one-shot
//! and the inline `SymmetricCipherDecryptor` streaming view (`acvp_gcm_helpers::run_decrypt_case`).
//!
//! # CAVP
//!
//! The six `GCM/cavp/` files (`gcmEncryptExtIV{128,192,256}.rsp`, `gcmDecrypt{128,192,256}.rsp`)
//! have 7875 cases each: IVs of 8, 96 and 1024 bits, tags of 32 to 128 bits, and payload and AAD
//! lengths that include empty inputs and partial blocks. `Gcm` fixes the nonce at 96 bits and
//! accepts tags of 96 to 128 bits, so 1875 cases per file can run; the rest are counted as not
//! supported and both counts asserted, so a change in the files' shape is visible. In the decrypt
//! files a record with `FAIL` in place of `PT` is a forgery, which must be rejected.
//!
//! The Wycheproof `aes_gcm_test.json` set, which `bc-test-data` also carries, is run by
//! `gcm_wycheproof.rs`.

// Not `mod common;`: this crate-private helper's `serde_json::Value` usage, if pulled into the
// shared `common` module that most other test binaries in this crate include via `mod common;`,
// makes `u8: PartialEq<_>` ambiguous (`core`'s impl vs. serde_json's `impl PartialEq<Value> for
// u8`) at every bare `assert_eq!(byte_array, [])` in *those* files too -- `ecb_tests.rs` hit this
// exactly. Giving it its own module path keeps that ambiguity local to the two files that actually
// need ACVP JSON parsing.
#[path = "common/acvp_gcm_helpers.rs"]
mod acvp_gcm_helpers;

use acvp_gcm_helpers::{GCM_NONCE_LEN, decode, run_decrypt_case, run_encrypt_case};
use bouncycastle_core_test_framework::test_data_loaders::bc_test_data;
use bouncycastle_hex as hex;
use serde_json::Value;
use std::collections::BTreeMap;

const TEST_DATA_DIR: &str = "crypto/aes_tdes_vectors/GCM";
const REQUEST_FILE: &str = "ACVP-AES-GCM.4014542.req.json";
const RESPONSE_FILE: &str = "ACVP-AES-GCM.4014542.rsp.json";

#[test]
fn acvp_aes_gcm_known_answer_tests() {
    let (Some(req), Some(rsp)) =
        (bc_test_data(TEST_DATA_DIR, REQUEST_FILE), bc_test_data(TEST_DATA_DIR, RESPONSE_FILE))
    else {
        return;
    };
    let req: Value = serde_json::from_str(&req).expect("valid ACVP request JSON");
    let rsp: Value = serde_json::from_str(&rsp).expect("valid ACVP response JSON");

    // The response file carries only the answer, against a tcId. Index it.
    let mut answers: BTreeMap<u64, Value> = BTreeMap::new();
    for group in rsp[1]["testGroups"].as_array().expect("response testGroups") {
        for test in group["tests"].as_array().expect("response tests") {
            let tc_id = test["tcId"].as_u64().expect("tcId");
            answers.insert(tc_id, test.clone());
        }
    }

    let groups = req[1]["testGroups"].as_array().expect("request testGroups");

    let mut checked = 0usize;
    let mut encrypt_checked = 0usize;
    let mut decrypt_failed_checked = 0usize;
    let mut per_kind: BTreeMap<String, usize> = BTreeMap::new();

    for group in groups {
        let direction = group["direction"].as_str().expect("direction");
        let tag_len = (group["tagLen"].as_u64().expect("tagLen") / 8) as usize;
        let iv_len = group["ivLen"].as_u64().expect("ivLen");
        assert_eq!(iv_len, 96, "every group in this set has a 96-bit IV");

        for test in group["tests"].as_array().expect("tests") {
            let tc_id = test["tcId"].as_u64().expect("tcId");
            let key_bytes = decode(test, "key", tc_id);
            let aad = decode(test, "aad", tc_id);
            let iv_bytes = decode(test, "iv", tc_id);
            let iv: [u8; GCM_NONCE_LEN] = iv_bytes
                .try_into()
                .unwrap_or_else(|_| panic!("tcId {tc_id}: expected a 12-byte IV"));

            match direction {
                "encrypt" => {
                    let pt = decode(test, "pt", tc_id);
                    let answer =
                        answers.get(&tc_id).unwrap_or_else(|| panic!("tcId {tc_id}: no answer"));
                    let ct = decode(answer, "ct", tc_id);
                    let tag = decode(answer, "tag", tc_id);
                    run_encrypt_case(&key_bytes, iv, &aad, &pt, tag_len, &ct, &tag);

                    // Also round-trip this known-good ciphertext through decryption, adding the
                    // encrypt groups' inputs to the valid-decrypt coverage that the non-forged
                    // decrypt cases (below) give.
                    run_decrypt_case(&key_bytes, iv, &aad, &ct, &tag, Some(&pt));
                    encrypt_checked += 1;
                }
                "decrypt" => {
                    let ct = decode(test, "ct", tc_id);
                    let tag = decode(test, "tag", tc_id);
                    let answer =
                        answers.get(&tc_id).unwrap_or_else(|| panic!("tcId {tc_id}: no answer"));
                    // A forgery reports `testPassed: false` and no plaintext; a valid case reports
                    // `pt` directly, with no `testPassed` field at all (ACVP's convention: the key
                    // is present only to report failure).
                    if answer.get("testPassed").and_then(Value::as_bool) == Some(false) {
                        run_decrypt_case(&key_bytes, iv, &aad, &ct, &tag, None);
                        decrypt_failed_checked += 1;
                    } else {
                        let pt = decode(answer, "pt", tc_id);
                        run_decrypt_case(&key_bytes, iv, &aad, &ct, &tag, Some(&pt));
                    }
                }
                other => panic!("unexpected direction {other}"),
            }

            *per_kind.entry(format!("AES-{} {direction}", key_bytes.len() * 8)).or_default() += 1;
            checked += 1;
        }
    }

    for (kind, n) in &per_kind {
        println!("ACVP AES-GCM {kind}: {n} cases");
    }
    println!(
        "ACVP AES-GCM: {checked} cases checked ({encrypt_checked} encrypt, also round-tripped \
         through decrypt; {decrypt_failed_checked} decrypt forgeries)"
    );

    assert_eq!(checked, 270, "expected all 270 ACVP AES-GCM cases to run");
    assert!(encrypt_checked > 0 && decrypt_failed_checked > 0, "expected both directions covered");
}

// ---------------------------------------------------------------------------------------------
// NIST CAVP (`GCM/cavp/`)
// ---------------------------------------------------------------------------------------------

const CAVP_DIR: &str = "crypto/aes_tdes_vectors/GCM/cavp";
const CAVP_CASES_PER_FILE: usize = 7875;
/// The 96-bit-IV sections with a tag of 96 bits or more: 5 tag lengths x 5 payload lengths x 5 AAD
/// lengths x 75 cases.
const CAVP_RUNNABLE_PER_FILE: usize = 1875;

/// One `Count` record of a CAVP GCM `.rsp` file, with its section's `[IVlen]` and `[Taglen]`.
struct CavpCase {
    iv_bits: usize,
    tag_bits: usize,
    key: Vec<u8>,
    iv: Vec<u8>,
    aad: Vec<u8>,
    ct: Vec<u8>,
    tag: Vec<u8>,
    /// `None` for a decrypt record marked `FAIL`.
    pt: Option<Vec<u8>>,
}

/// Parses a CAVP GCM `.rsp` file: blank-line-separated blocks of `[Name = bits]` section headers
/// and `Count = ` records of `Key`/`IV`/`PT`/`AAD`/`CT`/`Tag`, where a decrypt record has `FAIL`
/// in place of `PT`.
fn parse_cavp_file(content: &str) -> Vec<CavpCase> {
    let content = content.replace('\r', "");
    let (mut iv_bits, mut tag_bits) = (None, None);
    let mut cases = Vec::new();
    for block in content.split("\n\n") {
        let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
        let mut fail = false;
        for line in block.lines().map(str::trim) {
            if line.starts_with('#') {
                continue;
            } else if let Some(header) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                let (k, v) = header.split_once(" = ").expect("a [Name = value] header");
                let v: usize = v.parse().expect("a header value in bits");
                match k {
                    "IVlen" => iv_bits = Some(v),
                    "Taglen" => tag_bits = Some(v),
                    _ => {}
                }
            } else if line == "FAIL" {
                fail = true;
            } else if let Some((k, v)) = line.split_once(" =") {
                fields.insert(k, v.trim());
            }
        }
        let Some(count) = fields.get("Count") else { continue };
        let field = |k: &str| {
            let v = fields.get(k).unwrap_or_else(|| panic!("Count = {count}: no {k}"));
            hex::decode(v).unwrap_or_else(|e| panic!("Count = {count}: {k} is not hex: {e:?}"))
        };
        assert!(!(fail && fields.contains_key("PT")), "Count = {count}: both PT and FAIL");
        cases.push(CavpCase {
            iv_bits: iv_bits.expect("a record before [IVlen]"),
            tag_bits: tag_bits.expect("a record before [Taglen]"),
            key: field("Key"),
            iv: field("IV"),
            aad: field("AAD"),
            ct: field("CT"),
            tag: field("Tag"),
            pt: if fail { None } else { Some(field("PT")) },
        });
    }
    cases
}

/// Runs every case in one CAVP file that `Gcm` can express, and counts the rest as not supported.
fn run_cavp_file(filename: &str) {
    let Some(content) = bc_test_data(CAVP_DIR, filename) else { return };
    let cases = parse_cavp_file(&content);
    let encrypt = filename.starts_with("gcmEncrypt");

    let (mut checked, mut forgeries, mut unsupported) = (0usize, 0usize, 0usize);
    for c in &cases {
        // `Gcm` fixes the nonce at 96 bits and takes 96- to 128-bit tags.
        if c.iv_bits != 96 || c.tag_bits < 96 {
            unsupported += 1;
            continue;
        }
        assert_eq!(c.tag.len() * 8, c.tag_bits, "{filename}: Tag length vs [Taglen]");
        let iv: [u8; GCM_NONCE_LEN] = c.iv.as_slice().try_into().expect("a 96-bit IV");
        if encrypt {
            let pt = c.pt.as_deref().expect("encrypt records carry PT");
            run_encrypt_case(&c.key, iv, &c.aad, pt, c.tag.len(), &c.ct, &c.tag);
        } else {
            forgeries += usize::from(c.pt.is_none());
            run_decrypt_case(&c.key, iv, &c.aad, &c.ct, &c.tag, c.pt.as_deref());
        }
        checked += 1;
    }

    println!(
        "CAVP {filename}: {checked} cases checked ({forgeries} forgeries), \
         {unsupported} not supported"
    );
    assert_eq!(cases.len(), CAVP_CASES_PER_FILE, "{filename}: cases in the file");
    assert_eq!(checked, CAVP_RUNNABLE_PER_FILE, "{filename}: cases Gcm can run");
    if !encrypt {
        assert!(
            0 < forgeries && forgeries < checked,
            "{filename}: expected valid and forged cases"
        );
    }
}

#[test]
fn cavp_aes_gcm_encrypt_128() {
    run_cavp_file("gcmEncryptExtIV128.rsp");
}

#[test]
fn cavp_aes_gcm_encrypt_192() {
    run_cavp_file("gcmEncryptExtIV192.rsp");
}

#[test]
fn cavp_aes_gcm_encrypt_256() {
    run_cavp_file("gcmEncryptExtIV256.rsp");
}

#[test]
fn cavp_aes_gcm_decrypt_128() {
    run_cavp_file("gcmDecrypt128.rsp");
}

#[test]
fn cavp_aes_gcm_decrypt_192() {
    run_cavp_file("gcmDecrypt192.rsp");
}

#[test]
fn cavp_aes_gcm_decrypt_256() {
    run_cavp_file("gcmDecrypt256.rsp");
}
