//! NIST SP 800-232 known-answer tests for the four Ascon constructions.
//!
//! Each KAT file in `tests/data/` is parsed and every case is replayed
//! against the implementation. The test fails if any computed output
//! diverges from the file's expected value.

use bouncycastle_ascon::{AsconAead128, AsconCXof128, AsconHash256, AsconXof128};
use bouncycastle_hex as hex;

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const AEAD_TAG_BYTES: usize = 16;

#[derive(Default, Debug)]
struct TestStats {
    files_seen: usize,
    files_recognized: usize,
    hash_cases: usize,
    xof_cases: usize,
    cxof_cases: usize,
    aead_cases: usize,
}

impl TestStats {
    fn total_cases(&self) -> usize {
        self.hash_cases + self.xof_cases + self.cxof_cases + self.aead_cases
    }
}

fn test_data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("data")
}

fn decode_hex(label: &str, value: &str) -> TestResult<Vec<u8>> {
    let clean = value.trim();
    if clean.is_empty() {
        Ok(Vec::new())
    } else {
        hex::decode(clean).map_err(|e| format!("invalid hex for {label}: {clean:?}: {e:?}").into())
    }
}

fn required<'a>(
    case: &'a BTreeMap<String, String>,
    file: &Path,
    count: &str,
    names: &[&str],
) -> TestResult<&'a str> {
    for name in names {
        if let Some(value) = case.get(*name) {
            return Ok(value.as_str());
        }
    }
    Err(format!(
        "missing required field {:?} in file {} Count {}. Case fields were: {:?}",
        names,
        file.display(),
        count,
        case.keys().collect::<Vec<_>>()
    )
    .into())
}

fn case_count(case: &BTreeMap<String, String>) -> &str {
    case.get("Count").map(String::as_str).unwrap_or("?")
}

fn parse_kat_file(path: &Path) -> TestResult<Vec<BTreeMap<String, String>>> {
    let text = fs::read_to_string(path)?;
    let mut cases = Vec::new();
    let mut current = BTreeMap::new();

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            if !current.is_empty() {
                cases.push(current);
                current = BTreeMap::new();
            }
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim().to_string();
            let value = value.trim().to_string();
            if key == "Count" && !current.is_empty() {
                cases.push(current);
                current = BTreeMap::new();
            }
            current.insert(key, value);
        }
    }
    if !current.is_empty() {
        cases.push(current);
    }
    Ok(cases)
}

#[test]
fn ascon_kat_vectors() -> TestResult {
    let dir = test_data_dir();
    assert!(dir.is_dir(), "test data directory not found: {}", dir.display());

    let mut stats = TestStats::default();

    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("txt") {
            continue;
        }
        stats.files_seen += 1;
        let filename = path.file_name().and_then(|s| s.to_str()).unwrap_or("");

        if filename.contains("_HASH_KAT_256") {
            stats.files_recognized += 1;
            stats.hash_cases += run_hash256_file(&path)?;
        } else if filename.contains("_XOF_KAT_128_512") {
            stats.files_recognized += 1;
            stats.xof_cases += run_xof128_file(&path)?;
        } else if filename.contains("_CXOF_KAT_128_512") {
            stats.files_recognized += 1;
            stats.cxof_cases += run_cxof128_file(&path)?;
        } else if filename.contains("_AEAD_KAT_128_128") {
            stats.files_recognized += 1;
            stats.aead_cases += run_aead128_file(&path)?;
        }
    }

    assert!(stats.files_seen > 0, "no .txt files in {}", dir.display());
    assert!(stats.files_recognized > 0, "no recognized KAT files in {}", dir.display());
    assert!(stats.total_cases() > 0, "no test cases executed: {stats:?}");
    Ok(())
}

fn run_hash256_file(path: &Path) -> TestResult<usize> {
    let cases = parse_kat_file(path)?;
    assert!(!cases.is_empty(), "no cases in {}", path.display());

    let mut executed = 0usize;
    for case in &cases {
        let count = case_count(case);
        let msg = decode_hex("Hash256 Msg", required(case, path, count, &["Msg"])?)?;
        let expected = decode_hex("Hash256 MD", required(case, path, count, &["MD"])?)?;

        let mut h = AsconHash256::new();
        h.absorb(&msg);
        let mut got = [0u8; 32];
        h.finalize(&mut got).map_err(|e| format!("Hash256 finalize: {e:?}"))?;
        assert_eq!(
            got.as_slice(),
            expected.as_slice(),
            "Ascon-Hash256 mismatch in {} Count {count}",
            path.display(),
        );
        executed += 1;
    }
    Ok(executed)
}

fn run_xof128_file(path: &Path) -> TestResult<usize> {
    let cases = parse_kat_file(path)?;
    assert!(!cases.is_empty(), "no cases in {}", path.display());

    let mut executed = 0usize;
    for case in &cases {
        let count = case_count(case);
        let msg = decode_hex("XOF128 Msg", required(case, path, count, &["Msg"])?)?;
        let expected =
            decode_hex("XOF128 Output", required(case, path, count, &["MD", "Output"])?)?;

        let mut x = AsconXof128::new();
        x.absorb_input(&msg).map_err(|e| format!("XOF absorb: {e:?}"))?;
        let mut got = vec![0u8; expected.len()];
        x.squeeze_into(&mut got);
        assert_eq!(got, expected, "Ascon-XOF128 mismatch in {} Count {count}", path.display());
        executed += 1;
    }
    Ok(executed)
}

fn run_cxof128_file(path: &Path) -> TestResult<usize> {
    let cases = parse_kat_file(path)?;
    assert!(!cases.is_empty(), "no cases in {}", path.display());

    let mut executed = 0usize;
    for case in &cases {
        let count = case_count(case);
        let msg = decode_hex("CXOF128 Msg", required(case, path, count, &["Msg"])?)?;
        let z = decode_hex("CXOF128 Z", required(case, path, count, &["Z", "Customization"])?)?;
        let expected =
            decode_hex("CXOF128 Output", required(case, path, count, &["MD", "Output"])?)?;

        let mut x = AsconCXof128::with_customization(&z);
        x.absorb_input(&msg).map_err(|e| format!("CXOF absorb: {e:?}"))?;
        let mut got = vec![0u8; expected.len()];
        x.squeeze_into(&mut got);
        assert_eq!(got, expected, "Ascon-CXOF128 mismatch in {} Count {count}", path.display());
        executed += 1;
    }
    Ok(executed)
}

fn run_aead128_file(path: &Path) -> TestResult<usize> {
    let cases = parse_kat_file(path)?;
    assert!(!cases.is_empty(), "no cases in {}", path.display());

    let mut executed = 0usize;
    for case in &cases {
        let count = case_count(case);
        let key = decode_hex("AEAD Key", required(case, path, count, &["Key", "K"])?)?;
        let nonce = decode_hex("AEAD Nonce", required(case, path, count, &["Nonce", "N"])?)?;
        let ad = decode_hex("AEAD AD", required(case, path, count, &["AD", "A"])?)?;
        let pt = decode_hex("AEAD PT", required(case, path, count, &["PT", "P"])?)?;
        let expected_ct = decode_hex("AEAD CT", required(case, path, count, &["CT", "C"])?)?;

        let key_arr: [u8; 16] = key[..]
            .try_into()
            .map_err(|_| format!("AEAD key must be 16 bytes, got {}", key.len()))?;
        let nonce_arr: [u8; 16] = nonce[..]
            .try_into()
            .map_err(|_| format!("AEAD nonce must be 16 bytes, got {}", nonce.len()))?;

        let ad_opt = if ad.is_empty() { None } else { Some(&ad[..]) };

        let mut enc = AsconAead128::new(&key_arr, &nonce_arr, ad_opt, true);
        let mut got_ct = vec![0u8; pt.len() + AEAD_TAG_BYTES];
        let n = enc.encrypt_update(&pt, &mut got_ct);
        let m = enc
            .encrypt_finalize(&mut got_ct[n..])
            .map_err(|e| format!("encrypt_finalize: {e:?}"))?;
        got_ct.truncate(n + m);
        assert_eq!(
            got_ct, expected_ct,
            "Ascon-AEAD128 encrypt mismatch in {} Count {count}",
            path.display(),
        );

        let mut dec = AsconAead128::new(&key_arr, &nonce_arr, ad_opt, false);
        let mut got_pt = vec![0u8; pt.len()];
        let n = dec
            .try_decrypt_update(&expected_ct, &mut got_pt)
            .map_err(|e| format!("decrypt_update: {e:?}"))?;
        let m = dec
            .decrypt_finalize(&mut got_pt[n..])
            .map_err(|e| format!("decrypt_finalize: {e:?}"))?;
        got_pt.truncate(n + m);
        assert_eq!(
            got_pt, pt,
            "Ascon-AEAD128 decrypt mismatch in {} Count {count}",
            path.display(),
        );

        executed += 1;
    }
    Ok(executed)
}
