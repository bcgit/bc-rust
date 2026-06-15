use bouncycastle_ascon::ascon_aead128::AsconAead128;
use bouncycastle_ascon::ascon_cxof128::AsconCXof128;
use bouncycastle_ascon::ascon_hash256::AsconHash256;
use bouncycastle_ascon::ascon_xof128::AsconXof128;
use bouncycastle_core_test_framework::aead::TestFrameworkAead;
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
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
}

fn decode_hex(label: &str, value: &str) -> TestResult<Vec<u8>> {
    let clean = value.trim();

    if clean.is_empty() {
        Ok(Vec::new())
    } else {
        hex::decode(clean)
            .map_err(|e| format!("invalid hex for {label}: {clean:?}: {e:?}").into())
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

/* -------------------------------------------------------------------------- */
/* Hardcoded smoke tests                                                       */
/* -------------------------------------------------------------------------- */

#[test]
fn test_hardcoded_ascon_hash256_vector() -> TestResult {
    let msg_hex = "000102030405060708090A0B0C0D0E0F1011121314";
    let expected_hex = "41C8F733B9D823BE30B64EE717C322C576D36781FFC5F7D6C730ECA549789725";

    let msg = decode_hex("hardcoded Hash Msg", msg_hex)?;
    let expected = decode_hex("hardcoded Hash MD", expected_hex)?;

    let mut hasher = AsconHash256::new();
    hasher.update_bytes(&msg);

    let mut got = [0u8; 32];
    hasher.do_final_into(&mut got);

    println!(
        "[hardcoded Ascon-Hash256]\n  Msg:      {msg_hex}\n  Expected: {expected_hex}\n  Got:      {}\n  Result:   {}",
        hex::encode(got).to_uppercase(),
        if got.as_slice() == expected.as_slice() { "PASS" } else { "FAIL" }
    );

    assert_eq!(got.as_slice(), expected.as_slice(), "hardcoded Ascon-Hash256 failed");
    Ok(())
}

#[test]
fn test_hardcoded_ascon_xof128_vector() -> TestResult {
    let msg_hex = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C";
    let expected_hex = "259D670887F177CE377D40FDE81304BEA72B3246CC38DB7464BC20408B450CFB";

    let msg = decode_hex("hardcoded XOF Msg", msg_hex)?;
    let expected = decode_hex("hardcoded XOF Output", expected_hex)?;

    let mut xof = AsconXof128::new();
    xof.update(&msg);

    let mut got = vec![0u8; expected.len()];
    xof.squeeze_into(&mut got);

    println!(
        "[hardcoded Ascon-XOF128]\n  Msg:      {msg_hex}\n  Expected: {expected_hex}\n  Got:      {}\n  Result:   {}",
        hex::encode(&got).to_uppercase(),
        if got == expected { "PASS" } else { "FAIL" }
    );

    assert_eq!(got, expected, "hardcoded Ascon-XOF128 failed");
    Ok(())
}

#[test]
fn test_hardcoded_ascon_aead128_vector() -> TestResult {
    let key_hex = "000102030405060708090A0B0C0D0E0F";
    let nonce_hex = "000102030405060708090A0B0C0D0E0F";
    let ad_hex = "00";
    let pt_hex = "00";
    let ct_hex = "25EB4B700ED4AC8517DCBA20F673292230";

    let key = decode_hex("hardcoded AEAD Key", key_hex)?;
    let nonce = decode_hex("hardcoded AEAD Nonce", nonce_hex)?;
    let ad = decode_hex("hardcoded AEAD AD", ad_hex)?;
    let pt = decode_hex("hardcoded AEAD PT", pt_hex)?;
    let expected_ct = decode_hex("hardcoded AEAD CT", ct_hex)?;

    let got_ct = aead_encrypt(&key, &nonce, &ad, &pt);
    println!(
        "[hardcoded Ascon-AEAD128 encrypt]\n  Key:      {key_hex}\n  Nonce:    {nonce_hex}\n  AD:       {ad_hex}\n  PT:       {pt_hex}\n  Expected: {ct_hex}\n  Got:      {}\n  Result:   {}",
        hex::encode(&got_ct).to_uppercase(),
        if got_ct == expected_ct { "PASS" } else { "FAIL" }
    );
    assert_eq!(got_ct, expected_ct, "hardcoded Ascon-AEAD128 encrypt failed");

    let got_pt = aead_decrypt(&key, &nonce, &ad, &expected_ct)?;
    println!(
        "[hardcoded Ascon-AEAD128 decrypt]\n  CT:       {ct_hex}\n  Expected: {pt_hex}\n  Got:      {}\n  Result:   {}",
        hex::encode(&got_pt).to_uppercase(),
        if got_pt == pt { "PASS" } else { "FAIL" }
    );
    assert_eq!(got_pt, pt, "hardcoded Ascon-AEAD128 decrypt failed");

    Ok(())
}

/* -------------------------------------------------------------------------- */
/* AeadCipher trait conformance (via core-test-framework)                      */
/* -------------------------------------------------------------------------- */

#[test]
fn test_aead128_trait_framework() {
    let key: [u8; 16] = *b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    let nonce: [u8; 16] = *b"\x0f\x0e\x0d\x0c\x0b\x0a\x09\x08\x07\x06\x05\x04\x03\x02\x01\x00";
    let ad = b"framework-associated-data";

    let fw = TestFrameworkAead::new();

    // Cover empty, sub-block, exact-block, and multi-block plaintexts, with and without AD.
    for pt_len in [0usize, 1, 15, 16, 17, 31, 32, 33, 64, 100] {
        let pt: Vec<u8> = (0..pt_len).map(|i| i as u8).collect();

        fw.test_aead(
            || AsconAead128::new(&key, &nonce, Some(ad), true),
            || AsconAead128::new(&key, &nonce, Some(ad), false),
            &pt,
        );

        fw.test_aead(
            || AsconAead128::new(&key, &nonce, None, true),
            || AsconAead128::new(&key, &nonce, None, false),
            &pt,
        );
    }
}

/* -------------------------------------------------------------------------- */
/* File-vector test                                                            */
/* -------------------------------------------------------------------------- */

#[test]
fn test_ascon_test_vectors_from_files() -> TestResult {
    let dir = test_data_dir();

    assert!(
        dir.is_dir(),
        "test data directory not found: {}",
        dir.display()
    );

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
            stats.hash_cases += test_hash256_file(&path)?;
        } else if filename.contains("_XOF_KAT_128_512") {
            stats.files_recognized += 1;
            stats.xof_cases += test_xof128_file(&path)?;
        } else if filename.contains("_CXOF_KAT_128_512") {
            stats.files_recognized += 1;
            stats.cxof_cases += test_cxof128_file(&path)?;
        } else if filename.contains("_AEAD_KAT_128_128") {
            stats.files_recognized += 1;
            stats.aead_cases += test_aead128_file(&path)?;
        } else {
            println!("Skipping unrecognized vector file: {}", path.display());
        }
    }

    assert!(
        stats.files_seen > 0,
        "no .txt files found in test data directory: {}",
        dir.display()
    );

    assert!(
        stats.files_recognized > 0,
        "found {} .txt files in {}, but none matched recognized ASCON KAT filename patterns",
        stats.files_seen,
        dir.display()
    );

    assert!(
        stats.total_cases() > 0,
        "recognized ASCON KAT files were found, but zero test cases were executed: {:?}",
        stats
    );

    println!(
        "\n=== ASCON file-vector summary ===\n  Data dir:          {}\n  .txt files seen:   {}\n  recognized files:  {}\n  Hash256 cases:     {}\n  XOF128 cases:      {}\n  CXOF128 cases:     {}\n  AEAD128 cases:     {}\n  Total cases:       {}\n",
        dir.display(),
        stats.files_seen,
        stats.files_recognized,
        stats.hash_cases,
        stats.xof_cases,
        stats.cxof_cases,
        stats.aead_cases,
        stats.total_cases()
    );

    Ok(())
}

fn test_hash256_file(path: &Path) -> TestResult<usize> {
    let cases = parse_kat_file(path)?;

    assert!(
        !cases.is_empty(),
        "recognized Hash256 vector file had zero parsed cases: {}",
        path.display()
    );

    println!("\n=== Ascon-Hash256: {} ===", path.display());

    let mut executed = 0usize;

    for case in &cases {
        let count = case_count(case);
        let msg_hex = required(case, path, count, &["Msg"])?;
        let md_hex = required(case, path, count, &["MD"])?;

        let msg = decode_hex("Hash256 Msg", msg_hex)?;
        let expected = decode_hex("Hash256 MD", md_hex)?;

        let mut hasher = AsconHash256::new();
        hasher.update_bytes(&msg);

        let mut got = [0u8; 32];
        hasher.do_final_into(&mut got);

        let pass = got.as_slice() == expected.as_slice();

        println!(
            "  [Count {count}]\n    Msg({}B):  {msg_hex}\n    Expected: {} \n    Got:      {}\n    Result:   {}",
            msg.len(),
            md_hex,
            hex::encode(got).to_uppercase(),
            if pass { "PASS" } else { "FAIL" }
        );

        assert_eq!(
            got.as_slice(),
            expected.as_slice(),
            "Ascon-Hash256 failed in {} Count {}",
            path.display(),
            count
        );

        executed += 1;
    }

    Ok(executed)
}

fn test_xof128_file(path: &Path) -> TestResult<usize> {
    let cases = parse_kat_file(path)?;

    assert!(
        !cases.is_empty(),
        "recognized XOF128 vector file had zero parsed cases: {}",
        path.display()
    );

    println!("\n=== Ascon-XOF128: {} ===", path.display());

    let mut executed = 0usize;

    for case in &cases {
        let count = case_count(case);
        let msg_hex = required(case, path, count, &["Msg"])?;
        let out_hex = required(case, path, count, &["MD", "Output"])?;

        let msg = decode_hex("XOF128 Msg", msg_hex)?;
        let expected = decode_hex("XOF128 Output", out_hex)?;

        let mut xof = AsconXof128::new();
        xof.update(&msg);

        let mut got = vec![0u8; expected.len()];
        xof.squeeze_into(&mut got);

        let pass = got == expected;

        println!(
            "  [Count {count}]\n    Msg({}B):  {msg_hex}\n    Expected: {}\n    Got:      {}\n    Result:   {}",
            msg.len(),
            out_hex,
            hex::encode(&got).to_uppercase(),
            if pass { "PASS" } else { "FAIL" }
        );

        assert_eq!(
            got,
            expected,
            "Ascon-XOF128 failed in {} Count {}",
            path.display(),
            count
        );

        executed += 1;
    }

    Ok(executed)
}

fn test_cxof128_file(path: &Path) -> TestResult<usize> {
    let cases = parse_kat_file(path)?;

    assert!(
        !cases.is_empty(),
        "recognized CXOF128 vector file had zero parsed cases: {}",
        path.display()
    );

    println!("\n=== Ascon-CXOF128: {} ===", path.display());

    let mut executed = 0usize;

    for case in &cases {
        let count = case_count(case);
        let msg_hex = required(case, path, count, &["Msg"])?;
        let z_hex = required(case, path, count, &["Z", "Customization"])?;
        let out_hex = required(case, path, count, &["MD", "Output"])?;

        let msg = decode_hex("CXOF128 Msg", msg_hex)?;
        let z = decode_hex("CXOF128 Z", z_hex)?;
        let expected = decode_hex("CXOF128 Output", out_hex)?;

        let mut cxof = AsconCXof128::with_customization(&z);
        cxof.update(&msg);

        let mut got = vec![0u8; expected.len()];
        cxof.squeeze_into(&mut got);

        let pass = got == expected;

        println!(
            "  [Count {count}]\n    Z({}B):    {z_hex}\n    Msg({}B):  {msg_hex}\n    Expected: {}\n    Got:      {}\n    Result:   {}",
            z.len(),
            msg.len(),
            out_hex,
            hex::encode(&got).to_uppercase(),
            if pass { "PASS" } else { "FAIL" }
        );

        assert_eq!(
            got,
            expected,
            "Ascon-CXOF128 failed in {} Count {}",
            path.display(),
            count
        );

        executed += 1;
    }

    Ok(executed)
}

fn test_aead128_file(path: &Path) -> TestResult<usize> {
    let cases = parse_kat_file(path)?;

    assert!(
        !cases.is_empty(),
        "recognized AEAD128 vector file had zero parsed cases: {}",
        path.display()
    );

    println!("\n=== Ascon-AEAD128: {} ===", path.display());

    let mut executed = 0usize;

    for case in &cases {
        let count = case_count(case);
        let key_hex = required(case, path, count, &["Key", "K"])?;
        let nonce_hex = required(case, path, count, &["Nonce", "N"])?;
        let ad_hex = required(case, path, count, &["AD", "A"])?;
        let pt_hex = required(case, path, count, &["PT", "P"])?;
        let ct_hex = required(case, path, count, &["CT", "C"])?;

        let key = decode_hex("AEAD128 Key", key_hex)?;
        let nonce = decode_hex("AEAD128 Nonce", nonce_hex)?;
        let ad = decode_hex("AEAD128 AD", ad_hex)?;
        let pt = decode_hex("AEAD128 PT", pt_hex)?;
        let expected_ct = decode_hex("AEAD128 CT", ct_hex)?;

        let got_ct = aead_encrypt(&key, &nonce, &ad, &pt);
        let enc_pass = got_ct == expected_ct;

        println!(
            "  [Count {count}]\n    Key:      {key_hex}\n    Nonce:    {nonce_hex}\n    AD({}B):  {ad_hex}\n    PT({}B):  {pt_hex}",
            ad.len(),
            pt.len()
        );
        println!(
            "    Encrypt expected: {}\n    Encrypt got:      {}\n    Encrypt result:   {}",
            ct_hex,
            hex::encode(&got_ct).to_uppercase(),
            if enc_pass { "PASS" } else { "FAIL" }
        );

        assert_eq!(
            got_ct,
            expected_ct,
            "Ascon-AEAD128 encryption failed in {} Count {}",
            path.display(),
            count
        );

        let got_pt = aead_decrypt(&key, &nonce, &ad, &expected_ct)?;
        let dec_pass = got_pt == pt;

        println!(
            "    Decrypt expected: {}\n    Decrypt got:      {}\n    Decrypt result:   {}",
            pt_hex,
            hex::encode(&got_pt).to_uppercase(),
            if dec_pass { "PASS" } else { "FAIL" }
        );

        assert_eq!(
            got_pt,
            pt,
            "Ascon-AEAD128 decryption failed in {} Count {}",
            path.display(),
            count
        );

        executed += 1;
    }

    Ok(executed)
}

/* -------------------------------------------------------------------------- */
/* Thin adapters over the actual crate implementation                           */
/* -------------------------------------------------------------------------- */

fn aead_encrypt(key: &[u8], nonce: &[u8], ad: &[u8], pt: &[u8]) -> Vec<u8> {
    let key: &[u8; 16] = key.try_into().expect("AEAD key must be 16 bytes");
    let nonce: &[u8; 16] = nonce.try_into().expect("AEAD nonce must be 16 bytes");
    let mut enc = AsconAead128::new(
        key,
        nonce,
        if ad.is_empty() { None } else { Some(ad) },
        true,
    );

    let mut out = vec![0u8; pt.len() + AEAD_TAG_BYTES];
    let update_len = enc.encrypt_update(pt, &mut out);
    let final_len = enc.encrypt_finalize(&mut out[update_len..]);
    out.truncate(update_len + final_len);
    out
}

fn aead_decrypt(key: &[u8], nonce: &[u8], ad: &[u8], ct: &[u8]) -> TestResult<Vec<u8>> {
    assert!(
        ct.len() >= AEAD_TAG_BYTES,
        "AEAD ciphertext+tag is shorter than tag length: {} bytes",
        ct.len()
    );

    let key: &[u8; 16] = key.try_into().expect("AEAD key must be 16 bytes");
    let nonce: &[u8; 16] = nonce.try_into().expect("AEAD nonce must be 16 bytes");
    let mut dec = AsconAead128::new(
        key,
        nonce,
        if ad.is_empty() { None } else { Some(ad) },
        false,
    );

    let plaintext_len = ct.len() - AEAD_TAG_BYTES;
    let mut out = vec![0u8; plaintext_len];

    let update_len = dec.decrypt_update(ct, &mut out);
    let final_len = dec
        .decrypt_finalize(&mut out[update_len..])
        .map_err(|e| format!("AEAD decrypt authentication/finalize failed: {e:?}"))?;

    out.truncate(update_len + final_len);
    Ok(out)
}