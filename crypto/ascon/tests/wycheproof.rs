//! Test against the project wycheproof repo available at:
//!     https://github.com/C2SP/wycheproof
//! Requires that the wycheproof repository is cloned and available for testing at "../wycheproof"
//! relative to the root of this git project. When absent, these tests print a warning and skip.
//!
//! IMPORTANT — algorithm compatibility:
//! As of writing, wycheproof only ships the *pre-standardization CAESAR* Ascon AEAD vectors
//! (`ascon128_test.json`, `ascon128a_test.json`, `ascon80pq_test.json`). NIST SP 800-232
//! `Ascon-AEAD128` is a DIFFERENT algorithm: §1 of the standard switched the endianness from
//! big-endian to little-endian and changed the initial-value format. The CAESAR vectors therefore
//! do NOT validate this crate's `Ascon-AEAD128` and are intentionally not run here.
//!
//! This file is a ready-to-activate harness: it looks for a NIST-compatible Ascon-AEAD128 wycheproof
//! file (`ascon_aead128_test.json`). That file does not exist in wycheproof today, so the test
//! skips. If/when C2SP publishes NIST SP 800-232 vectors under that name, this test runs them with
//! no further changes.

#![allow(dead_code)]

#[cfg(test)]
mod wycheproof {
    use bouncycastle_ascon::ascon_aead128::AsconAead128;
    use bouncycastle_hex as hex;
    use std::fs;
    use std::path::Path;
    use std::sync::Once;

    const TEST_DATA_PATH_RELATIVE: &str = "../../../wycheproof/testvectors_v1";
    const TEST_DATA_PATH: &str = "../wycheproof/testvectors_v1";

    static TEST_DATA_CHECK: Once = Once::new();

    fn get_test_data(filename: &str) -> Result<String, ()> {
        let found: u8;
        if Path::new(TEST_DATA_PATH_RELATIVE).exists() {
            found = 1;
        } else if Path::new(TEST_DATA_PATH).exists() {
            found = 2;
        } else {
            found = 3;
        };

        // just print once
        TEST_DATA_CHECK.call_once(|| match found {
            1 => println!("wycheproof found at: {:?}", TEST_DATA_PATH_RELATIVE),
            2 => println!("wycheproof found at: {:?}", TEST_DATA_PATH),
            _ => println!("WARNING: wycheproof directory not found; tests will be skipped"),
        });

        // The requested file (a NIST-compatible Ascon-AEAD128 set) may not exist even when the repo
        // is present; treat that as a skip rather than a failure.
        let base = if Path::new(TEST_DATA_PATH_RELATIVE).exists() {
            TEST_DATA_PATH_RELATIVE
        } else if Path::new(TEST_DATA_PATH).exists() {
            TEST_DATA_PATH
        } else {
            return Err(());
        };

        match fs::read_to_string(base.to_string() + "/" + filename) {
            Ok(contents) => Ok(contents),
            Err(_) => {
                println!(
                    "WARNING: {filename} not found in wycheproof; test skipped \
                     (no NIST-compatible Ascon-AEAD128 vectors available)"
                );
                Err(())
            }
        }
    }

    fn dh(s: &str) -> Vec<u8> {
        if s.is_empty() { Vec::new() } else { hex::decode(s).expect("valid hex") }
    }

    fn to_16(bytes: &[u8], what: &str) -> [u8; 16] {
        bytes.try_into().unwrap_or_else(|_| panic!("{what} must be 16 bytes, got {}", bytes.len()))
    }

    /// Run an Aead wycheproof file (schema `aead_test_schema_v1`) against Ascon-AEAD128.
    /// Fields per test: `key`, `iv` (nonce), `aad`, `msg`, `ct`, `tag`, `result` (valid|invalid).
    /// For our API the authenticated ciphertext is `ct || tag`.
    fn run_aead_file(contents: &str) -> usize {
        let json: serde_json::Value =
            serde_json::from_str(contents).expect("test data is not valid JSON");
        let groups = json["testGroups"].as_array().expect("testGroups is not an array");

        let mut executed = 0usize;
        for group in groups {
            let tests = group["tests"].as_array().expect("tests is not an array");
            for test in tests {
                let tc_id = test["tcId"].as_u64().unwrap_or(0);
                let key = to_16(&dh(test["key"].as_str().unwrap_or("")), "key");
                let nonce = to_16(&dh(test["iv"].as_str().unwrap_or("")), "iv");
                let aad = dh(test["aad"].as_str().unwrap_or(""));
                let msg = dh(test["msg"].as_str().unwrap_or(""));
                let ct = dh(test["ct"].as_str().unwrap_or(""));
                let tag = dh(test["tag"].as_str().unwrap_or(""));
                let result = test["result"].as_str().unwrap_or("");
                let aad_opt = if aad.is_empty() { None } else { Some(aad.as_slice()) };

                let mut authenticated = ct.clone();
                authenticated.extend_from_slice(&tag);

                let mut pt_out = vec![0u8; authenticated.len()];
                let dec = AsconAead128::decrypt(&key, &nonce, aad_opt, &authenticated, &mut pt_out);

                match result {
                    "valid" => {
                        let m = dec.unwrap_or_else(|e| {
                            panic!("tcId {tc_id}: valid vector failed to authenticate: {e:?}")
                        });
                        pt_out.truncate(m);
                        assert_eq!(pt_out, msg, "tcId {tc_id}: decrypted plaintext mismatch");

                        // Encryption direction must reproduce ct || tag.
                        let mut enc_out = vec![0u8; msg.len() + 16];
                        let n = AsconAead128::encrypt(&key, &nonce, aad_opt, &msg, &mut enc_out);
                        enc_out.truncate(n);
                        assert_eq!(enc_out, authenticated, "tcId {tc_id}: ciphertext mismatch");
                    }
                    "invalid" => {
                        assert!(dec.is_err(), "tcId {tc_id}: invalid vector authenticated");
                    }
                    other => panic!("tcId {tc_id}: unexpected result {other:?}"),
                }
                executed += 1;
            }
        }
        executed
    }

    #[test]
    fn ascon_aead128_wycheproof() {
        // NIST-compatible Ascon-AEAD128 vectors (not present in wycheproof today -> skip).
        let contents = match get_test_data("ascon_aead128_test.json") {
            Ok(c) => c,
            Err(()) => return,
        };
        let n = run_aead_file(&contents);
        println!("Ascon-AEAD128 wycheproof: {n} cases passed");
    }
}
