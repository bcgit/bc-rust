//! Test against the bc-test-data repo.
//! Requires that the bc-test-data repository is cloned and available for testing at
//! "../bc-test-data" relative to the root of this git project (or "../../../bc-test-data" relative
//! to this crate). When the repo is absent these tests print a warning and are skipped.
//!
//! The NIST SP 800-232 ASCON known-answer test (KAT) vectors live under
//! `bc-test-data/crypto/ascon/<variant>/`. These full sweeps (1025–1089 cases each) complement the
//! small embedded vector sets in the per-primitive test files.

#![allow(dead_code)]

#[cfg(test)]
mod bc_test_data {
    use bouncycastle_ascon::ascon_aead128::AsconAead128;
    use bouncycastle_ascon::ascon_cxof128::AsconCXof128;
    use bouncycastle_ascon::ascon_hash256::AsconHash256;
    use bouncycastle_ascon::ascon_xof128::AsconXof128;
    use bouncycastle_core::traits::XOF;
    use bouncycastle_hex as hex;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::Path;
    use std::sync::Once;

    const TEST_DATA_PATH_RELATIVE: &str = "../../../bc-test-data/crypto/ascon";
    const TEST_DATA_PATH: &str = "../bc-test-data/crypto/ascon";

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
            1 => println!("bc-test-data found at: {:?}", TEST_DATA_PATH_RELATIVE),
            2 => println!("bc-test-data found at: {:?}", TEST_DATA_PATH),
            _ => println!("WARNING: bc-test-data directory not found; tests will be skipped"),
        });

        let contents = if Path::new(TEST_DATA_PATH_RELATIVE).exists() {
            fs::read_to_string(TEST_DATA_PATH_RELATIVE.to_string() + "/" + filename).unwrap()
        } else if Path::new(TEST_DATA_PATH).exists() {
            fs::read_to_string(TEST_DATA_PATH.to_string() + "/" + filename).unwrap()
        } else {
            return Err(());
        };

        Ok(contents)
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        let clean = value.trim();
        if clean.is_empty() { Vec::new() } else { hex::decode(clean).expect("valid hex") }
    }

    /// Parse a NIST LWC KAT file: blank-line-delimited `Tag = Value` cases.
    fn parse_kat(contents: &str) -> Vec<BTreeMap<String, String>> {
        let mut cases = Vec::new();
        let mut current = BTreeMap::new();

        for raw in contents.lines() {
            let line = raw.trim();
            if line.is_empty() {
                if !current.is_empty() {
                    cases.push(std::mem::take(&mut current));
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
                    cases.push(std::mem::take(&mut current));
                }
                current.insert(key, value);
            }
        }
        if !current.is_empty() {
            cases.push(current);
        }
        cases
    }

    fn field<'a>(case: &'a BTreeMap<String, String>, names: &[&str]) -> &'a str {
        for name in names {
            if let Some(v) = case.get(*name) {
                return v.as_str();
            }
        }
        panic!("missing field {names:?}; case had {:?}", case.keys().collect::<Vec<_>>());
    }

    fn to_16(bytes: &[u8], what: &str) -> [u8; 16] {
        bytes.try_into().unwrap_or_else(|_| panic!("{what} must be 16 bytes, got {}", bytes.len()))
    }

    #[test]
    fn ascon_aead128_kat() {
        let contents = match get_test_data("asconaead128/LWC_AEAD_KAT_128_128.txt") {
            Ok(c) => c,
            Err(()) => return,
        };
        let cases = parse_kat(&contents);
        assert!(!cases.is_empty(), "no AEAD cases parsed");

        for case in &cases {
            let key = to_16(&decode_hex(field(case, &["Key", "K"])), "key");
            let nonce = to_16(&decode_hex(field(case, &["Nonce", "N"])), "nonce");
            let ad = decode_hex(field(case, &["AD", "A"]));
            let pt = decode_hex(field(case, &["PT", "P"]));
            let expected_ct = decode_hex(field(case, &["CT", "C"]));
            let ad_opt = if ad.is_empty() { None } else { Some(ad.as_slice()) };

            // Encrypt.
            let mut ct = vec![0u8; pt.len() + 16];
            let n = AsconAead128::encrypt(&key, &nonce, ad_opt, &pt, &mut ct);
            ct.truncate(n);
            assert_eq!(ct, expected_ct, "encrypt mismatch (Count {})", field(case, &["Count"]));

            // Decrypt round-trip.
            let mut pt_out = vec![0u8; expected_ct.len()];
            let m = AsconAead128::decrypt(&key, &nonce, ad_opt, &expected_ct, &mut pt_out)
                .expect("decrypt should authenticate");
            pt_out.truncate(m);
            assert_eq!(pt_out, pt, "decrypt mismatch (Count {})", field(case, &["Count"]));
        }
        println!("Ascon-AEAD128: {} KAT cases passed", cases.len());
    }

    #[test]
    fn ascon_hash256_kat() {
        let contents = match get_test_data("asconhash256/LWC_HASH_KAT_256.txt") {
            Ok(c) => c,
            Err(()) => return,
        };
        let cases = parse_kat(&contents);
        assert!(!cases.is_empty(), "no Hash256 cases parsed");

        for case in &cases {
            let msg = decode_hex(field(case, &["Msg"]));
            let expected = decode_hex(field(case, &["MD"]));
            assert_eq!(
                AsconHash256::digest(&msg).as_slice(),
                expected.as_slice(),
                "Hash256 mismatch (Count {})",
                field(case, &["Count"])
            );
        }
        println!("Ascon-Hash256: {} KAT cases passed", cases.len());
    }

    #[test]
    fn ascon_xof128_kat() {
        let contents = match get_test_data("asconxof128/LWC_XOF_KAT_128_512.txt") {
            Ok(c) => c,
            Err(()) => return,
        };
        let cases = parse_kat(&contents);
        assert!(!cases.is_empty(), "no XOF128 cases parsed");

        for case in &cases {
            let msg = decode_hex(field(case, &["Msg"]));
            let expected = decode_hex(field(case, &["MD", "Output"]));
            let got = AsconXof128::new().hash_xof(&msg, expected.len());
            assert_eq!(got, expected, "XOF128 mismatch (Count {})", field(case, &["Count"]));
        }
        println!("Ascon-XOF128: {} KAT cases passed", cases.len());
    }

    #[test]
    fn ascon_cxof128_kat() {
        let contents = match get_test_data("asconcxof128/LWC_CXOF_KAT_128_512.txt") {
            Ok(c) => c,
            Err(()) => return,
        };
        let cases = parse_kat(&contents);
        assert!(!cases.is_empty(), "no CXOF128 cases parsed");

        for case in &cases {
            let msg = decode_hex(field(case, &["Msg"]));
            let z = decode_hex(field(case, &["Z", "Customization"]));
            let expected = decode_hex(field(case, &["MD", "Output"]));
            let got = AsconCXof128::with_customization(&z).hash_xof(&msg, expected.len());
            assert_eq!(got, expected, "CXOF128 mismatch (Count {})", field(case, &["Count"]));
        }
        println!("Ascon-CXOF128: {} KAT cases passed", cases.len());
    }
}
