//! Test against the bc-test-data repo.
//! Requires that the bc-test-data repository is cloned and available for testing at
//! "../bc-test-data" relative to the root of this git project (or "../../../bc-test-data" relative
//! to this crate). When the repo is absent these tests print a warning and are skipped.
//!
//! `bc-test-data/crypto/Blake2KAT.txt` holds records of five lines: `<alg>`, `<input hex>`,
//! `<key hex, may be empty>`, `<digest hex>`, `#`. The blake2b and blake2s records (512 of each:
//! input lengths 0..=255, unkeyed and keyed) are checked here; the blake2bp, blake2sp, blake2xb and
//! blake2xs records are variants this crate does not implement and are skipped.

#[cfg(test)]
mod bc_test_data {
    use bouncycastle_blake2::{BLAKE2b_512, BLAKE2b_512_MACKey, BLAKE2s_256, BLAKE2s_256_MACKey};
    use bouncycastle_core::key_material::{KeyMaterial, KeyType};
    use bouncycastle_core::symmetric_key::{
        FromAnyKeyMaterial, MacGenerationKey, MacVerificationKey,
    };
    use bouncycastle_core::traits::{Hash, MAC};
    use bouncycastle_hex as hex;
    use std::fs;
    use std::path::Path;
    use std::sync::Once;

    const TEST_DATA_PATH_RELATIVE: &str = "../../../bc-test-data/crypto";
    const TEST_DATA_PATH: &str = "../bc-test-data/crypto";

    static TEST_DATA_CHECK: Once = Once::new();

    fn get_test_data(filename: &str) -> Result<String, ()> {
        let found: u8 = if Path::new(TEST_DATA_PATH_RELATIVE).exists() {
            1
        } else if Path::new(TEST_DATA_PATH).exists() {
            2
        } else {
            3
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

    /// One Blake2KAT.txt record.
    struct Record {
        alg: String,
        input: Vec<u8>,
        key: Vec<u8>,
        digest: Vec<u8>,
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        let clean = value.trim();
        if clean.is_empty() { Vec::new() } else { hex::decode(clean).expect("valid hex") }
    }

    /// Parses the five-line records; panics on a malformed file rather than skipping records.
    fn parse(contents: &str) -> Vec<Record> {
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len() % 5, 0, "Blake2KAT.txt is not a whole number of 5-line records");
        lines
            .chunks(5)
            .map(|r| {
                assert_eq!(r[4].trim(), "#", "record for {} does not end in #", r[0]);
                Record {
                    alg: r[0].trim().to_string(),
                    input: decode_hex(r[1]),
                    key: decode_hex(r[2]),
                    digest: decode_hex(r[3]),
                }
            })
            .collect()
    }

    /// Runs one record through the hash (empty key) or the MAC (non-empty key), one-shot and
    /// streamed byte-at-a-time.
    fn check<
        HASH: Hash + Default,
        KEY: FromAnyKeyMaterial + MacGenerationKey + MacVerificationKey,
    >(
        r: &Record,
    ) {
        if r.key.is_empty() {
            assert_eq!(HASH::default().hash(&r.input), r.digest, "{} len {}", r.alg, r.input.len());
            let mut hash = HASH::default();
            for byte in &r.input {
                hash.do_update(core::slice::from_ref(byte));
            }
            assert_eq!(hash.do_final(), r.digest, "{} streamed len {}", r.alg, r.input.len());
        } else {
            let key = KeyMaterial::<64>::from_bytes_as_type(&r.key, KeyType::MACKey).unwrap();
            assert_eq!(
                KEY::from_key_material(&key).unwrap().mac(&r.input),
                r.digest,
                "keyed {} len {}",
                r.alg,
                r.input.len()
            );
            let key = KEY::from_key_material(&key).unwrap();
            let mut mac = key.create_verifier();
            for byte in &r.input {
                mac.do_update(core::slice::from_ref(byte));
            }
            assert!(
                mac.do_verify_final(&r.digest),
                "keyed {} streamed len {}",
                r.alg,
                r.input.len()
            );
        }
    }

    #[test]
    fn blake2_kat() {
        let contents = match get_test_data("Blake2KAT.txt") {
            Ok(c) => c,
            Err(()) => return,
        };
        let records = parse(&contents);

        let (mut b, mut s) = (0, 0);
        for r in &records {
            match r.alg.as_str() {
                "blake2b" => {
                    check::<BLAKE2b_512, BLAKE2b_512_MACKey>(r);
                    b += 1;
                }
                "blake2s" => {
                    check::<BLAKE2s_256, BLAKE2s_256_MACKey>(r);
                    s += 1;
                }
                _ => {}
            }
        }

        assert_eq!(b, 512, "blake2b records");
        assert_eq!(s, 512, "blake2s records");
        println!("BLAKE2: {b} blake2b and {s} blake2s KAT records passed");
    }
}
