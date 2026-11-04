//! NIST CAVP Hash_DRBG vectors (`drbgtestvectors.zip`, CAVS 14.3, 2013-04-02), from
//! `bc-test-data/crypto/cavp/drbg/` (the copies there have LF line endings where the zip has
//! CRLF; the content is otherwise identical and the parser trims): `drbgvectors_no_reseed/Hash_DRBG.rsp` (instantiate, two
//! generates) and `drbgvectors_pr_false/Hash_DRBG.rsp` (instantiate, reseed, two generates), the
//! SHA-256 and SHA-512 sections, with and without a personalization string and additional input.
//! The second generate's output is `ReturnedBits`. `drbgvectors_pr_true` is not read: the DRBG
//! does not support prediction resistance. The other hashes' sections are skipped: SHA-256 and
//! SHA-512 are the two the crate implements.
//!
//! A missing `bc-test-data` checkout skips these with the loader's warning, as the other crates'
//! CAVP suites do.

use bouncycastle_core::key_material::{KeyMaterial512, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core_test_framework::test_data_loaders::bc_test_data;
use bouncycastle_hex::decode as hex_decode;
use bouncycastle_rng::hazmat::NewUninitialized;
use bouncycastle_rng::{HashDRBG_SHA256, HashDRBG_SHA512, Sp80090ADrbg};

/// One `COUNT` block: the fields in file order, with the two `AdditionalInput` lines kept apart.
#[derive(Default)]
struct Record {
    count: String,
    entropy: Vec<u8>,
    nonce: Vec<u8>,
    personalization: Vec<u8>,
    entropy_reseed: Option<Vec<u8>>,
    additional_reseed: Vec<u8>,
    additional: Vec<Vec<u8>>,
    returned_bits: Vec<u8>,
}

/// The records of every `[SHA-256]` and `[SHA-512]` section, tagged with the section's hash.
fn parse(contents: &str) -> Vec<(&'static str, Record)> {
    let mut out = Vec::new();
    let mut hash: Option<&'static str> = None;
    let mut record: Option<Record> = None;
    for line in contents.lines().map(str::trim) {
        if line.starts_with('#') {
            continue;
        }
        if line.is_empty() {
            if let (Some(h), Some(r)) = (hash, record.take()) {
                out.push((h, r));
            }
            continue;
        }
        if let Some(section) = line.strip_prefix('[') {
            let section = section.trim_end_matches(']');
            if !section.contains('=') {
                hash = match section {
                    "SHA-256" => Some("SHA-256"),
                    "SHA-512" => Some("SHA-512"),
                    _ => None,
                };
            }
            continue;
        }
        let (key, value) = line.split_once('=').expect("a `key = value` line");
        let (key, value) = (key.trim(), value.trim());
        let bytes = || hex_decode(value).expect("hex");
        if key == "COUNT" {
            record = Some(Record { count: value.to_string(), ..Default::default() });
            continue;
        }
        let r = record.as_mut().expect("a field inside a COUNT block");
        match key {
            "EntropyInput" => r.entropy = bytes(),
            "Nonce" => r.nonce = bytes(),
            "PersonalizationString" => r.personalization = bytes(),
            "EntropyInputReseed" => r.entropy_reseed = Some(bytes()),
            "AdditionalInputReseed" => r.additional_reseed = bytes(),
            "AdditionalInput" => r.additional.push(bytes()),
            "ReturnedBits" => r.returned_bits = bytes(),
            other => panic!("unexpected field {other}"),
        }
    }
    if let (Some(h), Some(r)) = (hash, record.take()) {
        out.push((h, r));
    }
    out
}

fn seed(bytes: &[u8]) -> KeyMaterial512 {
    KeyMaterial512::from_bytes_as_type(bytes, KeyType::Seed).expect("a seed")
}

/// Drives one record as the CAVP procedure does and returns the second generate's output.
fn run<D: Sp80090ADrbg + NewUninitialized>(r: &Record, strength: SecurityStrength) -> Vec<u8> {
    let mut drbg = D::new_uninitialized();
    drbg.instantiate(false, seed(&r.entropy), &seed(&r.nonce), &r.personalization, strength)
        .unwrap_or_else(|e| panic!("COUNT {}: instantiate: {e:?}", r.count));
    if let Some(entropy_reseed) = &r.entropy_reseed {
        drbg.reseed(&seed(entropy_reseed), &r.additional_reseed)
            .unwrap_or_else(|e| panic!("COUNT {}: reseed: {e:?}", r.count));
    }
    assert_eq!(r.additional.len(), 2, "COUNT {}: two AdditionalInput lines", r.count);
    let n = r.returned_bits.len();
    drbg.generate(&r.additional[0], n)
        .unwrap_or_else(|e| panic!("COUNT {}: first generate: {e:?}", r.count));
    drbg.generate(&r.additional[1], n)
        .unwrap_or_else(|e| panic!("COUNT {}: second generate: {e:?}", r.count))
}

fn check_file(dir: &str) {
    let Some(contents) = bc_test_data(&format!("crypto/cavp/drbg/{dir}"), "Hash_DRBG.rsp") else {
        return;
    };
    let records = parse(&contents);
    let (mut sha256, mut sha512) = (0, 0);
    for (hash, r) in &records {
        let got = match *hash {
            "SHA-256" => {
                sha256 += 1;
                run::<HashDRBG_SHA256>(r, SecurityStrength::_128bit)
            }
            _ => {
                sha512 += 1;
                run::<HashDRBG_SHA512>(r, SecurityStrength::_256bit)
            }
        };
        assert_eq!(got, r.returned_bits, "{dir} {hash} COUNT {}", r.count);
    }
    println!("{dir}: {sha256} SHA-256 and {sha512} SHA-512 Hash_DRBG vectors passed");
    assert!(sha256 >= 100 && sha512 >= 100, "{dir}: the SHA-256 and SHA-512 sections were read");
}

#[test]
fn cavp_hash_drbg_no_reseed() {
    check_file("drbgvectors_no_reseed");
}

#[test]
fn cavp_hash_drbg_pr_false() {
    check_file("drbgvectors_pr_false");
}
