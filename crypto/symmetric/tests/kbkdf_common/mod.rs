//! What the suites share: a reader for the NIST CAVP "SP800-108 - KDF" response files
//! (`KDF*_gen.rsp` in `bc-test-data/crypto/cavp`), whose records each sit under the most recent
//! `[PRF=..]`, `[CTRLOCATION=..]` and `[RLEN=..]` headers and end at their `KO` line; the
//! dispatch of a record to its PRF; and the small helpers of the other tests.
#![allow(dead_code)]

use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey};
use bouncycastle_core_test_framework::test_data_loaders::{Value, bc_test_data, bc_test_data_json};
use bouncycastle_digest::hmac::HmacKey;
use bouncycastle_digest::sha2::{SHA224, SHA256, SHA384, SHA512};
use bouncycastle_symmetric::kbkdf::{
    CounterSize, PRF_CMAC_AES128, PRF_CMAC_AES192, PRF_CMAC_AES256, PRF_HMAC, Prf,
};

/// `bytes` as full-entropy key material.
pub fn random(bytes: &[u8]) -> KeyMaterial<512> {
    KeyMaterial::<512>::from_bytes_as_type(bytes, KeyType::CryptographicRandom).unwrap()
}

/// HMAC-SHA256 under `key` over `parts`, through the key object.
pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let key = KeyMaterial::<144>::from_bytes_as_type(key, KeyType::MACKey).unwrap();
    HmacKey::<SHA256>::from_key_material_allow_weak(&key).unwrap().mac(&parts.concat()).to_vec()
}

/// `v` decoded from hex; an empty string is no bytes.
pub fn hex(v: &str) -> Vec<u8> {
    if v.is_empty() { Vec::new() } else { bouncycastle_core::hex::decode(v).unwrap() }
}

/// A JSON string decoded from hex.
pub fn hex_value(v: &Value) -> Vec<u8> {
    hex(v.as_str().unwrap())
}

/// `filename` of the ACVP vector set `set` (in `bc-test-data/crypto/acvp`), which the suites
/// require rather than skip.
pub fn acvp_json(set: &str, filename: &str) -> Value {
    bc_test_data_json(&format!("crypto/acvp/{set}"), filename).unwrap_or_else(|| {
        panic!("bc-test-data not found beside this repository; the {set} ACVP suite requires it rather than skipping")
    })
}

pub struct Record {
    pub prf: String,
    /// `BEFORE_FIXED`, `AFTER_FIXED`, `MIDDLE_FIXED`, `BEFORE_ITER`, `AFTER_ITER`, or empty in
    /// the files without a counter.
    pub ctr_location: String,
    pub r: Option<CounterSize>,
    pub count: String,
    /// `L` in bytes; every `L` in these files is a multiple of 8.
    pub len: usize,
    pub ki: Vec<u8>,
    pub iv: Vec<u8>,
    /// The fixed input data; for a counter in the middle, what precedes it.
    pub fixed: Vec<u8>,
    /// For a counter in the middle of the fixed input data, what follows it.
    pub fixed_after: Vec<u8>,
    pub ko: Vec<u8>,
}

impl Record {
    pub fn name(&self) -> String {
        format!("{} {} {:?} COUNT {}", self.prf, self.ctr_location, self.r, self.count)
    }
}

/// The file, which the suites require rather than skip.
pub fn load(filename: &str) -> Vec<Record> {
    let content = bc_test_data("crypto/cavp", filename).unwrap_or_else(|| {
        panic!("bc-test-data not found beside this repository; the SP 800-108 CAVP suites require it rather than skipping")
    });
    parse(&content)
}

/// What a CAVP suite does with one record, over the record's PRF.
pub trait Check {
    fn check<P: Prf>(&self, r: &Record);
}

/// Hands every record over a PRF the crate has to `check`, and counts the others, so that a
/// change in what is skipped is noticed: returns (checked, HMAC-SHA1 records, CMAC-TDEA records).
pub fn check_each(records: &[Record], check: &impl Check) -> (usize, usize, usize) {
    let (mut checked, mut sha1, mut tdea) = (0, 0, 0);
    for r in records {
        match r.prf.as_str() {
            "HMAC_SHA224" => check.check::<PRF_HMAC<SHA224>>(r),
            "HMAC_SHA256" => check.check::<PRF_HMAC<SHA256>>(r),
            "HMAC_SHA384" => check.check::<PRF_HMAC<SHA384>>(r),
            "HMAC_SHA512" => check.check::<PRF_HMAC<SHA512>>(r),
            "CMAC_AES128" => check.check::<PRF_CMAC_AES128>(r),
            "CMAC_AES192" => check.check::<PRF_CMAC_AES192>(r),
            "CMAC_AES256" => check.check::<PRF_CMAC_AES256>(r),
            "HMAC_SHA1" => {
                sha1 += 1;
                continue;
            }
            "CMAC_TDES2" | "CMAC_TDES3" => {
                tdea += 1;
                continue;
            }
            other => panic!("unexpected PRF {other}"),
        }
        checked += 1;
    }
    (checked, sha1, tdea)
}

fn parse(content: &str) -> Vec<Record> {
    let mut out = Vec::new();
    let (mut prf, mut ctr_location, mut r) = (String::new(), String::new(), None);
    let (mut count, mut len, mut ki) = (String::new(), 0usize, Vec::new());
    let (mut iv, mut fixed, mut fixed_after) = (Vec::new(), Vec::new(), Vec::new());
    for raw in content.lines() {
        let line = raw.trim();
        if let Some(inner) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            let (k, v) = inner.split_once('=').expect("a header is KEY=VALUE");
            match k {
                "PRF" => prf = v.to_string(),
                "CTRLOCATION" => ctr_location = v.to_string(),
                "RLEN" => {
                    let bits = v.strip_suffix("_BITS").and_then(|bits| bits.parse().ok());
                    r = Some(
                        bits.and_then(CounterSize::from_bits)
                            .unwrap_or_else(|| panic!("unexpected RLEN {v}")),
                    )
                }
                other => panic!("unexpected header {other}"),
            }
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        let (k, v) = (k.trim(), v.trim());
        match k {
            "COUNT" => {
                count = v.to_string();
                iv.clear();
                fixed.clear();
                fixed_after.clear();
            }
            "L" => {
                let bits: usize = v.parse().unwrap();
                assert_eq!(bits % 8, 0, "L is a whole number of bytes in these files");
                len = bits / 8;
            }
            "KI" => ki = hex(v),
            "IV" => iv = hex(v),
            "FixedInputData" | "DataBeforeCtrData" => fixed = hex(v),
            "DataAfterCtrData" => fixed_after = hex(v),
            "KO" => {
                let ko = hex(v);
                assert_eq!(ko.len(), len, "KO is L bits");
                out.push(Record {
                    prf: prf.clone(),
                    ctr_location: ctr_location.clone(),
                    r,
                    count: count.clone(),
                    len,
                    ki: ki.clone(),
                    iv: iv.clone(),
                    fixed: fixed.clone(),
                    fixed_after: fixed_after.clone(),
                    ko,
                });
            }
            // The length fields restate the values; the intermediate values some files print
            // are not read.
            _ => {}
        }
    }
    out
}
