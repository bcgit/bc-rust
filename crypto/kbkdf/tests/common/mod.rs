//! A reader for the NIST CAVP "SP800-108 - KDF" response files (`KDF*_gen.rsp` in
//! `bc-test-data/crypto/cavp`). Each record sits under the most recent `[PRF=..]`,
//! `[CTRLOCATION=..]` and `[RLEN=..]` headers and ends at its `KO` line.
#![allow(dead_code)]

use bouncycastle_core_test_framework::test_data_loaders::bc_test_data;
use bouncycastle_kbkdf::CounterSize;

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

fn hex(v: &str) -> Vec<u8> {
    if v.is_empty() { Vec::new() } else { bouncycastle_hex::decode(v).unwrap() }
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
                    r = Some(match v {
                        "8_BITS" => CounterSize::_8bit,
                        "16_BITS" => CounterSize::_16bit,
                        "24_BITS" => CounterSize::_24bit,
                        "32_BITS" => CounterSize::_32bit,
                        other => panic!("unexpected RLEN {other}"),
                    })
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
