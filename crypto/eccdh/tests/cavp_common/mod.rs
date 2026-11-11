//! Parser for the legacy NIST CAVP `.txt` record format of `KAS_ECC_CDH_PrimitiveTest.txt` in
//! `bc-test-data/crypto/cavp/`, read through the framework's loader. A
//! missing `bc-test-data` checkout is a test **failure**, not a skip: these records are the only
//! external check of this crate's `Z` against NIST's own values. Clone `bc-test-data` next to this
//! repository (and symlink it at `/tmp/bc-test-data` for `cargo mutants`; see `CLAUDE.md`).

#![allow(dead_code)]

use bouncycastle_core_test_framework::test_data_loaders::bc_test_data;
use std::collections::BTreeMap;

/// The contents of `filename` from `bc-test-data/crypto/cavp/`, through the framework's loader;
/// panics if the checkout or the file is missing.
pub fn get_test_data(filename: &str) -> String {
    bc_test_data("crypto/cavp", filename).unwrap_or_else(|| {
        panic!("bc-test-data not found beside this repository; the ECC CDH CAVP suites require it rather than skipping")
    })
}

/// One `Key = value`-line record, plus the `[...]` section header it fell under.
pub struct Record {
    pub section: String,
    pub fields: BTreeMap<String, String>,
}

/// Every `Key = value` record in `content`, grouped by the most recent `[Section]` header; a
/// record ends at a blank line.
pub fn parse_records(content: &str) -> Vec<Record> {
    let mut records = Vec::new();
    let mut section = String::new();
    let mut current = BTreeMap::new();
    let flush = |current: &mut BTreeMap<String, String>,
                 records: &mut Vec<Record>,
                 section: &str| {
        if !current.is_empty() {
            records.push(Record { section: section.to_string(), fields: std::mem::take(current) });
        }
    };
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            flush(&mut current, &mut records, &section);
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        if let Some(inner) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            flush(&mut current, &mut records, &section);
            section = inner.to_string();
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            current.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    flush(&mut current, &mut records, &section);
    records
}

/// A CAVP hex field as big-endian bytes of exactly `width`: left-padded with zero bytes (and a
/// leading zero nibble when the hex string is odd-length), or stripped of leading zero bytes
/// where the file writes a value wider than the field, as the P-521 section's 67-byte `00`-led
/// coordinates are. A non-zero excess byte is a malformed record and panics.
pub fn hex_field(fields: &BTreeMap<String, String>, key: &str, width: usize) -> Vec<u8> {
    let hex = fields.get(key).unwrap_or_else(|| panic!("record missing field {key}"));
    let hex = if hex.len() % 2 == 1 { format!("0{hex}") } else { hex.clone() };
    let bytes =
        bouncycastle_hex::decode(&hex).unwrap_or_else(|e| panic!("bad hex in {key}: {e:?}"));
    let bytes = if bytes.len() > width {
        let (excess, rest) = bytes.split_at(bytes.len() - width);
        assert!(excess.iter().all(|b| *b == 0), "{key} is wider than {width} bytes");
        rest.to_vec()
    } else {
        bytes
    };
    let mut out = vec![0u8; width];
    out[width - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// SEC 1 Section 2.3.3's uncompressed `04 || X || Y`.
pub fn uncompressed_pk(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut out = vec![0x04u8];
    out.extend_from_slice(x);
    out.extend_from_slice(y);
    out
}
