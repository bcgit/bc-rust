//! Shared parser for the legacy (pre-ACVP, 2011-era) NIST CAVP `.rsp` text format used by
//! `ECDSA_SigVer.rsp`, `ECDSA_PKV.rsp` and `ECDSA_KeyPair.rsp` in `bc-test-data/crypto/cavp/` --
//! distinct from the newer JSON ACVP format the `aes`/`modes`/`mldsa`/`mlkem` crates' own
//! `bc-test-data.rs` files parse. Each test binary that includes this module uses a subset of it.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::Once;

const TEST_DATA_PATH_RELATIVE: &str = "../../../bc-test-data/crypto/cavp";
const TEST_DATA_PATH: &str = "../bc-test-data/crypto/cavp";

static TEST_DATA_CHECK: Once = Once::new();

/// Returns the contents of `filename` from `bc-test-data/crypto/cavp/`, or `None` (after a
/// one-time warning) if the repo is not checked out -- same convention as every other CAVP/ACVP
/// suite in this workspace, so `cargo test` stays green for someone who has only cloned this repo.
pub fn get_test_data(filename: &str) -> Option<String> {
    let dir = [TEST_DATA_PATH_RELATIVE, TEST_DATA_PATH].into_iter().find(|d| Path::new(d).exists());
    TEST_DATA_CHECK.call_once(|| match dir {
        Some(d) => println!("bc-test-data found at: {d:?}"),
        None => {
            println!("WARNING: bc-test-data directory not found; ECDSA CAVP tests will be skipped")
        }
    });
    let dir = dir?;
    Some(fs::read_to_string(format!("{dir}/{filename}")).expect("failed to read CAVP vector file"))
}

/// One `Key = value`-line record, plus the `[...]` section header it fell under.
pub struct Record {
    pub section: String,
    pub fields: BTreeMap<String, String>,
}

fn kv(line: &str) -> Option<(&str, &str)> {
    let (k, v) = line.split_once('=')?;
    Some((k.trim(), v.trim()))
}

/// Parses every `Key = value` record in `content`, grouped by the most recent `[Section]` header.
/// A record ends at the next blank line. Only bracket lines shaped like a curve name (`P-256`,
/// `K-163`, `B-233`, ...) update the section: `ECDSA_KeyPair.rsp` nests a second, descriptive
/// bracket line (`[B.4.2 Key Pair Generation by Testing Candidates]`) under each curve's, which
/// this deliberately ignores rather than losing the curve name. That file also has a lone `N = 10`
/// line before its first real record; callers filter records by the fields they actually need
/// (e.g. requiring `d`) rather than this parser guessing which stray lines are noise.
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
            if inner.starts_with("P-") || inner.starts_with("K-") || inner.starts_with("B-") {
                flush(&mut current, &mut records, &section);
                section = inner.to_string();
            }
            continue;
        }
        if let Some((k, v)) = kv(line) {
            current.insert(k.to_string(), v.to_string());
        }
    }
    flush(&mut current, &mut records, &section);
    records
}

/// Decodes a CAVP hex field into big-endian bytes, left-padded with zero bytes to at least
/// `width` (and, if needed, a single leading zero nibble to make the hex string even-length --
/// CAVP sometimes omits the leading zero nibble of the most significant byte, e.g. for P-521
/// values whose top byte only ever has 1 significant bit).
///
/// Deliberately does *not* reject or truncate a value wider than `width`: `ECDSA_PKV.rsp`'s
/// negative "Q_x or Q_y out of range" vectors are exactly that -- a coordinate one or more bytes
/// too wide to be a valid field element -- and the point of those vectors is to check that the
/// public-key decoder built from this value rejects it, which an oversized SEC 1 encoding does
/// naturally (wrong total length) without this helper needing to special-case the reason.
pub fn hex_field(fields: &BTreeMap<String, String>, key: &str, width: usize) -> Vec<u8> {
    let hex = fields.get(key).unwrap_or_else(|| panic!("record missing field {key}"));
    let hex = if hex.len() % 2 == 1 { format!("0{hex}") } else { hex.clone() };
    let bytes =
        bouncycastle_hex::decode(&hex).unwrap_or_else(|e| panic!("bad hex in {key}: {e:?}"));
    if bytes.len() >= width {
        return bytes;
    }
    let mut out = vec![0u8; width];
    out[width - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// Decodes a CAVP hex field of whatever length it happens to be (e.g. `Msg`, which is the message
/// itself, not a fixed-width field element).
pub fn hex_bytes(fields: &BTreeMap<String, String>, key: &str) -> Vec<u8> {
    let hex = fields.get(key).unwrap_or_else(|| panic!("record missing field {key}"));
    bouncycastle_hex::decode(hex).unwrap_or_else(|e| panic!("bad hex in {key}: {e:?}"))
}

/// `true` iff a CAVP `Result = P (0 )` / `Result = F (...)` field indicates success.
pub fn result_is_pass(fields: &BTreeMap<String, String>) -> bool {
    fields.get("Result").unwrap_or_else(|| panic!("record missing Result field")).starts_with('P')
}
