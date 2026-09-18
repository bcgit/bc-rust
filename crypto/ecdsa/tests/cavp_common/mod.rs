//! Shared parser for the legacy (pre-ACVP, 2011-era) NIST CAVP `.rsp` text format used by
//! `ECDSA_SigVer.rsp`, `ECDSA_PKV.rsp`, `ECDSA_KeyPair.rsp` and `ECDSA_SigGen.txt` in
//! `bc-test-data/crypto/cavp/` -- distinct from the newer JSON ACVP format the
//! `aes`/`modes`/`mldsa`/`mlkem` crates' own `bc-test-data.rs` files parse. Each test binary that
//! includes this module uses a subset of it.
//!
//! Unlike those other suites, a missing `bc-test-data` checkout is a test **failure** here, not a
//! warning and a vacuous pass: these files are the only external check on this crate's signing
//! and verification against NIST's own values, and a green run that never read them would be
//! indistinguishable from one that did. Clone `bc-test-data` next to this repository (and symlink
//! it at `/tmp/bc-test-data` for `cargo mutants`, whose copied tree resolves the relative path
//! there -- see `CLAUDE.md`).

#![allow(dead_code)]

use bouncycastle_core::errors::RNGError;
use bouncycastle_core::key_material::KeyMaterialTrait;
use bouncycastle_core::traits::{RNG, SecurityStrength};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

const TEST_DATA_PATH_RELATIVE: &str = "../../../bc-test-data/crypto/cavp";
const TEST_DATA_PATH: &str = "../bc-test-data/crypto/cavp";

/// Returns the contents of `filename` from `bc-test-data/crypto/cavp/`. Panics, failing the test,
/// if the repo is not checked out or the file is missing -- see the module docs for why this suite
/// does not skip.
pub fn get_test_data(filename: &str) -> String {
    let dir = [TEST_DATA_PATH_RELATIVE, TEST_DATA_PATH]
        .into_iter()
        .find(|d| Path::new(d).exists())
        .unwrap_or_else(|| {
            panic!(
                "bc-test-data not found (looked in {TEST_DATA_PATH_RELATIVE:?} and \
                 {TEST_DATA_PATH:?}); the ECDSA CAVP suites require it rather than skipping"
            )
        });
    fs::read_to_string(format!("{dir}/{filename}"))
        .unwrap_or_else(|e| panic!("failed to read CAVP vector file {dir}/{filename}: {e}"))
}

/// An [`RNG`] that hands out one fixed big-endian value, zero-padded on the left to whatever width
/// is asked for. This is how `ECDSA_SigGen.txt`'s per-message secret `k` is injected: every
/// curve's `sign_randomized` draws its DRBG bytes and reduces them per FIPS 186-5 Appendix A.4.1
/// (`x mod (n-1)`, then `+ 1`), so an RNG returning `k - 1` -- which is `< n - 1`, making the
/// reduction the identity -- produces exactly `k`, through the public API and with no test-only
/// hook in the crate. Only `next_bytes_out`/`next_bytes` are meaningful; nothing in the signing
/// path calls the rest.
pub struct FixedBytesRng {
    value_be: Vec<u8>,
}

impl FixedBytesRng {
    pub fn new(value_be: Vec<u8>) -> Self {
        Self { value_be }
    }
}

impl RNG for FixedBytesRng {
    fn add_seed_keymaterial(&mut self, _seed: &dyn KeyMaterialTrait) -> Result<(), RNGError> {
        Ok(())
    }

    fn next_int(&mut self) -> Result<u32, RNGError> {
        unimplemented!("FixedBytesRng only serves next_bytes_out")
    }

    fn next_bytes(&mut self, len: usize) -> Result<Vec<u8>, RNGError> {
        let mut out = vec![0u8; len];
        self.next_bytes_out(&mut out)?;
        Ok(out)
    }

    fn next_bytes_out(&mut self, out: &mut [u8]) -> Result<usize, RNGError> {
        assert!(
            out.len() >= self.value_be.len(),
            "requested {} bytes but the fixed value is {} bytes wide",
            out.len(),
            self.value_be.len()
        );
        let pad = out.len() - self.value_be.len();
        out[..pad].fill(0);
        out[pad..].copy_from_slice(&self.value_be);
        Ok(out.len())
    }

    fn fill_keymaterial_out(&mut self, _out: &mut dyn KeyMaterialTrait) -> Result<usize, RNGError> {
        unimplemented!("FixedBytesRng only serves next_bytes_out")
    }

    fn security_strength(&self) -> SecurityStrength {
        SecurityStrength::_256bit
    }
}

/// Big-endian `value - 1` in place. Only ever called on a CAVP `k`, which is in `[1, n-1]` and so
/// never zero; panics rather than wrap if it is.
pub fn decrement_be(value: &mut [u8]) {
    for byte in value.iter_mut().rev() {
        if *byte > 0 {
            *byte -= 1;
            return;
        }
        *byte = 0xff;
    }
    panic!("decrement_be called on zero");
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
