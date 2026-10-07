//! Loaders for the external test-vector repositories.
//!
//! Vector suites read from two repositories that are cloned beside this one rather than vendored:
//! [bc-test-data](https://github.com/bcgit/bc-test-data) at `../bc-test-data`, and
//! [Wycheproof](https://github.com/C2SP/wycheproof) at `../wycheproof`. Both are optional. When one
//! is absent its loader prints a warning, once per test binary, and returns `None`; the caller
//! returns early, so `cargo test` passes for someone who has cloned only this repository. When a
//! repository is present, a file missing from it is a failure rather than a skip.
//!
//! The paths are resolved from this crate's manifest directory, which is at the same depth as every
//! crate under `crypto/`, so they do not depend on the directory `cargo test` runs in. Under
//! `cargo mutants`, which copies the tree into `/tmp`, they resolve to `/tmp/bc-test-data` and
//! `/tmp/wycheproof`.

use bouncycastle_hex as hex;
use std::fs;
use std::path::Path;
use std::sync::Once;

/// The parsed form of a vector file, re-exported so that suites need no `serde_json` dependency
/// of their own.
pub use serde_json::Value;

const BC_TEST_DATA_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../bc-test-data");
const WYCHEPROOF_ROOT: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../../wycheproof/testvectors_v1");

static BC_TEST_DATA_CHECK: Once = Once::new();
static WYCHEPROOF_CHECK: Once = Once::new();

/// Returns the contents of `bc-test-data/<dir>/<filename>`, or `None` (after a one-time warning)
/// if bc-test-data is not cloned beside this repository.
///
/// Panics if bc-test-data is present but the file cannot be read.
pub fn bc_test_data(dir: &str, filename: &str) -> Option<String> {
    read(BC_TEST_DATA_ROOT, &BC_TEST_DATA_CHECK, "bc-test-data", &format!("{dir}/{filename}"))
}

/// Returns the contents of `wycheproof/testvectors_v1/<filename>`, or `None` (after a one-time
/// warning) if Wycheproof is not cloned beside this repository.
///
/// Panics if Wycheproof is present but the file cannot be read.
pub fn wycheproof(filename: &str) -> Option<String> {
    read(WYCHEPROOF_ROOT, &WYCHEPROOF_CHECK, "wycheproof", filename)
}

/// [`bc_test_data`], parsed as JSON.
///
/// Panics if the file is not valid JSON.
pub fn bc_test_data_json(dir: &str, filename: &str) -> Option<Value> {
    bc_test_data(dir, filename).map(|s| parse(&s, filename))
}

/// [`wycheproof`], parsed as JSON.
///
/// Panics if the file is not valid JSON.
pub fn wycheproof_json(filename: &str) -> Option<Value> {
    wycheproof(filename).map(|s| parse(&s, filename))
}

/// The hex-encoded `field` of one test case, decoded; a missing field or bad hex names the case.
pub fn hex_field(case: &Value, field: &str, tc_id: u64) -> Vec<u8> {
    let s = case
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("tcId {tc_id}: missing field {field}"));
    hex::decode(s).unwrap_or_else(|_| panic!("tcId {tc_id}: bad hex in {field}"))
}

fn parse(contents: &str, filename: &str) -> Value {
    serde_json::from_str(contents).unwrap_or_else(|e| panic!("{filename} is not valid JSON: {e}"))
}

fn read(root: &str, check: &Once, repo: &str, path: &str) -> Option<String> {
    let found = Path::new(root).is_dir();
    check.call_once(|| {
        if found {
            println!("{repo} found at: {root}");
        } else {
            println!("WARNING: {repo} not found at {root}; tests that need it will be skipped");
        }
    });
    if !found {
        return None;
    }
    let path = format!("{root}/{path}");
    Some(
        fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{repo} is present but {path} is unreadable: {e}")),
    )
}
