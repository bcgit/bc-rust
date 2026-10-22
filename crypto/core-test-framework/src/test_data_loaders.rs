//! Loaders for the external test-vector repositories.
//!
//! Vector suites read from two repositories that are cloned rather than vendored:
//! [bc-test-data](https://github.com/bcgit/bc-test-data) and
//! [Wycheproof](https://github.com/C2SP/wycheproof). Each is located, once per test binary, by
//! the first of:
//!
//! 1. the environment variable `BC_TEST_DATA_DIR` or `WYCHEPROOF_DIR`, naming the clone's root;
//! 2. a directory named `bc-test-data` or `wycheproof` in the current directory or any of its
//!    ancestors, nearest first. `cargo test` runs each test binary in its crate's directory, so a
//!    clone beside this repository is found.
//!
//! Both are optional. When one is not found its loader prints a warning, once per test binary, and
//! returns `None`; the caller returns early, so `cargo test` passes for someone who has cloned only
//! this repository. A variable naming a directory that does not exist panics rather than skipping,
//! as does a file missing from a repository that was found.

use bouncycastle_hex as hex;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// The parsed form of a vector file, re-exported so that suites need no `serde_json` dependency
/// of their own.
pub use serde_json::Value;

static BC_TEST_DATA_ROOT: OnceLock<Option<PathBuf>> = OnceLock::new();
static WYCHEPROOF_ROOT: OnceLock<Option<PathBuf>> = OnceLock::new();

/// Returns the contents of `bc-test-data/<dir>/<filename>`, or `None` (after a one-time warning)
/// if bc-test-data is not found.
///
/// Panics if bc-test-data is present but the file cannot be read.
pub fn bc_test_data(dir: &str, filename: &str) -> Option<String> {
    let root = BC_TEST_DATA_ROOT.get_or_init(|| locate("BC_TEST_DATA_DIR", "bc-test-data"));
    read(root.as_deref(), "bc-test-data", &format!("{dir}/{filename}"))
}

/// Returns the contents of `wycheproof/testvectors_v1/<filename>`, or `None` (after a one-time
/// warning) if Wycheproof is not found.
///
/// Panics if Wycheproof is present but the file cannot be read.
pub fn wycheproof(filename: &str) -> Option<String> {
    let root = WYCHEPROOF_ROOT.get_or_init(|| locate("WYCHEPROOF_DIR", "wycheproof"));
    read(root.as_deref(), "wycheproof", &format!("testvectors_v1/{filename}"))
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

/// Finds a repository from the environment variable `var`, else by searching the current directory
/// and its ancestors for a directory called `name`, and reports the outcome once.
fn locate(var: &str, name: &str) -> Option<PathBuf> {
    let found = match env::var_os(var) {
        Some(dir) => {
            let dir = PathBuf::from(dir);
            // A variable set to a bad path is a misconfiguration, not an absent repository: skipping
            // would let the suites pass vacuously.
            assert!(dir.is_dir(), "{var} is set to {}, which is not a directory", dir.display());
            Some(dir)
        }
        None => {
            let cwd = env::current_dir().expect("the current directory is readable");
            search_ancestors(&cwd, name)
        }
    };
    match &found {
        Some(dir) => println!("{name} found at: {}", dir.display()),
        None => println!(
            "WARNING: {name} not found (set {var}, or clone it into this directory or an ancestor); \
             tests that need it will be skipped"
        ),
    }
    found
}

/// The nearest `<ancestor>/name` directory, searching from `start` itself up to the filesystem root.
fn search_ancestors(start: &Path, name: &str) -> Option<PathBuf> {
    start.ancestors().map(|dir| dir.join(name)).find(|candidate| candidate.is_dir())
}

fn read(root: Option<&Path>, repo: &str, path: &str) -> Option<String> {
    let path = root?.join(path);
    Some(
        fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("{repo} is present but {} is unreadable: {e}", path.display())
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::search_ancestors;
    use std::fs;
    use std::path::PathBuf;

    /// A fresh, empty directory under the system temp directory, unique to `tag` and this process.
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bc-loader-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn search_finds_the_start_directory_itself() {
        let root = scratch("self");
        fs::create_dir(root.join("vectors")).unwrap();
        assert_eq!(search_ancestors(&root, "vectors"), Some(root.join("vectors")));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn search_finds_the_nearest_ancestor() {
        let root = scratch("nearest");
        let start = root.join("a/b/c");
        fs::create_dir_all(&start).unwrap();
        fs::create_dir(root.join("vectors")).unwrap();
        fs::create_dir(root.join("a/vectors")).unwrap();
        assert_eq!(search_ancestors(&start, "vectors"), Some(root.join("a/vectors")));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn search_skips_a_file_of_that_name() {
        let root = scratch("file");
        let start = root.join("a");
        fs::create_dir_all(&start).unwrap();
        fs::write(start.join("vectors"), b"").unwrap();
        fs::create_dir(root.join("vectors")).unwrap();
        assert_eq!(search_ancestors(&start, "vectors"), Some(root.join("vectors")));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn search_returns_none_when_absent() {
        let root = scratch("absent");
        assert_eq!(search_ancestors(&root, "no-such-repo-anywhere-c0ffee"), None);
        fs::remove_dir_all(&root).unwrap();
    }
}
