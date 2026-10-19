//! Locating files in the external vector repositories, `bc-test-data` and `wycheproof`, which are
//! cloned beside this one and never packaged with a crate.

use std::path::PathBuf;

/// An external vector repository.
#[derive(Clone, Copy, Debug)]
pub enum ExternalVectors {
    /// `bc-test-data`, overridden by the `BC_TEST_DATA` environment variable.
    BcTestData,
    /// `wycheproof`, overridden by the `WYCHEPROOF_ROOT` environment variable.
    Wycheproof,
}

impl ExternalVectors {
    fn dir_name(self) -> &'static str {
        match self {
            Self::BcTestData => "bc-test-data",
            Self::Wycheproof => "wycheproof",
        }
    }

    fn override_var(self) -> &'static str {
        match self {
            Self::BcTestData => "BC_TEST_DATA",
            Self::Wycheproof => "WYCHEPROOF_ROOT",
        }
    }
}

/// The file `relative` inside `repo`, or `None` with a printed warning if it is not there; callers
/// return early on `None`, so `cargo test` stays green for someone who has cloned only this
/// repository.
///
/// Looks in the repository cloned beside this one, seen from a crate directory or from the
/// workspace root. If the repository's environment variable is set, its value is the root to use
/// instead: this is for a checkout the relative paths cannot reach, such as a scratch worktree or
/// the temporary copy `cargo mutants` builds in.
pub fn external_vector_file(repo: ExternalVectors, relative: &str) -> Option<PathBuf> {
    let candidates: Vec<PathBuf> = match std::env::var_os(repo.override_var()) {
        Some(root) => vec![PathBuf::from(root).join(relative)],
        None => vec![
            PathBuf::from("../../..").join(repo.dir_name()).join(relative),
            PathBuf::from("..").join(repo.dir_name()).join(relative),
        ],
    };
    if let Some(found) = candidates.iter().find(|path| path.exists()) {
        return Some(found.clone());
    }
    println!(
        "WARNING: {relative} not found (looked in {candidates:?}; set {} to override); \
         external vectors skipped",
        repo.override_var()
    );
    None
}
