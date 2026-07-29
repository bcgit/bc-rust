//! Test against the project wycheproof repo available at:
//!     https://github.com/C2SP/wycheproof
//! Requires that the wycheproof repository is cloned and available for testing at "../wycheproof"
//! relative to the root of this git project.
//!
//! TODO: port the wycheproof vectors for AES. Nothing is wired up here yet -- this file is a
//! placeholder so that the crate has the standard test layout, and so that whoever picks this up
//! has the context in one place.
//!
//! Notes for whoever does the port:
//!
//! * Wycheproof has no test set for the bare AES permutation; its AES coverage is all
//!   mode-of-operation based (`aes_cbc_pkcs5_test.json`, `aes_gcm_test.json`, `aes_ccm_test.json`,
//!   `aes_siv_cmac_test.json`, `aes_eax_test.json`, `aes_cmac_test.json`, ...). Those vectors
//!   belong to the crates that implement those modes, not to this crate, and most of them exercise
//!   exactly the things a raw engine has no opinion about: padding, tag checks, and nonce handling.
//! * The one thing worth extracting here is any test group that pins raw single-block behaviour,
//!   which in practice means using a mode's vectors with a single full block and no padding as an
//!   indirect check.
//! * Until the mode crates exist, the block-level coverage in `aes_tests.rs` (FIPS 197 Appendix B
//!   plus the NIST "AES Core" ECB-AES128/192/256 vectors, in both directions) is the authoritative
//!   set for this crate.
//! * See `crypto/mlkem/tests/wycheproof.rs` for the established pattern: locate the repo at either
//!   `../wycheproof/testvectors_v1` or `../../../wycheproof/testvectors_v1`, skip the tests with a
//!   printed warning if it is absent, and drive each test group from a parsed struct.
//!
//! The AES known-answer tests against the bc-test-data repo are a separate, similarly outstanding
//! task; see `crypto/mlkem/tests/bc_test_data.rs` for that pattern.
