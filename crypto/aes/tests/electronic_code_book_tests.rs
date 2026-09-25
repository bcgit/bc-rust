//! `ElectronicCodeBook` trait conformance, via the shared test framework.
//!
//! The framework checks the properties every implementor must have -- both directions are
//! inverses, the permutation is injective, the two- and four-block methods are indistinguishable
//! from two or four single-block calls *including their order*, and the key checks behave. That
//! batching property matters here specifically: this crate overrides `encrypt_2blocks`,
//! `decrypt_2blocks`, `encrypt_4blocks` and `decrypt_4blocks` with its `u32` and `u64` plane
//! paths, so the default implementations are not what runs.

use bouncycastle_aes::BLOCK_LEN;
use bouncycastle_aes::aes_internal::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_core_test_framework::electronic_code_book::TestFrameworkElectronicCodeBook;

#[test]
fn aes128_conforms_to_electronic_code_book() {
    TestFrameworkElectronicCodeBook::new().test::<16, BLOCK_LEN, AES128Internal>();
}

#[test]
fn aes192_conforms_to_electronic_code_book() {
    TestFrameworkElectronicCodeBook::new().test::<24, BLOCK_LEN, AES192Internal>();
}

#[test]
fn aes256_conforms_to_electronic_code_book() {
    TestFrameworkElectronicCodeBook::new().test::<32, BLOCK_LEN, AES256Internal>();
}
