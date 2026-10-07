//! `ElectronicCodeBook` trait conformance, via the shared test framework.
//!
//! The framework checks the properties every implementor must have -- both directions are
//! inverses, the permutation is injective, the two- and four-block methods are indistinguishable
//! from two or four single-block calls *including their order*, and the key checks behave. That
//! batching property matters here specifically: this crate overrides `encrypt_2blocks`,
//! `decrypt_2blocks`, `encrypt_4blocks` and `decrypt_4blocks` with its `u32` and `u64` plane
//! paths, so the default implementations are not what runs.

use bouncycastle_aes::AES_BLOCK_LEN;
use bouncycastle_aes::hazmat::{AES_ECB_128_Key, AES_ECB_192_Key, AES_ECB_256_Key};
use bouncycastle_aes::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_core_test_framework::electronic_code_book::TestFrameworkElectronicCodeBook;

#[test]
fn aes128_conforms_to_electronic_code_book() {
    TestFrameworkElectronicCodeBook::new()
        .test::<16, AES_BLOCK_LEN, AES_ECB_128_Key, AES128Internal>();
}

#[test]
fn aes192_conforms_to_electronic_code_book() {
    TestFrameworkElectronicCodeBook::new()
        .test::<24, AES_BLOCK_LEN, AES_ECB_192_Key, AES192Internal>();
}

#[test]
fn aes256_conforms_to_electronic_code_book() {
    TestFrameworkElectronicCodeBook::new()
        .test::<32, AES_BLOCK_LEN, AES_ECB_256_Key, AES256Internal>();
}
