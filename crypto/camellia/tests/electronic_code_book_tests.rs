//! `ElectronicCodeBook` trait conformance, via the shared test framework, for all three key
//! lengths.
//!
//! The framework checks the properties every implementor must have -- both directions are
//! inverses, the permutation is injective, the pair and four-block methods are indistinguishable
//! from single-block calls in every slot, and the key checks behave. All three types override the
//! pair and four-block methods, so this is what pins those overrides to the trait's contract.

use bouncycastle_camellia::BLOCK_LEN;
use bouncycastle_camellia::hazmat::{
    Camellia128Internal, Camellia192Internal, Camellia256Internal,
};
use bouncycastle_core_test_framework::electronic_code_book::TestFrameworkElectronicCodeBook;

#[test]
fn camellia128_conforms_to_electronic_code_book() {
    TestFrameworkElectronicCodeBook::new().test::<16, BLOCK_LEN, Camellia128Internal>();
}

#[test]
fn camellia192_conforms_to_electronic_code_book() {
    TestFrameworkElectronicCodeBook::new().test::<24, BLOCK_LEN, Camellia192Internal>();
}

#[test]
fn camellia256_conforms_to_electronic_code_book() {
    TestFrameworkElectronicCodeBook::new().test::<32, BLOCK_LEN, Camellia256Internal>();
}
