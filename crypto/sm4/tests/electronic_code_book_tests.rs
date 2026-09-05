//! `ElectronicCodeBook` trait conformance, via the shared test framework.
//!
//! The framework checks the properties every implementor must have -- both directions are
//! inverses, the permutation is injective, the pair methods are indistinguishable from two
//! single-block calls, and the key checks behave. `SM4` does not override the pair methods, so
//! here the framework is exercising the trait's defaults over the single-block implementation.

use bouncycastle_core_test_framework::electronic_code_book::TestFrameworkElectronicCodeBook;
use bouncycastle_sm4::{BLOCK_LEN, KEY_LEN, SM4};

#[test]
fn sm4_conforms_to_electronic_code_book() {
    TestFrameworkElectronicCodeBook::new().test::<KEY_LEN, BLOCK_LEN, SM4>();
}
