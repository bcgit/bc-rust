//! `ElectronicCodeBook` trait conformance, via the shared test framework.
//!
//! The framework checks the properties every implementor must have -- both directions are
//! inverses, the permutation is injective, the pair and four-block methods are indistinguishable
//! from single-block calls *including their order*, and the key checks behave, including the
//! security-strength policy against `MAX_SECURITY_STRENGTH` (112 bits here, not the 192 a 24-byte
//! key would otherwise imply).
//!
//! The framework's key is the first 24 (or 16) bytes of `DUMMY_SEED`, `00 01 02 ..`, whose 8-byte
//! components are distinct and not weak, so it is a valid bundle for either engine.
//!
//! For [`TDES2Key`] the strength policy is against `MAX_SECURITY_STRENGTH = None`, so every
//! strength the framework tries must be accepted; the framework checks that too.

use bouncycastle_core_test_framework::electronic_code_book::TestFrameworkElectronicCodeBook;
use bouncycastle_tdes::{BLOCK_LEN, KEY_LEN, KEY_LEN_2KEY, TDES, TDES2Key};

#[test]
fn tdes_conforms_to_electronic_code_book() {
    TestFrameworkElectronicCodeBook::new().test::<KEY_LEN, BLOCK_LEN, TDES>();
}

#[test]
fn tdes2key_conforms_to_electronic_code_book() {
    TestFrameworkElectronicCodeBook::new().test::<KEY_LEN_2KEY, BLOCK_LEN, TDES2Key>();
}
