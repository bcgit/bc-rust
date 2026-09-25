//! `ElectronicCodeBook` trait conformance, via the shared test framework.
//!
//! The framework checks the properties every implementor must have -- both directions are
<<<<<<< HEAD
//! inverses, the permutation is injective, the pair methods are indistinguishable from two
//! single-block calls *including their order*, and the key checks behave. That last pair of
//! properties matters here specifically: this crate's pair methods run the bit-sliced engine
//! rather than two single-block calls, so the equivalence is not true by construction.
=======
//! inverses, the permutation is injective, the pair and four-block methods are indistinguishable
//! from two or four single-block calls *including their order*, and the key checks behave. That
//! batching property matters here specifically: this crate overrides `encrypt_2blocks`,
//! `decrypt_2blocks`, `encrypt_4blocks` and `decrypt_4blocks` with its `u32` and `u64` plane
//! paths, so the default implementations are not what runs.
>>>>>>> 5393bea (* BIG CHANGE: refactored this from Pornin's 32-bit bitsliced impl to be able to handle `Planes<T>` with T: u16 (for single bloc), u32 (for 2block), and u64 (for 4block).)

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
