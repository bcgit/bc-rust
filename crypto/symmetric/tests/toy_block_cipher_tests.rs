//! Pins the toy permutation in `common/toy_block_cipher.rs` to the [`ElectronicCodeBook`]
//! contract through the shared conformance suite, so that the doctests and tests using it as a
//! stand-in can rely on it behaving like a real implementor: both directions are inverses, the
//! permutation is injective, the batch methods agree with the single-block ones, and the key
//! policy is enforced.
//!
//! [`ElectronicCodeBook`]: bouncycastle_core::hazmat::ElectronicCodeBook

#[path = "common/toy_block_cipher.rs"]
mod toy_block_cipher;

use bouncycastle_core_test_framework::electronic_code_book::TestFrameworkElectronicCodeBook;
use toy_block_cipher::{TOY_BLOCK_LEN, ToyBlockCipher};

#[test]
fn the_toy_block_cipher_conforms_to_the_trait() {
    TestFrameworkElectronicCodeBook::new().test::<TOY_BLOCK_LEN, TOY_BLOCK_LEN, ToyBlockCipher>();
}
