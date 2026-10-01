//! Pins [`ToyBlockCipher`] to the [`ElectronicCodeBook`] contract through this crate's own
//! conformance suite, so that a crate using the toy as a stand-in can rely on it behaving like a
//! real implementor: both directions are inverses, the permutation is injective, the batch
//! methods agree with the single-block ones, and the key policy is enforced.
//!
//! [`ElectronicCodeBook`]: bouncycastle_core::hazmat::ElectronicCodeBook

use bouncycastle_core_test_framework::electronic_code_book::TestFrameworkElectronicCodeBook;
use bouncycastle_core_test_framework::{TOY_BLOCK_LEN, ToyBlockCipher};

#[test]
fn the_toy_block_cipher_conforms_to_the_trait() {
    TestFrameworkElectronicCodeBook::new().test::<TOY_BLOCK_LEN, TOY_BLOCK_LEN, ToyBlockCipher>();
}
