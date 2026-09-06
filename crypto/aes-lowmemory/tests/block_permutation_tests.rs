//! `BlockPermutation` trait conformance, via the shared test framework.
//!
//! The framework checks the properties every implementor must have -- both directions are
//! inverses, the permutation is injective, the pair methods are indistinguishable from two
//! single-block calls *including their order*, and the key checks behave. That last pair of
//! properties matters here specifically: this crate overrides `encrypt_blocks2` and
//! `decrypt_blocks2`, so the default implementation is not what runs.

use bouncycastle_aes_lowmemory::{Aes128, Aes192, Aes256, BLOCK_LEN};
use bouncycastle_core_test_framework::block_permutation::TestFrameworkBlockPermutation;

#[test]
fn aes128_conforms_to_block_permutation() {
    TestFrameworkBlockPermutation::new().test::<16, BLOCK_LEN, Aes128>();
}

#[test]
fn aes192_conforms_to_block_permutation() {
    TestFrameworkBlockPermutation::new().test::<24, BLOCK_LEN, Aes192>();
}

#[test]
fn aes256_conforms_to_block_permutation() {
    TestFrameworkBlockPermutation::new().test::<32, BLOCK_LEN, Aes256>();
}
