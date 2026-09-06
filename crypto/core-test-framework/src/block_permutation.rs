//! Shared conformance tests for [`BlockPermutation`] implementors.

use crate::DUMMY_SEED;
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::{
    KeyMaterial, KeyMaterialTrait, KeyType, do_hazardous_operations,
};
use bouncycastle_core::traits::{BlockCipher, BlockPermutation, SecurityStrength};

/// Instance of the test framework.
pub struct TestFrameworkBlockPermutation {
    // Put any config options here
}

impl Default for TestFrameworkBlockPermutation {
    fn default() -> Self {
        Self::new()
    }
}

impl TestFrameworkBlockPermutation {
    ///
    pub fn new() -> Self {
        Self {}
    }

    /// Exercises the trait contract for one implementor.
    ///
    /// Checks, in order:
    /// * `decrypt_block` inverts `encrypt_block` on every block of [`DUMMY_SEED`];
    /// * the permutation actually permutes (a block is not left unchanged);
    /// * distinct inputs give distinct outputs, i.e. it is injective on the blocks tested;
    /// * `encrypt_blocks2` agrees with two `encrypt_block` calls **including their order**, and
    ///   likewise for `decrypt_blocks2` -- this is what pins an override to the default's
    ///   semantics, and it is the reason the pair methods are worth having in the trait at all;
    /// * the pair methods round-trip each other;
    /// * a key of the wrong [`KeyType`] is rejected;
    /// * the security-strength policy matches [`BlockCipher::MAX_SECURITY_STRENGTH`].
    pub fn test<
        const KEY_LEN: usize,
        const BLOCK_LEN: usize,
        P: BlockPermutation<KEY_LEN, BLOCK_LEN>,
    >(
        &self,
    ) {
        let key = KeyMaterial::<KEY_LEN>::from_bytes_as_type(
            &DUMMY_SEED[..KEY_LEN],
            KeyType::SymmetricCipherKey,
        )
        .unwrap();
        let perm = P::new(&key).unwrap();

        let blocks = DUMMY_SEED.as_chunks::<BLOCK_LEN>().0;

        // encrypt / decrypt are inverses, and the permutation is not the identity.
        for block in blocks.iter() {
            let mut buf = *block;
            perm.encrypt_block(&mut buf);
            assert_ne!(&buf, block, "encrypt_block must not be the identity");
            perm.decrypt_block(&mut buf);
            assert_eq!(&buf, block, "decrypt_block must invert encrypt_block");

            // ...and the other way round, since a mode may call either direction first.
            let mut buf = *block;
            perm.decrypt_block(&mut buf);
            assert_ne!(&buf, block, "decrypt_block must not be the identity");
            perm.encrypt_block(&mut buf);
            assert_eq!(&buf, block, "encrypt_block must invert decrypt_block");
        }

        // Distinct inputs must give distinct outputs. A permutation is injective, so this catches
        // an implementation that collapses inputs (e.g. one that masks part of the block away).
        for pair in blocks.as_chunks::<2>().0.iter() {
            let [a, b] = pair;
            assert_ne!(a, b, "DUMMY_SEED blocks should differ; test setup problem");
            let mut ea = *a;
            let mut eb = *b;
            perm.encrypt_block(&mut ea);
            perm.encrypt_block(&mut eb);
            assert_ne!(ea, eb, "distinct blocks must encrypt to distinct blocks");
        }

        // The pair methods must be indistinguishable from the single-block ones, in both slots.
        // An override that swapped the two results, or that processed only one of them, fails here.
        for pair in blocks.as_chunks::<2>().0.iter() {
            let [a, b] = pair;

            let mut singly = [*a, *b];
            perm.encrypt_block(&mut singly[0]);
            perm.encrypt_block(&mut singly[1]);
            let mut paired = [*a, *b];
            perm.encrypt_blocks2(&mut paired);
            assert_eq!(paired, singly, "encrypt_blocks2 must match two encrypt_block calls");

            let mut singly = [*a, *b];
            perm.decrypt_block(&mut singly[0]);
            perm.decrypt_block(&mut singly[1]);
            let mut paired = [*a, *b];
            perm.decrypt_blocks2(&mut paired);
            assert_eq!(paired, singly, "decrypt_blocks2 must match two decrypt_block calls");

            // Round-trip through the pair methods alone.
            let mut buf = [*a, *b];
            perm.encrypt_blocks2(&mut buf);
            perm.decrypt_blocks2(&mut buf);
            assert_eq!(buf, [*a, *b], "decrypt_blocks2 must invert encrypt_blocks2");
        }

        // A pair of *identical* blocks must give a pair of identical outputs. This catches an
        // implementation whose two lanes are not actually independent.
        let block = blocks[0];
        let mut buf = [block, block];
        perm.encrypt_blocks2(&mut buf);
        assert_eq!(buf[0], buf[1], "identical inputs must give identical outputs");
        let mut single = block;
        perm.encrypt_block(&mut single);
        assert_eq!(buf[0], single);

        // error case: KeyMaterial of the wrong type
        let mac_key =
            KeyMaterial::<KEY_LEN>::from_bytes_as_type(&DUMMY_SEED[..KEY_LEN], KeyType::MACKey)
                .unwrap();
        match P::new(&mac_key) {
            Err(SymmetricCipherError::KeyMaterialError(_)) => { /* good */ }
            _ => panic!("A key that is not a SymmetricCipherKey should have been rejected"),
        };

        // error case: security strengths too weak, and strong enough
        let mut key = KeyMaterial::<KEY_LEN>::from_bytes_as_type(
            &DUMMY_SEED[..KEY_LEN],
            KeyType::SymmetricCipherKey,
        )
        .unwrap();
        let security_strengths = [
            SecurityStrength::None,
            SecurityStrength::_112bit,
            SecurityStrength::_128bit,
            SecurityStrength::_192bit,
            SecurityStrength::_256bit,
        ];
        for ss in security_strengths.iter() {
            // `set_security_strength` enforces its key-length guard even inside a
            // do_hazardous_operations() closure, so skip the strengths a KEY_LEN-byte key cannot
            // carry. Do NOT relax that guard in `KeyMaterial`: core's
            // `test_hazardous_ops_error_handling` requires it to stay enforced.
            if ss > &SecurityStrength::from_bytes(KEY_LEN) {
                continue;
            }

            // Tag the key at an arbitrary strength for the purpose of this test.
            do_hazardous_operations(&mut key, |key| key.set_security_strength(ss.clone())).unwrap();

            match P::new(&key) {
                Ok(_) => assert!(
                    ss >= &<P as BlockCipher>::MAX_SECURITY_STRENGTH,
                    "should have required a key at least as strong as the algorithm"
                ),
                Err(SymmetricCipherError::KeyMaterialError(_)) => assert!(
                    ss < &<P as BlockCipher>::MAX_SECURITY_STRENGTH,
                    "should not have rejected a key strong enough for the algorithm"
                ),
                _ => panic!("Unexpected error"),
            };
        }
    }
}
