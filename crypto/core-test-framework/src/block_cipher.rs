//! Shared conformance tests for [`BlockCipherEncryptor`] / [`BlockCipherDecryptor`] implementors:
//! the whole-block refinement of the symmetric cipher traits.

use crate::{DUMMY_SEED, FixedSeedRNG};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor};

/// Instance of the test framework.
pub struct TestFrameworkBlockCipher {
    // Put any config options here
}

impl TestFrameworkBlockCipher {
    ///
    pub fn new() -> Self {
        Self {}
    }

    ///
    pub fn test<
        const KEY_LEN: usize,
        const INIT_DATA_LEN: usize,
        const BLOCK_LEN: usize,
        E: BlockCipherEncryptor<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
        D: BlockCipherDecryptor<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
    >(
        &self,
    ) {
        let key = KeyMaterial::<KEY_LEN>::from_bytes_as_type(
            &DUMMY_SEED[..KEY_LEN],
            KeyType::SymmetricCipherKey,
        )
        .unwrap();

        // to test blocks, we'll chunk our dummy seed
        let (mut encryptor, iv) = E::do_encrypt_init(&key).unwrap();
        let mut decryptor = D::do_decrypt_init(&key, &iv).unwrap();

        // one block at a time, through the flat streaming methods (LEN = BLOCK_LEN), in place
        for msg_chunk in DUMMY_SEED.as_chunks::<BLOCK_LEN>().0.iter() {
            let mut buf = *msg_chunk;
            encryptor.do_encrypt_inplace(&mut buf).unwrap();
            decryptor.do_decrypt_inplace(&mut buf).unwrap();
            assert_eq!(msg_chunk, &buf);
        }

        // multi-block (two at a time) through the implementor hook `do_*_blocks`: blocks encrypted together
        // must decrypt both together and one at a time, and blocks encrypted one at a time must
        // decrypt together.
        let (mut encryptor, iv) = E::do_encrypt_init(&key).unwrap();
        let mut decryptor = D::do_decrypt_init(&key, &iv).unwrap();

        for msg_pair in DUMMY_SEED.as_chunks::<BLOCK_LEN>().0.as_chunks::<2>().0.iter() {
            // encrypt together, decrypt together
            let mut buf = *msg_pair;
            encryptor.do_encrypt_blocks_inplace(&mut buf).unwrap();
            decryptor.do_decrypt_blocks_inplace(&mut buf).unwrap();
            assert_eq!(msg_pair, &buf);

            // encrypt together, decrypt one at a time
            let mut buf = *msg_pair;
            encryptor.do_encrypt_blocks_inplace(&mut buf).unwrap();
            for (msg_chunk, block) in msg_pair.iter().zip(buf.iter_mut()) {
                decryptor.do_decrypt_inplace(block).unwrap();
                assert_eq!(msg_chunk, block);
            }

            // encrypt one at a time, decrypt together
            let mut buf = *msg_pair;
            for block in buf.iter_mut() {
                encryptor.do_encrypt_inplace(block).unwrap();
            }
            decryptor.do_decrypt_blocks_inplace(&mut buf).unwrap();
            assert_eq!(msg_pair, &buf);
        }

        // one-shot API: a block-aligned byte array, in place. It must round-trip and agree with the
        // streaming API for the same key and init data. Only LEN = BLOCK_LEN can be formed
        // generically here (`2 * BLOCK_LEN` needs generic_const_exprs); multi-block one-shots are
        // covered by the modes crate's tests with a concrete BLOCK_LEN.
        let one_block: &[u8; BLOCK_LEN] = &DUMMY_SEED.as_chunks::<BLOCK_LEN>().0[0];
        let mut buf = *one_block;
        let (n, iv) = E::encrypt_inplace(&key, &mut buf).unwrap();
        assert_eq!(n, BLOCK_LEN, "encrypt must report the number of bytes written");
        let ct = buf;
        let n = D::decrypt_inplace(&key, &iv, &mut buf).unwrap();
        assert_eq!(n, BLOCK_LEN, "decrypt must report the number of bytes written");
        assert_eq!(buf, *one_block);
        // ...and it must agree with the streaming API under the same init data.
        let mut streamed = D::do_decrypt_init(&key, &iv).unwrap();
        let mut buf = ct;
        streamed.do_decrypt_inplace(&mut buf).unwrap();
        assert_eq!(buf, *one_block);

        // The RNG-taking constructor is only exercised for a cipher that has init data to
        // generate. Its contract requires an implementation with `INIT_DATA_LEN == 0` (ECB) to
        // panic instead, so driving it here would fail that implementor for conforming.
        if INIT_DATA_LEN > 0 {
            // the RNG-taking one-shot must give the streaming API's answer for the same RNG stream
            let pinned = [0xA5u8; INIT_DATA_LEN];
            let mut expected = *one_block;
            let (mut streamed, iv_streamed) =
                E::do_encrypt_init_rng(&key, &mut FixedSeedRNG::<INIT_DATA_LEN>::new(pinned))
                    .unwrap();
            streamed.do_encrypt_inplace(&mut expected).unwrap();
            let mut buf = *one_block;
            let (n, iv) = E::encrypt_rng_inplace(
                &key,
                &mut FixedSeedRNG::<INIT_DATA_LEN>::new(pinned),
                &mut buf,
            )
            .unwrap();
            assert_eq!(n, BLOCK_LEN, "encrypt_rng must report the number of bytes written");
            assert_eq!(iv, iv_streamed);
            assert_eq!(buf, expected);
        }

        // test that the iv is random (ie not the same on two runs). A mode with no init data at all
        // (ECB, INIT_DATA_LEN == 0) has nothing to compare: two empty arrays are always equal.
        if INIT_DATA_LEN > 0 {
            let (_encryptor, iv1) = E::do_encrypt_init(&key).unwrap();
            let (_encryptor, iv2) = E::do_encrypt_init(&key).unwrap();
            assert_ne!(iv1, iv2);
        }

        // error case: KeyMaterial of wrong type
        let mac_key =
            KeyMaterial::<KEY_LEN>::from_bytes_as_type(&DUMMY_SEED[..KEY_LEN], KeyType::MACKey)
                .unwrap();
        match E::do_encrypt_init(&mac_key) {
            Err(SymmetricCipherError::KeyMaterialError(_)) => { /* good */ }
            _ => panic!("Unexpected error"),
        };

        // error case: security strengths too weak and too strong
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
        let mut strengths_tested = 0;
        for ss in security_strengths.iter() {
            // `set_security_strength` enforces its key-length guard even inside a
            // do_hazardous_operations() closure -- a KEY_LEN-byte key cannot be tagged at a
            // strength above `from_bytes(KEY_LEN)` -- so skip the strengths this key cannot carry
            // rather than unwrapping an error. (A 16-byte key can reach 128-bit and no higher.)
            // Do NOT "fix" this by relaxing that guard in `KeyMaterial`: core's
            // `test_hazardous_ops_error_handling` requires it to stay enforced.
            if ss > &SecurityStrength::from_bytes(KEY_LEN) {
                continue;
            }
            // Inside a do_hazardous_operations() closure set_security_strength() raises the
            // strength without complaining; any error here is a framework bug, hence unwrap().
            do_hazardous_operations(&mut key, |key| key.set_security_strength(ss.clone())).unwrap();
            strengths_tested += 1;

            match E::do_encrypt_init(&key) {
                Ok(_) => {
                    if ss >= &E::MAX_SECURITY_STRENGTH { /* good */
                    } else {
                        panic!("Should have been a strong enough key");
                    }
                }
                Err(SymmetricCipherError::KeyMaterialError(_)) => {
                    if ss < &E::MAX_SECURITY_STRENGTH { /* good */
                    } else {
                        panic!("Should not have accepted a key weaker than algorithm");
                    }
                }
                _ => panic!("Unexpected error"),
            };
        }
        assert!(strengths_tested > 0, "strength sweep must not be vacuous");
    }
}
