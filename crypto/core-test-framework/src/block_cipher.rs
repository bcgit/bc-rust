//! Shared conformance tests for [`BlockCipherEncryptor`] / [`BlockCipherDecryptor`] implementors:
//! the whole-block refinement of the symmetric cipher traits.

use crate::{DUMMY_SEED, FixedSeedRNG};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::hazmat::{EcbDecryptionKey, EcbEncryptionKey};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{BlockDecryptionKey, BlockEncryptionKey};
use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor, RNG};

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
                decryptor.do_decrypt_blocks_inplace(block.as_chunks_mut().0).unwrap();
                assert_eq!(msg_chunk, block);
            }

            // encrypt one at a time, decrypt together
            let mut buf = *msg_pair;
            for block in buf.iter_mut() {
                encryptor.do_encrypt_blocks_inplace(block.as_chunks_mut().0).unwrap();
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
        streamed.do_decrypt_blocks_inplace(buf.as_chunks_mut().0).unwrap();
        assert_eq!(buf, *one_block);

        // The one-shots take a runtime length, so they must refuse data that is not a whole number
        // of blocks, before touching it.
        for len in [1, BLOCK_LEN - 1, BLOCK_LEN + 1, 2 * BLOCK_LEN + 1] {
            let mut bad = DUMMY_SEED[..len].to_vec();
            assert!(
                matches!(
                    E::encrypt_inplace(&key, &mut bad),
                    Err(SymmetricCipherError::DataNotBlockAligned)
                ),
                "len {len}: an unaligned plaintext must be refused"
            );
            // The RNG one-shot is only driven for a cipher with init data; see below.
            if INIT_DATA_LEN > 0 {
                assert!(
                    matches!(
                        E::encrypt_rng_inplace(
                            &key,
                            &mut FixedSeedRNG::<INIT_DATA_LEN>::new([0xA5u8; INIT_DATA_LEN]),
                            &mut bad
                        ),
                        Err(SymmetricCipherError::DataNotBlockAligned)
                    ),
                    "len {len}: an unaligned plaintext must be refused by the RNG one-shot"
                );
            }
            assert!(
                matches!(
                    D::decrypt_inplace(&key, &iv, &mut bad),
                    Err(SymmetricCipherError::DataNotBlockAligned)
                ),
                "len {len}: an unaligned ciphertext must be refused"
            );
            assert_eq!(bad, DUMMY_SEED[..len], "len {len}: refused data must be untouched");
        }

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
            streamed.do_encrypt_blocks_inplace(expected.as_chunks_mut().0).unwrap();
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
    /// The [`BlockEncryptionKey`] / [`BlockDecryptionKey`] form of [`test`](Self::test), with
    /// `rng` supplying every init data draw. The key-policy checks are
    /// `TestFrameworkFromKeyMaterial`'s.
    pub fn test_key<
        const KEY_LEN: usize,
        const INIT_DATA_LEN: usize,
        const BLOCK_LEN: usize,
        K: BlockEncryptionKey<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>
            + BlockDecryptionKey<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
    >(
        &self,
        key: &K,
        rng: &mut dyn RNG,
    ) {
        let (mut encryptor, iv) = key.create_encryptor(rng).unwrap();
        let mut decryptor = key.create_decryptor(&iv);
        Self::round_trip_blocks(&mut encryptor, &mut decryptor);

        let (mut encryptor, iv) = key.create_encryptor(rng).unwrap();
        let mut decryptor = key.create_decryptor(&iv);
        Self::round_trip_pairs(&mut encryptor, &mut decryptor);

        // one-shot API: a block-aligned byte array, in place; see `test`.
        let one_block: &[u8; BLOCK_LEN] = &DUMMY_SEED.as_chunks::<BLOCK_LEN>().0[0];
        let mut buf = *one_block;
        let (n, iv) = key.encrypt_inplace(rng, &mut buf).unwrap();
        assert_eq!(n, BLOCK_LEN, "encrypt must report the number of bytes written");
        let ct = buf;
        let n = key.decrypt_inplace(&iv, &mut buf).unwrap();
        assert_eq!(n, BLOCK_LEN, "decrypt must report the number of bytes written");
        assert_eq!(buf, *one_block);
        let mut streamed = key.create_decryptor(&iv);
        let mut buf = ct;
        streamed.do_decrypt_blocks_inplace(core::slice::from_mut(&mut buf)).unwrap();
        assert_eq!(buf, *one_block);

        // the RNG-driven one-shot must give the streaming API's answer for the same RNG stream
        let pinned = [0xA5u8; INIT_DATA_LEN];
        let mut expected = *one_block;
        let (mut streamed, iv_streamed) =
            key.create_encryptor(&mut FixedSeedRNG::<INIT_DATA_LEN>::new(pinned)).unwrap();
        streamed.do_encrypt_blocks_inplace(core::slice::from_mut(&mut expected)).unwrap();
        let mut buf = *one_block;
        let (n, iv) =
            key.encrypt_inplace(&mut FixedSeedRNG::<INIT_DATA_LEN>::new(pinned), &mut buf).unwrap();
        assert_eq!(n, BLOCK_LEN, "encrypt_inplace must report the number of bytes written");
        assert_eq!(iv, iv_streamed);
        assert_eq!(buf, expected);

        // The one-shots take a runtime length, so they must refuse data that is not a whole number
        // of blocks, before touching it.
        for len in [1, BLOCK_LEN - 1, BLOCK_LEN + 1, 2 * BLOCK_LEN + 1] {
            let mut bad = DUMMY_SEED[..len].to_vec();
            assert!(
                matches!(
                    key.encrypt_inplace(rng, &mut bad),
                    Err(SymmetricCipherError::DataNotBlockAligned)
                ),
                "len {len}: an unaligned plaintext must be refused"
            );
            assert!(
                matches!(
                    key.decrypt_inplace(&iv, &mut bad),
                    Err(SymmetricCipherError::DataNotBlockAligned)
                ),
                "len {len}: an unaligned ciphertext must be refused"
            );
            assert_eq!(bad, DUMMY_SEED[..len], "len {len}: refused data must be untouched");
        }

        // the iv is random: not the same on two runs
        let (_encryptor, iv1) = key.create_encryptor(rng).unwrap();
        let (_encryptor, iv2) = key.create_encryptor(rng).unwrap();
        assert_ne!(iv1, iv2);
    }

    /// The [`EcbEncryptionKey`] / [`EcbDecryptionKey`] form of [`test`](Self::test): no init
    /// data, so nothing is drawn and nothing can differ between two runs.
    pub fn test_ecb_key<
        const KEY_LEN: usize,
        const BLOCK_LEN: usize,
        K: EcbEncryptionKey<KEY_LEN, BLOCK_LEN> + EcbDecryptionKey<KEY_LEN, BLOCK_LEN>,
    >(
        &self,
        key: &K,
    ) {
        let mut encryptor = key.create_encryptor();
        let mut decryptor = key.create_decryptor();
        Self::round_trip_blocks(&mut encryptor, &mut decryptor);

        let mut encryptor = key.create_encryptor();
        let mut decryptor = key.create_decryptor();
        Self::round_trip_pairs(&mut encryptor, &mut decryptor);

        let one_block: &[u8; BLOCK_LEN] = &DUMMY_SEED.as_chunks::<BLOCK_LEN>().0[0];
        let mut buf = *one_block;
        let n = key.encrypt_inplace(&mut buf).unwrap();
        assert_eq!(n, BLOCK_LEN, "encrypt must report the number of bytes written");
        let ct = buf;
        assert_ne!(ct, *one_block, "encryption must change the block");
        let n = key.decrypt_inplace(&mut buf).unwrap();
        assert_eq!(n, BLOCK_LEN, "decrypt must report the number of bytes written");
        assert_eq!(buf, *one_block);
        let mut streamed = key.create_decryptor();
        let mut buf = ct;
        streamed.do_decrypt_blocks_inplace(core::slice::from_mut(&mut buf)).unwrap();
        assert_eq!(buf, *one_block);

        // The one-shots take a runtime length, so they must refuse data that is not a whole number
        // of blocks, before touching it.
        for len in [1, BLOCK_LEN - 1, BLOCK_LEN + 1] {
            let mut bad = DUMMY_SEED[..len].to_vec();
            assert!(
                matches!(
                    key.encrypt_inplace(&mut bad),
                    Err(SymmetricCipherError::DataNotBlockAligned)
                ),
                "len {len}: an unaligned plaintext must be refused"
            );
            assert!(
                matches!(
                    key.decrypt_inplace(&mut bad),
                    Err(SymmetricCipherError::DataNotBlockAligned)
                ),
                "len {len}: an unaligned ciphertext must be refused"
            );
            assert_eq!(bad, DUMMY_SEED[..len], "len {len}: refused data must be untouched");
        }

        // with no init data the codebook is fixed: the same block encrypts the same way twice
        let mut again = *one_block;
        key.encrypt_inplace(&mut again).unwrap();
        assert_eq!(again, ct);
    }

    /// One block at a time, through the flat streaming methods (LEN = BLOCK_LEN), in place.
    fn round_trip_blocks<
        const KEY_LEN: usize,
        const INIT_DATA_LEN: usize,
        const BLOCK_LEN: usize,
        E: BlockCipherEncryptor<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
        D: BlockCipherDecryptor<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
    >(
        encryptor: &mut E,
        decryptor: &mut D,
    ) {
        for msg_chunk in DUMMY_SEED.as_chunks::<BLOCK_LEN>().0.iter() {
            let mut buf = *msg_chunk;
            encryptor.do_encrypt_blocks_inplace(core::slice::from_mut(&mut buf)).unwrap();
            decryptor.do_decrypt_blocks_inplace(core::slice::from_mut(&mut buf)).unwrap();
            assert_eq!(msg_chunk, &buf);
        }
    }

    /// Two blocks at a time through the implementor hook `do_*_blocks_inplace`: blocks encrypted
    /// together must decrypt both together and one at a time, and blocks encrypted one at a time
    /// must decrypt together.
    fn round_trip_pairs<
        const KEY_LEN: usize,
        const INIT_DATA_LEN: usize,
        const BLOCK_LEN: usize,
        E: BlockCipherEncryptor<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
        D: BlockCipherDecryptor<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
    >(
        encryptor: &mut E,
        decryptor: &mut D,
    ) {
        for msg_pair in DUMMY_SEED.as_chunks::<BLOCK_LEN>().0.as_chunks::<2>().0.iter() {
            let mut buf = *msg_pair;
            encryptor.do_encrypt_blocks_inplace(&mut buf).unwrap();
            decryptor.do_decrypt_blocks_inplace(&mut buf).unwrap();
            assert_eq!(msg_pair, &buf);

            let mut buf = *msg_pair;
            encryptor.do_encrypt_blocks_inplace(&mut buf).unwrap();
            for (msg_chunk, block) in msg_pair.iter().zip(buf.iter_mut()) {
                decryptor.do_decrypt_blocks_inplace(core::slice::from_mut(block)).unwrap();
                assert_eq!(msg_chunk, block);
            }

            let mut buf = *msg_pair;
            for block in buf.iter_mut() {
                encryptor.do_encrypt_blocks_inplace(core::slice::from_mut(block)).unwrap();
            }
            decryptor.do_decrypt_blocks_inplace(&mut buf).unwrap();
            assert_eq!(msg_pair, &buf);
        }
    }
}
