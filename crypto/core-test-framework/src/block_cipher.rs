//! Shared conformance tests for [`BlockCipherEncryptor`] / [`BlockCipherDecryptor`] implementors:
//! the whole-block refinement of the symmetric cipher traits.

use crate::{DUMMY_SEED, FixedSeedRNG};
use bouncycastle_core::hazmat::{EcbDecryptionKey, EcbEncryptionKey};
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

    /// The block-cipher contract over a [`BlockEncryptionKey`] / [`BlockDecryptionKey`] pair, with
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
        streamed.do_decrypt_inplace(&mut buf).unwrap();
        assert_eq!(buf, *one_block);

        // the RNG-driven one-shot must give the streaming API's answer for the same RNG stream
        let pinned = [0xA5u8; INIT_DATA_LEN];
        let mut expected = *one_block;
        let (mut streamed, iv_streamed) =
            key.create_encryptor(&mut FixedSeedRNG::<INIT_DATA_LEN>::new(pinned)).unwrap();
        streamed.do_encrypt_inplace(&mut expected).unwrap();
        let mut buf = *one_block;
        let (n, iv) =
            key.encrypt_inplace(&mut FixedSeedRNG::<INIT_DATA_LEN>::new(pinned), &mut buf).unwrap();
        assert_eq!(n, BLOCK_LEN, "encrypt_inplace must report the number of bytes written");
        assert_eq!(iv, iv_streamed);
        assert_eq!(buf, expected);

        // the iv is random: not the same on two runs
        let (_encryptor, iv1) = key.create_encryptor(rng).unwrap();
        let (_encryptor, iv2) = key.create_encryptor(rng).unwrap();
        assert_ne!(iv1, iv2);
    }

    /// The same contract over an [`EcbEncryptionKey`] / [`EcbDecryptionKey`] pair: no init
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
        streamed.do_decrypt_inplace(&mut buf).unwrap();
        assert_eq!(buf, *one_block);

        // with no init data the codebook is fixed: the same block encrypts the same way twice
        let mut again = *one_block;
        key.encrypt_inplace(&mut again).unwrap();
        assert_eq!(again, ct);
    }

    /// One block at a time, through the flat streaming methods (LEN = BLOCK_LEN), in place.
    fn round_trip_blocks<
        const INIT_DATA_LEN: usize,
        const BLOCK_LEN: usize,
        E: BlockCipherEncryptor<INIT_DATA_LEN, BLOCK_LEN>,
        D: BlockCipherDecryptor<INIT_DATA_LEN, BLOCK_LEN>,
    >(
        encryptor: &mut E,
        decryptor: &mut D,
    ) {
        for msg_chunk in DUMMY_SEED.as_chunks::<BLOCK_LEN>().0.iter() {
            let mut buf = *msg_chunk;
            encryptor.do_encrypt_inplace(&mut buf).unwrap();
            decryptor.do_decrypt_inplace(&mut buf).unwrap();
            assert_eq!(msg_chunk, &buf);
        }
    }

    /// Two blocks at a time through the implementor hook `do_*_blocks_inplace`: blocks encrypted
    /// together must decrypt both together and one at a time, and blocks encrypted one at a time
    /// must decrypt together.
    fn round_trip_pairs<
        const INIT_DATA_LEN: usize,
        const BLOCK_LEN: usize,
        E: BlockCipherEncryptor<INIT_DATA_LEN, BLOCK_LEN>,
        D: BlockCipherDecryptor<INIT_DATA_LEN, BLOCK_LEN>,
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
                decryptor.do_decrypt_inplace(block).unwrap();
                assert_eq!(msg_chunk, block);
            }

            let mut buf = *msg_pair;
            for block in buf.iter_mut() {
                encryptor.do_encrypt_inplace(block).unwrap();
            }
            decryptor.do_decrypt_blocks_inplace(&mut buf).unwrap();
            assert_eq!(msg_pair, &buf);
        }
    }
}
