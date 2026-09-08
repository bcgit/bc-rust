//! Generic behaviour tests for the symmetric cipher traits.

use crate::{DUMMY_SEED, FixedSeedRNG};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::{
    KeyMaterial, KeyMaterialTrait, KeyType, do_hazardous_operations,
};
use bouncycastle_core::traits::{
    AEADCipher, BlockCipherDecryptor, BlockCipherEncryptor, SecurityStrength, StreamCipher,
    SymmetricCipher, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};

/// Instance of the test framework.
pub struct TestFrameworkSymmetricCipher {
    /// For [`test_encryptor_decryptor`](Self::test_encryptor_decryptor): the plaintext length
    /// granularity the pair accepts. 1 (the default) means every length round-trips. A larger value
    /// -- the block length, for a `PaddedEncryptor` over `NoPadding` -- means only multiples of it
    /// round-trip, and every other length must be *rejected* by `do_final` / `encrypt_out` with a
    /// `PaddingError`, which the test then asserts instead.
    pub required_alignment: usize,
}

impl TestFrameworkSymmetricCipher {
    ///
    pub fn new() -> Self {
        Self { required_alignment: 1 }
    }

    /// Test all the members of trait SymmetricCipher against the given input-output pair.
    /// This gives good baseline test coverage, but is not exhaustive.
    pub fn test<
        const KEY_LEN: usize,
        const INIT_DATA_LEN: usize,
        C: SymmetricCipher<KEY_LEN, INIT_DATA_LEN>,
    >(
        &self,
    ) {
        let msg = b"The quick brown fox jumps over the lazy dog";

        let key = KeyMaterial::<KEY_LEN>::from_bytes_as_type(
            &DUMMY_SEED[..KEY_LEN],
            KeyType::SymmetricCipherKey,
        )
        .unwrap();

        // one-shot API
        let mut ct = [0u8; 1024];
        let (iv, ct_bytes_written) = C::encrypt_out(&key, msg, &mut ct).unwrap();
        assert_ne!(ct_bytes_written, 0);

        let mut pt = [0u8; 1024];
        let pt_bytes_written = C::decrypt_out(&key, iv, &ct[..ct_bytes_written], &mut pt).unwrap();
        assert_ne!(pt_bytes_written, 0);
        assert_eq!(msg, &pt[..pt_bytes_written]);

        // todo -- add tests for encrypt() / decrypt() wrapped in a #[cfg(std)]

        // messing with the ciphertext does not give back the same plaintext (or failing to decrypt is also ok)
        ct[17] ^= 0xFF;
        match C::decrypt_out(&key, iv, &ct[..ct_bytes_written], &mut pt) {
            Ok(bytes_written) => {
                // so it decrypted something, but it had better not match the original plaintext
                assert_eq!(bytes_written, pt_bytes_written);
                assert_ne!(&pt[..bytes_written], msg);
            }
            Err(SymmetricCipherError::DecryptionFailed) => { /* also ok */ }
            _ => panic!("Unexpected error"),
        };

        // error case: KeyMaterial of wrong type
        let mac_key =
            KeyMaterial::<KEY_LEN>::from_bytes_as_type(&DUMMY_SEED[..KEY_LEN], KeyType::MACKey)
                .unwrap();
        match C::encrypt_out(&mac_key, msg, &mut ct) {
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
            // A key can only carry a strength its length supports (a 16-byte key cannot be
            // tagged at 192- or 256-bit), so strengths above the key length do not apply to
            // this cipher.
            if *ss > SecurityStrength::from_bytes(KEY_LEN) {
                continue;
            }
            // Inside a do_hazardous_operations() closure set_security_strength() raises the
            // strength without complaining; any error here is a framework bug, hence unwrap().
            do_hazardous_operations(&mut key, |key| key.set_security_strength(ss.clone())).unwrap();
            strengths_tested += 1;

            match C::encrypt_out(&key, msg, &mut ct) {
                Ok(_) => {
                    if ss >= &C::MAX_SECURITY_STRENGTH { /* good */
                    } else {
                        panic!("Should have been a strong enough key");
                    }
                }
                Err(SymmetricCipherError::KeyMaterialError(_)) => {
                    if ss < &C::MAX_SECURITY_STRENGTH { /* good */
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

impl TestFrameworkSymmetricCipher {
    /// Exercises the [`SymmetricCipherEncryptor`] / [`SymmetricCipherDecryptor`] contract for a
    /// paired implementor.
    ///
    /// Checks, in order:
    /// * the one-shot `encrypt_out` / `decrypt_out` round-trip for every plaintext length from
    ///   0 to a few times `FINAL_LEN`, writing exactly `encrypt_out_len` bytes and at most
    ///   `decrypt_out_max_len`;
    /// * the `std` one-shots agree with the `_out` ones;
    /// * streaming in every chunking agrees with the one-shot, `update_out_len` is exact on every
    ///   call, and `do_final_out` agrees with `do_final`;
    /// * a driven RNG reproduces its init data, and the same key and init data give the same
    ///   ciphertext through `do_encrypt_init_rng` and `encrypt_out_rng`;
    /// * a corrupted ciphertext either fails to decrypt or decrypts to something else;
    /// * an output buffer that is too short is refused, naming the required length, before any
    ///   work is done;
    /// * a key of the wrong [`KeyType`] is rejected, and the security-strength policy matches
    ///   [`Algorithm::MAX_SECURITY_STRENGTH`].
    ///
    /// [`Algorithm::MAX_SECURITY_STRENGTH`]: bouncycastle_core::traits::Algorithm::MAX_SECURITY_STRENGTH
    pub fn test_encryptor_decryptor<
        const KEY_LEN: usize,
        const INIT_DATA_LEN: usize,
        const FINAL_LEN: usize,
        E: SymmetricCipherEncryptor<KEY_LEN, INIT_DATA_LEN, FINAL_LEN>,
        D: SymmetricCipherDecryptor<KEY_LEN, INIT_DATA_LEN, FINAL_LEN>,
    >(
        &self,
    ) {
        let key = KeyMaterial::<KEY_LEN>::from_bytes_as_type(
            &DUMMY_SEED[..KEY_LEN],
            KeyType::SymmetricCipherKey,
        )
        .unwrap();
        // Enough plaintext lengths to cross several final-chunk boundaries (a block, for padding).
        let align = self.required_alignment.max(1);
        let max_len = (3 * FINAL_LEN.max(1) + 5).next_multiple_of(align);

        // one-shot round trip, every (accepted) length; every other length must be refused
        for len in 0..=max_len {
            let msg = &DUMMY_SEED[..len];
            if !len.is_multiple_of(align) {
                let mut ct = vec![0u8; E::encrypt_out_len(len) + FINAL_LEN];
                match E::encrypt_out(&key, msg, &mut ct) {
                    Err(SymmetricCipherError::PaddingError(_)) => {}
                    other => panic!("len {len} is not aligned and must be refused, got {other:?}"),
                }
                let (mut enc, _) = E::do_encrypt_init(&key).unwrap();
                let mut buf = vec![0u8; enc.update_out_len(len)];
                enc.do_update_out(msg, &mut buf).unwrap();
                assert!(
                    matches!(enc.do_final(), Err(SymmetricCipherError::PaddingError(_))),
                    "len {len}: streaming do_final must refuse an unaligned message"
                );
                continue;
            }
            let mut ct = vec![0u8; E::encrypt_out_len(len)];
            let (init_data, ct_len) = E::encrypt_out(&key, msg, &mut ct).unwrap();
            assert_eq!(ct_len, ct.len(), "encrypt_out must write exactly encrypt_out_len bytes");

            let mut pt = vec![0u8; D::decrypt_out_max_len(ct_len)];
            let pt_len = D::decrypt_out(&key, &init_data, &ct[..ct_len], &mut pt).unwrap();
            assert!(pt_len <= pt.len(), "decrypt_out_max_len must bound the plaintext");
            assert_eq!(&pt[..pt_len], msg, "one-shot round trip, len {len}");

            // the std one-shots agree with the _out ones for the same init data
            let (init_data2, ct2) = E::encrypt(&key, msg).unwrap();
            assert_eq!(ct2.len(), ct_len, "encrypt must return exactly the bytes written");
            let pt2 = D::decrypt(&key, &init_data2, &ct2).unwrap();
            assert_eq!(pt2, msg, "std round trip, len {len}");
            let pt3 = D::decrypt(&key, &init_data, &ct[..ct_len]).unwrap();
            assert_eq!(pt3, msg, "decrypt must agree with decrypt_out");
        }

        // streaming in every chunking agrees with the one-shot
        let len = max_len;
        let msg = &DUMMY_SEED[..len];
        let chunkings: [usize; 8] =
            [1, 2, 3, 7, FINAL_LEN.max(1), FINAL_LEN + 1, 2 * FINAL_LEN + 3, len];
        for chunk in chunkings {
            // encrypt in chunks, checking update_out_len is exact each time
            let (mut enc, init_data) = E::do_encrypt_init(&key).unwrap();
            let mut ct = Vec::new();
            for piece in msg.chunks(chunk) {
                let expect = enc.update_out_len(piece.len());
                let mut buf = vec![0u8; expect];
                let n = enc.do_update_out(piece, &mut buf).unwrap();
                assert_eq!(n, expect, "update_out_len must be exact (encrypt, chunk {chunk})");
                ct.extend_from_slice(&buf[..n]);
            }
            let mut last = [0u8; FINAL_LEN];
            let last_len = enc.do_final_out(&mut last).unwrap();
            assert!(last_len <= FINAL_LEN, "do_final_out must not claim more than FINAL_LEN bytes");
            ct.extend_from_slice(&last[..last_len]);
            assert_eq!(
                ct.len(),
                E::encrypt_out_len(len),
                "streaming total must match encrypt_out_len"
            );

            // one-shot decrypt of the streamed ciphertext
            let mut pt = vec![0u8; D::decrypt_out_max_len(ct.len())];
            let m = D::decrypt_out(&key, &init_data, &ct, &mut pt).unwrap();
            assert_eq!(
                &pt[..m],
                msg,
                "streamed ciphertext must decrypt in one shot (chunk {chunk})"
            );

            // decrypt in the same chunks, via do_final and via do_final_out
            for use_out in [false, true] {
                let mut dec = D::do_decrypt_init(&key, &init_data).unwrap();
                let mut rec = Vec::new();
                for piece in ct.chunks(chunk) {
                    let expect = dec.update_out_len(piece.len());
                    let mut buf = vec![0u8; expect];
                    let n = dec.do_update_out(piece, &mut buf).unwrap();
                    assert_eq!(n, expect, "update_out_len must be exact (decrypt, chunk {chunk})");
                    rec.extend_from_slice(&buf[..n]);
                }
                let (block, data_len) = if use_out {
                    let mut block = [0u8; FINAL_LEN];
                    let data_len = dec.do_final_out(&mut block).unwrap();
                    (block, data_len)
                } else {
                    dec.do_final().unwrap()
                };
                rec.extend_from_slice(&block[..data_len]);
                assert_eq!(rec, msg, "streamed round trip (chunk {chunk}, do_final_out {use_out})");
            }
        }

        // a driven RNG reproduces its init data, and determines the ciphertext
        let seed: [u8; INIT_DATA_LEN] = core::array::from_fn(|i| DUMMY_SEED[100 + i]);
        let (mut enc, init_data) =
            E::do_encrypt_init_rng(&key, &mut FixedSeedRNG::<INIT_DATA_LEN>::new(seed)).unwrap();
        assert_eq!(init_data, seed, "a fixed RNG must yield its stream as the init data");
        let mut streamed = vec![0u8; enc.update_out_len(len)];
        let n = enc.do_update_out(msg, &mut streamed).unwrap();
        streamed.truncate(n);
        let (last, last_len) = enc.do_final().unwrap();
        streamed.extend_from_slice(&last[..last_len]);
        let mut one_shot = vec![0u8; E::encrypt_out_len(len)];
        let (init_data2, n2) = E::encrypt_out_rng(
            &key,
            &mut FixedSeedRNG::<INIT_DATA_LEN>::new(seed),
            msg,
            &mut one_shot,
        )
        .unwrap();
        assert_eq!(init_data2, seed);
        assert_eq!(
            &one_shot[..n2],
            &streamed[..],
            "same key and init data must give the same ciphertext"
        );

        // corrupting the ciphertext does not give back the plaintext (or fails to decrypt)
        let mut ct = vec![0u8; E::encrypt_out_len(len)];
        let (init_data, ct_len) = E::encrypt_out(&key, msg, &mut ct).unwrap();
        assert!(ct_len > 0, "the test message is non-empty, so its ciphertext must be");
        for flip in [0usize, ct_len / 2, ct_len - 1] {
            let mut bad = ct[..ct_len].to_vec();
            bad[flip] ^= 0x80;
            let mut pt = vec![0u8; D::decrypt_out_max_len(ct_len)];
            match D::decrypt_out(&key, &init_data, &bad, &mut pt) {
                Ok(m) => {
                    assert_ne!(&pt[..m], msg, "corrupted byte {flip} decrypted to the plaintext")
                }
                Err(SymmetricCipherError::DecryptionFailed)
                | Err(SymmetricCipherError::PaddingError(_))
                | Err(SymmetricCipherError::AEADTagCheckFailed) => { /* also fine */ }
                Err(e) => panic!("unexpected error for corrupted byte {flip}: {e:?}"),
            }
        }

        // too-short output buffers are refused with the required length, before any work is done
        let need = E::encrypt_out_len(len);
        let mut short = vec![0u8; need - 1];
        match E::encrypt_out(&key, msg, &mut short) {
            Err(SymmetricCipherError::IncorrectOutputBufferLength(_, n)) => assert_eq!(n, need),
            other => panic!("encrypt_out into a short buffer: {other:?}"),
        }
        let need = D::decrypt_out_max_len(ct_len);
        if need > 0 {
            let mut short = vec![0u8; need - 1];
            match D::decrypt_out(&key, &init_data, &ct[..ct_len], &mut short) {
                Err(SymmetricCipherError::IncorrectOutputBufferLength(_, n)) => assert_eq!(n, need),
                other => panic!("decrypt_out into a short buffer: {other:?}"),
            }
        }
        let (mut enc, _) = E::do_encrypt_init(&key).unwrap();
        let need = enc.update_out_len(len);
        if need > 0 {
            let mut short = vec![0u8; need - 1];
            match enc.do_update_out(msg, &mut short) {
                Err(SymmetricCipherError::IncorrectOutputBufferLength(_, n)) => assert_eq!(n, need),
                other => panic!("do_update_out into a short buffer: {other:?}"),
            }
        }

        // error case: KeyMaterial of the wrong type
        let mac_key =
            KeyMaterial::<KEY_LEN>::from_bytes_as_type(&DUMMY_SEED[..KEY_LEN], KeyType::MACKey)
                .unwrap();
        match E::do_encrypt_init(&mac_key) {
            Err(SymmetricCipherError::KeyMaterialError(_)) => { /* good */ }
            _ => panic!("A key that is not a SymmetricCipherKey should have been rejected"),
        };
        match D::do_decrypt_init(&mac_key, &init_data) {
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
            // Skip the strengths a KEY_LEN-byte key cannot carry; see `TestFrameworkElectronicCodeBook`.
            if ss > &SecurityStrength::from_bytes(KEY_LEN) {
                continue;
            }
            do_hazardous_operations(&mut key, |key| key.set_security_strength(*ss)).unwrap();

            match E::do_encrypt_init(&key) {
                Ok(_) => assert!(
                    ss >= &E::MAX_SECURITY_STRENGTH,
                    "should have required a key at least as strong as the algorithm"
                ),
                Err(SymmetricCipherError::KeyMaterialError(_)) => assert!(
                    ss < &E::MAX_SECURITY_STRENGTH,
                    "should not have rejected a key strong enough for the algorithm"
                ),
                _ => panic!("Unexpected error"),
            };
            match D::do_decrypt_init(&key, &init_data) {
                Ok(_) => assert!(ss >= &D::MAX_SECURITY_STRENGTH),
                Err(SymmetricCipherError::KeyMaterialError(_)) => {
                    assert!(ss < &D::MAX_SECURITY_STRENGTH)
                }
                _ => panic!("Unexpected error"),
            };
        }
    }
}

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
            encryptor.do_encrypt(&mut buf).unwrap();
            decryptor.do_decrypt(&mut buf).unwrap();
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
            encryptor.do_encrypt_blocks(&mut buf).unwrap();
            decryptor.do_decrypt_blocks(&mut buf).unwrap();
            assert_eq!(msg_pair, &buf);

            // encrypt together, decrypt one at a time
            let mut buf = *msg_pair;
            encryptor.do_encrypt_blocks(&mut buf).unwrap();
            for (msg_chunk, block) in msg_pair.iter().zip(buf.iter_mut()) {
                decryptor.do_decrypt(block).unwrap();
                assert_eq!(msg_chunk, block);
            }

            // encrypt one at a time, decrypt together
            let mut buf = *msg_pair;
            for block in buf.iter_mut() {
                encryptor.do_encrypt(block).unwrap();
            }
            decryptor.do_decrypt_blocks(&mut buf).unwrap();
            assert_eq!(msg_pair, &buf);
        }

        // one-shot API: a block-aligned byte array, in place. It must round-trip and agree with the
        // streaming API for the same key and init data. Only LEN = BLOCK_LEN can be formed
        // generically here (`2 * BLOCK_LEN` needs generic_const_exprs); multi-block one-shots are
        // covered by the modes crate's tests with a concrete BLOCK_LEN.
        let one_block: &[u8; BLOCK_LEN] = &DUMMY_SEED.as_chunks::<BLOCK_LEN>().0[0];
        let mut buf = *one_block;
        let iv = E::encrypt(&key, &mut buf).unwrap();
        let ct = buf;
        D::decrypt(&key, &iv, &mut buf).unwrap();
        assert_eq!(buf, *one_block);
        // ...and it must agree with the streaming API under the same init data.
        let mut streamed = D::do_decrypt_init(&key, &iv).unwrap();
        let mut buf = ct;
        streamed.do_decrypt(&mut buf).unwrap();
        assert_eq!(buf, *one_block);

        // the RNG-taking one-shot must give the streaming API's answer for the same RNG stream
        let pinned = [0xA5u8; INIT_DATA_LEN];
        let mut expected = *one_block;
        let (mut streamed, iv_streamed) =
            E::do_encrypt_init_rng(&key, &mut FixedSeedRNG::<INIT_DATA_LEN>::new(pinned)).unwrap();
        streamed.do_encrypt(&mut expected).unwrap();
        let mut buf = *one_block;
        let iv = E::encrypt_rng(&key, &mut FixedSeedRNG::<INIT_DATA_LEN>::new(pinned), &mut buf)
            .unwrap();
        assert_eq!(iv, iv_streamed);
        assert_eq!(buf, expected);

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

/// Instance of the test framework.
pub struct TestFrameworkAEADCipher {
    // Put any config options here
}

impl TestFrameworkAEADCipher {
    ///
    pub fn new() -> Self {
        Self {}
    }

    /// Test all the members of trait AEADCipher against the given input-output pair.
    /// This gives good baseline test coverage, but is not exhaustive.
    pub fn test<
        const KEY_LEN: usize,
        const NONCE_LEN: usize,
        const TAG_LEN: usize,
        C: AEADCipher<KEY_LEN, NONCE_LEN, TAG_LEN>,
    >(
        &self,
    ) {
        let msg = b"The quick brown fox jumps over the lazy dog";
        let aad = b"some associated data";

        let key = KeyMaterial::<KEY_LEN>::from_bytes_as_type(
            &DUMMY_SEED[..KEY_LEN],
            KeyType::SymmetricCipherKey,
        )
        .unwrap();

        // one-shot API
        let mut ct = [0u8; 1024];
        let (nonce, ct_bytes_written, tag) = C::aead_encrypt_out(&key, aad, msg, &mut ct).unwrap();
        if nonce.len() != 0 {
            assert_ne!(nonce, [0u8; NONCE_LEN]);
        }
        assert_ne!(ct_bytes_written, 0);
        assert_ne!(tag, [0u8; TAG_LEN]);

        let mut pt = [0u8; 1024];
        let pt_bytes_written =
            C::aead_decrypt_out(&key, &nonce, aad, &ct[..ct_bytes_written], &tag, &mut pt).unwrap();
        assert_ne!(pt_bytes_written, 0);
        assert_eq!(msg, &pt[..pt_bytes_written]);

        // todo -- add tests for aead_encrypt() / aead_decrypt() wrapped in a #[cfg(std)]

        // Modifying the ciphertext MUST cause an AEAD failure: unlike an unauthenticated cipher,
        // a conformant AEAD must never return plaintext for a ciphertext that fails its tag check.
        ct[17] ^= 0xFF;
        pt[..ct_bytes_written].fill(0xAA);
        match C::aead_decrypt_out(&key, &nonce, aad, &ct[..ct_bytes_written], &tag, &mut pt) {
            Err(SymmetricCipherError::AEADTagCheckFailed) => { /* good */ }
            Err(SymmetricCipherError::DecryptionFailed) => { /* also acceptable */ }
            _ => panic!("Modified ciphertext must fail the AEAD tag check"),
        };
        assert!(
            pt[..ct_bytes_written].iter().all(|&b| b == 0),
            "AEAD must not leave plaintext in the output buffer after a failed tag check"
        );
        // restore the ciphertext so the AAD- and tag-tamper checks below each test one variable
        ct[17] ^= 0xFF;

        // messing with the aad causes the aead_decrypt to fail
        pt[..ct_bytes_written].fill(0xAA);
        match C::aead_decrypt_out(
            &key,
            &nonce,
            b"not the right associated data",
            &ct[..ct_bytes_written],
            &tag,
            &mut pt,
        ) {
            Err(SymmetricCipherError::AEADTagCheckFailed) => { /* good */ }
            _ => panic!("Expected TagCheckFailed error"),
        };
        assert!(
            pt[..ct_bytes_written].iter().all(|&b| b == 0),
            "AEAD must not leave plaintext in the output buffer after a failed tag check"
        );

        // messing with the tag causes the aead_decrypt to fail
        pt[..ct_bytes_written].fill(0xAA);
        match C::aead_decrypt_out(
            &key,
            &nonce,
            aad,
            &ct[..ct_bytes_written],
            &[3u8; TAG_LEN],
            &mut pt,
        ) {
            Err(SymmetricCipherError::AEADTagCheckFailed) => { /* good */ }
            _ => panic!("Expected TagCheckFailed error"),
        };
        assert!(
            pt[..ct_bytes_written].iter().all(|&b| b == 0),
            "AEAD must not leave plaintext in the output buffer after a failed tag check"
        );

        // multiple invocations give different nonces
        let (nonce1, _ct_bytes_written, _tag) =
            C::aead_encrypt_out(&key, aad, msg, &mut ct).unwrap();
        let (nonce2, _ct_bytes_written, _tag) =
            C::aead_encrypt_out(&key, aad, msg, &mut ct).unwrap();
        assert_ne!(nonce1, nonce2);

        // error case: KeyMaterial of wrong type
        let mac_key =
            KeyMaterial::<KEY_LEN>::from_bytes_as_type(&DUMMY_SEED[..KEY_LEN], KeyType::MACKey)
                .unwrap();
        match C::aead_encrypt_out(&mac_key, aad, msg, &mut ct) {
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
            // A key can only carry a strength its length supports (a 16-byte key cannot be
            // tagged at 192- or 256-bit), so strengths above the key length do not apply to
            // this cipher.
            if *ss > SecurityStrength::from_bytes(KEY_LEN) {
                continue;
            }
            // Inside a do_hazardous_operations() closure set_security_strength() raises the
            // strength without complaining; any error here is a framework bug, hence unwrap().
            do_hazardous_operations(&mut key, |key| key.set_security_strength(ss.clone())).unwrap();
            strengths_tested += 1;

            // The key-strength requirement must be enforced both by the AEAD one-shot and by the
            // inherited SymmetricCipher one-shot (encrypt_out), so exercise both.
            let check_strength = |result: Result<(), SymmetricCipherError>| match result {
                Ok(_) => {
                    if ss >= &C::MAX_SECURITY_STRENGTH { /* good */
                    } else {
                        panic!("Should have been a strong enough key");
                    }
                }
                Err(SymmetricCipherError::KeyMaterialError(_)) => {
                    if ss < &C::MAX_SECURITY_STRENGTH { /* good */
                    } else {
                        panic!("Should not have accepted a key weaker than algorithm");
                    }
                }
                _ => panic!("Unexpected error"),
            };
            check_strength(C::aead_encrypt_out(&key, aad, msg, &mut ct).map(|_| ()));
            check_strength(C::encrypt_out(&key, msg, &mut ct).map(|_| ()));
        }
        assert!(strengths_tested > 0, "strength sweep must not be vacuous");
    }
}

/// Instance of the test framework.
pub struct TestFrameworkStreamCipher {
    // Put any config options here
}

impl TestFrameworkStreamCipher {
    ///
    pub fn new() -> Self {
        Self {}
    }

    /// Test all the members of trait StreamCipher against the given input-output pair.
    /// This gives good baseline test coverage, but is not exhaustive.
    pub fn test<
        const KEY_LEN: usize,
        const INIT_DATA_LEN: usize,
        C: StreamCipher<KEY_LEN, INIT_DATA_LEN>,
    >(
        &self,
    ) {
        todo!()
    }
}
