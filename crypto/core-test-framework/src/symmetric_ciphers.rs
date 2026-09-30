//! Generic behaviour tests for the symmetric cipher traits: [`SymmetricCipherEncryptor`] /
//! [`SymmetricCipherDecryptor`] and their stream-cipher refinement. The block-cipher and AEAD
//! refinements have their own runners in [`crate::block_cipher`] and [`crate::aead`].

use crate::{DUMMY_SEED, FixedSeedRNG};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::{
    KeyMaterial, KeyMaterialTrait, KeyType, do_hazardous_operations,
};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    StreamCipherDecryptor, StreamCipherEncryptor, SymmetricCipherDecryptor,
    SymmetricCipherEncryptor,
};

/// Instance of the test framework.
pub struct TestFrameworkSymmetricCipher {
    /// For [`test_encryptor_decryptor`](Self::test_encryptor_decryptor): the plaintext length
    /// granularity the pair accepts. 1 (the default) means every length round-trips. A larger value
    /// -- the block length, for a `PaddedBlockCipherEncryptor` over `NoPadding` -- means only
    /// multiples of it round-trip, and every other length must be *rejected* by `do_final` /
    /// `encrypt_out` with a `PaddingError`, which the test then asserts instead.
    pub required_alignment: usize,
    /// For [`test_encryptor_decryptor`](Self::test_encryptor_decryptor): the longest message the
    /// pair's streaming methods accept. `usize::MAX` (the default) means there is no limit. A
    /// cipher that has to buffer the whole message before it can process any of it -- CCM, whose
    /// `B0` block encodes the payload length -- sets its buffer's capacity here, and the test caps
    /// every message it tries at that length.
    pub max_message_len: usize,
}

impl TestFrameworkSymmetricCipher {
    ///
    pub fn new() -> Self {
        Self { required_alignment: 1, max_message_len: usize::MAX }
    }

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
        let max_len = (3 * FINAL_LEN.max(1) + 5).next_multiple_of(align).min(self.max_message_len);

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
                let mut buf = vec![0u8; enc.do_encrypt_out_len(len)];
                enc.do_encrypt_out(msg, &mut buf).unwrap();
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
                let expect = enc.do_encrypt_out_len(piece.len());
                let mut buf = vec![0u8; expect];
                let n = enc.do_encrypt_out(piece, &mut buf).unwrap();
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
                    let expect = dec.do_decrypt_out_len(piece.len());
                    let mut buf = vec![0u8; expect];
                    let n = dec.do_decrypt_out(piece, &mut buf).unwrap();
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

        // The RNG-taking constructor is only exercised for a cipher that has init data to
        // generate. Its contract requires an implementation with `INIT_DATA_LEN == 0` (ECB) to
        // panic instead, so driving it here would fail that implementor for conforming.
        if INIT_DATA_LEN > 0 {
            // a driven RNG reproduces its init data, and determines the ciphertext
            let seed: [u8; INIT_DATA_LEN] = core::array::from_fn(|i| DUMMY_SEED[100 + i]);
            let (mut enc, init_data) =
                E::do_encrypt_init_rng(&key, &mut FixedSeedRNG::<INIT_DATA_LEN>::new(seed))
                    .unwrap();
            assert_eq!(init_data, seed, "a fixed RNG must yield its stream as the init data");
            let mut streamed = vec![0u8; enc.do_encrypt_out_len(len)];
            let n = enc.do_encrypt_out(msg, &mut streamed).unwrap();
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
        }

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
            Err(SymmetricCipherError::OutputBufferTooSmall(n)) => assert_eq!(n, need),
            other => panic!("encrypt_out into a short buffer: {other:?}"),
        }
        let need = D::decrypt_out_max_len(ct_len);
        if need > 0 {
            let mut short = vec![0u8; need - 1];
            match D::decrypt_out(&key, &init_data, &ct[..ct_len], &mut short) {
                Err(SymmetricCipherError::OutputBufferTooSmall(n)) => assert_eq!(n, need),
                other => panic!("decrypt_out into a short buffer: {other:?}"),
            }
        }
        // ...and ones with room to spare are accepted: without this each `<` guard can be flipped
        // to `>` and the short-buffer probes above still "pass".
        let mut roomy = vec![0u8; E::encrypt_out_len(len) + 3];
        let (_, n) = E::encrypt_out(&key, msg, &mut roomy).unwrap();
        assert_eq!(n, E::encrypt_out_len(len), "encrypt_out into a roomy buffer");
        let mut roomy = vec![0u8; need + 3];
        let n = D::decrypt_out(&key, &init_data, &ct[..ct_len], &mut roomy).unwrap();
        assert_eq!(&roomy[..n], msg, "decrypt_out into a roomy buffer");
        let (mut enc, _) = E::do_encrypt_init(&key).unwrap();
        let need = enc.do_encrypt_out_len(len);
        if need > 0 {
            let mut short = vec![0u8; need - 1];
            match enc.do_encrypt_out(msg, &mut short) {
                Err(SymmetricCipherError::OutputBufferTooSmall(n)) => assert_eq!(n, need),
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
pub struct TestFrameworkStreamCipher {
    // Put any config options here
}

impl TestFrameworkStreamCipher {
    ///
    pub fn new() -> Self {
        Self {}
    }

    /// Test the contract of a [`StreamCipherEncryptor`] / [`StreamCipherDecryptor`] pair: every
    /// chunking of the streaming API agrees with the one-shot and round-trips through the other
    /// direction, the RNG-taking constructors reproduce their init data, and the key-type and
    /// security-strength policy is enforced. This gives good baseline test coverage, but is not
    /// exhaustive; algorithm-specific test vectors belong in the implementing crate.
    pub fn test<
        const KEY_LEN: usize,
        const INIT_DATA_LEN: usize,
        E: StreamCipherEncryptor<KEY_LEN, INIT_DATA_LEN>,
        D: StreamCipherDecryptor<KEY_LEN, INIT_DATA_LEN>,
    >(
        &self,
    ) {
        let key = KeyMaterial::<KEY_LEN>::from_bytes_as_type(
            &DUMMY_SEED[..KEY_LEN],
            KeyType::SymmetricCipherKey,
        )
        .unwrap();

        // one-shot, in place: must round-trip, and report every byte as written.
        let mut buf = *DUMMY_SEED;
        let (n, iv) = E::encrypt_in_place(&key, &mut buf).unwrap();
        assert_eq!(n, buf.len(), "encrypt must report the number of bytes written");
        let reference_ct = buf;
        assert_ne!(&reference_ct[..], &DUMMY_SEED[..], "encryption must change the data");
        let n = D::decrypt_in_place(&key, &iv, &mut buf).unwrap();
        assert_eq!(n, buf.len(), "decrypt must report the number of bytes written");
        assert_eq!(&buf[..], &DUMMY_SEED[..]);

        // the streaming API under the same init data must give the one-shot's answer whatever
        // the chunking, including chunks that are not a multiple of any internal keystream block
        // and empty chunks; and encrypting in one chunking must decrypt in any other.
        let chunkings: &[usize] = &[1, 3, 7, 16, 63, 64, 65, 250, DUMMY_SEED.len()];
        for &enc_chunk in chunkings {
            let mut buf = *DUMMY_SEED;
            let (mut encryptor, iv2) = E::do_encrypt_init(&key).unwrap();
            // stream through the encryptor, with an empty chunk thrown in at the start and end
            encryptor.do_encrypt(&mut []).unwrap();
            for chunk in buf.chunks_mut(enc_chunk) {
                encryptor.do_encrypt(chunk).unwrap();
            }
            encryptor.do_encrypt(&mut []).unwrap();
            let ct = buf;

            for &dec_chunk in chunkings {
                let mut buf = ct;
                let mut decryptor = D::do_decrypt_init(&key, &iv2).unwrap();
                decryptor.do_decrypt(&mut []).unwrap();
                for chunk in buf.chunks_mut(dec_chunk) {
                    decryptor.do_decrypt(chunk).unwrap();
                }
                decryptor.do_decrypt(&mut []).unwrap();
                assert_eq!(
                    &buf[..],
                    &DUMMY_SEED[..],
                    "enc chunk {enc_chunk}, dec chunk {dec_chunk}"
                );
            }

            // and the one-shot decrypt agrees with every streaming encryption
            let mut buf = ct;
            D::decrypt_in_place(&key, &iv2, &mut buf).unwrap();
            assert_eq!(&buf[..], &DUMMY_SEED[..]);
        }

        // the streaming decryptor must agree with the one-shot encryptor under its init data
        let mut buf = reference_ct;
        let mut streamed = D::do_decrypt_init(&key, &iv).unwrap();
        for chunk in buf.chunks_mut(5) {
            streamed.do_decrypt(chunk).unwrap();
        }
        assert_eq!(&buf[..], &DUMMY_SEED[..]);

        // The RNG-taking constructor is only exercised for a cipher that has init data to
        // generate. Its contract requires an implementation with `INIT_DATA_LEN == 0` (ECB) to
        // panic instead, so driving it here would fail that implementor for conforming.
        if INIT_DATA_LEN > 0 {
            // the RNG-taking one-shot must give the streaming API's answer for the same RNG stream,
            // and the same init data.
            let pinned = [0xA5u8; INIT_DATA_LEN];
            let mut expected = *DUMMY_SEED;
            let (mut streamed, iv_streamed) =
                E::do_encrypt_init_rng(&key, &mut FixedSeedRNG::<INIT_DATA_LEN>::new(pinned))
                    .unwrap();
            streamed.do_encrypt(&mut expected).unwrap();
            let mut buf = *DUMMY_SEED;
            let (n, iv) = E::encrypt_in_place_rng(
                &key,
                &mut FixedSeedRNG::<INIT_DATA_LEN>::new(pinned),
                &mut buf,
            )
            .unwrap();
            assert_eq!(n, buf.len(), "encrypt_rng must report the number of bytes written");
            assert_eq!(iv, iv_streamed);
            assert_eq!(&buf[..], &expected[..]);
            // ...and a driven RNG determines the ciphertext: the same RNG stream again gives the same
            // init data and ciphertext, so the ciphertext is a function of (key, init data) alone.
            let mut buf2 = *DUMMY_SEED;
            let (_, iv_again) = E::encrypt_in_place_rng(
                &key,
                &mut FixedSeedRNG::<INIT_DATA_LEN>::new(pinned),
                &mut buf2,
            )
            .unwrap();
            assert_eq!(iv, iv_again);
            assert_eq!(&buf[..], &buf2[..]);
        }

        // test that the init data is random (ie not the same on two runs). A cipher with no init
        // data at all (INIT_DATA_LEN == 0) has nothing to compare: two empty arrays are always equal.
        if INIT_DATA_LEN > 0 {
            let (_encryptor, iv1) = E::do_encrypt_init(&key).unwrap();
            let (_encryptor, iv2) = E::do_encrypt_init(&key).unwrap();
            assert_ne!(iv1, iv2);
            // and different init data under the same key gives different ciphertext
            let mut a = *DUMMY_SEED;
            let mut b = *DUMMY_SEED;
            let (_, iv_a) = E::encrypt_in_place(&key, &mut a).unwrap();
            let (_, iv_b) = E::encrypt_in_place(&key, &mut b).unwrap();
            assert_ne!(iv_a, iv_b);
            assert_ne!(&a[..], &b[..]);
        }

        // error case: KeyMaterial of wrong type, for both directions
        let mac_key =
            KeyMaterial::<KEY_LEN>::from_bytes_as_type(&DUMMY_SEED[..KEY_LEN], KeyType::MACKey)
                .unwrap();
        match E::do_encrypt_init(&mac_key) {
            Err(SymmetricCipherError::KeyMaterialError(_)) => { /* good */ }
            _ => panic!("Unexpected error"),
        };
        match D::do_decrypt_init(&mac_key, &[0u8; INIT_DATA_LEN]) {
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

            // Tag the key at an arbitrary strength for the purpose of this test.
            do_hazardous_operations(&mut key, |key| key.set_security_strength(ss.clone())).unwrap();

            let check = |r: Result<(), SymmetricCipherError>, max: &SecurityStrength| match r {
                Ok(_) => {
                    if ss >= max { /* good */
                    } else {
                        panic!("Should have been a strong enough key");
                    }
                }
                Err(SymmetricCipherError::KeyMaterialError(_)) => {
                    if ss < max { /* good */
                    } else {
                        panic!("Should not have accepted a key weaker than algorithm");
                    }
                }
                _ => panic!("Unexpected error"),
            };
            check(E::do_encrypt_init(&key).map(|_| ()), &E::MAX_SECURITY_STRENGTH);
            check(
                D::do_decrypt_init(&key, &[0u8; INIT_DATA_LEN]).map(|_| ()),
                &D::MAX_SECURITY_STRENGTH,
            );
        }
    }
}
