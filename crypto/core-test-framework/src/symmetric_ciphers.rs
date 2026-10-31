//! Generic behaviour tests for the symmetric cipher traits: [`SymmetricCipherEncryptor`] /
//! [`SymmetricCipherDecryptor`] and their stream-cipher refinement. The block-cipher and AEAD
//! refinements have their own runners in [`crate::block_cipher`] and [`crate::aead`].

use crate::{DUMMY_SEED, FixedSeedRNG};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::symmetric_key::{SymmetricDecryptionKey, SymmetricEncryptionKey};
use bouncycastle_core::traits::{
    RNG, StreamCipherDecryptor, StreamCipherEncryptor, SymmetricCipherDecryptor,
    SymmetricCipherEncryptor,
};

/// Instance of the test framework.
pub struct TestFrameworkSymmetricCipher {
    /// For [`test_key`](Self::test_key): the plaintext length
    /// granularity the pair accepts. 1 (the default) means every length round-trips. A larger value
    /// -- the block length, for a `PaddedBlockCipherEncryptor` over `NoPadding` -- means only
    /// multiples of it round-trip, and every other length must be *rejected* by `do_encrypt_final`
    /// / `encrypt_out` with `DataNotBlockAligned`, which the test then asserts instead.
    pub required_alignment: usize,
    /// For [`test_key`](Self::test_key): the one message length
    /// the pair's streaming methods accept, if they accept only one. `None` (the default) means
    /// any length. A cipher whose payload length is fixed by its type -- CCM, whose `B0` block
    /// encodes the payload length, through its `DATA_LEN` parameter -- sets it here: the
    /// streaming checks then run at exactly that length, the one-shots are checked to round trip
    /// every other length while a stream of it is refused, and the test also checks that one byte
    /// more is refused at the update and one byte fewer at the final, on both sides.
    pub fixed_message_len: Option<usize>,
}

impl TestFrameworkSymmetricCipher {
    ///
    pub fn new() -> Self {
        Self { required_alignment: 1, fixed_message_len: None }
    }

    /// The [`SymmetricEncryptionKey`] / [`SymmetricDecryptionKey`] form of
    /// the symmetric-cipher contract reached
    /// through a key object, with `rng` supplying every init data draw. The key-policy checks
    /// are not here, since the key is already made; see `TestFrameworkFromKeyMaterial`.
    pub fn test_key<
        const KEY_LEN: usize,
        const INIT_DATA_LEN: usize,
        const FINAL_LEN: usize,
        K: SymmetricEncryptionKey<KEY_LEN, INIT_DATA_LEN, FINAL_LEN>
            + SymmetricDecryptionKey<KEY_LEN, INIT_DATA_LEN, FINAL_LEN>,
    >(
        &self,
        key: &K,
        rng: &mut dyn RNG,
    ) {
        // Enough plaintext lengths to cross several final-chunk boundaries (a block, for padding).
        let align = self.required_alignment.max(1);
        let max_len = (3 * FINAL_LEN.max(1) + 5).next_multiple_of(align);
        if let Some(fixed) = self.fixed_message_len {
            assert!(fixed <= DUMMY_SEED.len(), "fixed_message_len must fit the seed buffer");
        }
        let encrypt_out_len = |len: usize| {
            <K::Encryptor<'_> as SymmetricCipherEncryptor<INIT_DATA_LEN, FINAL_LEN>>::encrypt_out_len(len)
        };
        let decrypt_out_len = |len: usize| {
            <K::Decryptor<'_> as SymmetricCipherDecryptor<INIT_DATA_LEN, FINAL_LEN>>::decrypt_out_len(len)
        };

        // one-shot round trip, every (accepted) length; every other length must be refused
        for len in 0..=max_len {
            let msg = &DUMMY_SEED[..len];
            if !len.is_multiple_of(align) {
                let mut ct = vec![0u8; encrypt_out_len(len) + FINAL_LEN];
                match key.encrypt_out(rng, msg, &mut ct) {
                    Err(SymmetricCipherError::DataNotBlockAligned) => {}
                    other => panic!("len {len} is not aligned and must be refused, got {other:?}"),
                }
                let (mut enc, _) = key.create_encryptor(rng).unwrap();
                let mut buf = vec![0u8; enc.do_encrypt_out_len(len)];
                enc.do_encrypt_out(msg, &mut buf).unwrap();
                assert!(
                    matches!(
                        enc.do_encrypt_final(),
                        Err(SymmetricCipherError::DataNotBlockAligned)
                    ),
                    "len {len}: streaming do_encrypt_final must refuse an unaligned message"
                );
                continue;
            }
            // a fixed-length pair takes only that length, through the key's one-shots as well as
            // its streams, since the one-shots are written over the streams
            if let Some(fixed) = self.fixed_message_len
                && fixed != len
            {
                let mut ct = vec![0u8; encrypt_out_len(len)];
                assert!(
                    key.encrypt_out(rng, msg, &mut ct).is_err(),
                    "fixed length: a {len}-byte one-shot must be refused"
                );
                let (mut enc, _) = key.create_encryptor(rng).unwrap();
                let mut buf = vec![0u8; enc.do_encrypt_out_len(len)];
                assert!(
                    enc.do_encrypt_out(msg, &mut buf).is_err() || enc.do_encrypt_final().is_err(),
                    "fixed length: a {len}-byte stream must be refused"
                );
                continue;
            }
            let mut ct = vec![0u8; encrypt_out_len(len)];
            let (ct_len, init_data) = key.encrypt_out(rng, msg, &mut ct).unwrap();
            assert_eq!(ct_len, ct.len(), "encrypt_out must write exactly encrypt_out_len bytes");

            let mut pt = vec![0u8; decrypt_out_len(ct_len)];
            let pt_len = key.decrypt_out(&init_data, &ct[..ct_len], &mut pt).unwrap();
            assert!(pt_len <= pt.len(), "decrypt_out_len must bound the plaintext");
            assert_eq!(&pt[..pt_len], msg, "one-shot round trip, len {len}");

            // the std one-shots agree with the _out ones for the same init data
            let (init_data2, ct2) = key.encrypt(rng, msg).unwrap();
            assert_eq!(ct2.len(), ct_len, "encrypt must return exactly the bytes written");
            let pt2 = key.decrypt(&init_data2, &ct2).unwrap();
            assert_eq!(pt2, msg, "std round trip, len {len}");
            let pt3 = key.decrypt(&init_data, &ct[..ct_len]).unwrap();
            assert_eq!(pt3, msg, "decrypt must agree with decrypt_out");
        }

        // streaming in every chunking agrees with the one-shot
        let len = self.fixed_message_len.unwrap_or(max_len);
        let msg = &DUMMY_SEED[..len];
        let chunkings: [usize; 8] =
            [1, 2, 3, 7, FINAL_LEN.max(1), FINAL_LEN + 1, 2 * FINAL_LEN + 3, len.max(1)];
        for chunk in chunkings {
            // encrypt in chunks, checking update_out_len is exact each time
            let (mut enc, init_data) = key.create_encryptor(rng).unwrap();
            let mut ct = Vec::new();
            for piece in msg.chunks(chunk) {
                let expect = enc.do_encrypt_out_len(piece.len());
                let mut buf = vec![0u8; expect];
                let n = enc.do_encrypt_out(piece, &mut buf).unwrap();
                assert_eq!(n, expect, "update_out_len must be exact (encrypt, chunk {chunk})");
                ct.extend_from_slice(&buf[..n]);
            }
            let mut last = [0u8; FINAL_LEN];
            let last_len = enc.do_encrypt_final_out(&mut last).unwrap();
            assert!(
                last_len <= FINAL_LEN,
                "do_encrypt_final_out must not claim more than FINAL_LEN bytes"
            );
            ct.extend_from_slice(&last[..last_len]);
            assert_eq!(
                ct.len(),
                encrypt_out_len(len),
                "streaming total must match encrypt_out_len"
            );

            // one-shot decrypt of the streamed ciphertext
            let mut pt = vec![0u8; decrypt_out_len(ct.len())];
            let m = key.decrypt_out(&init_data, &ct, &mut pt).unwrap();
            assert_eq!(
                &pt[..m],
                msg,
                "streamed ciphertext must decrypt in one shot (chunk {chunk})"
            );

            // decrypt in the same chunks, via do_decrypt_final and via do_decrypt_final_out
            for use_out in [false, true] {
                let mut dec = key.create_decryptor(&init_data);
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
                    let data_len = dec.do_decrypt_final_out(&mut block).unwrap();
                    (block, data_len)
                } else {
                    dec.do_decrypt_final().unwrap()
                };
                rec.extend_from_slice(&block[..data_len]);
                assert_eq!(
                    rec, msg,
                    "streamed round trip (chunk {chunk}, do_decrypt_final_out {use_out})"
                );
            }
        }

        // a fixed message length is enforced on both sides: one byte more is refused at the
        // update, consuming nothing, and one byte fewer is refused at the final.
        if let Some(fixed) = self.fixed_message_len {
            let (mut enc, init_data) = key.create_encryptor(rng).unwrap();
            let mut ct = vec![0u8; enc.do_encrypt_out_len(fixed)];
            let n = enc.do_encrypt_out(msg, &mut ct).unwrap();
            ct.truncate(n);
            let mut more = vec![0u8; enc.do_encrypt_out_len(1) + 1];
            assert!(
                enc.do_encrypt_out(&DUMMY_SEED[..1], &mut more).is_err(),
                "fixed length: one byte more must be refused at the update"
            );
            let (last, last_len) = enc.do_encrypt_final().unwrap();
            ct.extend_from_slice(&last[..last_len]);
            let mut pt = vec![0u8; decrypt_out_len(ct.len())];
            let m = key.decrypt_out(&init_data, &ct, &mut pt).unwrap();
            assert_eq!(&pt[..m], msg, "fixed length: a refused update must not disturb the state");

            if fixed > 0 {
                let (mut enc, _) = key.create_encryptor(rng).unwrap();
                let mut buf = vec![0u8; enc.do_encrypt_out_len(fixed - 1)];
                enc.do_encrypt_out(&msg[..fixed - 1], &mut buf).unwrap();
                assert!(
                    enc.do_encrypt_final().is_err(),
                    "fixed length: one byte fewer must be refused at the final (encrypt)"
                );
                let mut dec = key.create_decryptor(&init_data);
                let mut buf = vec![0u8; dec.do_decrypt_out_len(fixed - 1)];
                dec.do_decrypt_out(&ct[..fixed - 1], &mut buf).unwrap();
                assert!(
                    dec.do_decrypt_final().is_err(),
                    "fixed length: one byte fewer must be refused at the final (decrypt)"
                );
            }
            let mut dec = key.create_decryptor(&init_data);
            let mut rec = vec![0u8; dec.do_decrypt_out_len(ct.len())];
            let n = dec.do_decrypt_out(&ct, &mut rec).unwrap();
            rec.truncate(n);
            let mut more = vec![0u8; dec.do_decrypt_out_len(1) + 1];
            assert!(
                dec.do_decrypt_out(&DUMMY_SEED[..1], &mut more).is_err(),
                "fixed length: one byte more must be refused at the update (decrypt)"
            );
            let (last, data_len) = dec.do_decrypt_final().unwrap();
            rec.extend_from_slice(&last[..data_len]);
            assert_eq!(
                rec, msg,
                "fixed length: a refused update must not disturb the state (decrypt)"
            );
        }

        if INIT_DATA_LEN > 0 {
            // a driven RNG reproduces its init data, and determines the ciphertext
            let seed: [u8; INIT_DATA_LEN] = core::array::from_fn(|i| DUMMY_SEED[100 + i]);
            let (mut enc, init_data) =
                key.create_encryptor(&mut FixedSeedRNG::<INIT_DATA_LEN>::new(seed)).unwrap();
            assert_eq!(init_data, seed, "a fixed RNG must yield its stream as the init data");
            let mut streamed = vec![0u8; enc.do_encrypt_out_len(len)];
            let n = enc.do_encrypt_out(msg, &mut streamed).unwrap();
            streamed.truncate(n);
            let (last, last_len) = enc.do_encrypt_final().unwrap();
            streamed.extend_from_slice(&last[..last_len]);
            let mut one_shot = vec![0u8; encrypt_out_len(len)];
            let (n2, init_data2) = key
                .encrypt_out(&mut FixedSeedRNG::<INIT_DATA_LEN>::new(seed), msg, &mut one_shot)
                .unwrap();
            assert_eq!(init_data2, seed);
            assert_eq!(
                &one_shot[..n2],
                &streamed[..],
                "same key and init data must give the same ciphertext"
            );

            // ...and two draws from a real RNG differ
            let (_, a) = key.create_encryptor(rng).unwrap();
            let (_, b) = key.create_encryptor(rng).unwrap();
            assert_ne!(a, b, "two encryptions must not share init data");
        }

        // corrupting the ciphertext does not give back the plaintext (or fails to decrypt)
        let mut ct = vec![0u8; encrypt_out_len(len)];
        let (ct_len, init_data) = key.encrypt_out(rng, msg, &mut ct).unwrap();
        assert!(ct_len > 0, "the test message is non-empty, so its ciphertext must be");
        for flip in [0usize, ct_len / 2, ct_len - 1] {
            let mut bad = ct[..ct_len].to_vec();
            bad[flip] ^= 0x80;
            let mut pt = vec![0u8; decrypt_out_len(ct_len)];
            match key.decrypt_out(&init_data, &bad, &mut pt) {
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
        let need = encrypt_out_len(len);
        let mut short = vec![0u8; need - 1];
        match key.encrypt_out(rng, msg, &mut short) {
            Err(SymmetricCipherError::OutputBufferTooSmall(n)) => assert_eq!(n, need),
            other => panic!("encrypt_out into a short buffer: {other:?}"),
        }
        let need = decrypt_out_len(ct_len);
        if need > 0 {
            let mut short = vec![0u8; need - 1];
            match key.decrypt_out(&init_data, &ct[..ct_len], &mut short) {
                Err(SymmetricCipherError::OutputBufferTooSmall(n)) => assert_eq!(n, need),
                other => panic!("decrypt_out into a short buffer: {other:?}"),
            }
        }
        // ...and ones with room to spare are accepted
        let mut roomy = vec![0u8; encrypt_out_len(len) + 3];
        let (n, _) = key.encrypt_out(rng, msg, &mut roomy).unwrap();
        assert_eq!(n, encrypt_out_len(len), "encrypt_out into a roomy buffer");
        let mut roomy = vec![0u8; need + 3];
        let n = key.decrypt_out(&init_data, &ct[..ct_len], &mut roomy).unwrap();
        assert_eq!(&roomy[..n], msg, "decrypt_out into a roomy buffer");
        let (mut enc, _) = key.create_encryptor(rng).unwrap();
        let need = enc.do_encrypt_out_len(len);
        if need > 0 {
            let mut short = vec![0u8; need - 1];
            match enc.do_encrypt_out(msg, &mut short) {
                Err(SymmetricCipherError::OutputBufferTooSmall(n)) => assert_eq!(n, need),
                other => panic!("do_update_out into a short buffer: {other:?}"),
            }
        }

        // Output-buffer contract, for every method that writes into a caller's buffer: a buffer
        // larger than needed is accepted, the returned count is what that call wrote, and every
        // byte past it is zeroed.
        const SENTINEL: u8 = 0xA5;
        const EXTRA: usize = 7;
        let assert_tail_zeroed = |buf: &[u8], n: usize, what: &str| {
            assert!(
                n <= buf.len(),
                "{what}: claims {n} bytes written to a {}-byte buffer",
                buf.len()
            );
            assert!(
                buf[n..].iter().all(|&b| b == 0),
                "{what}: the bytes past the {n} written must be zeroed"
            );
        };

        let need = encrypt_out_len(len);
        let mut ct = vec![SENTINEL; need + EXTRA];
        let (ct_len, init_data) = key.encrypt_out(rng, msg, &mut ct).unwrap();
        assert_eq!(ct_len, need, "encrypt_out into an oversized buffer must write encrypt_out_len");
        assert_tail_zeroed(&ct, ct_len, "encrypt_out");
        ct.truncate(ct_len);
        let mut pt = vec![SENTINEL; decrypt_out_len(ct_len) + EXTRA];
        let n = key.decrypt_out(&init_data, &ct, &mut pt).unwrap();
        assert_eq!(&pt[..n], msg, "decrypt_out into an oversized buffer");
        assert_tail_zeroed(&pt, n, "decrypt_out");

        // Streaming, in pieces of 1 byte, FINAL_LEN + 1 bytes and the rest: a cipher that holds
        // data back then releases nothing on some calls after earlier calls released data, which is
        // where a running total and a per-call count differ. Each call must report its own
        // `do_*_out_len`, and the per-call counts must add up to exactly the whole stream's
        // length, which a running total would overshoot.
        let cuts = |total: usize| [0, 1.min(total), (FINAL_LEN + 2).min(total), total];
        let c = cuts(len);
        let (mut enc, init_data) = key.create_encryptor(rng).unwrap();
        let mut streamed = Vec::new();
        for w in c.windows(2) {
            let piece = &msg[w[0]..w[1]];
            let expect = enc.do_encrypt_out_len(piece.len());
            let mut buf = vec![SENTINEL; expect + EXTRA];
            let n = enc.do_encrypt_out(piece, &mut buf).unwrap();
            assert_eq!(n, expect, "do_encrypt_out must report the bytes this call wrote");
            assert_tail_zeroed(&buf, n, "do_encrypt_out");
            streamed.extend_from_slice(&buf[..n]);
        }
        let mut last = [SENTINEL; FINAL_LEN];
        let last_len = enc.do_encrypt_final_out(&mut last).unwrap();
        assert_tail_zeroed(&last, last_len, "do_encrypt_final_out");
        streamed.extend_from_slice(&last[..last_len]);
        assert_eq!(
            streamed.len(),
            encrypt_out_len(len),
            "the per-call counts must sum to encrypt_out_len, not overshoot it as running totals"
        );

        let c = cuts(streamed.len());
        let mut dec = key.create_decryptor(&init_data);
        let mut rec = Vec::new();
        for w in c.windows(2) {
            let piece = &streamed[w[0]..w[1]];
            let expect = dec.do_decrypt_out_len(piece.len());
            let mut buf = vec![SENTINEL; expect + EXTRA];
            let n = dec.do_decrypt_out(piece, &mut buf).unwrap();
            assert_eq!(n, expect, "do_decrypt_out must report the bytes this call wrote");
            assert_tail_zeroed(&buf, n, "do_decrypt_out");
            rec.extend_from_slice(&buf[..n]);
        }
        let mut last = [SENTINEL; FINAL_LEN];
        let data_len = dec.do_decrypt_final_out(&mut last).unwrap();
        assert_tail_zeroed(&last, data_len, "do_decrypt_final_out");
        rec.extend_from_slice(&last[..data_len]);
        assert_eq!(
            rec, msg,
            "the per-call counts must sum to the plaintext, not overshoot it as running totals"
        );
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

    /// The stream-cipher contract over a [`SymmetricEncryptionKey`] /
    /// [`SymmetricDecryptionKey`] pair whose workers are stream ciphers, with `rng` supplying
    /// every init data draw. The key-policy checks are `TestFrameworkFromKeyMaterial`'s.
    pub fn test_key<
        'k,
        const KEY_LEN: usize,
        const INIT_DATA_LEN: usize,
        K: SymmetricEncryptionKey<KEY_LEN, INIT_DATA_LEN, 0>
            + SymmetricDecryptionKey<KEY_LEN, INIT_DATA_LEN, 0>,
    >(
        &self,
        key: &'k K,
        rng: &mut dyn RNG,
    ) where
        K::Encryptor<'k>: StreamCipherEncryptor<INIT_DATA_LEN>,
        K::Decryptor<'k>: StreamCipherDecryptor<INIT_DATA_LEN>,
    {
        // one-shot, in place: must round-trip, and report every byte as written.
        let mut buf = *DUMMY_SEED;
        let (n, iv) = key.encrypt_inplace(rng, &mut buf).unwrap();
        assert_eq!(n, buf.len(), "encrypt must report the number of bytes written");
        let reference_ct = buf;
        assert_ne!(&reference_ct[..], &DUMMY_SEED[..], "encryption must change the data");
        let n = key.decrypt_inplace(&iv, &mut buf).unwrap();
        assert_eq!(n, buf.len(), "decrypt must report the number of bytes written");
        assert_eq!(&buf[..], &DUMMY_SEED[..]);

        // the streaming API under the same init data must give the one-shot's answer whatever
        // the chunking, and encrypting in one chunking must decrypt in any other.
        let chunkings: &[usize] = &[1, 3, 7, 16, 63, 64, 65, 250, DUMMY_SEED.len()];
        for &enc_chunk in chunkings {
            let mut buf = *DUMMY_SEED;
            let (mut encryptor, iv2) = key.create_encryptor(rng).unwrap();
            encryptor.do_encrypt_inplace(&mut []).unwrap();
            for chunk in buf.chunks_mut(enc_chunk) {
                encryptor.do_encrypt_inplace(chunk).unwrap();
            }
            encryptor.do_encrypt_inplace(&mut []).unwrap();
            let ct = buf;

            for &dec_chunk in chunkings {
                let mut buf = ct;
                let mut decryptor = key.create_decryptor(&iv2);
                decryptor.do_decrypt_inplace(&mut []).unwrap();
                for chunk in buf.chunks_mut(dec_chunk) {
                    decryptor.do_decrypt_inplace(chunk).unwrap();
                }
                decryptor.do_decrypt_inplace(&mut []).unwrap();
                assert_eq!(
                    &buf[..],
                    &DUMMY_SEED[..],
                    "enc chunk {enc_chunk}, dec chunk {dec_chunk}"
                );
            }

            // and the one-shot decrypt agrees with every streaming encryption
            let mut buf = ct;
            key.decrypt_inplace(&iv2, &mut buf).unwrap();
            assert_eq!(&buf[..], &DUMMY_SEED[..]);
        }

        // the streaming decryptor must agree with the one-shot encryptor under its init data
        let mut buf = reference_ct;
        let mut streamed = key.create_decryptor(&iv);
        for chunk in buf.chunks_mut(5) {
            streamed.do_decrypt_inplace(chunk).unwrap();
        }
        assert_eq!(&buf[..], &DUMMY_SEED[..]);

        // the separate-output methods of the symmetric traits agree with the in-place ones
        let out_len =
            <K::Encryptor<'k> as SymmetricCipherEncryptor<INIT_DATA_LEN, 0>>::encrypt_out_len(
                DUMMY_SEED.len(),
            );
        let mut out = vec![0u8; out_len];
        let (n, iv3) = key.encrypt_out(rng, DUMMY_SEED, &mut out).unwrap();
        assert_eq!(n, DUMMY_SEED.len(), "a stream cipher never changes the length");
        let mut back = out.clone();
        key.decrypt_inplace(&iv3, &mut back).unwrap();
        assert_eq!(&back[..], &DUMMY_SEED[..]);
        let pt_len =
            <K::Decryptor<'k> as SymmetricCipherDecryptor<INIT_DATA_LEN, 0>>::decrypt_out_len(n);
        let mut pt = vec![0u8; pt_len];
        let m = key.decrypt_out(&iv3, &out[..n], &mut pt).unwrap();
        assert_eq!(&pt[..m], &DUMMY_SEED[..]);

        // the RNG-driven one-shot must give the streaming API's answer for the same RNG stream,
        // and the same init data; a driven RNG determines the ciphertext.
        let pinned = [0xA5u8; INIT_DATA_LEN];
        let mut expected = *DUMMY_SEED;
        let (mut streamed, iv_streamed) =
            key.create_encryptor(&mut FixedSeedRNG::<INIT_DATA_LEN>::new(pinned)).unwrap();
        streamed.do_encrypt_inplace(&mut expected).unwrap();
        let mut buf = *DUMMY_SEED;
        let (n, iv) =
            key.encrypt_inplace(&mut FixedSeedRNG::<INIT_DATA_LEN>::new(pinned), &mut buf).unwrap();
        assert_eq!(n, buf.len(), "encrypt_inplace must report the number of bytes written");
        assert_eq!(iv, iv_streamed);
        assert_eq!(&buf[..], &expected[..]);
        let mut buf2 = *DUMMY_SEED;
        let (_, iv_again) = key
            .encrypt_inplace(&mut FixedSeedRNG::<INIT_DATA_LEN>::new(pinned), &mut buf2)
            .unwrap();
        assert_eq!(iv, iv_again);
        assert_eq!(&buf[..], &buf2[..]);

        // the init data is random: not the same on two runs, and different init data under the
        // same key gives different ciphertext
        let (_encryptor, iv1) = key.create_encryptor(rng).unwrap();
        let (_encryptor, iv2) = key.create_encryptor(rng).unwrap();
        assert_ne!(iv1, iv2);
        let mut a = *DUMMY_SEED;
        let mut b = *DUMMY_SEED;
        let (_, iv_a) = key.encrypt_inplace(rng, &mut a).unwrap();
        let (_, iv_b) = key.encrypt_inplace(rng, &mut b).unwrap();
        assert_ne!(iv_a, iv_b);
        assert_ne!(&a[..], &b[..]);
    }
}
