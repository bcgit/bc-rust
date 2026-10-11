//! Shared conformance tests for [`AEADCipherEncryptor`] / [`AEADCipherDecryptor`] implementors.
//!
//! Two runners:
//!
//! * [`TestFrameworkAEADCipher`] checks the whole AEAD contract -- it runs the
//!   [`SymmetricCipherEncryptor`] / [`SymmetricCipherDecryptor`] suite first, then the AAD and tag
//!   behaviour on top.
//! * [`TestFrameworkAEADTaggedLayout`] concentrates on the byte-boundary edges of the inline
//!   `ciphertext || tag` layout -- where the tag lands, what a decryptor holds back, what happens
//!   when the input is shorter than the tag -- at every length across a few multiples of `TAG_LEN`
//!   and under every chunking, which is where an implementor's own bookkeeping goes wrong. Every
//!   encryption there is driven through a [`FixedSeedRNG`] so that the nonce is the same on every
//!   path and streaming output can be compared byte for byte with one-shot output.
//!
//! [`SymmetricCipherEncryptor`]: bouncycastle_core::traits::SymmetricCipherEncryptor
//! [`SymmetricCipherDecryptor`]: bouncycastle_core::traits::SymmetricCipherDecryptor

use crate::symmetric_ciphers::TestFrameworkSymmetricCipher;
use crate::{DUMMY_SEED, FixedSeedRNG};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{AEADCipherDecryptor, AEADCipherEncryptor};

/// Instance of the test framework.
pub struct TestFrameworkAEADCipher {
    /// The one message length the pair's streaming methods accept, if they accept only one; see
    /// [`TestFrameworkSymmetricCipher::fixed_message_len`], which this is passed on to. `None`
    /// (the default) means any length. The streaming checks here then run at that length only,
    /// and the one-shots at every length up to and including it.
    ///
    /// [`TestFrameworkSymmetricCipher::fixed_message_len`]: crate::symmetric_ciphers::TestFrameworkSymmetricCipher::fixed_message_len
    pub fixed_message_len: Option<usize>,
}

impl TestFrameworkAEADCipher {
    ///
    pub fn new() -> Self {
        Self { fixed_message_len: None }
    }

    /// Exercises the [`AEADCipherEncryptor`] / [`AEADCipherDecryptor`] streaming contract for a
    /// paired implementor. The counterpart of [`TestFrameworkBlockCipher::test`] for an
    /// authenticated cipher.
    ///
    /// Checks, in order:
    /// * the whole [`TestFrameworkSymmetricCipher::test_encryptor_decryptor`] suite, since an AEAD
    ///   with no associated data and the tag inline *is* a [`SymmetricCipherEncryptor`] /
    ///   [`SymmetricCipherDecryptor`] pair, and that `FINAL_LEN` has room for the tag;
    /// * the detached one-shot round trip for every message length from 0 to a few times
    ///   `TAG_LEN`, and that the tag is not the all-zero array;
    /// * the inline layout with associated data, one-shot and streaming, is exactly the detached
    ///   ciphertext with the tag appended, and a stream shorter than the tag is a failed
    ///   decryption;
    /// * streaming in every chunking, of both the AAD and the data, agrees with `update_out_len`
    ///   on every call and gives the one-shot's ciphertext and tag byte for byte, and decrypts in
    ///   every chunking;
    /// * an empty AAD is a no-op -- it gives what absorbing no AAD at all gives -- and a message
    ///   with no data still authenticates its AAD;
    /// * `do_update_aad` with non-empty AAD after the first `do_update_out` is refused with a
    ///   [`SymmetricCipherError::StateError`], and the refusal leaves the value usable;
    /// * a tampered ciphertext, tag, AAD or nonce all fail the tag check, and the one-shots leave
    ///   no plaintext behind when they do;
    /// * two encryptions under the same key draw different nonces;
    /// * every AEAD method that writes into a caller's buffer accepts one larger than needed,
    ///   returns the number of bytes that call wrote, and zeroes every byte past that count;
    /// * a key of the wrong [`KeyType`] is rejected, and the security-strength policy matches
    ///   [`Algorithm::MAX_SECURITY_STRENGTH`].
    ///
    /// `bouncycastle-core`'s own `tests/aead_buffering_toy_tests.rs` separately pins that a cipher
    /// which holds back more than the tag is handled correctly by the traits' default one-shots,
    /// since `E`/`D` here are supplied by the caller and might not hold anything back.
    ///
    /// [`Algorithm::MAX_SECURITY_STRENGTH`]: bouncycastle_core::traits::Algorithm::MAX_SECURITY_STRENGTH
    ///
    /// [`TestFrameworkBlockCipher::test`]: crate::block_cipher::TestFrameworkBlockCipher::test
    /// [`TestFrameworkSymmetricCipher::test_encryptor_decryptor`]: crate::symmetric_ciphers::TestFrameworkSymmetricCipher::test_encryptor_decryptor
    /// [`SymmetricCipherEncryptor`]: bouncycastle_core::traits::SymmetricCipherEncryptor
    /// [`SymmetricCipherDecryptor`]: bouncycastle_core::traits::SymmetricCipherDecryptor
    pub fn test_encryptor_decryptor<
        const KEY_LEN: usize,
        const NONCE_LEN: usize,
        const TAG_LEN: usize,
        const FINAL_LEN: usize,
        E: AEADCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
        D: AEADCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
    >(
        &self,
    ) {
        assert!(
            FINAL_LEN >= TAG_LEN,
            "FINAL_LEN must have room for the inline tag the decryptor holds back"
        );
        // No AAD and the tag inline is the plain symmetric-cipher contract.
        let mut symmetric = TestFrameworkSymmetricCipher::new();
        symmetric.fixed_message_len = self.fixed_message_len;
        symmetric.test_encryptor_decryptor::<KEY_LEN, NONCE_LEN, FINAL_LEN, E, D>();

        let key = KeyMaterial::<KEY_LEN>::from_bytes_as_type(
            &DUMMY_SEED[..KEY_LEN],
            KeyType::SymmetricCipherKey,
        )
        .unwrap();
        let aad: &[u8] = b"some associated data";
        let pinned = [0xA5u8; NONCE_LEN];

        // one-shot round trip, every length up to a few times the tag length (and up to the fixed
        // length, if there is one, so that the streaming checks inside the loop reach it)
        let max_len = (3 * TAG_LEN.max(1) + 5).max(self.fixed_message_len.unwrap_or(0));
        assert!(max_len <= DUMMY_SEED.len(), "the fixed message length must fit the seed buffer");
        for len in 0..=max_len {
            let msg = &DUMMY_SEED[..len];
            // a fixed-length pair takes only that length, on every entry point: the one-shots
            // are the trait's own, provided over the streaming methods that enforce it
            if let Some(fixed) = self.fixed_message_len
                && fixed != len
            {
                let mut ct = vec![0u8; E::encrypt_detached_out_len(len)];
                assert!(
                    E::encrypt_detached_out(&key, aad, msg, &mut ct).is_err(),
                    "fixed length: a {len}-byte detached one-shot must be refused"
                );
                let mut inline = vec![0u8; E::encrypt_out_len(len)];
                assert!(
                    E::encrypt_with_aad_out(&key, aad, msg, &mut inline).is_err(),
                    "fixed length: a {len}-byte inline one-shot must be refused"
                );
                // ...and so is a ciphertext of any length but the frame's
                let fixed_msg = &DUMMY_SEED[..fixed];
                let mut sealed = vec![0u8; E::encrypt_out_len(fixed)];
                let (nonce, n) =
                    E::encrypt_with_aad_out(&key, aad, fixed_msg, &mut sealed).unwrap();
                let mut wrong = sealed[..n].to_vec();
                wrong.resize(len + TAG_LEN, 0);
                let mut pt = vec![0u8; D::decrypt_out_len(wrong.len())];
                assert!(
                    D::decrypt_with_aad_out(&key, &nonce, aad, &wrong, &mut pt).is_err(),
                    "fixed length: a {}-byte ciphertext must be refused",
                    wrong.len()
                );
                continue;
            }
            let mut ct = vec![0u8; E::encrypt_detached_out_len(len)];
            let (nonce, ct_len, tag) = E::encrypt_detached_out(&key, aad, msg, &mut ct).unwrap();
            ct.truncate(ct_len);
            assert_ne!(tag, [0u8; TAG_LEN], "len {len}: the tag must not be all zeros");
            // Only assert the ciphertext differs from the plaintext once there is enough of it for
            // an accidental match to be negligible rather than a 1-in-256 flake.
            if len >= 8 {
                assert_ne!(&ct[..], msg, "len {len}: the ciphertext must not be the plaintext");
            }
            let mut pt = vec![0u8; D::decrypt_detached_out_len(ct.len())];
            let pt_len = D::decrypt_detached_out(&key, &nonce, aad, &ct, &tag, &mut pt).unwrap();
            pt.truncate(pt_len);
            assert_eq!(&pt[..], msg, "one-shot round trip, len {len}");

            // the std one-shots agree with the _out ones for the same nonce
            let (nonce2, ct2, tag2) = E::encrypt_detached(&key, aad, msg).unwrap();
            assert_eq!(ct2.len(), ct_len, "encrypt_detached must return exactly the bytes written");
            let pt2 = D::decrypt_detached(&key, &nonce2, aad, &ct2, &tag2).unwrap();
            assert_eq!(pt2, msg, "std round trip, len {len}");
            let pt3 = D::decrypt_detached(&key, &nonce, aad, &ct, &tag).unwrap();
            assert_eq!(pt3, msg, "decrypt_detached must agree with decrypt_detached_out");

            // the inline `ciphertext || tag` layout with AAD: `encrypt_with_aad_out` must write exactly
            // the detached ciphertext with the tag appended -- the same bytes under the same
            // nonce -- and both the one-shot and the streaming finalizer must round trip it.
            let mut detached = vec![0u8; E::encrypt_detached_out_len(len)];
            let (pinned_nonce, detached_len, detached_tag) = E::encrypt_detached_rng_out(
                &key,
                &mut FixedSeedRNG::<NONCE_LEN>::new(pinned),
                aad,
                msg,
                &mut detached,
            )
            .unwrap();
            detached.truncate(detached_len);
            detached.extend_from_slice(&detached_tag);

            let mut inline = vec![0u8; E::encrypt_out_len(len)];
            let (inline_nonce, inline_len) =
                E::encrypt_with_aad_out(&key, aad, msg, &mut inline).unwrap();
            assert_eq!(
                inline_len,
                E::encrypt_detached_out_len(len) + TAG_LEN,
                "encrypt_with_aad_out must write the ciphertext plus the tag, len {len}"
            );
            let mut pt4 = vec![0u8; D::decrypt_out_len(inline_len)];
            let pt4_len =
                D::decrypt_with_aad_out(&key, &inline_nonce, aad, &inline[..inline_len], &mut pt4)
                    .unwrap();
            assert_eq!(&pt4[..pt4_len], msg, "tagged one-shot round trip, len {len}");

            // ...and so must the RNG-driven and allocating inline-with-AAD one-shots. The roomy
            // buffer is deliberate: see the `encrypt_detached_rng_out` probe below.
            let mut inline_rng = vec![0u8; E::encrypt_out_len(len) + 3];
            let (rng_nonce, rng_len) = E::encrypt_with_aad_rng_out(
                &key,
                &mut FixedSeedRNG::<NONCE_LEN>::new(pinned),
                aad,
                msg,
                &mut inline_rng,
            )
            .unwrap();
            assert_eq!(rng_nonce, pinned_nonce, "the same RNG stream must give the same nonce");
            assert_eq!(
                &inline_rng[..rng_len],
                &detached[..],
                "len {len}: encrypt_with_aad_rng_out must be the detached ciphertext and its tag"
            );
            // exactly the length it asks for must be enough too
            let mut exact = vec![0u8; E::encrypt_out_len(len)];
            let (_, exact_len) = E::encrypt_with_aad_rng_out(
                &key,
                &mut FixedSeedRNG::<NONCE_LEN>::new(pinned),
                aad,
                msg,
                &mut exact,
            )
            .unwrap();
            assert_eq!(&exact[..exact_len], &detached[..], "len {len}: exact-size buffer");
            let mut short = vec![0u8; E::encrypt_out_len(len) - 1];
            match E::encrypt_with_aad_rng_out(
                &key,
                &mut FixedSeedRNG::<NONCE_LEN>::new(pinned),
                aad,
                msg,
                &mut short,
            ) {
                Err(SymmetricCipherError::OutputBufferTooSmall(n)) => {
                    assert_eq!(n, E::encrypt_out_len(len))
                }
                other => panic!("encrypt_with_aad_rng_out into a short buffer: {other:?}"),
            }
            let (alloc_nonce, alloc_ct) = E::encrypt_with_aad(&key, aad, msg).unwrap();
            assert_eq!(
                alloc_ct.len(),
                inline_len,
                "encrypt_with_aad must return the bytes written"
            );
            let alloc_pt = D::decrypt_with_aad(&key, &alloc_nonce, aad, &alloc_ct).unwrap();
            assert_eq!(alloc_pt, msg, "allocating inline-with-AAD round trip, len {len}");

            let (mut enc5, nonce5) =
                E::do_encrypt_init_rng(&key, &mut FixedSeedRNG::<NONCE_LEN>::new(pinned)).unwrap();
            assert_eq!(nonce5, pinned_nonce, "the same RNG stream must give the same nonce");
            enc5.do_update_aad(aad).unwrap();
            let mut inline5 = vec![0u8; enc5.do_encrypt_out_len(len)];
            let written5 = enc5.do_encrypt_out(msg, &mut inline5).unwrap();
            inline5.truncate(written5);
            let (last5, last5_len) = enc5.do_encrypt_final().unwrap();
            inline5.extend_from_slice(&last5[..last5_len]);
            assert_eq!(
                inline5.len(),
                inline_len,
                "tagged streaming must write as much as the one-shot"
            );
            assert_eq!(
                inline5, detached,
                "len {len}: the inline layout must be the detached ciphertext followed by its tag"
            );
            let mut dec5 = D::do_decrypt_init(&key, &nonce5).unwrap();
            dec5.do_update_aad(aad).unwrap();
            let mut pt5 = vec![0u8; dec5.do_decrypt_out_len(inline5.len())];
            let got5 = dec5.do_decrypt_out(&inline5, &mut pt5).unwrap();
            pt5.truncate(got5);
            let (last, data_len) = dec5.do_decrypt_final().unwrap();
            pt5.extend_from_slice(&last[..data_len]);
            assert_eq!(pt5, msg, "tagged streaming round trip, len {len}");

            // a stream that ends before a whole tag has been seen is not a short buffer, it
            // is a failed decryption
            if TAG_LEN > 0 {
                let mut dec6 = D::do_decrypt_init(&key, &nonce5).unwrap();
                dec6.do_update_aad(aad).unwrap();
                let short = &inline5[..TAG_LEN - 1];
                let mut scratch = vec![0u8; dec6.do_decrypt_out_len(short.len())];
                dec6.do_decrypt_out(short, &mut scratch).unwrap();
                assert!(
                    matches!(dec6.do_decrypt_final(), Err(SymmetricCipherError::DecryptionFailed)),
                    "a stream shorter than the tag must be DecryptionFailed, len {len}"
                );
            }

            // too-short output buffers on the one-shots are refused with the required length,
            // before any work is done
            let need = E::encrypt_detached_out_len(len);
            if need > 0 {
                let mut short = vec![0u8; need - 1];
                match E::encrypt_detached_out(&key, aad, msg, &mut short) {
                    Err(SymmetricCipherError::OutputBufferTooSmall(n)) => {
                        assert_eq!(n, need)
                    }
                    other => panic!("encrypt_detached_out into a short buffer: {other:?}"),
                }
                let mut short = vec![0u8; need - 1];
                match E::encrypt_detached_rng_out(
                    &key,
                    &mut FixedSeedRNG::<NONCE_LEN>::new([0xA5u8; NONCE_LEN]),
                    aad,
                    msg,
                    &mut short,
                ) {
                    Err(SymmetricCipherError::OutputBufferTooSmall(n)) => {
                        assert_eq!(n, need)
                    }
                    other => panic!("encrypt_detached_rng_out into a short buffer: {other:?}"),
                }
                // ...and one with room to spare must be accepted: without this the guard can be
                // flipped to `>` and every short-buffer probe still "passes", because the error
                // then comes from `do_update_out` behind it with the same variant and length.
                let mut roomy = vec![0u8; need + 3];
                let (_, n, _) = E::encrypt_detached_out(&key, aad, msg, &mut roomy).unwrap();
                assert_eq!(n, need, "encrypt_detached_out into a roomy buffer");
                let mut roomy = vec![0u8; need + 3];
                let (_, n, _) = E::encrypt_detached_rng_out(
                    &key,
                    &mut FixedSeedRNG::<NONCE_LEN>::new([0xA5u8; NONCE_LEN]),
                    aad,
                    msg,
                    &mut roomy,
                )
                .unwrap();
                assert_eq!(
                    n, need,
                    "encrypt_detached_rng_out must write exactly encrypt_detached_out_len bytes"
                );
            }
            let need = E::encrypt_out_len(len);
            let mut short = vec![0u8; need - 1];
            match E::encrypt_with_aad_out(&key, aad, msg, &mut short) {
                Err(SymmetricCipherError::OutputBufferTooSmall(n)) => assert_eq!(n, need),
                other => panic!("encrypt_with_aad_out into a short buffer: {other:?}"),
            }
            let need = D::decrypt_detached_out_len(ct.len());
            if need > 0 {
                let mut short = vec![0u8; need - 1];
                match D::decrypt_detached_out(&key, &nonce, aad, &ct, &tag, &mut short) {
                    Err(SymmetricCipherError::OutputBufferTooSmall(n)) => {
                        assert_eq!(n, need)
                    }
                    other => panic!("decrypt_detached_out into a short buffer: {other:?}"),
                }
            }
            let need = D::decrypt_out_len(inline_len);
            if need > 0 {
                let mut short = vec![0u8; need - 1];
                match D::decrypt_with_aad_out(&key, &inline_nonce, aad, &inline, &mut short) {
                    Err(SymmetricCipherError::OutputBufferTooSmall(n)) => {
                        assert_eq!(n, need)
                    }
                    other => panic!("decrypt_with_aad_out into a short buffer: {other:?}"),
                }
            }
        }

        // streaming in every chunking agrees with the one-shot, for both the AAD and the data.
        // The pinned RNG is what makes the nonce -- and so the ciphertext -- comparable.
        let msg = &DUMMY_SEED[..self.fixed_message_len.unwrap_or(max_len.max(17))];
        let mut ct_ref = vec![0u8; E::encrypt_detached_out_len(msg.len())];
        let (nonce_ref, ct_ref_len, tag_ref) = E::encrypt_detached_rng_out(
            &key,
            &mut FixedSeedRNG::<NONCE_LEN>::new(pinned),
            aad,
            msg,
            &mut ct_ref,
        )
        .unwrap();
        ct_ref.truncate(ct_ref_len);

        for chunk in [1usize, 2, 3, 7, TAG_LEN.max(1), TAG_LEN + 1, msg.len().max(1)] {
            let (mut enc, nonce) =
                E::do_encrypt_init_rng(&key, &mut FixedSeedRNG::<NONCE_LEN>::new(pinned)).unwrap();
            assert_eq!(nonce, nonce_ref, "the same RNG stream must give the same nonce");
            for piece in aad.chunks(chunk) {
                enc.do_update_aad(piece).unwrap();
            }
            let mut ct = Vec::new();
            for piece in msg.chunks(chunk) {
                let expect = enc.do_encrypt_out_len(piece.len());
                let mut buf = vec![0u8; expect];
                let n = enc.do_encrypt_out(piece, &mut buf).unwrap();
                assert_eq!(n, expect, "chunk {chunk}: update_out_len must be exact (encrypt)");
                ct.extend_from_slice(&buf[..n]);
            }
            let mut final_buf = [0u8; FINAL_LEN];
            let (final_len, tag) = enc.do_encrypt_final_detachedtag_out(&mut final_buf).unwrap();
            assert!(
                final_len + TAG_LEN <= FINAL_LEN,
                "chunk {chunk}: the detached flush must leave FINAL_LEN room for the tag"
            );
            ct.extend_from_slice(&final_buf[..final_len]);
            assert_eq!(ct, ct_ref, "chunk {chunk}: streaming must give the one-shot ciphertext");
            assert_eq!(tag, tag_ref, "chunk {chunk}: streaming must give the one-shot tag");

            // ...and the decryptor agrees in every chunking too
            let mut dec = D::do_decrypt_init(&key, &nonce).unwrap();
            for piece in aad.chunks(chunk) {
                dec.do_update_aad(piece).unwrap();
            }
            let mut pt = Vec::new();
            for piece in ct.chunks(chunk) {
                let expect = dec.do_decrypt_out_len(piece.len());
                let mut buf = vec![0u8; expect];
                let n = dec.do_decrypt_out(piece, &mut buf).unwrap();
                assert_eq!(n, expect, "chunk {chunk}: update_out_len must be exact (decrypt)");
                pt.extend_from_slice(&buf[..n]);
            }
            let mut final_buf = [0u8; FINAL_LEN];
            let final_len = dec.do_decrypt_final_detachedtag_out(&tag, &mut final_buf).unwrap();
            pt.extend_from_slice(&final_buf[..final_len]);
            assert_eq!(pt, msg, "chunk {chunk}: streaming round trip");
        }

        // the array-returning finals agree with the `_out` ones the chunked loop above used
        let (mut enc, nonce) =
            E::do_encrypt_init_rng(&key, &mut FixedSeedRNG::<NONCE_LEN>::new(pinned)).unwrap();
        enc.do_update_aad(aad).unwrap();
        let mut ct = vec![0u8; enc.do_encrypt_out_len(msg.len())];
        let n = enc.do_encrypt_out(msg, &mut ct).unwrap();
        ct.truncate(n);
        let (last, last_len, tag) = enc.do_encrypt_final_detachedtag().unwrap();
        ct.extend_from_slice(&last[..last_len]);
        assert_eq!(ct, ct_ref, "do_encrypt_final_detachedtag must give the one-shot ciphertext");
        assert_eq!(tag, tag_ref, "do_encrypt_final_detachedtag must give the one-shot tag");
        let mut dec = D::do_decrypt_init(&key, &nonce).unwrap();
        dec.do_update_aad(aad).unwrap();
        let mut pt = vec![0u8; dec.do_decrypt_out_len(ct.len())];
        let n = dec.do_decrypt_out(&ct, &mut pt).unwrap();
        pt.truncate(n);
        let (last, data_len) = dec.do_decrypt_final_detachedtag(&tag).unwrap();
        pt.extend_from_slice(&last[..data_len]);
        assert_eq!(pt, msg, "do_decrypt_final_detachedtag must round trip");
        let mut wrong_tag = tag;
        wrong_tag[0] ^= 0xFF;
        let mut dec = D::do_decrypt_init(&key, &nonce).unwrap();
        dec.do_update_aad(aad).unwrap();
        let mut pt = vec![0u8; dec.do_decrypt_out_len(ct.len())];
        dec.do_decrypt_out(&ct, &mut pt).unwrap();
        assert!(
            matches!(
                dec.do_decrypt_final_detachedtag(&wrong_tag),
                Err(SymmetricCipherError::AEADTagCheckFailed)
            ),
            "do_decrypt_final_detachedtag must check the tag"
        );

        // an empty AAD is a no-op: it must give exactly what absorbing no AAD at all gives
        let mut with_empty = vec![0u8; E::encrypt_detached_out_len(msg.len())];
        let (nonce_empty, len_empty, tag_empty) = E::encrypt_detached_rng_out(
            &key,
            &mut FixedSeedRNG::<NONCE_LEN>::new(pinned),
            b"",
            msg,
            &mut with_empty,
        )
        .unwrap();
        with_empty.truncate(len_empty);
        let mut without = vec![0u8; E::encrypt_detached_out_len(msg.len())];
        let (nonce_none, len_none, tag_none) = E::encrypt_detached_rng_out(
            &key,
            &mut FixedSeedRNG::<NONCE_LEN>::new(pinned),
            &[],
            msg,
            &mut without,
        )
        .unwrap();
        without.truncate(len_none);
        assert_eq!(nonce_empty, nonce_none);
        assert_eq!(tag_empty, tag_none, "an empty AAD must be a no-op");
        assert_eq!(with_empty, without, "an empty AAD must be a no-op");

        // ...and no AAD at all is what the inherited `SymmetricCipherEncryptor` one-shot gives
        let mut plain = vec![0u8; E::encrypt_out_len(msg.len())];
        let (nonce_plain, len_plain) =
            E::encrypt_rng_out(&key, &mut FixedSeedRNG::<NONCE_LEN>::new(pinned), msg, &mut plain)
                .unwrap();
        assert_eq!(nonce_plain, nonce_none);
        assert_eq!(&plain[..len_plain - TAG_LEN], &without[..], "no-AAD inline ciphertext");
        assert_eq!(&plain[len_plain - TAG_LEN..len_plain], &tag_none, "no-AAD inline tag");

        // a message with no data at all still authenticates its AAD (unless the pair's fixed
        // length rules an empty message out)
        if self.fixed_message_len.is_none_or(|fixed| fixed == 0) {
            let (nonce, _ct_len, tag) = E::encrypt_detached_out(&key, aad, &[], &mut []).unwrap();
            D::decrypt_detached_out(&key, &nonce, aad, &[], &tag, &mut []).unwrap();
            match D::decrypt_detached_out(
                &key,
                &nonce,
                b"different associated data",
                &[],
                &tag,
                &mut [],
            ) {
                Err(SymmetricCipherError::AEADTagCheckFailed) => { /* good */ }
                other => panic!("an empty message must still authenticate its AAD, got {other:?}"),
            };
        }

        // the AAD phase is over once data has been fed in -- on both sides, and on the decrypting
        // side even when all of it is still being held back as a possible tag. (Not for a message
        // with no data at all, where there is no data call to end it.)
        if !msg.is_empty() {
            let (mut enc, nonce) = E::do_encrypt_init(&key).unwrap();
            let mut ct = vec![0u8; enc.do_encrypt_out_len(msg.len())];
            enc.do_encrypt_out(msg, &mut ct).unwrap();
            match enc.do_update_aad(aad) {
                Err(SymmetricCipherError::StateError(_)) => { /* good */ }
                other => panic!("AAD after data must be refused, got {other:?}"),
            };
            // an empty AAD stays a no-op even here, and the refused call must not have disturbed
            // the state: the value is still good for the rest of the flow.
            enc.do_update_aad(b"").unwrap();
            let mut final_buf = [0u8; FINAL_LEN];
            let (final_len, tag) = enc.do_encrypt_final_detachedtag_out(&mut final_buf).unwrap();
            ct.extend_from_slice(&final_buf[..final_len]);

            let mut dec = D::do_decrypt_init(&key, &nonce).unwrap();
            let mut pt = vec![0u8; dec.do_decrypt_out_len(1)];
            let mut got = dec.do_decrypt_out(&ct[..1], &mut pt).unwrap();
            pt.truncate(got);
            match dec.do_update_aad(aad) {
                Err(SymmetricCipherError::StateError(_)) => { /* good */ }
                other => panic!("AAD after data must be refused, got {other:?}"),
            };
            dec.do_update_aad(b"").unwrap();
            let mut rest = vec![0u8; dec.do_decrypt_out_len(ct.len() - 1)];
            got = dec.do_decrypt_out(&ct[1..], &mut rest).unwrap();
            pt.extend_from_slice(&rest[..got]);
            let mut final_buf = [0u8; FINAL_LEN];
            let final_len = dec.do_decrypt_final_detachedtag_out(&tag, &mut final_buf).unwrap();
            pt.extend_from_slice(&final_buf[..final_len]);
            assert_eq!(&pt[..], msg, "a refused do_update_aad must not disturb the state");
        }

        // tampering: every one of these must fail the tag check, and the one-shots must leave no
        // plaintext behind when they do. A message long enough to have a byte 3 to flip, unless
        // the pair's fixed length says otherwise.
        let msg = &DUMMY_SEED[..self.fixed_message_len.unwrap_or(max_len.max(17))];
        let mut ct = vec![0u8; E::encrypt_detached_out_len(msg.len())];
        let (nonce, ct_len, tag) = E::encrypt_detached_out(&key, aad, msg, &mut ct).unwrap();
        ct.truncate(ct_len);

        if ct.len() > 3 {
            let mut tampered = ct.clone();
            tampered[3] ^= 0xFF;
            let mut buf = vec![0u8; D::decrypt_detached_out_len(tampered.len())];
            match D::decrypt_detached_out(&key, &nonce, aad, &tampered, &tag, &mut buf) {
                Err(SymmetricCipherError::AEADTagCheckFailed) => { /* good */ }
                other => panic!("a modified ciphertext must fail the tag check, got {other:?}"),
            };
            assert!(
                buf.iter().all(|&b| b == 0),
                "the one-shot decrypt must zeroize the buffer when the tag check fails"
            );
        }

        let mut tampered_inline = ct.clone();
        tampered_inline.extend_from_slice(&tag);
        tampered_inline[3] ^= 0xFF;
        for with_aad in [false, true] {
            let mut buf = vec![0u8; D::decrypt_out_len(tampered_inline.len())];
            let result = if with_aad {
                D::decrypt_with_aad_out(&key, &nonce, aad, &tampered_inline, &mut buf)
            } else {
                D::decrypt_out(&key, &nonce, &tampered_inline, &mut buf)
            };
            // Without the AAD the tag was never going to verify; either way what matters is the
            // failure and the zeroized buffer.
            match result {
                Err(SymmetricCipherError::AEADTagCheckFailed) => { /* good */ }
                other => panic!("a modified inline ciphertext must fail, got {other:?}"),
            };
            assert!(
                buf.iter().all(|&b| b == 0),
                "the inline one-shot (aad {with_aad}) must zeroize the buffer on a failed check"
            );
        }
        match D::decrypt_with_aad(&key, &nonce, aad, &tampered_inline) {
            Err(SymmetricCipherError::AEADTagCheckFailed) => { /* good */ }
            other => panic!("decrypt_with_aad of a modified ciphertext must fail, got {other:?}"),
        };

        let mut wrong_tag = tag;
        wrong_tag[0] ^= 0xFF;
        let mut buf = vec![0u8; D::decrypt_detached_out_len(ct.len())];
        match D::decrypt_detached_out(&key, &nonce, aad, &ct, &wrong_tag, &mut buf) {
            Err(SymmetricCipherError::AEADTagCheckFailed) => { /* good */ }
            other => panic!("a modified tag must fail the tag check, got {other:?}"),
        };

        let mut buf = vec![0u8; D::decrypt_detached_out_len(ct.len())];
        match D::decrypt_detached_out(
            &key,
            &nonce,
            b"not the right associated data",
            &ct,
            &tag,
            &mut buf,
        ) {
            Err(SymmetricCipherError::AEADTagCheckFailed) => { /* good */ }
            other => panic!("a modified AAD must fail the tag check, got {other:?}"),
        };

        if NONCE_LEN > 0 {
            let mut wrong_nonce = nonce;
            wrong_nonce[0] ^= 0xFF;
            let mut buf = vec![0u8; D::decrypt_detached_out_len(ct.len())];
            match D::decrypt_detached_out(&key, &wrong_nonce, aad, &ct, &tag, &mut buf) {
                Err(SymmetricCipherError::AEADTagCheckFailed) => { /* good */ }
                other => panic!("a modified nonce must fail the tag check, got {other:?}"),
            };

            // two encryptions under the same key must not reuse a nonce
            let (_enc1, nonce1) = E::do_encrypt_init(&key).unwrap();
            let (_enc2, nonce2) = E::do_encrypt_init(&key).unwrap();
            assert_ne!(nonce1, nonce2);
        }

        // Output-buffer contract for the AEAD `_out` methods, as the symmetric suite above checks it
        // for the inherited ones: a buffer larger than needed is accepted, the returned count is
        // what that call wrote, and every byte past it is zeroed, whatever the buffer held on the
        // way in. Each buffer is pre-filled with a non-zero sentinel, so a byte left as the caller
        // had it shows up. The detached finals' buffers are `[u8; FINAL_LEN]` by type and so
        // cannot be oversized; for them only the zeroed tail is checked.
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
        let len = self.fixed_message_len.unwrap_or(max_len);
        let msg = &DUMMY_SEED[..len];

        // the detached one-shots
        let need = E::encrypt_detached_out_len(len);
        let mut ct = vec![SENTINEL; need + EXTRA];
        let (nonce, n, tag) = E::encrypt_detached_out(&key, aad, msg, &mut ct).unwrap();
        assert_eq!(n, need, "encrypt_detached_out into an oversized buffer");
        assert_tail_zeroed(&ct, n, "encrypt_detached_out");
        ct.truncate(n);
        let mut buf = vec![SENTINEL; need + EXTRA];
        let (_, n, _) = E::encrypt_detached_rng_out(
            &key,
            &mut FixedSeedRNG::<NONCE_LEN>::new(pinned),
            aad,
            msg,
            &mut buf,
        )
        .unwrap();
        assert_eq!(n, need, "encrypt_detached_rng_out into an oversized buffer");
        assert_tail_zeroed(&buf, n, "encrypt_detached_rng_out");
        let mut pt = vec![SENTINEL; D::decrypt_detached_out_len(ct.len()) + EXTRA];
        let n = D::decrypt_detached_out(&key, &nonce, aad, &ct, &tag, &mut pt).unwrap();
        assert_eq!(&pt[..n], msg, "decrypt_detached_out into an oversized buffer");
        assert_tail_zeroed(&pt, n, "decrypt_detached_out");

        // the inline one-shots with associated data
        let need = E::encrypt_out_len(len);
        let mut sealed = vec![SENTINEL; need + EXTRA];
        let (nonce, n) = E::encrypt_with_aad_out(&key, aad, msg, &mut sealed).unwrap();
        assert_eq!(n, need, "encrypt_with_aad_out into an oversized buffer");
        assert_tail_zeroed(&sealed, n, "encrypt_with_aad_out");
        sealed.truncate(n);
        let mut buf = vec![SENTINEL; need + EXTRA];
        let (_, n) = E::encrypt_with_aad_rng_out(
            &key,
            &mut FixedSeedRNG::<NONCE_LEN>::new(pinned),
            aad,
            msg,
            &mut buf,
        )
        .unwrap();
        assert_eq!(n, need, "encrypt_with_aad_rng_out into an oversized buffer");
        assert_tail_zeroed(&buf, n, "encrypt_with_aad_rng_out");
        let mut pt = vec![SENTINEL; D::decrypt_out_len(sealed.len()) + EXTRA];
        let n = D::decrypt_with_aad_out(&key, &nonce, aad, &sealed, &mut pt).unwrap();
        assert_eq!(&pt[..n], msg, "decrypt_with_aad_out into an oversized buffer");
        assert_tail_zeroed(&pt, n, "decrypt_with_aad_out");

        // the detached finals: each reports only what it wrote itself, so with what the update
        // released it adds up to exactly the message
        let (mut enc, nonce) = E::do_encrypt_init(&key).unwrap();
        enc.do_update_aad(aad).unwrap();
        let mut ct = vec![0u8; enc.do_encrypt_out_len(len)];
        let written = enc.do_encrypt_out(msg, &mut ct).unwrap();
        ct.truncate(written);
        let mut last = [SENTINEL; FINAL_LEN];
        let (last_len, tag) = enc.do_encrypt_final_detachedtag_out(&mut last).unwrap();
        assert_tail_zeroed(&last, last_len, "do_encrypt_final_detachedtag_out");
        ct.extend_from_slice(&last[..last_len]);
        assert_eq!(
            ct.len(),
            E::encrypt_detached_out_len(len),
            "do_encrypt_out and do_encrypt_final_detachedtag_out must report only their own bytes"
        );
        let mut dec = D::do_decrypt_init(&key, &nonce).unwrap();
        dec.do_update_aad(aad).unwrap();
        let mut rec = vec![0u8; dec.do_decrypt_out_len(ct.len())];
        let released = dec.do_decrypt_out(&ct, &mut rec).unwrap();
        rec.truncate(released);
        let mut last = [SENTINEL; FINAL_LEN];
        let data_len = dec.do_decrypt_final_detachedtag_out(&tag, &mut last).unwrap();
        assert_tail_zeroed(&last, data_len, "do_decrypt_final_detachedtag_out");
        rec.extend_from_slice(&last[..data_len]);
        assert_eq!(
            rec, msg,
            "do_decrypt_out and do_decrypt_final_detachedtag_out must report only their own bytes"
        );

        // The key-type and security-strength checks on `do_encrypt_init` / `do_decrypt_init` are
        // covered by the `TestFrameworkSymmetricCipher` suite run above.
    }
}

/// Instance of the test framework.
pub struct TestFrameworkAEADTaggedLayout {
    // Put any config options here
}

impl Default for TestFrameworkAEADTaggedLayout {
    fn default() -> Self {
        Self::new()
    }
}

/// The associated data every case is run under.
const AAD: &[u8] = b"aad";

impl TestFrameworkAEADTaggedLayout {
    ///
    pub fn new() -> Self {
        Self {}
    }

    /// Exercises the inline-layout contract for one encryptor/decryptor pair.
    ///
    /// Checks, in order:
    /// * at every message length from 0 to `4 * TAG_LEN + 5`: the one-shot pair round-trips, the
    ///   detached one-shot is the same ciphertext with the tag split off, and for every chunking
    ///   the streaming pair agrees with the one-shot byte for byte -- with the decryptor, not the
    ///   caller, holding back the possible tag, in both the inline and the detached finalization;
    /// * a tampered inline stream fails at finalization on both entry points and the one-shots
    ///   zeroize their buffer, and an input shorter than the tag is `DecryptionFailed` rather
    ///   than a panic on the short slice;
    /// * every inline one-shot refuses an output buffer one byte short, naming the length it
    ///   needs, and accepts one of exactly that length.
    pub fn test<
        const KEY_LEN: usize,
        const NONCE_LEN: usize,
        const TAG_LEN: usize,
        const FINAL_LEN: usize,
        E: AEADCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
        D: AEADCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
    >(
        &self,
    ) {
        let key = KeyMaterial::<KEY_LEN>::from_bytes_as_type(
            &DUMMY_SEED[..KEY_LEN],
            KeyType::SymmetricCipherKey,
        )
        .unwrap();
        Self::round_trip_at_every_length_and_chunking::<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN, E, D>(
            &key,
        );
        Self::tampering_and_short_input_are_rejected::<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN, E, D>(
            &key,
        );
        Self::undersized_buffers_are_rejected::<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN, E, D>(&key);
    }

    /// The pinned RNG every encryption draws its nonce from, so that all paths use one nonce.
    fn rng<const NONCE_LEN: usize>() -> FixedSeedRNG<NONCE_LEN> {
        FixedSeedRNG::<NONCE_LEN>::new(core::array::from_fn(|i| 0xA5 ^ (i as u8)))
    }

    /// Encrypts `msg` into the inline layout with the one-shot, under the pinned nonce, and
    /// returns it with that nonce.
    fn tagged_ct<
        const KEY_LEN: usize,
        const NONCE_LEN: usize,
        const TAG_LEN: usize,
        const FINAL_LEN: usize,
        E: AEADCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
    >(
        key: &KeyMaterial<KEY_LEN>,
        msg: &[u8],
    ) -> (Vec<u8>, [u8; NONCE_LEN]) {
        let mut ct = vec![0u8; E::encrypt_out_len(msg.len())];
        let (nonce, written) =
            E::encrypt_with_aad_rng_out(key, &mut Self::rng::<NONCE_LEN>(), AAD, msg, &mut ct)
                .unwrap();
        assert_eq!(written, msg.len() + TAG_LEN, "inline layout is ciphertext || tag");
        ct.truncate(written);
        (ct, nonce)
    }

    fn round_trip_at_every_length_and_chunking<
        const KEY_LEN: usize,
        const NONCE_LEN: usize,
        const TAG_LEN: usize,
        const FINAL_LEN: usize,
        E: AEADCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
        D: AEADCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
    >(
        key: &KeyMaterial<KEY_LEN>,
    ) {
        for len in 0..=(4 * TAG_LEN + 5) {
            let msg = &DUMMY_SEED[..len];
            let (ct, nonce) =
                Self::tagged_ct::<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN, E>(key, msg);

            let mut pt = vec![0u8; D::decrypt_out_len(ct.len())];
            let n = D::decrypt_with_aad_out(key, &nonce, AAD, &ct, &mut pt).unwrap();
            assert_eq!(&pt[..n], msg, "len {len}: one-shot round trip");

            // The detached layout is the same ciphertext with the tag split off.
            let mut detached = vec![0u8; E::encrypt_detached_out_len(len)];
            let (d_nonce, d_len, d_tag) = E::encrypt_detached_rng_out(
                key,
                &mut Self::rng::<NONCE_LEN>(),
                AAD,
                msg,
                &mut detached,
            )
            .unwrap();
            assert_eq!(d_nonce, nonce, "len {len}: the pinned RNG must give the same nonce");
            assert_eq!(&detached[..d_len], &ct[..len], "len {len}: detached ciphertext");
            assert_eq!(&d_tag[..], &ct[len..], "len {len}: detached tag");

            for chunk in [1usize, 2, 3, TAG_LEN.max(1), len.max(1)] {
                // Encrypt in chunks, finishing with the tag appended by the streaming finalizer.
                let (mut enc, stream_nonce) =
                    E::do_encrypt_init_rng(key, &mut Self::rng::<NONCE_LEN>()).unwrap();
                assert_eq!(stream_nonce, nonce, "len {len}: streaming init draws the same nonce");
                enc.do_update_aad(AAD).unwrap();
                let mut stream_ct = vec![0u8; len + FINAL_LEN];
                let mut written = 0;
                for piece in msg.chunks(chunk) {
                    written += enc.do_encrypt_out(piece, &mut stream_ct[written..]).unwrap();
                }
                let mut last = [0u8; FINAL_LEN];
                let last_len = enc.do_encrypt_final_out(&mut last).unwrap();
                stream_ct[written..written + last_len].copy_from_slice(&last[..last_len]);
                written += last_len;
                stream_ct.truncate(written);
                assert_eq!(
                    stream_ct, ct,
                    "len {len}, chunk {chunk}: streaming must match the one-shot"
                );

                // Decrypt in chunks, tag and all: the decryptor holds the tag back itself, so
                // nothing past the plaintext is ever released, and the final call releases
                // whatever plaintext it was still holding and nothing more.
                let mut dec = D::do_decrypt_init(key, &stream_nonce).unwrap();
                dec.do_update_aad(AAD).unwrap();
                let mut out = vec![0u8; stream_ct.len() + FINAL_LEN];
                let mut written = 0;
                for piece in stream_ct.chunks(chunk) {
                    written += dec.do_decrypt_out(piece, &mut out[written..]).unwrap();
                }
                assert!(written <= len, "len {len}, chunk {chunk}: the tag must be held back");
                let (last, data_len) = dec.do_decrypt_final().unwrap();
                assert_eq!(
                    written + data_len,
                    len,
                    "len {len}, chunk {chunk}: the final call releases exactly the rest"
                );
                out[written..written + data_len].copy_from_slice(&last[..data_len]);
                out.truncate(written + data_len);
                assert_eq!(out, msg, "len {len}, chunk {chunk}: streaming round trip");

                // The same held-back bytes are ciphertext if the tag is detached.
                let mut dec = D::do_decrypt_init(key, &stream_nonce).unwrap();
                dec.do_update_aad(AAD).unwrap();
                let mut out = vec![0u8; len + FINAL_LEN];
                let mut written = 0;
                for piece in stream_ct[..len].chunks(chunk) {
                    written += dec.do_decrypt_out(piece, &mut out[written..]).unwrap();
                }
                let mut last = [0u8; FINAL_LEN];
                let last_len = dec.do_decrypt_final_detachedtag_out(&d_tag, &mut last).unwrap();
                assert_eq!(
                    written + last_len,
                    len,
                    "len {len}, chunk {chunk}: detached final flushes the rest"
                );
                out[written..written + last_len].copy_from_slice(&last[..last_len]);
                out.truncate(written + last_len);
                assert_eq!(out, msg, "len {len}, chunk {chunk}: detached streaming round trip");
            }
        }
    }

    fn tampering_and_short_input_are_rejected<
        const KEY_LEN: usize,
        const NONCE_LEN: usize,
        const TAG_LEN: usize,
        const FINAL_LEN: usize,
        E: AEADCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
        D: AEADCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
    >(
        key: &KeyMaterial<KEY_LEN>,
    ) {
        let msg = &DUMMY_SEED[..10];
        let (ct, nonce) = Self::tagged_ct::<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN, E>(key, msg);

        let mut tampered = ct.clone();
        tampered[0] ^= 0xFF;
        let mut pt = vec![0u8; tampered.len()];
        assert!(matches!(
            D::decrypt_with_aad_out(key, &nonce, AAD, &tampered, &mut pt),
            Err(SymmetricCipherError::AEADTagCheckFailed)
        ));
        assert_eq!(pt, vec![0u8; tampered.len()], "the one-shot zeroizes on a failed tag check");

        let mut dec = D::do_decrypt_init(key, &nonce).unwrap();
        dec.do_update_aad(AAD).unwrap();
        dec.do_decrypt_out(&tampered, &mut pt).unwrap();
        assert!(matches!(dec.do_decrypt_final(), Err(SymmetricCipherError::AEADTagCheckFailed)));

        // A wrong detached tag fails, and `decrypt_detached_out` zeroizes what it wrote.
        let mut wrong_tag = [0u8; TAG_LEN];
        wrong_tag.copy_from_slice(&ct[msg.len()..]);
        wrong_tag[0] ^= 0xFF;
        let mut pt = vec![0u8; msg.len()];
        assert!(matches!(
            D::decrypt_detached_out(key, &nonce, AAD, &ct[..msg.len()], &wrong_tag, &mut pt),
            Err(SymmetricCipherError::AEADTagCheckFailed)
        ));
        assert_eq!(pt, vec![0u8; msg.len()], "the detached one-shot zeroizes on a failed check");

        for short_len in 0..TAG_LEN {
            let mut pt = vec![0u8; TAG_LEN];
            assert!(
                matches!(
                    D::decrypt_with_aad_out(key, &nonce, AAD, &ct[..short_len], &mut pt),
                    Err(SymmetricCipherError::DecryptionFailed)
                ),
                "{short_len} bytes cannot carry a {TAG_LEN}-byte tag (one-shot)"
            );
            let mut dec = D::do_decrypt_init(key, &nonce).unwrap();
            assert_eq!(dec.do_decrypt_out(&ct[..short_len], &mut pt).unwrap(), 0);
            assert!(
                matches!(dec.do_decrypt_final(), Err(SymmetricCipherError::DecryptionFailed)),
                "{short_len} bytes cannot carry a {TAG_LEN}-byte tag (streaming)"
            );
        }
    }

    fn undersized_buffers_are_rejected<
        const KEY_LEN: usize,
        const NONCE_LEN: usize,
        const TAG_LEN: usize,
        const FINAL_LEN: usize,
        E: AEADCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
        D: AEADCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
    >(
        key: &KeyMaterial<KEY_LEN>,
    ) {
        let msg = &DUMMY_SEED[..8];
        let (ct, nonce) = Self::tagged_ct::<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN, E>(key, msg);

        let needed = E::encrypt_out_len(msg.len());
        assert_eq!(needed, msg.len() + TAG_LEN);
        let mut short = vec![0u8; needed - 1];
        match E::encrypt_with_aad_rng_out(key, &mut Self::rng::<NONCE_LEN>(), AAD, msg, &mut short)
        {
            Err(SymmetricCipherError::OutputBufferTooSmall(n)) => assert_eq!(n, needed),
            other => panic!("encrypt_with_aad_out into a short buffer: {other:?}"),
        }

        let needed = D::decrypt_out_len(ct.len());
        assert_eq!(needed, msg.len());
        let mut short = vec![0u8; needed - 1];
        match D::decrypt_with_aad_out(key, &nonce, AAD, &ct, &mut short) {
            Err(SymmetricCipherError::OutputBufferTooSmall(n)) => assert_eq!(n, needed),
            other => panic!("decrypt_with_aad_out into a short buffer: {other:?}"),
        }

        // A buffer of exactly the length it asks for must be accepted. Without this the
        // `plaintext.len() < needed` guard can be weakened to `<=` or `==` without any test
        // noticing: a too-short buffer is caught either way, by the guard or by `do_update_out`
        // behind it, and both report the same error with the same length.
        let mut exact = vec![0u8; needed];
        let n = D::decrypt_with_aad_out(key, &nonce, AAD, &ct, &mut exact).unwrap();
        assert_eq!(&exact[..n], msg, "a buffer of exactly `needed` bytes must be enough");
    }
}
