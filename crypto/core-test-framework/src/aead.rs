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

use crate::{DUMMY_SEED, FixedSeedRNG};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey};
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, RNG, SymmetricCipherDecryptor,
    SymmetricCipherEncryptor,
};

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

    /// The AEAD contract over an [`AeadEncryptionKey`] / [`AeadDecryptionKey`] pair: the AAD and
    /// tag contract reached through a key object, with `rng` supplying every nonce draw that is not
    /// pinned. The key-policy checks are `TestFrameworkFromKeyMaterial`'s, and the no-AAD
    /// symmetric contract is reached here as the AEAD one with an empty AAD.
    ///
    /// A key whose workers take one message length ([`fixed_message_len`](Self::fixed_message_len))
    /// takes it through the one-shots too, since those are written over the workers; every other
    /// length is checked to be refused.
    pub fn test_key<
        const KEY_LEN: usize,
        const NONCE_LEN: usize,
        const TAG_LEN: usize,
        const FINAL_LEN: usize,
        K: AeadEncryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>
            + AeadDecryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
    >(
        &self,
        key: &K,
        rng: &mut dyn RNG,
    ) {
        assert!(
            FINAL_LEN >= TAG_LEN,
            "FINAL_LEN must have room for the inline tag the decryptor holds back"
        );
        let encrypt_out_len = |len: usize| {
            <K::Encryptor<'_> as SymmetricCipherEncryptor<NONCE_LEN, FINAL_LEN>>::encrypt_out_len(
                len,
            )
        };
        let encrypt_detached_out_len = |len: usize| {
            <K::Encryptor<'_> as AEADCipherEncryptor<NONCE_LEN, TAG_LEN, FINAL_LEN>>::encrypt_detached_out_len(len)
        };
        let decrypt_out_len = |len: usize| {
            <K::Decryptor<'_> as SymmetricCipherDecryptor<NONCE_LEN, FINAL_LEN>>::decrypt_out_len(
                len,
            )
        };
        let decrypt_detached_out_len = |len: usize| {
            <K::Decryptor<'_> as AEADCipherDecryptor<NONCE_LEN, TAG_LEN, FINAL_LEN>>::decrypt_detached_out_len(len)
        };
        let aad: &[u8] = b"some associated data";
        let pinned = [0xA5u8; NONCE_LEN];
        let fixed_rng = || FixedSeedRNG::<NONCE_LEN>::new(pinned);

        // one-shot round trip, every length up to a few times the tag length (and up to the fixed
        // length, if there is one)
        let max_len = (3 * TAG_LEN.max(1) + 5).max(self.fixed_message_len.unwrap_or(0));
        assert!(max_len <= DUMMY_SEED.len(), "the fixed message length must fit the seed buffer");
        for len in 0..=max_len {
            let msg = &DUMMY_SEED[..len];
            // a fixed-length key takes only that length, one-shot or streamed
            if let Some(fixed) = self.fixed_message_len
                && fixed != len
            {
                let mut ct = vec![0u8; encrypt_detached_out_len(len)];
                assert!(
                    key.encrypt_detached_out(rng, aad, msg, &mut ct).is_err(),
                    "fixed length: a {len}-byte detached one-shot must be refused"
                );
                let mut inline = vec![0u8; encrypt_out_len(len)];
                assert!(
                    key.encrypt_with_aad_out(rng, aad, msg, &mut inline).is_err(),
                    "fixed length: a {len}-byte inline one-shot must be refused"
                );
                let (mut enc, _) = key.create_encryptor(rng).unwrap();
                enc.do_update_aad(aad).unwrap();
                let mut buf = vec![0u8; enc.do_encrypt_out_len(len)];
                assert!(
                    enc.do_encrypt_out(msg, &mut buf).is_err() || enc.do_encrypt_final().is_err(),
                    "fixed length: a {len}-byte stream must be refused"
                );
                continue;
            }
            let mut ct = vec![0u8; encrypt_detached_out_len(len)];
            let (ct_len, nonce, tag) = key.encrypt_detached_out(rng, aad, msg, &mut ct).unwrap();
            ct.truncate(ct_len);
            assert_ne!(tag, [0u8; TAG_LEN], "len {len}: the tag must not be all zeros");
            if len >= 8 {
                assert_ne!(&ct[..], msg, "len {len}: the ciphertext must not be the plaintext");
            }
            let mut pt = vec![0xEEu8; decrypt_detached_out_len(ct.len())];
            let pt_len = key.decrypt_detached_out(&nonce, aad, &ct, &tag, &mut pt).unwrap();
            pt.truncate(pt_len);
            assert_eq!(&pt[..], msg, "one-shot round trip, len {len}");

            // the std one-shots agree with the _out ones for the same nonce
            let (nonce2, ct2, tag2) = key.encrypt_detached(rng, aad, msg).unwrap();
            assert_eq!(ct2.len(), ct_len, "encrypt_detached must return exactly the bytes written");
            let pt2 = key.decrypt_detached(&nonce2, aad, &ct2, &tag2).unwrap();
            assert_eq!(pt2, msg, "std round trip, len {len}");
            let pt3 = key.decrypt_detached(&nonce, aad, &ct, &tag).unwrap();
            assert_eq!(pt3, msg, "decrypt_detached must agree with decrypt_detached_out");

            // the inline `ciphertext || tag` layout with AAD must be exactly the detached
            // ciphertext with the tag appended -- the same bytes under the same nonce -- and both
            // the one-shot and the streaming finalizer must round trip it.
            let mut detached = vec![0u8; encrypt_detached_out_len(len)];
            let (detached_len, pinned_nonce, detached_tag) =
                key.encrypt_detached_out(&mut fixed_rng(), aad, msg, &mut detached).unwrap();
            assert_eq!(pinned_nonce, pinned, "a fixed RNG must yield its stream as the nonce");
            detached.truncate(detached_len);
            detached.extend_from_slice(&detached_tag);

            let mut inline = vec![0u8; encrypt_out_len(len)];
            let (inline_len, inline_nonce) =
                key.encrypt_with_aad_out(rng, aad, msg, &mut inline).unwrap();
            assert_eq!(
                inline_len,
                encrypt_detached_out_len(len) + TAG_LEN,
                "encrypt_with_aad_out must write the ciphertext plus the tag, len {len}"
            );
            let mut pt4 = vec![0xEEu8; decrypt_out_len(inline_len)];
            let pt4_len = key
                .decrypt_with_aad_out(&inline_nonce, aad, &inline[..inline_len], &mut pt4)
                .unwrap();
            assert_eq!(&pt4[..pt4_len], msg, "tagged one-shot round trip, len {len}");

            // the pinned inline one-shot, into a roomy buffer and an exact one
            let mut inline_rng = vec![0u8; encrypt_out_len(len) + 3];
            let (rng_len, rng_nonce) =
                key.encrypt_with_aad_out(&mut fixed_rng(), aad, msg, &mut inline_rng).unwrap();
            assert_eq!(rng_nonce, pinned_nonce, "the same RNG stream must give the same nonce");
            assert_eq!(
                &inline_rng[..rng_len],
                &detached[..],
                "len {len}: the inline layout must be the detached ciphertext and its tag"
            );
            let mut exact = vec![0u8; encrypt_out_len(len)];
            let (exact_len, _) =
                key.encrypt_with_aad_out(&mut fixed_rng(), aad, msg, &mut exact).unwrap();
            assert_eq!(&exact[..exact_len], &detached[..], "len {len}: exact-size buffer");

            // the supplied-nonce forms: the nonce the pinned RNG produced, supplied directly,
            // must give the same bytes from the one-shots, the allocating one-shots, the in-place
            // one-shots and the streaming constructor alike
            let mut by_nonce = vec![0u8; encrypt_detached_out_len(len)];
            let (n_len, n_tag) =
                key.encrypt_detached_nonce_out(&pinned_nonce, aad, msg, &mut by_nonce).unwrap();
            by_nonce.truncate(n_len);
            by_nonce.extend_from_slice(&n_tag);
            assert_eq!(by_nonce, detached, "len {len}: encrypt_detached_nonce_out under the nonce");
            let mut by_nonce = vec![0u8; encrypt_out_len(len)];
            let n_len =
                key.encrypt_with_aad_nonce_out(&pinned_nonce, aad, msg, &mut by_nonce).unwrap();
            assert_eq!(&by_nonce[..n_len], &detached[..], "len {len}: encrypt_with_aad_nonce_out");
            let mut short = vec![0u8; encrypt_out_len(len) - 1];
            match key.encrypt_with_aad_nonce_out(&pinned_nonce, aad, msg, &mut short) {
                Err(SymmetricCipherError::OutputBufferTooSmall(n)) => {
                    assert_eq!(n, encrypt_out_len(len))
                }
                other => panic!("encrypt_with_aad_nonce_out into a short buffer: {other:?}"),
            }
            let (mut alloc_ct, alloc_tag) =
                key.encrypt_detached_nonce(&pinned_nonce, aad, msg).unwrap();
            alloc_ct.extend_from_slice(&alloc_tag);
            assert_eq!(alloc_ct, detached, "len {len}: encrypt_detached_nonce");
            assert_eq!(
                key.encrypt_with_aad_nonce(&pinned_nonce, aad, msg).unwrap(),
                detached,
                "len {len}: encrypt_with_aad_nonce"
            );
            let mut enc_n = key.create_encryptor_nonce(&pinned_nonce);
            enc_n.do_update_aad(aad).unwrap();
            let mut streamed = vec![0u8; enc_n.do_encrypt_out_len(len)];
            let w = enc_n.do_encrypt_out(msg, &mut streamed).unwrap();
            streamed.truncate(w);
            let (last_n, last_n_len) = enc_n.do_encrypt_final().unwrap();
            streamed.extend_from_slice(&last_n[..last_n_len]);
            assert_eq!(streamed, detached, "len {len}: create_encryptor_nonce streaming");
            let mut short = vec![0u8; encrypt_out_len(len) - 1];
            match key.encrypt_with_aad_out(&mut fixed_rng(), aad, msg, &mut short) {
                Err(SymmetricCipherError::OutputBufferTooSmall(n)) => {
                    assert_eq!(n, encrypt_out_len(len))
                }
                other => panic!("encrypt_with_aad_out into a short buffer: {other:?}"),
            }
            let (alloc_nonce, alloc_ct) = key.encrypt_with_aad(rng, aad, msg).unwrap();
            assert_eq!(
                alloc_ct.len(),
                inline_len,
                "encrypt_with_aad must return the bytes written"
            );
            let alloc_pt = key.decrypt_with_aad(&alloc_nonce, aad, &alloc_ct).unwrap();
            assert_eq!(alloc_pt, msg, "allocating inline-with-AAD round trip, len {len}");

            // the in-place one-shots, drawing and supplied-nonce
            let mut buf = msg.to_vec();
            let (ip_nonce, ip_tag) =
                key.encrypt_detached_in_place(&mut fixed_rng(), aad, &mut buf).unwrap();
            assert_eq!(ip_nonce, pinned_nonce, "len {len}: in place, the pinned nonce");
            assert_eq!((&buf[..], ip_tag), (&detached[..len], detached_tag), "len {len}: in place");
            key.decrypt_detached_in_place(&ip_nonce, aad, &mut buf, &ip_tag).unwrap();
            assert_eq!(&buf[..], msg, "len {len}: in-place round trip");
            let ip_tag = key.encrypt_detached_in_place_nonce(&pinned_nonce, aad, &mut buf).unwrap();
            assert_eq!((&buf[..], ip_tag), (&detached[..len], detached_tag), "len {len}: in place");
            key.decrypt_detached_in_place(&pinned_nonce, aad, &mut buf, &ip_tag).unwrap();
            assert_eq!(&buf[..], msg, "len {len}: in-place round trip under the nonce");

            // the streaming constructor under the pinned RNG draws the pinned nonce, and the
            // inline stream decrypts
            let (mut enc5, nonce5) = key.create_encryptor(&mut fixed_rng()).unwrap();
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
            let mut dec5 = key.create_decryptor(&nonce5);
            dec5.do_update_aad(aad).unwrap();
            let mut pt5 = vec![0u8; dec5.do_decrypt_out_len(inline5.len())];
            let got5 = dec5.do_decrypt_out(&inline5, &mut pt5).unwrap();
            pt5.truncate(got5);
            let (last, data_len) = dec5.do_decrypt_final().unwrap();
            pt5.extend_from_slice(&last[..data_len]);
            assert_eq!(pt5, msg, "tagged streaming round trip, len {len}");

            // a stream that ends before a whole tag has been seen is a failed decryption
            if TAG_LEN > 0 {
                let mut dec6 = key.create_decryptor(&nonce5);
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
            let need = encrypt_detached_out_len(len);
            if need > 0 {
                let mut short = vec![0u8; need - 1];
                match key.encrypt_detached_out(rng, aad, msg, &mut short) {
                    Err(SymmetricCipherError::OutputBufferTooSmall(n)) => assert_eq!(n, need),
                    other => panic!("encrypt_detached_out into a short buffer: {other:?}"),
                }
                let mut roomy = vec![0u8; need + 3];
                let (n, _, _) = key.encrypt_detached_out(rng, aad, msg, &mut roomy).unwrap();
                assert_eq!(n, need, "encrypt_detached_out into a roomy buffer");
            }
            let need = encrypt_out_len(len);
            let mut short = vec![0u8; need - 1];
            match key.encrypt_with_aad_out(rng, aad, msg, &mut short) {
                Err(SymmetricCipherError::OutputBufferTooSmall(n)) => assert_eq!(n, need),
                other => panic!("encrypt_with_aad_out into a short buffer: {other:?}"),
            }
            let need = decrypt_detached_out_len(ct.len());
            if need > 0 {
                let mut short = vec![0u8; need - 1];
                match key.decrypt_detached_out(&nonce, aad, &ct, &tag, &mut short) {
                    Err(SymmetricCipherError::OutputBufferTooSmall(n)) => assert_eq!(n, need),
                    other => panic!("decrypt_detached_out into a short buffer: {other:?}"),
                }
            }
            let need = decrypt_out_len(inline_len);
            if need > 0 {
                let mut short = vec![0u8; need - 1];
                match key.decrypt_with_aad_out(&inline_nonce, aad, &inline, &mut short) {
                    Err(SymmetricCipherError::OutputBufferTooSmall(n)) => assert_eq!(n, need),
                    other => panic!("decrypt_with_aad_out into a short buffer: {other:?}"),
                }
            }
        }

        // streaming in every chunking agrees with the one-shot, for both the AAD and the data.
        let msg = &DUMMY_SEED[..self.fixed_message_len.unwrap_or(max_len.max(17))];
        let mut ct_ref = vec![0u8; encrypt_detached_out_len(msg.len())];
        let (ct_ref_len, nonce_ref, tag_ref) =
            key.encrypt_detached_out(&mut fixed_rng(), aad, msg, &mut ct_ref).unwrap();
        ct_ref.truncate(ct_ref_len);

        for chunk in [1usize, 2, 3, 7, TAG_LEN.max(1), TAG_LEN + 1, msg.len().max(1)] {
            let (mut enc, nonce) = key.create_encryptor(&mut fixed_rng()).unwrap();
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
            let (final_len, tag) = enc.do_encrypt_final_detached_out(&mut final_buf).unwrap();
            assert!(
                final_len + TAG_LEN <= FINAL_LEN,
                "chunk {chunk}: the detached flush must leave FINAL_LEN room for the tag"
            );
            ct.extend_from_slice(&final_buf[..final_len]);
            assert_eq!(ct, ct_ref, "chunk {chunk}: streaming must give the one-shot ciphertext");
            assert_eq!(tag, tag_ref, "chunk {chunk}: streaming must give the one-shot tag");

            let mut dec = key.create_decryptor(&nonce);
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
            let final_len = dec.do_decrypt_final_detached_out(&tag, &mut final_buf).unwrap();
            pt.extend_from_slice(&final_buf[..final_len]);
            assert_eq!(pt, msg, "chunk {chunk}: streaming round trip");
        }

        // a wrong detached tag is refused at the final
        let mut wrong_tag = tag_ref;
        wrong_tag[0] ^= 0xFF;
        let mut dec = key.create_decryptor(&nonce_ref);
        dec.do_update_aad(aad).unwrap();
        let mut pt = vec![0u8; dec.do_decrypt_out_len(ct_ref.len())];
        dec.do_decrypt_out(&ct_ref, &mut pt).unwrap();
        let mut last = [0u8; FINAL_LEN];
        assert!(
            matches!(
                dec.do_decrypt_final_detached_out(&wrong_tag, &mut last),
                Err(SymmetricCipherError::AEADTagCheckFailed)
            ),
            "do_decrypt_final_detached_out must check the tag"
        );
        assert!(last.iter().all(|&b| b == 0), "a failed detached final must leave zeros");

        // an empty AAD is a no-op: it must give exactly what absorbing no AAD at all gives, and
        // the inline layout with an empty AAD is the no-AAD symmetric contract
        let mut with_empty = vec![0u8; encrypt_detached_out_len(msg.len())];
        let (len_empty, nonce_empty, tag_empty) =
            key.encrypt_detached_out(&mut fixed_rng(), b"", msg, &mut with_empty).unwrap();
        with_empty.truncate(len_empty);
        let mut without = vec![0u8; encrypt_detached_out_len(msg.len())];
        let (len_none, nonce_none, tag_none) =
            key.encrypt_detached_out(&mut fixed_rng(), &[], msg, &mut without).unwrap();
        without.truncate(len_none);
        assert_eq!(nonce_empty, nonce_none);
        assert_eq!(tag_empty, tag_none, "an empty AAD must be a no-op");
        assert_eq!(with_empty, without, "an empty AAD must be a no-op");
        let mut plain = vec![0u8; encrypt_out_len(msg.len())];
        let (len_plain, nonce_plain) =
            key.encrypt_with_aad_out(&mut fixed_rng(), &[], msg, &mut plain).unwrap();
        assert_eq!(nonce_plain, nonce_none);
        assert_eq!(&plain[..len_plain - TAG_LEN], &without[..], "no-AAD inline ciphertext");
        assert_eq!(&plain[len_plain - TAG_LEN..len_plain], &tag_none, "no-AAD inline tag");

        // a message with no data at all still authenticates its AAD
        if self.fixed_message_len.is_none_or(|fixed| fixed == 0) {
            let (_ct_len, nonce, tag) = key.encrypt_detached_out(rng, aad, &[], &mut []).unwrap();
            key.decrypt_detached_out(&nonce, aad, &[], &tag, &mut []).unwrap();
            match key.decrypt_detached_out(&nonce, b"different associated data", &[], &tag, &mut [])
            {
                Err(SymmetricCipherError::AEADTagCheckFailed) => { /* good */ }
                other => panic!("an empty message must still authenticate its AAD, got {other:?}"),
            };
        }

        // the AAD phase is over once data has been fed in -- on both sides, and on the decrypting
        // side even when all of it is still being held back as a possible tag.
        if !msg.is_empty() {
            let (mut enc, nonce) = key.create_encryptor(rng).unwrap();
            let mut ct = vec![0u8; enc.do_encrypt_out_len(msg.len())];
            enc.do_encrypt_out(msg, &mut ct).unwrap();
            match enc.do_update_aad(aad) {
                Err(SymmetricCipherError::StateError(_)) => { /* good */ }
                other => panic!("AAD after data must be refused, got {other:?}"),
            };
            enc.do_update_aad(b"").unwrap();
            let mut final_buf = [0u8; FINAL_LEN];
            let (final_len, tag) = enc.do_encrypt_final_detached_out(&mut final_buf).unwrap();
            ct.extend_from_slice(&final_buf[..final_len]);

            let mut dec = key.create_decryptor(&nonce);
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
            let final_len = dec.do_decrypt_final_detached_out(&tag, &mut final_buf).unwrap();
            pt.extend_from_slice(&final_buf[..final_len]);
            assert_eq!(&pt[..], msg, "a refused do_update_aad must not disturb the state");
        }

        // tampering: every one of these must fail the tag check, and the one-shots must leave no
        // plaintext behind when they do. Their buffers are pre-filled with a non-zero byte, so one
        // the decryptor never wrote is not mistaken for one it zeroized. A message long enough to
        // have a byte 3 to flip, unless the pair's fixed length says otherwise.
        let msg = &DUMMY_SEED[..self.fixed_message_len.unwrap_or(max_len.max(17))];
        let mut ct = vec![0u8; encrypt_detached_out_len(msg.len())];
        let (ct_len, nonce, tag) = key.encrypt_detached_out(rng, aad, msg, &mut ct).unwrap();
        ct.truncate(ct_len);

        if ct.len() > 3 {
            let mut tampered = ct.clone();
            tampered[3] ^= 0xFF;
            let mut buf = vec![0xEEu8; decrypt_detached_out_len(tampered.len())];
            match key.decrypt_detached_out(&nonce, aad, &tampered, &tag, &mut buf) {
                Err(SymmetricCipherError::AEADTagCheckFailed) => { /* good */ }
                other => panic!("a modified ciphertext must fail the tag check, got {other:?}"),
            };
            assert!(
                buf.iter().all(|&b| b == 0),
                "the one-shot decrypt must zeroize the buffer when the tag check fails"
            );
            let mut buf = tampered.clone();
            match key.decrypt_detached_in_place(&nonce, aad, &mut buf, &tag) {
                Err(SymmetricCipherError::AEADTagCheckFailed) => { /* good */ }
                other => panic!("a modified ciphertext must fail in place too, got {other:?}"),
            };
            assert!(
                buf.iter().all(|&b| b == 0),
                "the in-place decrypt must zeroize the buffer when the tag check fails"
            );
        }

        let mut tampered_inline = ct.clone();
        tampered_inline.extend_from_slice(&tag);
        tampered_inline[3] ^= 0xFF;
        for with_aad in [false, true] {
            let mut buf = vec![0xEEu8; decrypt_out_len(tampered_inline.len())];
            let aad_used: &[u8] = if with_aad { aad } else { &[] };
            // Without the AAD the tag was never going to verify; either way what matters is the
            // failure and the zeroized buffer.
            match key.decrypt_with_aad_out(&nonce, aad_used, &tampered_inline, &mut buf) {
                Err(SymmetricCipherError::AEADTagCheckFailed) => { /* good */ }
                other => panic!("a modified inline ciphertext must fail, got {other:?}"),
            };
            assert!(
                buf.iter().all(|&b| b == 0),
                "the inline one-shot (aad {with_aad}) must zeroize the buffer on a failed check"
            );
        }
        match key.decrypt_with_aad(&nonce, aad, &tampered_inline) {
            Err(SymmetricCipherError::AEADTagCheckFailed) => { /* good */ }
            other => panic!("decrypt_with_aad of a modified ciphertext must fail, got {other:?}"),
        };

        let mut wrong_tag = tag;
        wrong_tag[0] ^= 0xFF;
        let mut buf = vec![0xEEu8; decrypt_detached_out_len(ct.len())];
        match key.decrypt_detached_out(&nonce, aad, &ct, &wrong_tag, &mut buf) {
            Err(SymmetricCipherError::AEADTagCheckFailed) => { /* good */ }
            other => panic!("a modified tag must fail the tag check, got {other:?}"),
        };
        assert!(buf.iter().all(|&b| b == 0), "a modified tag must leave the buffer zeroized");

        let mut buf = vec![0xEEu8; decrypt_detached_out_len(ct.len())];
        match key.decrypt_detached_out(
            &nonce,
            b"not the right associated data",
            &ct,
            &tag,
            &mut buf,
        ) {
            Err(SymmetricCipherError::AEADTagCheckFailed) => { /* good */ }
            other => panic!("a modified AAD must fail the tag check, got {other:?}"),
        };
        assert!(buf.iter().all(|&b| b == 0), "a modified AAD must leave the buffer zeroized");

        if NONCE_LEN > 0 {
            let mut wrong_nonce = nonce;
            wrong_nonce[0] ^= 0xFF;
            let mut buf = vec![0xEEu8; decrypt_detached_out_len(ct.len())];
            match key.decrypt_detached_out(&wrong_nonce, aad, &ct, &tag, &mut buf) {
                Err(SymmetricCipherError::AEADTagCheckFailed) => { /* good */ }
                other => panic!("a modified nonce must fail the tag check, got {other:?}"),
            };
            assert!(buf.iter().all(|&b| b == 0), "a modified nonce must leave the buffer zeroized");

            // two encryptions under the same key must not reuse a nonce
            let (_enc1, nonce1) = key.create_encryptor(rng).unwrap();
            let (_enc2, nonce2) = key.create_encryptor(rng).unwrap();
            assert_ne!(nonce1, nonce2);
        }

        // Output-buffer contract for the AEAD `_out` methods: a buffer larger than needed is
        // accepted, the returned count is what that call wrote, and every byte past it is zeroed.
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

        let need = encrypt_detached_out_len(len);
        let mut ct = vec![SENTINEL; need + EXTRA];
        let (n, nonce, tag) = key.encrypt_detached_out(rng, aad, msg, &mut ct).unwrap();
        assert_eq!(n, need, "encrypt_detached_out into an oversized buffer");
        assert_tail_zeroed(&ct, n, "encrypt_detached_out");
        ct.truncate(n);
        let mut pt = vec![SENTINEL; decrypt_detached_out_len(ct.len()) + EXTRA];
        let n = key.decrypt_detached_out(&nonce, aad, &ct, &tag, &mut pt).unwrap();
        assert_eq!(&pt[..n], msg, "decrypt_detached_out into an oversized buffer");
        assert_tail_zeroed(&pt, n, "decrypt_detached_out");

        let need = encrypt_out_len(len);
        let mut sealed = vec![SENTINEL; need + EXTRA];
        let (n, nonce) = key.encrypt_with_aad_out(rng, aad, msg, &mut sealed).unwrap();
        assert_eq!(n, need, "encrypt_with_aad_out into an oversized buffer");
        assert_tail_zeroed(&sealed, n, "encrypt_with_aad_out");
        sealed.truncate(n);
        let mut pt = vec![SENTINEL; decrypt_out_len(sealed.len()) + EXTRA];
        let n = key.decrypt_with_aad_out(&nonce, aad, &sealed, &mut pt).unwrap();
        assert_eq!(&pt[..n], msg, "decrypt_with_aad_out into an oversized buffer");
        assert_tail_zeroed(&pt, n, "decrypt_with_aad_out");

        // the detached finals: each reports only what it wrote itself
        let (mut enc, nonce) = key.create_encryptor(rng).unwrap();
        enc.do_update_aad(aad).unwrap();
        let mut ct = vec![0u8; enc.do_encrypt_out_len(len)];
        let written = enc.do_encrypt_out(msg, &mut ct).unwrap();
        ct.truncate(written);
        let mut last = [SENTINEL; FINAL_LEN];
        let (last_len, tag) = enc.do_encrypt_final_detached_out(&mut last).unwrap();
        assert_tail_zeroed(&last, last_len, "do_encrypt_final_detached_out");
        ct.extend_from_slice(&last[..last_len]);
        assert_eq!(
            ct.len(),
            encrypt_detached_out_len(len),
            "do_encrypt_out and do_encrypt_final_detached_out must report only their own bytes"
        );
        let mut dec = key.create_decryptor(&nonce);
        dec.do_update_aad(aad).unwrap();
        let mut rec = vec![0u8; dec.do_decrypt_out_len(ct.len())];
        let released = dec.do_decrypt_out(&ct, &mut rec).unwrap();
        rec.truncate(released);
        let mut last = [SENTINEL; FINAL_LEN];
        let data_len = dec.do_decrypt_final_detached_out(&tag, &mut last).unwrap();
        assert_tail_zeroed(&last, data_len, "do_decrypt_final_detached_out");
        rec.extend_from_slice(&last[..data_len]);
        assert_eq!(
            rec, msg,
            "do_decrypt_out and do_decrypt_final_detached_out must report only their own bytes"
        );
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

    /// The pinned RNG every encryption draws its nonce from, so that all paths use one nonce.
    fn rng<const NONCE_LEN: usize>() -> FixedSeedRNG<NONCE_LEN> {
        FixedSeedRNG::<NONCE_LEN>::new(core::array::from_fn(|i| 0xA5 ^ (i as u8)))
    }

    /// The two tag layouts' contract over an [`AeadEncryptionKey`] /
    /// [`AeadDecryptionKey`] pair; every nonce is drawn from the pinned RNG.
    pub fn test_key<
        const KEY_LEN: usize,
        const NONCE_LEN: usize,
        const TAG_LEN: usize,
        const FINAL_LEN: usize,
        K: AeadEncryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>
            + AeadDecryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
    >(
        &self,
        key: &K,
    ) {
        let encrypt_out_len = |len: usize| {
            <K::Encryptor<'_> as SymmetricCipherEncryptor<NONCE_LEN, FINAL_LEN>>::encrypt_out_len(
                len,
            )
        };
        let encrypt_detached_out_len = |len: usize| {
            <K::Encryptor<'_> as AEADCipherEncryptor<NONCE_LEN, TAG_LEN, FINAL_LEN>>::encrypt_detached_out_len(len)
        };
        let decrypt_out_len = |len: usize| {
            <K::Decryptor<'_> as SymmetricCipherDecryptor<NONCE_LEN, FINAL_LEN>>::decrypt_out_len(
                len,
            )
        };
        // Encrypts `msg` into the inline layout with the one-shot, under the pinned nonce.
        let tagged_ct = |msg: &[u8]| -> (Vec<u8>, [u8; NONCE_LEN]) {
            let mut ct = vec![0u8; encrypt_out_len(msg.len())];
            let (written, nonce) =
                key.encrypt_with_aad_out(&mut Self::rng::<NONCE_LEN>(), AAD, msg, &mut ct).unwrap();
            assert_eq!(written, msg.len() + TAG_LEN, "inline layout is ciphertext || tag");
            ct.truncate(written);
            (ct, nonce)
        };

        // round trip at every length and chunking
        for len in 0..=(4 * TAG_LEN + 5) {
            let msg = &DUMMY_SEED[..len];
            let (ct, nonce) = tagged_ct(msg);

            let mut pt = vec![0xEEu8; decrypt_out_len(ct.len())];
            let n = key.decrypt_with_aad_out(&nonce, AAD, &ct, &mut pt).unwrap();
            assert_eq!(&pt[..n], msg, "len {len}: one-shot round trip");

            // The detached layout is the same ciphertext with the tag split off.
            let mut detached = vec![0u8; encrypt_detached_out_len(len)];
            let (d_len, d_nonce, d_tag) = key
                .encrypt_detached_out(&mut Self::rng::<NONCE_LEN>(), AAD, msg, &mut detached)
                .unwrap();
            assert_eq!(d_nonce, nonce, "len {len}: the pinned RNG must give the same nonce");
            assert_eq!(&detached[..d_len], &ct[..len], "len {len}: detached ciphertext");
            assert_eq!(&d_tag[..], &ct[len..], "len {len}: detached tag");

            for chunk in [1usize, 2, 3, TAG_LEN.max(1), len.max(1)] {
                let (mut enc, stream_nonce) =
                    key.create_encryptor(&mut Self::rng::<NONCE_LEN>()).unwrap();
                assert_eq!(stream_nonce, nonce, "len {len}: streaming init draws the same nonce");
                enc.do_update_aad(AAD).unwrap();
                let mut stream_ct = vec![0u8; len + FINAL_LEN];
                let mut written = 0;
                for piece in msg.chunks(chunk) {
                    written += enc.do_encrypt_out(piece, &mut stream_ct[written..]).unwrap();
                }
                let (last, last_len) = enc.do_encrypt_final().unwrap();
                stream_ct[written..written + last_len].copy_from_slice(&last[..last_len]);
                written += last_len;
                stream_ct.truncate(written);
                assert_eq!(
                    stream_ct, ct,
                    "len {len}, chunk {chunk}: streaming must match the one-shot"
                );

                // the decryptor holds the tag back itself
                let mut dec = key.create_decryptor(&stream_nonce);
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
                let mut dec = key.create_decryptor(&stream_nonce);
                dec.do_update_aad(AAD).unwrap();
                let mut out = vec![0u8; len + FINAL_LEN];
                let mut written = 0;
                for piece in stream_ct[..len].chunks(chunk) {
                    written += dec.do_decrypt_out(piece, &mut out[written..]).unwrap();
                }
                let mut last = [0u8; FINAL_LEN];
                let last_len = dec.do_decrypt_final_detached_out(&d_tag, &mut last).unwrap();
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

        // tampering and short input are rejected
        let msg = &DUMMY_SEED[..10];
        let (ct, nonce) = tagged_ct(msg);
        let mut tampered = ct.clone();
        tampered[0] ^= 0xFF;
        let mut pt = vec![0xEEu8; tampered.len()];
        assert!(matches!(
            key.decrypt_with_aad_out(&nonce, AAD, &tampered, &mut pt),
            Err(SymmetricCipherError::AEADTagCheckFailed)
        ));
        assert_eq!(pt, vec![0u8; tampered.len()], "the one-shot zeroizes on a failed tag check");
        let mut dec = key.create_decryptor(&nonce);
        dec.do_update_aad(AAD).unwrap();
        dec.do_decrypt_out(&tampered, &mut pt).unwrap();
        assert!(matches!(dec.do_decrypt_final(), Err(SymmetricCipherError::AEADTagCheckFailed)));

        let mut wrong_tag = [0u8; TAG_LEN];
        wrong_tag.copy_from_slice(&ct[msg.len()..]);
        wrong_tag[0] ^= 0xFF;
        let mut pt = vec![0xEEu8; msg.len()];
        assert!(matches!(
            key.decrypt_detached_out(&nonce, AAD, &ct[..msg.len()], &wrong_tag, &mut pt),
            Err(SymmetricCipherError::AEADTagCheckFailed)
        ));
        assert_eq!(pt, vec![0u8; msg.len()], "the detached one-shot zeroizes on a failed check");

        for short_len in 0..TAG_LEN {
            let mut pt = vec![0u8; TAG_LEN];
            assert!(
                matches!(
                    key.decrypt_with_aad_out(&nonce, AAD, &ct[..short_len], &mut pt),
                    Err(SymmetricCipherError::DecryptionFailed)
                ),
                "{short_len} bytes cannot carry a {TAG_LEN}-byte tag (one-shot)"
            );
            let mut dec = key.create_decryptor(&nonce);
            assert_eq!(dec.do_decrypt_out(&ct[..short_len], &mut pt).unwrap(), 0);
            assert!(
                matches!(dec.do_decrypt_final(), Err(SymmetricCipherError::DecryptionFailed)),
                "{short_len} bytes cannot carry a {TAG_LEN}-byte tag (streaming)"
            );
        }

        // undersized buffers are rejected, and one of exactly the length asked for is accepted
        let msg = &DUMMY_SEED[..8];
        let (ct, nonce) = tagged_ct(msg);
        let needed = encrypt_out_len(msg.len());
        assert_eq!(needed, msg.len() + TAG_LEN);
        let mut short = vec![0u8; needed - 1];
        match key.encrypt_with_aad_out(&mut Self::rng::<NONCE_LEN>(), AAD, msg, &mut short) {
            Err(SymmetricCipherError::OutputBufferTooSmall(n)) => assert_eq!(n, needed),
            other => panic!("encrypt_with_aad_out into a short buffer: {other:?}"),
        }
        let needed = decrypt_out_len(ct.len());
        assert_eq!(needed, msg.len());
        let mut short = vec![0u8; needed - 1];
        match key.decrypt_with_aad_out(&nonce, AAD, &ct, &mut short) {
            Err(SymmetricCipherError::OutputBufferTooSmall(n)) => assert_eq!(n, needed),
            other => panic!("decrypt_with_aad_out into a short buffer: {other:?}"),
        }
        let mut exact = vec![0u8; needed];
        let n = key.decrypt_with_aad_out(&nonce, AAD, &ct, &mut exact).unwrap();
        assert_eq!(&exact[..n], msg, "a buffer of exactly `needed` bytes must be enough");
    }
}
