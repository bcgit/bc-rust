//! Testing the default implementations of the AEAD traits.
//!
//! Every one-shot on [`AEADCipherEncryptor`] / [`AEADCipherDecryptor`] and their supertraits is a
//! default method in `bouncycastle-core` that stitches a streaming call and a final call together,
//! so the `written + final_len` arithmetic in each of them is only observable when the final call
//! releases data. No real cipher in the workspace does that a few bytes at a time -- GCM and Ascon
//! hold back nothing but the tag, CCM's adapters hold back everything -- so this is this crate's
//! own test of those defaults, over a toy built to hold back up to three bytes. It lives here
//! rather than in `bouncycastle-core-test-framework` because it tests code in this crate, and
//! because using the framework from here would make the two crates dev-depend on each other.
//!
//! [`AEADCipherEncryptor`]: bouncycastle_core::traits::AEADCipherEncryptor
//! [`AEADCipherDecryptor`]: bouncycastle_core::traits::AEADCipherDecryptor

/// Pins that a *genuinely buffering* `AEADCipherEncryptor` / `AEADCipherDecryptor` pair's
/// `update_out_len` is honoured through every chunking, against a toy built to hold back up to
/// three bytes at a time before releasing them -- more than the tag the decryptor has to hold
/// back anyway -- the property `TestFrameworkAEADCipher::test_encryptor_decryptor` cannot pin on its own, since
/// a caller-supplied `E`/`D` might hold back nothing but the tag (Ascon-AEAD128 holds back
/// nothing else). Modelled on the toy permutations `crypto/cipher/tests/modes/common/mod.rs` uses for
/// the equivalent block-cipher property.
///
/// The toy's "ciphertext" is the plaintext with a per-byte counter XORed in, released three
/// bytes behind what it has consumed when encrypting and three plus `TAG_LEN` when decrypting;
/// its "tag" is a length check. Not remotely a real AEAD -- it exists solely to make holding
/// data back observable.
#[test]
fn a_buffering_pair_is_handled_by_every_default_method() {
    use bouncycastle_core::errors::SymmetricCipherError;
    use bouncycastle_core::key_material::{KeyMaterial, KeyType};
    use bouncycastle_core::security_strength::SecurityStrength;
    use bouncycastle_core::traits::{
        AEADCipherDecryptor, AEADCipherEncryptor, Algorithm, RNG, SymmetricCipherDecryptor,
        SymmetricCipherEncryptor,
    };

    const HOLD_BACK: usize = 3;
    const KEY_LEN: usize = 4;
    const NONCE_LEN: usize = 4;
    const TAG_LEN: usize = 1;
    // What either side's final call can produce: the encryptor's held-back bytes plus the tag
    // after them, or everything the decryptor held back.
    const FINAL_LEN: usize = HOLD_BACK + TAG_LEN;

    struct Buffered {
        hold: usize,
        pos: u8,
        held: [u8; FINAL_LEN],
        held_len: usize,
        len_seen: usize,
    }

    impl Buffered {
        fn new(hold: usize) -> Self {
            Self { hold, pos: 0, held: [0u8; FINAL_LEN], held_len: 0, len_seen: 0 }
        }

        fn update_out_len(&self, input_len: usize) -> usize {
            (self.held_len + input_len).saturating_sub(self.hold)
        }

        /// Feeds `input` in, holding back the last `hold` bytes and releasing (XORed with a
        /// running counter) everything older than that into `output`.
        fn update_out(&mut self, input: &[u8], output: &mut [u8]) -> usize {
            self.len_seen += input.len();
            let total = self.held_len + input.len();
            let releasable = total.saturating_sub(self.hold);
            let from_held = self.held_len.min(releasable);
            let from_new = releasable - from_held;
            for (i, b) in self.held[..from_held].iter().enumerate() {
                output[i] = *b ^ self.pos;
                self.pos = self.pos.wrapping_add(1);
            }
            for (i, b) in input[..from_new].iter().enumerate() {
                output[from_held + i] = *b ^ self.pos;
                self.pos = self.pos.wrapping_add(1);
            }
            // The amount kept is `total - releasable`, which is `hold` once `total` reaches it
            // but only `total` itself before that -- so the tail of `new_held` actually in use
            // is `new_len`, not always the full `hold`.
            let new_len = total - releasable;
            let mut new_held = [0u8; FINAL_LEN];
            let kept_from_held = self.held_len - from_held;
            new_held[..kept_from_held].copy_from_slice(&self.held[from_held..self.held_len]);
            new_held[kept_from_held..new_len].copy_from_slice(&input[from_new..]);
            self.held = new_held;
            self.held_len = new_len;
            releasable
        }

        /// Releases the first `n` held-back bytes into `output`.
        fn finish(&mut self, n: usize, output: &mut [u8]) {
            for (i, b) in self.held[..n].iter().enumerate() {
                output[i] = *b ^ self.pos;
                self.pos = self.pos.wrapping_add(1);
            }
        }
    }

    fn toy_tag(data_len: usize) -> [u8; TAG_LEN] {
        [(data_len % 256) as u8; TAG_LEN]
    }

    struct Enc(Buffered);
    struct Dec(Buffered);

    impl Algorithm for Enc {
        const ALG_NAME: &'static str = "buffering-toy";
        const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::None;
    }
    impl Algorithm for Dec {
        const ALG_NAME: &'static str = "buffering-toy";
        const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::None;
    }

    impl SymmetricCipherEncryptor<KEY_LEN, NONCE_LEN, FINAL_LEN> for Enc {
        fn do_encrypt_init(
            _key: &KeyMaterial<KEY_LEN>,
        ) -> Result<(Self, [u8; NONCE_LEN]), SymmetricCipherError> {
            Ok((Self(Buffered::new(HOLD_BACK)), [0u8; NONCE_LEN]))
        }
        fn do_encrypt_init_rng(
            key: &KeyMaterial<KEY_LEN>,
            _rng: &mut dyn RNG,
        ) -> Result<(Self, [u8; NONCE_LEN]), SymmetricCipherError> {
            Self::do_encrypt_init(key)
        }
        fn do_encrypt_out_len(&self, input_len: usize) -> usize {
            self.0.update_out_len(input_len)
        }
        fn do_encrypt_out(
            &mut self,
            plaintext: &[u8],
            ciphertext: &mut [u8],
        ) -> Result<usize, SymmetricCipherError> {
            ciphertext.fill(0);
            Ok(self.0.update_out(plaintext, ciphertext))
        }
        fn do_encrypt_final(self) -> Result<([u8; FINAL_LEN], usize), SymmetricCipherError> {
            let mut out = [0u8; FINAL_LEN];
            let (n, tag) = self.do_encrypt_final_detachedtag_out(&mut out)?;
            out[n..n + TAG_LEN].copy_from_slice(&tag);
            Ok((out, n + TAG_LEN))
        }
        fn encrypt_out_len(plaintext_len: usize) -> usize {
            plaintext_len + TAG_LEN
        }
    }

    impl AEADCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN> for Enc {
        fn do_update_aad(&mut self, _aad: &[u8]) -> Result<(), SymmetricCipherError> {
            Ok(())
        }
        fn do_encrypt_init_nonce(
            key: &KeyMaterial<KEY_LEN>,
            _nonce: &[u8; NONCE_LEN],
        ) -> Result<Self, SymmetricCipherError> {
            Ok(Self::do_encrypt_init(key)?.0)
        }
        fn do_encrypt_final_detachedtag_out(
            mut self,
            ciphertext: &mut [u8; FINAL_LEN],
        ) -> Result<(usize, [u8; TAG_LEN]), SymmetricCipherError> {
            ciphertext.fill(0);
            let n = self.0.held_len;
            self.0.finish(n, ciphertext);
            Ok((n, toy_tag(self.0.len_seen)))
        }
    }

    impl SymmetricCipherDecryptor<KEY_LEN, NONCE_LEN, FINAL_LEN> for Dec {
        fn do_decrypt_init(
            _key: &KeyMaterial<KEY_LEN>,
            _nonce: &[u8; NONCE_LEN],
        ) -> Result<Self, SymmetricCipherError> {
            Ok(Self(Buffered::new(FINAL_LEN)))
        }
        fn do_decrypt_out_len(&self, input_len: usize) -> usize {
            self.0.update_out_len(input_len)
        }
        fn do_decrypt_out(
            &mut self,
            ciphertext: &[u8],
            plaintext: &mut [u8],
        ) -> Result<usize, SymmetricCipherError> {
            plaintext.fill(0);
            Ok(self.0.update_out(ciphertext, plaintext))
        }
        /// The last `TAG_LEN` held-back bytes are the tag, the rest ciphertext.
        fn do_decrypt_final(mut self) -> Result<([u8; FINAL_LEN], usize), SymmetricCipherError> {
            let Some(n) = self.0.held_len.checked_sub(TAG_LEN) else {
                return Err(SymmetricCipherError::DecryptionFailed);
            };
            let mut out = [0u8; FINAL_LEN];
            self.0.finish(n, &mut out);
            if self.0.held[n..n + TAG_LEN] != toy_tag(self.0.len_seen - TAG_LEN) {
                return Err(SymmetricCipherError::AEADTagCheckFailed);
            }
            Ok((out, n))
        }
        fn decrypt_out_len(ciphertext_len: usize) -> usize {
            ciphertext_len.saturating_sub(TAG_LEN)
        }
    }

    impl AEADCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN> for Dec {
        fn do_update_aad(&mut self, _aad: &[u8]) -> Result<(), SymmetricCipherError> {
            Ok(())
        }
        fn do_decrypt_final_detachedtag_out(
            mut self,
            tag: &[u8; TAG_LEN],
            plaintext: &mut [u8; FINAL_LEN],
        ) -> Result<usize, SymmetricCipherError> {
            plaintext.fill(0);
            let n = self.0.held_len;
            self.0.finish(n, plaintext);
            if *tag != toy_tag(self.0.len_seen) {
                return Err(SymmetricCipherError::AEADTagCheckFailed);
            }
            Ok(n)
        }
    }

    // The bytes every key and message is cut from: `0x00, 0x01, ...`, long enough for the longest
    // message below.
    let seed: [u8; 64] = core::array::from_fn(|i| i as u8);
    let key =
        KeyMaterial::<KEY_LEN>::from_bytes_as_type(&seed[..KEY_LEN], KeyType::SymmetricCipherKey)
            .unwrap();

    for len in 0..=(3 * FINAL_LEN + 5) {
        let msg = &seed[..len];
        let mut ct = vec![0u8; len];
        let (nonce, ct_len, tag) = Enc::encrypt_detached_out(&key, b"", msg, &mut ct).unwrap();
        assert_eq!(ct_len, len, "the toy never expands the data, only the finalizer flushes");

        for chunk in [1usize, 2, 3, HOLD_BACK, FINAL_LEN, FINAL_LEN + 1, len.max(1)] {
            let (mut enc, _) = Enc::do_encrypt_init(&key).unwrap();
            let mut chunked = Vec::new();
            for piece in msg.chunks(chunk) {
                let expect = enc.do_encrypt_out_len(piece.len());
                let mut buf = vec![0u8; expect];
                let n = enc.do_encrypt_out(piece, &mut buf).unwrap();
                assert_eq!(n, expect, "len {len} chunk {chunk}: update_out_len must be exact");
                chunked.extend_from_slice(&buf[..n]);
            }
            let mut final_buf = [0u8; FINAL_LEN];
            let (final_len, chunked_tag) =
                enc.do_encrypt_final_detachedtag_out(&mut final_buf).unwrap();
            chunked.extend_from_slice(&final_buf[..final_len]);
            assert_eq!(chunked, ct, "len {len} chunk {chunk}: chunking must not be visible");
            assert_eq!(
                chunked_tag, tag,
                "len {len} chunk {chunk}: tag must not depend on chunking"
            );

            // detached: the decryptor releases what it held back as a possible tag in
            // `do_decrypt_final_detachedtag_out`, alongside what it held back of its own accord
            let mut dec = Dec::do_decrypt_init(&key, &nonce).unwrap();
            let mut pt = Vec::new();
            for piece in ct.chunks(chunk) {
                let expect = dec.do_decrypt_out_len(piece.len());
                let mut buf = vec![0u8; expect];
                let n = dec.do_decrypt_out(piece, &mut buf).unwrap();
                assert_eq!(n, expect, "len {len} chunk {chunk}: update_out_len must be exact");
                pt.extend_from_slice(&buf[..n]);
            }
            let mut final_buf = [0u8; FINAL_LEN];
            let final_len = dec.do_decrypt_final_detachedtag_out(&tag, &mut final_buf).unwrap();
            pt.extend_from_slice(&final_buf[..final_len]);
            assert_eq!(pt, msg, "len {len} chunk {chunk}: detached round trip");

            // inline: the same stream with the tag on the end, chunked the same way
            let mut inline = ct.clone();
            inline.extend_from_slice(&tag);
            let mut dec = Dec::do_decrypt_init(&key, &nonce).unwrap();
            let mut pt = Vec::new();
            for piece in inline.chunks(chunk) {
                let expect = dec.do_decrypt_out_len(piece.len());
                let mut buf = vec![0u8; expect];
                let n = dec.do_decrypt_out(piece, &mut buf).unwrap();
                assert_eq!(n, expect, "len {len} chunk {chunk}: update_out_len must be exact");
                pt.extend_from_slice(&buf[..n]);
            }
            let (last, data_len) = dec.do_decrypt_final().unwrap();
            pt.extend_from_slice(&last[..data_len]);
            assert_eq!(pt, msg, "len {len} chunk {chunk}: inline round trip");
        }

        // The inline `ciphertext || tag` layout, which is where a buffering cipher makes
        // `do_encrypt_final` do two things at once: flush the held-back bytes and then append the
        // tag after them.
        let (mut enc, nonce) = Enc::do_encrypt_init(&key).unwrap();
        let mut inline = vec![0u8; enc.do_encrypt_out_len(len)];
        let written = enc.do_encrypt_out(msg, &mut inline).unwrap();
        assert!(written < len || len == 0, "len {len}: the toy must be holding something back");
        let (last, last_len) = enc.do_encrypt_final().unwrap();
        inline.extend_from_slice(&last[..last_len]);
        assert_eq!(
            inline.len(),
            len + TAG_LEN,
            "len {len}: inline layout is the message plus a tag"
        );

        let mut one = vec![0u8; Enc::encrypt_out_len(len)];
        let (one_nonce, one_len) = Enc::encrypt_with_aad_out(&key, b"", msg, &mut one).unwrap();
        assert_eq!(&one[..one_len], &inline[..], "len {len}: one-shot must agree");
        assert_eq!(one_nonce, nonce);
        // Exactly the buffer it asks for: that is what makes the `+ data_len` arithmetic in
        // the one-shot observable, since with a generous buffer any arithmetic there would do.
        let mut back = vec![0u8; Dec::decrypt_out_len(one_len)];
        let back_len =
            Dec::decrypt_with_aad_out(&key, &one_nonce, b"", &one[..one_len], &mut back).unwrap();
        assert_eq!(&back[..back_len], msg, "len {len}: inline one-shot round trip");

        // Every other one-shot over the toy too: its final calls flush real data, which is
        // what makes the `written + final_len` arithmetic in each of them observable.
        let mut ct_rng = vec![0u8; len];
        let (_, n_rng, tag_rng) = Enc::encrypt_detached_rng_out(
            &key,
            &mut bouncycastle_rng::DefaultRNG::default(),
            b"",
            msg,
            &mut ct_rng,
        )
        .unwrap();
        assert_eq!(&ct_rng[..n_rng], &ct[..], "len {len}: encrypt_detached_rng_out");
        assert_eq!(tag_rng, tag, "len {len}: encrypt_detached_rng_out tag");
        let mut back = vec![0u8; len];
        let back_len = Dec::decrypt_detached_out(&key, &nonce, b"", &ct, &tag, &mut back).unwrap();
        assert_eq!(&back[..back_len], msg, "len {len}: decrypt_detached_out");
        let mut plain = vec![0u8; Enc::encrypt_out_len(len)];
        let (plain_nonce, plain_len) = Enc::encrypt_out(&key, msg, &mut plain).unwrap();
        assert_eq!(&plain[..plain_len], &inline[..], "len {len}: encrypt_out");
        let mut back = vec![0u8; Dec::decrypt_out_len(plain_len)];
        let back_len =
            Dec::decrypt_out(&key, &plain_nonce, &plain[..plain_len], &mut back).unwrap();
        assert_eq!(&back[..back_len], msg, "len {len}: decrypt_out");

        // For any length past the hold-back window, at least one prefix of the input must be
        // held back rather than released immediately -- the property this whole test exists
        // to pin. (For `len < HOLD_BACK` nothing is ever releasable until `do_encrypt_final`, which
        // is also correct but does not exercise `do_update_out` returning less than it was given.)
        if len > HOLD_BACK {
            let (mut enc, _) = Enc::do_encrypt_init(&key).unwrap();
            let first = &msg[..1];
            let mut buf = vec![0u8; enc.do_encrypt_out_len(first.len())];
            let n = enc.do_encrypt_out(first, &mut buf).unwrap();
            assert_eq!(n, 0, "len {len}: the first byte alone must be held back, not released");
        }
    }
}
