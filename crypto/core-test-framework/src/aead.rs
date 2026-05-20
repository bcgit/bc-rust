//! Known-Answer-Test framework for the [`AeadCipher`] trait.
//!
//! Unlike the other trait test frameworks in this crate, this one cannot
//! construct its own AEAD instance: [`AeadCipher`] is intentionally **not**
//! parameterised over key/nonce shape (see the trait docs in
//! [`bouncycastle_core_interface::traits`]). The framework therefore takes
//! a closure that builds a fresh, fully-initialised context for the
//! caller's (key, nonce) pair. AD is fed in by the framework via the
//! trait's [`AeadCipher::process_aad_bytes`] /
//! [`AeadCipher::process_aad_byte`] so the trait surface is exercised end
//! to end.
//!
//! # What is tested
//! For one (key, nonce, AD, plaintext, expected_ciphertext) tuple, every
//! member of [`AeadCipher`] is driven:
//!
//! * Encryption via one-shot [`AeadCipher::process_bytes`], via
//!   byte-at-a-time [`AeadCipher::process_byte`], and across a fan of
//!   chunk sizes. AD is also fed both as a single slice and as individual
//!   bytes, and the framework verifies all paths produce the same
//!   ciphertext.
//! * The tag returned by [`AeadCipher::get_mac`] matches the trailing
//!   bytes of the expected ciphertext.
//! * Round-trip decryption recovers the plaintext.
//! * [`AeadCipher::get_update_output_size`] and
//!   [`AeadCipher::get_output_size`] correctly predict the bytes produced
//!   by the next `process_bytes` / by `process_bytes` + `do_final`.
//! * Tampered ciphertext and tampered tag cause [`AeadCipher::do_final`]
//!   to panic on decrypt (caught via [`std::panic::catch_unwind`]). This
//!   is the contract documented on the trait: the trait surface has no
//!   `Result` on `do_final`, so auth-fail manifests as a panic. Callers
//!   that need graceful handling are expected to use an inherent fallible
//!   variant, which the framework does *not* test (that is per-impl).

use bouncycastle_core_interface::traits::AeadCipher;
use std::panic::AssertUnwindSafe;

/// Known-Answer-Test driver for [`AeadCipher`].
pub struct TestFrameworkAeadCipher {
    /// Authentication-tag length in bytes. Must match the trailing
    /// segment of `expected_ciphertext` passed to [`Self::test_aead`].
    pub tag_len: usize,
}

impl TestFrameworkAeadCipher {
    /// Construct a new driver for an AEAD with the given tag length in bytes.
    pub fn new(tag_len: usize) -> Self {
        Self { tag_len }
    }

    /// Drive every member of [`AeadCipher`] against a single KAT vector.
    ///
    /// `make_context(for_encryption)` MUST return a freshly-initialised
    /// AEAD context bound to the test's (key, nonce) but with **no AD
    /// pre-absorbed** — the framework feeds AD via the trait surface so
    /// `process_aad_byte` / `process_aad_bytes` are exercised. Calling the
    /// closure multiple times with the same direction MUST yield
    /// contexts that produce identical output (i.e. the closure is
    /// effectively constructing the same instance fresh each time).
    ///
    /// `expected_ciphertext` is the full output of encrypt:
    /// `ciphertext_body || tag`, of length `plaintext.len() + self.tag_len`.
    ///
    /// # Panics
    /// On any check failure. Tampered-ciphertext / tampered-tag sub-tests
    /// expect [`AeadCipher::do_final`] itself to panic; if it does not,
    /// this function panics with an informative message.
    pub fn test_aead<A: AeadCipher>(
        &self,
        make_context: &dyn Fn(bool) -> A,
        ad: &[u8],
        plaintext: &[u8],
        expected_ciphertext: &[u8],
    ) {
        let tag_len = self.tag_len;
        let total_ct_len = plaintext.len() + tag_len;
        assert_eq!(
            expected_ciphertext.len(),
            total_ct_len,
            "expected_ciphertext length should be plaintext.len() + tag_len ({total_ct_len})",
        );
        let expected_tag = &expected_ciphertext[plaintext.len()..];

        self.encrypt_one_shot::<A>(make_context, ad, plaintext, expected_ciphertext, expected_tag);
        self.encrypt_byte_at_a_time::<A>(make_context, ad, plaintext, expected_ciphertext);
        self.encrypt_chunked::<A>(make_context, ad, plaintext, expected_ciphertext);
        self.encrypt_aad_chunked::<A>(make_context, ad, plaintext, expected_ciphertext);

        self.decrypt_one_shot::<A>(make_context, ad, plaintext, expected_ciphertext);
        self.decrypt_byte_at_a_time::<A>(make_context, ad, plaintext, expected_ciphertext);
        self.decrypt_chunked::<A>(make_context, ad, plaintext, expected_ciphertext);

        self.decrypt_tampered_tag_panics::<A>(make_context, ad, plaintext, expected_ciphertext);
        if !plaintext.is_empty() {
            self.decrypt_tampered_body_panics::<A>(
                make_context,
                ad,
                plaintext,
                expected_ciphertext,
            );
        }
    }

    /* ---------------------------- encrypt paths ---------------------------- */

    /// One-shot encrypt: AAD as a single slice, plaintext as a single
    /// `process_bytes` call. Also exercises `get_update_output_size` and
    /// `get_output_size` predictions, and `get_mac`.
    fn encrypt_one_shot<A: AeadCipher>(
        &self,
        make_context: &dyn Fn(bool) -> A,
        ad: &[u8],
        plaintext: &[u8],
        expected_ciphertext: &[u8],
        expected_tag: &[u8],
    ) {
        let total_ct_len = expected_ciphertext.len();

        let mut enc = make_context(true);

        // get_mac before encryption finalize must be empty.
        assert!(
            enc.get_mac().is_empty(),
            "get_mac() must be empty before encryption finalize",
        );

        if !ad.is_empty() {
            enc.process_aad_bytes(ad);
        }

        // Size predictions before pushing plaintext.
        let predicted_total = enc.get_output_size(plaintext.len());
        assert_eq!(
            predicted_total, total_ct_len,
            "get_output_size mismatch on encrypt: predicted {predicted_total}, expected {total_ct_len}",
        );
        let predicted_update = enc.get_update_output_size(plaintext.len());

        let mut out = vec![0u8; total_ct_len];
        let n = enc.process_bytes(plaintext, &mut out);
        assert_eq!(
            n, predicted_update,
            "process_bytes wrote {n} bytes but get_update_output_size predicted {predicted_update}",
        );

        enc.do_final(&mut out[n..]);
        assert_eq!(out, expected_ciphertext, "ciphertext mismatch (one-shot encrypt)");

        let tag = enc.get_mac();
        assert_eq!(tag, expected_tag, "get_mac() should return the authentication tag after encrypt");
    }

    /// Byte-at-a-time encrypt: AAD via `process_aad_byte`, plaintext via
    /// `process_byte`. Verifies the byte-level entry points produce the
    /// same ciphertext as the slice-level path.
    fn encrypt_byte_at_a_time<A: AeadCipher>(
        &self,
        make_context: &dyn Fn(bool) -> A,
        ad: &[u8],
        plaintext: &[u8],
        expected_ciphertext: &[u8],
    ) {
        let mut enc = make_context(true);
        for &b in ad {
            enc.process_aad_byte(b);
        }
        let mut out = vec![0u8; expected_ciphertext.len()];
        let mut off = 0;
        // Per-byte output buffer: a full rate-sized block is the most a
        // single-byte push can release. We use 64 bytes to comfortably
        // cover any rate up to 512 bits.
        let mut tmp = [0u8; 64];
        for &b in plaintext {
            let n = enc.process_byte(b, &mut tmp);
            assert!(
                off + n <= out.len(),
                "process_byte overran predicted output buffer",
            );
            out[off..off + n].copy_from_slice(&tmp[..n]);
            off += n;
        }
        enc.do_final(&mut out[off..]);
        assert_eq!(out, expected_ciphertext, "ciphertext mismatch (byte-at-a-time encrypt)");
    }

    /// Encrypt with the plaintext fed in fixed-size chunks. Exercised
    /// across a fan of chunk sizes including sizes coprime to common
    /// AEAD rates (8 and 16).
    fn encrypt_chunked<A: AeadCipher>(
        &self,
        make_context: &dyn Fn(bool) -> A,
        ad: &[u8],
        plaintext: &[u8],
        expected_ciphertext: &[u8],
    ) {
        if plaintext.is_empty() {
            return;
        }
        for &chunk in &[1usize, 3, 7, 8, 13, 15, 16, 17, 31, 32, 64] {
            if chunk > plaintext.len() && chunk != 1 {
                continue;
            }
            let mut enc = make_context(true);
            if !ad.is_empty() {
                enc.process_aad_bytes(ad);
            }
            let mut out = vec![0u8; expected_ciphertext.len()];
            let mut off = 0;
            for c in plaintext.chunks(chunk) {
                let n = enc.process_bytes(c, &mut out[off..]);
                off += n;
            }
            enc.do_final(&mut out[off..]);
            assert_eq!(out, expected_ciphertext, "ciphertext mismatch at chunk size {chunk}");
        }
    }

    /// Encrypt with AAD fed in chunks of various sizes. Validates the
    /// trait's "process_aad_bytes may be called multiple times" contract.
    fn encrypt_aad_chunked<A: AeadCipher>(
        &self,
        make_context: &dyn Fn(bool) -> A,
        ad: &[u8],
        plaintext: &[u8],
        expected_ciphertext: &[u8],
    ) {
        if ad.is_empty() {
            return;
        }
        for &chunk in &[1usize, 3, 7, 8, 13, 15, 16, 17] {
            if chunk > ad.len() && chunk != 1 {
                continue;
            }
            let mut enc = make_context(true);
            for c in ad.chunks(chunk) {
                enc.process_aad_bytes(c);
            }
            let mut out = vec![0u8; expected_ciphertext.len()];
            let n = enc.process_bytes(plaintext, &mut out);
            enc.do_final(&mut out[n..]);
            assert_eq!(out, expected_ciphertext, "ciphertext mismatch at AAD chunk size {chunk}");
        }
    }

    /* ---------------------------- decrypt paths ---------------------------- */

    /// One-shot decrypt: ciphertext+tag in a single `process_bytes` call.
    /// Also exercises `get_output_size` on decrypt.
    fn decrypt_one_shot<A: AeadCipher>(
        &self,
        make_context: &dyn Fn(bool) -> A,
        ad: &[u8],
        plaintext: &[u8],
        expected_ciphertext: &[u8],
    ) {
        let mut dec = make_context(false);
        if !ad.is_empty() {
            dec.process_aad_bytes(ad);
        }

        let predicted_total = dec.get_output_size(expected_ciphertext.len());
        assert_eq!(
            predicted_total,
            plaintext.len(),
            "get_output_size mismatch on decrypt: predicted {predicted_total}, expected {}",
            plaintext.len(),
        );

        let mut out = vec![0u8; plaintext.len()];
        let n = dec.process_bytes(expected_ciphertext, &mut out);
        dec.do_final(&mut out[n..]);
        assert_eq!(out.as_slice(), plaintext, "decrypt round-trip mismatch (one-shot)");
    }

    /// Byte-at-a-time decrypt: AAD via `process_aad_byte`, ciphertext via
    /// `process_byte`.
    fn decrypt_byte_at_a_time<A: AeadCipher>(
        &self,
        make_context: &dyn Fn(bool) -> A,
        ad: &[u8],
        plaintext: &[u8],
        expected_ciphertext: &[u8],
    ) {
        let mut dec = make_context(false);
        for &b in ad {
            dec.process_aad_byte(b);
        }
        let mut out = vec![0u8; plaintext.len()];
        let mut off = 0;
        let mut tmp = [0u8; 64];
        for &b in expected_ciphertext {
            let n = dec.process_byte(b, &mut tmp);
            assert!(
                off + n <= out.len(),
                "process_byte overran predicted plaintext buffer",
            );
            out[off..off + n].copy_from_slice(&tmp[..n]);
            off += n;
        }
        dec.do_final(&mut out[off..]);
        assert_eq!(out.as_slice(), plaintext, "decrypt round-trip mismatch (byte-at-a-time)");
    }

    /// Decrypt with the ciphertext fed in fixed-size chunks.
    fn decrypt_chunked<A: AeadCipher>(
        &self,
        make_context: &dyn Fn(bool) -> A,
        ad: &[u8],
        plaintext: &[u8],
        expected_ciphertext: &[u8],
    ) {
        if expected_ciphertext.len() <= 1 {
            return;
        }
        for &chunk in &[1usize, 3, 7, 8, 13, 15, 16, 17, 31, 32, 64] {
            if chunk > expected_ciphertext.len() && chunk != 1 {
                continue;
            }
            let mut dec = make_context(false);
            if !ad.is_empty() {
                dec.process_aad_bytes(ad);
            }
            let mut out = vec![0u8; plaintext.len()];
            let mut off = 0;
            for c in expected_ciphertext.chunks(chunk) {
                let n = dec.process_bytes(c, &mut out[off..]);
                off += n;
            }
            dec.do_final(&mut out[off..]);
            assert_eq!(out.as_slice(), plaintext, "decrypt mismatch at chunk size {chunk}");
        }
    }

    /* ---------------------------- auth-fail paths ---------------------------- */

    /// Flip a bit in the body of the ciphertext (not in the tag) and
    /// expect `do_final` to panic. Skipped for empty plaintext (no body
    /// to tamper with).
    fn decrypt_tampered_body_panics<A: AeadCipher>(
        &self,
        make_context: &dyn Fn(bool) -> A,
        ad: &[u8],
        plaintext: &[u8],
        expected_ciphertext: &[u8],
    ) {
        let mut tampered = expected_ciphertext.to_vec();
        tampered[0] ^= 0x01;

        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let mut dec = make_context(false);
            if !ad.is_empty() {
                dec.process_aad_bytes(ad);
            }
            let mut out = vec![0u8; plaintext.len()];
            let n = dec.process_bytes(&tampered, &mut out);
            dec.do_final(&mut out[n..]);
        }));
        assert!(
            result.is_err(),
            "AeadCipher::do_final should have panicked on tampered ciphertext body",
        );
    }

    /// Flip a bit in the trailing tag and expect `do_final` to panic.
    fn decrypt_tampered_tag_panics<A: AeadCipher>(
        &self,
        make_context: &dyn Fn(bool) -> A,
        ad: &[u8],
        plaintext: &[u8],
        expected_ciphertext: &[u8],
    ) {
        let mut tampered = expected_ciphertext.to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x80;

        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let mut dec = make_context(false);
            if !ad.is_empty() {
                dec.process_aad_bytes(ad);
            }
            let mut out = vec![0u8; plaintext.len()];
            let n = dec.process_bytes(&tampered, &mut out);
            dec.do_final(&mut out[n..]);
        }));
        assert!(
            result.is_err(),
            "AeadCipher::do_final should have panicked on tampered authentication tag",
        );
    }
}
