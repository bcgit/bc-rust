//! Adapts an [`AEADCipherEncryptor`] /
//! [`AEADCipherDecryptor`] pair to the separate-output
//! [`SimpleCipherEncryptor`] /
//! [`SimpleCipherDecryptor`] shape by inlining the tag as
//! the last `TAG_LEN` bytes of the ciphertext stream -- the `ciphertext || tag` layout most wire
//! formats and files use, as opposed to the AEAD pair's own detached-tag shape.
//!
//! This is deliberately the *inverse* direction from every other adapter in this crate: instead
//! of adding capability (an AEAD's AAD, its generated nonce), it *drops* the AAD phase, because
//! [`SimpleCipherEncryptor`] has nowhere to carry one. An
//! AEAD wrapped here can still be driven with AAD through the inherent
//! [`TaggedEncryptor::do_update_aad`] / [`TaggedDecryptor::do_update_aad`], which forward to the
//! wrapped value's own method (see their docs for why this can't be part of the
//! `SimpleCipherEncryptor`/`SimpleCipherDecryptor` impl itself); a caller who does not need AAD
//! can ignore that entirely and use [`SimpleCipherEncryptor`]'s
//! full one-shot and streaming API unchanged.
//!
//! # Restricted to non-buffering ciphers
//!
//! Both adapters require the wrapped `FINAL_LEN` to be `0` -- nothing held back at
//! finalization -- which covers Ascon-AEAD128 and any other AEAD that releases every ciphertext
//! byte as soon as it produces it. A cipher that also buffers a partial final block would need
//! this adapter's own `FINAL_LEN` to be `INNER_FINAL_LEN + TAG_LEN`, a value derived from two
//! other const generics; Rust's stable const generics cannot express that as a trait argument
//! (it needs the still-incomplete `generic_const_exprs`), so supporting it is left to a future,
//! more general adapter.

use crate::errors::SymmetricCipherError;
use crate::key_material::KeyMaterial;
use crate::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, Algorithm, RNG, SecurityStrength,
    SimpleCipherDecryptor, SimpleCipherEncryptor,
};

/// Adapts an [`AEADCipherEncryptor`] with `FINAL_LEN = 0` to
/// [`SimpleCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN>`], appending the tag as the final segment
/// so the output stream is `ciphertext || tag`. See the module docs for the AAD caveat and the
/// `FINAL_LEN = 0` restriction.
pub struct TaggedEncryptor<E>(E);

impl<E> TaggedEncryptor<E> {
    /// Absorbs `aad` on the wrapped encryptor; see
    /// [`AEADCipherEncryptor::do_update_aad`]
    /// for the rules (repeatable before the first `do_update_out`, an empty slice always a no-op).
    /// Not part of the [`SimpleCipherEncryptor`] impl below, which has no AAD concept at all.
    pub fn do_update_aad<const KEY_LEN: usize, const NONCE_LEN: usize, const TAG_LEN: usize>(
        &mut self,
        aad: &[u8],
    ) -> Result<(), SymmetricCipherError>
    where
        E: AEADCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN, 0>,
    {
        self.0.do_update_aad(aad)
    }
}

// Bounded on `Algorithm` alone, not the full `AEADCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN, 0>`
// used below: those three consts appear only in a `where` clause, which Rust's coherence check
// does not accept as constraining an impl's generic parameters (E0207), and `Algorithm`'s own
// consts do not need them.
impl<E: Algorithm> Algorithm for TaggedEncryptor<E> {
    const ALG_NAME: &'static str = E::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = E::MAX_SECURITY_STRENGTH;
}

impl<E, const KEY_LEN: usize, const NONCE_LEN: usize, const TAG_LEN: usize>
    SimpleCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN> for TaggedEncryptor<E>
where
    E: AEADCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN, 0>,
{
    fn do_encrypt_init(
        key: &KeyMaterial<KEY_LEN>,
    ) -> Result<(Self, [u8; NONCE_LEN]), SymmetricCipherError> {
        let (inner, nonce) = E::do_encrypt_init(key)?;
        Ok((Self(inner), nonce))
    }

    fn do_encrypt_init_rng(
        key: &KeyMaterial<KEY_LEN>,
        rng: &mut dyn RNG,
    ) -> Result<(Self, [u8; NONCE_LEN]), SymmetricCipherError> {
        let (inner, nonce) = E::do_encrypt_init_rng(key, rng)?;
        Ok((Self(inner), nonce))
    }

    /// Identical to the wrapped encryptor's: this adapter never itself buffers, since the tag has
    /// nowhere to go until `do_final`.
    fn update_out_len(&self, input_len: usize) -> usize {
        self.0.update_out_len(input_len)
    }

    fn do_update_out(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        self.0.do_update_out(plaintext, ciphertext)
    }

    /// Finishes the inner encryptor (with an empty flush buffer, since `FINAL_LEN = 0` on the
    /// bound above) and returns its tag as this trait's own `FINAL_LEN`-byte final segment.
    fn do_final(self) -> Result<([u8; TAG_LEN], usize), SymmetricCipherError> {
        let mut nothing = [0u8; 0];
        let (flushed, tag) = self.0.do_encrypt_final(&mut nothing)?;
        debug_assert_eq!(flushed, 0, "FINAL_LEN = 0 on the AEADCipherEncryptor bound");
        Ok((tag, TAG_LEN))
    }

    /// The plaintext length plus the tag: the inline layout this adapter produces.
    fn encrypt_out_len(plaintext_len: usize) -> usize {
        plaintext_len + TAG_LEN
    }
}

/// Adapts an [`AEADCipherDecryptor`] with `FINAL_LEN = 0` to
/// [`SimpleCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN>`], reading the tag as the last `TAG_LEN`
/// bytes of the ciphertext stream. `FINAL_LEN` here is `TAG_LEN` only to match
/// [`TaggedEncryptor`]'s own `FINAL_LEN` -- the pair contract [`SimpleCipherEncryptor`] /
/// [`SimpleCipherDecryptor`] share -- not because anything is actually flushed; see this type's
/// `do_final` impl. See the module docs for the AAD caveat and the wrapped AEAD's own
/// `FINAL_LEN = 0` restriction.
///
/// # Holding back the tag
///
/// The wire format gives no advance notice of where the ciphertext ends and the tag begins --
/// that boundary is only known once the whole stream has been seen -- so this type holds back the
/// last `TAG_LEN` bytes it has been given at all times, in `tail`, releasing everything older than
/// that through the wrapped decryptor as soon as it is known not to be part of the tag. This is
/// the same technique `cli/src/ascon_cmd.rs`'s `aead128_decrypt_stream` used by hand before this
/// adapter existed.
pub struct TaggedDecryptor<D, const TAG_LEN: usize> {
    inner: D,
    tail: [u8; TAG_LEN],
    tail_len: usize,
}

impl<D, const TAG_LEN: usize> TaggedDecryptor<D, TAG_LEN> {
    /// Absorbs `aad` on the wrapped decryptor; see
    /// [`AEADCipherDecryptor::do_update_aad`]
    /// for the rules. Not part of the [`SimpleCipherDecryptor`] impl below, which has no AAD
    /// concept at all.
    pub fn do_update_aad<const KEY_LEN: usize, const NONCE_LEN: usize>(
        &mut self,
        aad: &[u8],
    ) -> Result<(), SymmetricCipherError>
    where
        D: AEADCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN, 0>,
    {
        self.inner.do_update_aad(aad)
    }
}

// See the equivalent impl on `TaggedEncryptor` for why this bounds on `Algorithm` alone.
impl<D: Algorithm, const TAG_LEN: usize> Algorithm for TaggedDecryptor<D, TAG_LEN> {
    const ALG_NAME: &'static str = D::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = D::MAX_SECURITY_STRENGTH;
}

impl<D, const KEY_LEN: usize, const NONCE_LEN: usize, const TAG_LEN: usize>
    SimpleCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN> for TaggedDecryptor<D, TAG_LEN>
where
    D: AEADCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN, 0>,
{
    fn do_decrypt_init(
        key: &KeyMaterial<KEY_LEN>,
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Self, SymmetricCipherError> {
        Ok(Self { inner: D::do_decrypt_init(key, nonce)?, tail: [0u8; TAG_LEN], tail_len: 0 })
    }

    /// Only the bytes no longer eligible to be the tag: `tail_len + input_len - TAG_LEN`, floored
    /// at `0` while the stream is still shorter than the tag itself.
    fn update_out_len(&self, input_len: usize) -> usize {
        (self.tail_len + input_len).saturating_sub(TAG_LEN)
    }

    fn do_update_out(
        &mut self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        let releasable = self.update_out_len(ciphertext.len());
        if plaintext.len() < releasable {
            return Err(SymmetricCipherError::IncorrectOutputBufferLength("plaintext", releasable));
        }

        let total = self.tail_len + ciphertext.len();
        if total <= TAG_LEN {
            // Everything seen so far might still be the tag; buffer it and release nothing.
            self.tail[self.tail_len..total].copy_from_slice(ciphertext);
            self.tail_len = total;
            return Ok(0);
        }

        // Release the old tail (in full, or as much of it as `releasable` allows) followed by
        // however much of the new input is also releasable; two streaming calls into the wrapped
        // decryptor, equivalent to one over their concatenation.
        let from_tail = self.tail_len.min(releasable);
        let from_new = releasable - from_tail;
        if from_tail > 0 {
            self.inner.do_update_out(&self.tail[..from_tail], &mut plaintext[..from_tail])?;
        }
        if from_new > 0 {
            self.inner
                .do_update_out(&ciphertext[..from_new], &mut plaintext[from_tail..releasable])?;
        }

        // The new tail is whatever was not just released -- the suffix of the old tail, then the
        // suffix of the new ciphertext -- which together are exactly TAG_LEN bytes, since
        // `total - releasable == TAG_LEN` by construction of `releasable` above.
        let mut new_tail = [0u8; TAG_LEN];
        let old_tail_kept = self.tail_len - from_tail;
        new_tail[..old_tail_kept].copy_from_slice(&self.tail[from_tail..self.tail_len]);
        new_tail[old_tail_kept..].copy_from_slice(&ciphertext[from_new..]);
        self.tail = new_tail;
        self.tail_len = TAG_LEN;

        Ok(releasable)
    }

    /// Nothing is held back for release -- every plaintext byte was already emitted by
    /// `do_update_out` -- so this is purely the tag check, against whatever ended up in `tail`.
    /// The returned array is `FINAL_LEN = TAG_LEN` bytes only to match
    /// [`TaggedEncryptor`]'s `FINAL_LEN` (the pair contract both traits share); the `0` data-byte
    /// count says none of it is meaningful, exactly the case [`SimpleCipherDecryptor::do_final`]'s
    /// own docs anticipate ("an authenticated cipher may release nothing at all once it has
    /// checked the tag").
    ///
    /// # Errors
    /// [`SymmetricCipherError::DecryptionFailed`] if fewer than `TAG_LEN` bytes were ever seen (the
    /// input was shorter than the tag). Otherwise, whatever
    /// [`AEADCipherDecryptor::do_decrypt_final`]
    /// returns, most notably [`SymmetricCipherError::AEADTagCheckFailed`].
    fn do_final(self) -> Result<([u8; TAG_LEN], usize), SymmetricCipherError> {
        if self.tail_len < TAG_LEN {
            return Err(SymmetricCipherError::DecryptionFailed);
        }
        let mut nothing = [0u8; 0];
        self.inner.do_decrypt_final(&self.tail, &mut nothing)?;
        Ok(([0u8; TAG_LEN], 0))
    }

    /// The ciphertext length minus the tag, floored at `0` for an input shorter than the tag
    /// (which `do_final` rejects rather than `do_update_out`, so the buffer must still be sized).
    fn decrypt_out_max_len(ciphertext_len: usize) -> usize {
        ciphertext_len.saturating_sub(TAG_LEN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_material::{KeyMaterialTrait, KeyType, do_hazardous_operations};
    use crate::traits::RNG;
    use bouncycastle_utils::secret::Secret;

    const KEY_LEN: usize = 4;
    const NONCE_LEN: usize = 4;
    const TAG_LEN: usize = 3;

    /// A toy AEAD: "ciphertext" is the plaintext XORed byte-by-byte with the key (cycled), and the
    /// "tag" is a running XOR of every AAD/plaintext byte seen, repeated to `TAG_LEN` bytes. Not
    /// remotely secure -- it exists only to drive `TaggedEncryptor`/`TaggedDecryptor` through
    /// [`crate::traits::SimpleCipherEncryptor`]/[`SimpleCipherDecryptor`]'s chunked-equivalence
    /// contract at exact byte-boundary edge cases around `TAG_LEN`, which is what this module's
    /// hand-written tail bookkeeping needs pinned directly (see CLAUDE.md on testing
    /// behaviour-critical private logic in-file).
    #[derive(Clone)]
    struct Toy {
        key: Secret<[u8; KEY_LEN]>,
        pos: usize,
        acc: u8,
    }

    impl Toy {
        fn new(key: &KeyMaterial<KEY_LEN>) -> Result<Self, SymmetricCipherError> {
            let mut k = Secret::<[u8; KEY_LEN]>::new();
            k.copy_from_slice(key.ref_to_bytes());
            Ok(Self { key: k, pos: 0, acc: 0 })
        }

        /// Transforms `data` in place, accumulating `acc` over the *plaintext* byte on both
        /// sides: encrypting, `data` starts as plaintext, so `acc` is updated before the XOR;
        /// decrypting, `data` starts as ciphertext, so the XOR (which recovers the plaintext byte
        /// into the same slot) must happen first.
        fn transform(&mut self, data: &mut [u8], encrypting: bool) {
            for b in data.iter_mut() {
                if encrypting {
                    self.acc ^= *b;
                }
                *b ^= self.key[self.pos % KEY_LEN];
                if !encrypting {
                    self.acc ^= *b;
                }
                self.pos += 1;
            }
        }
    }

    struct ToyEnc(Toy);
    struct ToyDec(Toy);

    impl Algorithm for ToyEnc {
        const ALG_NAME: &'static str = "toy-aead";
        const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::None;
    }
    impl Algorithm for ToyDec {
        const ALG_NAME: &'static str = "toy-aead";
        const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::None;
    }

    impl AEADCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN, 0> for ToyEnc {
        fn do_encrypt_init(
            key: &KeyMaterial<KEY_LEN>,
        ) -> Result<(Self, [u8; NONCE_LEN]), SymmetricCipherError> {
            Ok((Self(Toy::new(key)?), [0u8; NONCE_LEN]))
        }
        fn do_encrypt_init_rng(
            key: &KeyMaterial<KEY_LEN>,
            _rng: &mut dyn RNG,
        ) -> Result<(Self, [u8; NONCE_LEN]), SymmetricCipherError> {
            Self::do_encrypt_init(key)
        }
        fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError> {
            for &b in aad {
                self.0.acc ^= b;
            }
            Ok(())
        }
        fn update_out_len(&self, input_len: usize) -> usize {
            input_len
        }
        fn do_update_out(
            &mut self,
            plaintext: &[u8],
            ciphertext: &mut [u8],
        ) -> Result<usize, SymmetricCipherError> {
            if ciphertext.len() < plaintext.len() {
                return Err(SymmetricCipherError::IncorrectOutputBufferLength(
                    "ciphertext",
                    plaintext.len(),
                ));
            }
            let out = &mut ciphertext[..plaintext.len()];
            out.copy_from_slice(plaintext);
            self.0.transform(out, true);
            Ok(plaintext.len())
        }
        fn do_encrypt_final(
            self,
            _output: &mut [u8; 0],
        ) -> Result<(usize, [u8; TAG_LEN]), SymmetricCipherError> {
            Ok((0, [self.0.acc; TAG_LEN]))
        }
    }

    impl AEADCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN, 0> for ToyDec {
        fn do_decrypt_init(
            key: &KeyMaterial<KEY_LEN>,
            _nonce: &[u8; NONCE_LEN],
        ) -> Result<Self, SymmetricCipherError> {
            Ok(Self(Toy::new(key)?))
        }
        fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError> {
            for &b in aad {
                self.0.acc ^= b;
            }
            Ok(())
        }
        fn update_out_len(&self, input_len: usize) -> usize {
            input_len
        }
        fn do_update_out(
            &mut self,
            ciphertext: &[u8],
            plaintext: &mut [u8],
        ) -> Result<usize, SymmetricCipherError> {
            if plaintext.len() < ciphertext.len() {
                return Err(SymmetricCipherError::IncorrectOutputBufferLength(
                    "plaintext",
                    ciphertext.len(),
                ));
            }
            let out = &mut plaintext[..ciphertext.len()];
            out.copy_from_slice(ciphertext);
            self.0.transform(out, false);
            Ok(ciphertext.len())
        }
        fn do_decrypt_final(
            self,
            tag: &[u8; TAG_LEN],
            _output: &mut [u8; 0],
        ) -> Result<usize, SymmetricCipherError> {
            if [self.0.acc; TAG_LEN] != *tag {
                return Err(SymmetricCipherError::AEADTagCheckFailed);
            }
            Ok(0)
        }
    }

    fn key() -> KeyMaterial<KEY_LEN> {
        let mut km =
            KeyMaterial::<KEY_LEN>::from_bytes_as_type(&[1, 2, 3, 4], KeyType::SymmetricCipherKey)
                .unwrap();
        do_hazardous_operations(&mut km, |k| {
            k.set_key_type(KeyType::SymmetricCipherKey)?;
            k.set_security_strength(SecurityStrength::None)
        })
        .unwrap();
        km
    }

    /// The one-shot round trip through the adapters, at every message length crossing a few
    /// multiples of `TAG_LEN`, and every chunking of `do_update_out` on both sides -- this is what
    /// pins the tail bookkeeping's off-by-one edges directly, complementing the framework's own
    /// generic `test_encryptor_decryptor` coverage (which this same adapter pair is expected to
    /// pass against `SimpleCipherEncryptor`/`SimpleCipherDecryptor`'s contract elsewhere).
    #[test]
    fn tagged_round_trip_at_every_length_and_chunking() {
        let km = key();
        for len in 0..=(4 * TAG_LEN + 5) {
            let msg: Vec<u8> =
                (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(7)).collect();

            let (mut enc, nonce) = <TaggedEncryptor<ToyEnc> as SimpleCipherEncryptor<
                KEY_LEN,
                NONCE_LEN,
                TAG_LEN,
            >>::do_encrypt_init(&km)
            .unwrap();
            enc.do_update_aad::<KEY_LEN, NONCE_LEN, TAG_LEN>(b"aad").unwrap();
            let mut ct = vec![0u8; msg.len() + TAG_LEN];
            for chunk in [1usize, 2, 3, TAG_LEN.max(1), len.max(1)] {
                let mut enc = {
                    let (mut e, _) = <TaggedEncryptor<ToyEnc> as SimpleCipherEncryptor<
                        KEY_LEN,
                        NONCE_LEN,
                        TAG_LEN,
                    >>::do_encrypt_init(&km)
                    .unwrap();
                    e.do_update_aad::<KEY_LEN, NONCE_LEN, TAG_LEN>(b"aad").unwrap();
                    e
                };
                let mut written = 0;
                for piece in msg.chunks(chunk) {
                    written += enc.do_update_out(piece, &mut ct[written..]).unwrap();
                }
                let mut last = [0u8; TAG_LEN];
                let last_len = <TaggedEncryptor<ToyEnc> as SimpleCipherEncryptor<
                    KEY_LEN,
                    NONCE_LEN,
                    TAG_LEN,
                >>::do_final_out(enc, &mut last)
                .unwrap();
                ct[written..written + last_len].copy_from_slice(&last[..last_len]);
                written += last_len;
                ct.truncate(written);

                let mut dec = <TaggedDecryptor<ToyDec, TAG_LEN> as SimpleCipherDecryptor<
                    KEY_LEN,
                    NONCE_LEN,
                    TAG_LEN,
                >>::do_decrypt_init(&km, &nonce)
                .unwrap();
                dec.do_update_aad::<KEY_LEN, NONCE_LEN>(b"aad").unwrap();
                let mut pt = vec![0u8; ct.len()];
                let mut written = 0;
                for piece in ct.chunks(chunk) {
                    written += dec.do_update_out(piece, &mut pt[written..]).unwrap();
                }
                let (_, data_len) = dec.do_final().unwrap();
                pt.truncate(written + data_len);
                assert_eq!(pt, msg, "len {len}, chunk {chunk}");

                ct.resize(msg.len() + TAG_LEN, 0);
            }
        }
    }

    /// A tampered inline stream must fail at `do_final`, and a stream shorter than the tag must be
    /// rejected as `DecryptionFailed` rather than panicking on the short slice.
    #[test]
    fn tampering_and_short_input_are_rejected() {
        let km = key();
        let (mut enc, nonce) = <TaggedEncryptor<ToyEnc> as SimpleCipherEncryptor<
            KEY_LEN,
            NONCE_LEN,
            TAG_LEN,
        >>::do_encrypt_init(&km)
        .unwrap();
        let mut ct = vec![0u8; 10 + TAG_LEN];
        let written = enc.do_update_out(&[7u8; 10], &mut ct).unwrap();
        let mut last = [0u8; TAG_LEN];
        let last_len = <TaggedEncryptor<ToyEnc> as SimpleCipherEncryptor<
            KEY_LEN,
            NONCE_LEN,
            TAG_LEN,
        >>::do_final_out(enc, &mut last)
        .unwrap();
        ct[written..written + last_len].copy_from_slice(&last[..last_len]);

        let mut tampered = ct.clone();
        tampered[0] ^= 0xFF;
        let mut dec = <TaggedDecryptor<ToyDec, TAG_LEN> as SimpleCipherDecryptor<
            KEY_LEN,
            NONCE_LEN,
            TAG_LEN,
        >>::do_decrypt_init(&km, &nonce)
        .unwrap();
        let mut pt = vec![0u8; tampered.len()];
        let mut written = 0;
        written += dec.do_update_out(&tampered, &mut pt[written..]).unwrap();
        let _ = written;
        assert!(matches!(dec.do_final(), Err(SymmetricCipherError::AEADTagCheckFailed)));

        for short_len in 0..TAG_LEN {
            let dec = <TaggedDecryptor<ToyDec, TAG_LEN> as SimpleCipherDecryptor<
                KEY_LEN,
                NONCE_LEN,
                TAG_LEN,
            >>::do_decrypt_init(&km, &nonce)
            .unwrap();
            let mut dec = dec;
            let mut pt = vec![0u8; short_len];
            dec.do_update_out(&ct[..short_len], &mut pt).unwrap();
            assert!(matches!(dec.do_final(), Err(SymmetricCipherError::DecryptionFailed)));
        }
    }
}
