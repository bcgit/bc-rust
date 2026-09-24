//! Integration tests for the inline `ciphertext || tag` layout on
//! [`AEADCipherEncryptor`]/[`AEADCipherDecryptor`] -- the `encrypt_out_with_aad` / `decrypt_out_with_aad`
//! one-shots, and the inherited `SymmetricCipherEncryptor` / `SymmetricCipherDecryptor` streaming
//! and one-shot methods they sit beside -- driven over a toy AEAD, which is what lets the length
//! and tag-placement edges be checked exactly.

use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::{
    KeyMaterial, KeyMaterialTrait, KeyType, do_hazardous_operations,
};
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, Algorithm, RNG, SecurityStrength,
    SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};
use bouncycastle_utils::secret::Secret;

const KEY_LEN: usize = 4;
const NONCE_LEN: usize = 4;
const TAG_LEN: usize = 3;

/// A toy AEAD: "ciphertext" is the plaintext XORed byte-by-byte with the key (cycled), and the
/// "tag" is a running XOR of every AAD/plaintext byte seen, repeated to `TAG_LEN` bytes. Not
/// remotely secure -- it exists only to drive the inline-layout defaults at exact byte-boundary edge
/// cases around `TAG_LEN`, with a `TAG_LEN` small enough (3) that "the tag is the last few bytes"
/// and "the message is shorter than the tag" are both cheap to enumerate.
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

impl Algorithm for ToyEnc {
    const ALG_NAME: &'static str = "toy-aead";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::None;
}
impl Algorithm for ToyDec {
    const ALG_NAME: &'static str = "toy-aead";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::None;
}

impl SymmetricCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN> for ToyEnc {
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
    fn update_out_len(&self, input_len: usize) -> usize {
        input_len
    }
    fn do_update_out(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        if ciphertext.len() < plaintext.len() {
            return Err(SymmetricCipherError::OutputBufferTooSmall(plaintext.len()));
        }
        let out = &mut ciphertext[..plaintext.len()];
        out.copy_from_slice(plaintext);
        self.0.transform(out, true);
        Ok(plaintext.len())
    }
    fn do_final(self) -> Result<([u8; TAG_LEN], usize), SymmetricCipherError> {
        Ok(([self.0.acc; TAG_LEN], TAG_LEN))
    }
    fn encrypt_out_len(plaintext_len: usize) -> usize {
        plaintext_len + TAG_LEN
    }
}

impl AEADCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN, TAG_LEN> for ToyEnc {
    fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError> {
        for &b in aad {
            self.0.acc ^= b;
        }
        Ok(())
    }
    fn do_final_out_detached(
        self,
        _ciphertext: &mut [u8; TAG_LEN],
    ) -> Result<(usize, [u8; TAG_LEN]), SymmetricCipherError> {
        Ok((0, [self.0.acc; TAG_LEN]))
    }
}

/// Holds back the last `TAG_LEN` bytes of ciphertext seen, as every AEAD decryptor must.
struct ToyDec {
    toy: Toy,
    held: [u8; TAG_LEN],
    held_len: usize,
}

impl SymmetricCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN> for ToyDec {
    fn do_decrypt_init(
        key: &KeyMaterial<KEY_LEN>,
        _nonce: &[u8; NONCE_LEN],
    ) -> Result<Self, SymmetricCipherError> {
        Ok(Self { toy: Toy::new(key)?, held: [0u8; TAG_LEN], held_len: 0 })
    }
    fn update_out_len(&self, input_len: usize) -> usize {
        (self.held_len + input_len).saturating_sub(TAG_LEN)
    }
    fn do_update_out(
        &mut self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        let release = self.update_out_len(ciphertext.len());
        if plaintext.len() < release {
            return Err(SymmetricCipherError::OutputBufferTooSmall(release));
        }
        // The same byte-queue shuffle as `AsconAead128Decryptor::do_update_out`, over a stream of
        // `held || ciphertext`.
        let mut stream = self.held[..self.held_len].to_vec();
        stream.extend_from_slice(ciphertext);
        let out = &mut plaintext[..release];
        out.copy_from_slice(&stream[..release]);
        self.toy.transform(out, false);
        self.held_len = stream.len() - release;
        self.held[..self.held_len].copy_from_slice(&stream[release..]);
        Ok(release)
    }
    fn do_final(self) -> Result<([u8; TAG_LEN], usize), SymmetricCipherError> {
        if self.held_len < TAG_LEN {
            return Err(SymmetricCipherError::DecryptionFailed);
        }
        if [self.toy.acc; TAG_LEN] != self.held {
            return Err(SymmetricCipherError::AEADTagCheckFailed);
        }
        Ok(([0u8; TAG_LEN], 0))
    }
    fn decrypt_out_max_len(ciphertext_len: usize) -> usize {
        ciphertext_len.saturating_sub(TAG_LEN)
    }
}

impl AEADCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN, TAG_LEN> for ToyDec {
    fn do_update_aad(&mut self, aad: &[u8]) -> Result<(), SymmetricCipherError> {
        for &b in aad {
            self.toy.acc ^= b;
        }
        Ok(())
    }
    fn do_final_out_detached(
        mut self,
        tag: &[u8; TAG_LEN],
        plaintext: &mut [u8; TAG_LEN],
    ) -> Result<usize, SymmetricCipherError> {
        let n = self.held_len;
        plaintext[..n].copy_from_slice(&self.held[..n]);
        self.toy.transform(&mut plaintext[..n], false);
        if [self.toy.acc; TAG_LEN] != *tag {
            return Err(SymmetricCipherError::AEADTagCheckFailed);
        }
        Ok(n)
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

const AAD: &[u8] = b"aad";

/// Encrypts `msg` into the inline layout with the one-shot, and returns it.
fn tagged_ct(km: &KeyMaterial<KEY_LEN>, msg: &[u8]) -> (Vec<u8>, [u8; NONCE_LEN]) {
    let mut ct = vec![0u8; ToyEnc::encrypt_out_len(msg.len())];
    let (nonce, written) = ToyEnc::encrypt_out_with_aad(km, AAD, msg, &mut ct).unwrap();
    assert_eq!(written, msg.len() + TAG_LEN, "inline layout is ciphertext || tag");
    ct.truncate(written);
    (ct, nonce)
}

/// The one-shot pair round-trips at every length crossing a few multiples of `TAG_LEN`, and the
/// streaming pair agrees with it for every chunking -- the decryptor, not the caller, holding back
/// the last `TAG_LEN` bytes as the possible tag.
#[test]
fn tagged_round_trip_at_every_length_and_chunking() {
    let km = key();
    for len in 0..=(4 * TAG_LEN + 5) {
        let msg: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(7)).collect();
        let (ct, nonce) = tagged_ct(&km, &msg);

        let mut pt = vec![0u8; ToyDec::decrypt_out_max_len(ct.len())];
        let n = ToyDec::decrypt_out_with_aad(&km, &nonce, AAD, &ct, &mut pt).unwrap();
        assert_eq!(&pt[..n], &msg[..], "len {len}: one-shot round trip");

        // The detached layout is the same ciphertext with the tag split off.
        let mut detached = vec![0u8; ToyEnc::encrypt_out_len_detached(len)];
        let (_, d_len, d_tag) =
            ToyEnc::encrypt_out_detached(&km, AAD, &msg, &mut detached).unwrap();
        assert_eq!(&detached[..d_len], &ct[..len], "len {len}: detached ciphertext");
        assert_eq!(&d_tag[..], &ct[len..], "len {len}: detached tag");

        for chunk in [1usize, 2, 3, TAG_LEN.max(1), len.max(1)] {
            // Encrypt in chunks, finishing with the tag appended by the streaming finalizer.
            let (mut enc, stream_nonce) = ToyEnc::do_encrypt_init(&km).unwrap();
            enc.do_update_aad(AAD).unwrap();
            let mut stream_ct = vec![0u8; msg.len() + TAG_LEN];
            let mut written = 0;
            for piece in msg.chunks(chunk) {
                written += enc.do_update_out(piece, &mut stream_ct[written..]).unwrap();
            }
            let mut last = [0u8; TAG_LEN];
            let last_len = enc.do_final_out(&mut last).unwrap();
            stream_ct[written..written + last_len].copy_from_slice(&last[..last_len]);
            written += last_len;
            stream_ct.truncate(written);
            assert_eq!(
                stream_ct, ct,
                "len {len}, chunk {chunk}: streaming must match the one-shot"
            );

            // Decrypt in chunks, tag and all: the decryptor holds the tag back itself.
            let mut dec = ToyDec::do_decrypt_init(&km, &stream_nonce).unwrap();
            dec.do_update_aad(AAD).unwrap();
            let mut out = vec![0u8; stream_ct.len()];
            let mut written = 0;
            for piece in stream_ct.chunks(chunk) {
                written += dec.do_update_out(piece, &mut out[written..]).unwrap();
            }
            assert_eq!(written, len, "len {len}, chunk {chunk}: the tag must be held back");
            let (last, data_len) = dec.do_final().unwrap();
            assert_eq!(data_len, 0, "len {len}: nothing but the tag was held back");
            out[written..written + data_len].copy_from_slice(&last[..data_len]);
            out.truncate(written + data_len);
            assert_eq!(out, msg, "len {len}, chunk {chunk}: streaming round trip");

            // The same held-back bytes are ciphertext if the tag is detached.
            let mut dec = ToyDec::do_decrypt_init(&km, &stream_nonce).unwrap();
            dec.do_update_aad(AAD).unwrap();
            let mut out = vec![0u8; len];
            let mut written = 0;
            for piece in stream_ct[..len].chunks(chunk) {
                written += dec.do_update_out(piece, &mut out[written..]).unwrap();
            }
            let mut last = [0u8; TAG_LEN];
            let last_len = dec.do_final_out_detached(&d_tag, &mut last).unwrap();
            assert_eq!(written + last_len, len, "len {len}: detached final flushes the rest");
            out[written..].copy_from_slice(&last[..last_len]);
            assert_eq!(out, msg, "len {len}, chunk {chunk}: detached streaming round trip");
        }
    }
}

/// A tampered inline stream fails at finalization on both entry points, zeroizing the one-shot's
/// buffer, and an input shorter than the tag is rejected as `DecryptionFailed` rather than
/// panicking on the short slice.
#[test]
fn tampering_and_short_input_are_rejected() {
    let km = key();
    let msg = [7u8; 10];
    let (ct, nonce) = tagged_ct(&km, &msg);

    let mut tampered = ct.clone();
    tampered[0] ^= 0xFF;
    let mut pt = vec![0u8; tampered.len()];
    assert!(matches!(
        ToyDec::decrypt_out_with_aad(&km, &nonce, AAD, &tampered, &mut pt),
        Err(SymmetricCipherError::AEADTagCheckFailed)
    ));
    assert_eq!(pt, vec![0u8; tampered.len()], "the one-shot zeroizes on a failed tag check");

    let mut dec = ToyDec::do_decrypt_init(&km, &nonce).unwrap();
    dec.do_update_aad(AAD).unwrap();
    dec.do_update_out(&tampered, &mut pt).unwrap();
    assert!(matches!(dec.do_final(), Err(SymmetricCipherError::AEADTagCheckFailed)));

    // A wrong detached tag fails, and `decrypt_out_detached` zeroizes what it wrote.
    let mut wrong_tag = [0u8; TAG_LEN];
    wrong_tag.copy_from_slice(&ct[msg.len()..]);
    wrong_tag[0] ^= 0xFF;
    let mut pt = vec![0u8; msg.len()];
    assert!(matches!(
        ToyDec::decrypt_out_detached(&km, &nonce, AAD, &ct[..msg.len()], &wrong_tag, &mut pt),
        Err(SymmetricCipherError::AEADTagCheckFailed)
    ));
    assert_eq!(pt, vec![0u8; msg.len()], "the detached one-shot zeroizes on a failed tag check");

    for short_len in 0..TAG_LEN {
        let mut pt = vec![0u8; TAG_LEN];
        assert!(matches!(
            ToyDec::decrypt_out_with_aad(&km, &nonce, AAD, &ct[..short_len], &mut pt),
            Err(SymmetricCipherError::DecryptionFailed)
        ));
        let mut dec = ToyDec::do_decrypt_init(&km, &nonce).unwrap();
        assert_eq!(dec.do_update_out(&ct[..short_len], &mut pt).unwrap(), 0);
        assert!(matches!(dec.do_final(), Err(SymmetricCipherError::DecryptionFailed)));
    }
}

/// Every inline one-shot refuses an output buffer that is one byte short, naming the length it
/// needs, and does so before touching the cipher; one of exactly that length is accepted.
#[test]
fn tagged_undersized_buffers_are_rejected() {
    let km = key();
    let msg = [3u8; 8];
    let (ct, nonce) = tagged_ct(&km, &msg);

    let needed = ToyEnc::encrypt_out_len(msg.len());
    assert_eq!(needed, msg.len() + TAG_LEN);
    let mut short = vec![0u8; needed - 1];
    match ToyEnc::encrypt_out_with_aad(&km, AAD, &msg, &mut short) {
        Err(SymmetricCipherError::OutputBufferTooSmall(n)) => assert_eq!(n, needed),
        other => panic!("encrypt_out_with_aad into a short buffer: {other:?}"),
    }

    let needed = ToyDec::decrypt_out_max_len(ct.len());
    assert_eq!(needed, msg.len());
    let mut short = vec![0u8; needed - 1];
    match ToyDec::decrypt_out_with_aad(&km, &nonce, AAD, &ct, &mut short) {
        Err(SymmetricCipherError::OutputBufferTooSmall(n)) => assert_eq!(n, needed),
        other => panic!("decrypt_out_with_aad into a short buffer: {other:?}"),
    }

    // A buffer of exactly the length it asks for must be accepted. Without this the
    // `plaintext.len() < needed` guard can be weakened to `<=` or `==` without any test noticing:
    // a too-short buffer is caught either way, by the guard or by `do_update_out` behind it, and
    // both report the same error with the same length.
    let mut exact = vec![0u8; needed];
    let n = ToyDec::decrypt_out_with_aad(&km, &nonce, AAD, &ct, &mut exact).unwrap();
    assert_eq!(&exact[..n], &msg[..], "a buffer of exactly `needed` bytes must be enough");
}
