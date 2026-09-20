//! Integration tests for the inline `ciphertext || tag` layout on
//! [`AEADCipherEncryptor`]/[`AEADCipherDecryptor`] -- `tagged_encrypt`,
//! `tagged_do_aead_encrypt_final`, `tagged_decrypt` and `tagged_do_aead_decrypt_final` -- driven
//! over a toy AEAD, which is what lets the length and tag-placement edges be checked exactly.

use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::{
    KeyMaterial, KeyMaterialTrait, KeyType, do_hazardous_operations,
};
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, Algorithm, RNG, SecurityStrength,
};
use bouncycastle_utils::secret::Secret;

const KEY_LEN: usize = 4;
const NONCE_LEN: usize = 4;
const TAG_LEN: usize = 3;

/// A toy AEAD: "ciphertext" is the plaintext XORed byte-by-byte with the key (cycled), and the
/// "tag" is a running XOR of every AAD/plaintext byte seen, repeated to `TAG_LEN` bytes. Not
/// remotely secure -- it exists only to drive the `tagged_*` defaults at exact byte-boundary edge
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

const AAD: &[u8] = b"aad";

/// Encrypts `msg` into the inline layout with the one-shot, and returns it.
fn tagged_ct(km: &KeyMaterial<KEY_LEN>, msg: &[u8]) -> (Vec<u8>, [u8; NONCE_LEN]) {
    let mut ct = vec![0u8; ToyEnc::tagged_encrypt_out_len(msg.len())];
    let (nonce, written) = ToyEnc::tagged_encrypt(km, AAD, msg, &mut ct).unwrap();
    assert_eq!(written, msg.len() + TAG_LEN, "inline layout is ciphertext || tag");
    ct.truncate(written);
    (ct, nonce)
}

/// The one-shot pair round-trips at every length crossing a few multiples of `TAG_LEN`, and the
/// streaming pair agrees with it for every chunking -- the caller holding back the last `TAG_LEN`
/// bytes itself, as `tagged_do_aead_decrypt_final`'s docs require.
#[test]
fn tagged_round_trip_at_every_length_and_chunking() {
    let km = key();
    for len in 0..=(4 * TAG_LEN + 5) {
        let msg: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(7)).collect();
        let (ct, nonce) = tagged_ct(&km, &msg);

        let mut pt = vec![0u8; ToyDec::tagged_decrypt_out_max_len(ct.len())];
        let n = ToyDec::tagged_decrypt(&km, &nonce, AAD, &ct, &mut pt).unwrap();
        assert_eq!(&pt[..n], &msg[..], "len {len}: one-shot round trip");

        for chunk in [1usize, 2, 3, TAG_LEN.max(1), len.max(1)] {
            // Encrypt in chunks, finishing with the tag appended by the streaming finalizer.
            let (mut enc, stream_nonce) = ToyEnc::do_encrypt_init(&km).unwrap();
            enc.do_update_aad(AAD).unwrap();
            let mut stream_ct = vec![0u8; msg.len() + TAG_LEN];
            let mut written = 0;
            for piece in msg.chunks(chunk) {
                written += enc.do_update_out(piece, &mut stream_ct[written..]).unwrap();
            }
            written += enc.tagged_do_aead_encrypt_final(&mut stream_ct[written..]).unwrap();
            stream_ct.truncate(written);
            assert_eq!(
                stream_ct, ct,
                "len {len}, chunk {chunk}: streaming must match the one-shot"
            );

            // Decrypt in chunks, holding back the last TAG_LEN bytes for the finalizer.
            let mut dec = ToyDec::do_decrypt_init(&km, &stream_nonce).unwrap();
            dec.do_update_aad(AAD).unwrap();
            let body_len = stream_ct.len() - TAG_LEN;
            let mut out = vec![0u8; stream_ct.len()];
            let mut written = 0;
            for piece in stream_ct[..body_len].chunks(chunk) {
                written += dec.do_update_out(piece, &mut out[written..]).unwrap();
            }
            written += dec
                .tagged_do_aead_decrypt_final(&stream_ct[body_len..], &mut out[written..])
                .unwrap();
            out.truncate(written);
            assert_eq!(out, msg, "len {len}, chunk {chunk}: streaming round trip");
        }
    }
}

/// A tampered inline stream fails at finalization on both entry points, and an input shorter than
/// the tag is rejected as `DecryptionFailed` rather than panicking on the short slice.
#[test]
fn tampering_and_short_input_are_rejected() {
    let km = key();
    let msg = [7u8; 10];
    let (ct, nonce) = tagged_ct(&km, &msg);

    let mut tampered = ct.clone();
    tampered[0] ^= 0xFF;
    let mut pt = vec![0u8; tampered.len()];
    assert!(matches!(
        ToyDec::tagged_decrypt(&km, &nonce, AAD, &tampered, &mut pt),
        Err(SymmetricCipherError::AEADTagCheckFailed)
    ));
    assert_eq!(pt, vec![0u8; tampered.len()], "the one-shot zeroizes on a failed tag check");

    let mut dec = ToyDec::do_decrypt_init(&km, &nonce).unwrap();
    dec.do_update_aad(AAD).unwrap();
    assert!(matches!(
        dec.tagged_do_aead_decrypt_final(&tampered, &mut pt),
        Err(SymmetricCipherError::AEADTagCheckFailed)
    ));

    for short_len in 0..TAG_LEN {
        let mut pt = vec![0u8; TAG_LEN];
        assert!(matches!(
            ToyDec::tagged_decrypt(&km, &nonce, AAD, &ct[..short_len], &mut pt),
            Err(SymmetricCipherError::DecryptionFailed)
        ));
        let dec = ToyDec::do_decrypt_init(&km, &nonce).unwrap();
        assert!(matches!(
            dec.tagged_do_aead_decrypt_final(&ct[..short_len], &mut pt),
            Err(SymmetricCipherError::DecryptionFailed)
        ));
    }
}

/// Every `tagged_*` entry point refuses an output buffer that is one byte short, naming the length
/// it needs, and does so before touching the cipher.
#[test]
fn tagged_undersized_buffers_are_rejected() {
    let km = key();
    let msg = [3u8; 8];
    let (ct, nonce) = tagged_ct(&km, &msg);

    let needed = ToyEnc::tagged_encrypt_out_len(msg.len());
    assert_eq!(needed, msg.len() + TAG_LEN);
    let mut short = vec![0u8; needed - 1];
    match ToyEnc::tagged_encrypt(&km, AAD, &msg, &mut short) {
        Err(SymmetricCipherError::IncorrectOutputBufferLength(_, n)) => assert_eq!(n, needed),
        other => panic!("tagged_encrypt into a short buffer: {other:?}"),
    }

    let (enc, _) = ToyEnc::do_encrypt_init(&km).unwrap();
    let mut short = [0u8; TAG_LEN - 1];
    match enc.tagged_do_aead_encrypt_final(&mut short) {
        Err(SymmetricCipherError::IncorrectOutputBufferLength(_, n)) => assert_eq!(n, TAG_LEN),
        other => panic!("tagged_do_aead_encrypt_final into a short buffer: {other:?}"),
    }

    let needed = ToyDec::tagged_decrypt_out_max_len(ct.len());
    assert_eq!(needed, msg.len());
    let mut short = vec![0u8; needed - 1];
    match ToyDec::tagged_decrypt(&km, &nonce, AAD, &ct, &mut short) {
        Err(SymmetricCipherError::IncorrectOutputBufferLength(_, n)) => assert_eq!(n, needed),
        other => panic!("tagged_decrypt into a short buffer: {other:?}"),
    }

    let dec = ToyDec::do_decrypt_init(&km, &nonce).unwrap();
    let mut short = vec![0u8; msg.len() - 1];
    match dec.tagged_do_aead_decrypt_final(&ct, &mut short) {
        Err(SymmetricCipherError::IncorrectOutputBufferLength(_, n)) => assert_eq!(n, msg.len()),
        other => panic!("tagged_do_aead_decrypt_final into a short buffer: {other:?}"),
    }

    // A buffer of exactly the length it asks for must be accepted. Without this the
    // `plaintext.len() < needed` guard can be weakened to `<=` or `==` without any test noticing:
    // a too-short buffer is caught either way, by the guard or by `do_update_out` behind it, and
    // both report the same error with the same length.
    let mut dec = ToyDec::do_decrypt_init(&km, &nonce).unwrap();
    dec.do_update_aad(AAD).unwrap();
    let mut exact = vec![0u8; msg.len()];
    let n = dec.tagged_do_aead_decrypt_final(&ct, &mut exact).unwrap();
    assert_eq!(&exact[..n], &msg[..], "a buffer of exactly `needed` bytes must be enough");
}
