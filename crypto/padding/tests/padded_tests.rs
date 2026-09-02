//! Tests for PaddedEncryptor / PaddedDecryptor.
//!
//! No real block cipher exists in the workspace yet, so these tests drive the adapters with a toy
//! CBC-style cipher whose "block permutation" is XOR with the key. It is cryptographically worthless
//! but exercises every code path of the adapters: IV generation, chaining state across calls, and
//! the one-block lag on decryption.

use bouncycastle_core::errors::{KeyMaterialError, PaddingError, SymmetricCipherError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{
    BlockCipher, BlockCipherDecryptor, BlockCipherEncryptor, RNG, SecurityStrength,
};
use bouncycastle_core_test_framework::symmetric_ciphers::TestFrameworkBlockCipher;
use bouncycastle_padding::{PKCS7, PaddedDecryptor, PaddedEncryptor};
use bouncycastle_rng::hash_drbg80090a::{HashDRBG80090A, HashDRBG80090AParams_SHA256};

const B: usize = 8;

/// c_j = p_j ^ c_{j-1} ^ key ; p_j = c_j ^ c_{j-1} ^ key
struct ToyCbc {
    key: [u8; B],
    chain: [u8; B],
}

impl ToyCbc {
    fn check_key(key: &KeyMaterial<B>) -> Result<[u8; B], SymmetricCipherError> {
        if key.key_type() != KeyType::SymmetricCipherKey {
            return Err(KeyMaterialError::InvalidKeyType("expected SymmetricCipherKey"))?;
        }
        if key.security_strength() < Self::MAX_SECURITY_STRENGTH {
            return Err(KeyMaterialError::GenericError("key too weak"))?;
        }
        let mut k = [0u8; B];
        k.copy_from_slice(key.ref_to_bytes());
        Ok(k)
    }
}

impl BlockCipher for ToyCbc {
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::None;
}

impl BlockCipherEncryptor<B, B, B> for ToyCbc {
    fn do_encrypt_init(key: &KeyMaterial<B>) -> Result<(Self, [u8; B]), SymmetricCipherError> {
        let mut rng = HashDRBG80090A::<HashDRBG80090AParams_SHA256>::new_from_os();
        Self::do_encrypt_init_rng(key, &mut rng)
    }
    fn do_encrypt_init_rng(
        key: &KeyMaterial<B>,
        rng: &mut dyn RNG,
    ) -> Result<(Self, [u8; B]), SymmetricCipherError> {
        let key = Self::check_key(key)?;
        let mut iv = [0u8; B];
        rng.next_bytes_out(&mut iv)?;
        Ok((Self { key, chain: iv }, iv))
    }
    fn do_encrypt_blocks<const N: usize>(
        &mut self,
        plaintext: &[[u8; B]; N],
    ) -> Result<[[u8; B]; N], SymmetricCipherError> {
        let mut ct = [[0u8; B]; N];
        self.do_encrypt_blocks_out(plaintext, &mut ct)?;
        Ok(ct)
    }
    fn do_encrypt_blocks_out<const N: usize>(
        &mut self,
        plaintext: &[[u8; B]; N],
        ciphertext: &mut [[u8; B]; N],
    ) -> Result<usize, SymmetricCipherError> {
        for (p, c) in plaintext.iter().zip(ciphertext.iter_mut()) {
            for i in 0..B {
                c[i] = p[i] ^ self.chain[i] ^ self.key[i];
            }
            self.chain = *c;
        }
        Ok(N * B)
    }
}

impl BlockCipherDecryptor<B, B, B> for ToyCbc {
    fn do_decrypt_init(key: &KeyMaterial<B>, iv: &[u8; B]) -> Result<Self, SymmetricCipherError> {
        Ok(Self { key: Self::check_key(key)?, chain: *iv })
    }
    fn do_decrypt_blocks<const N: usize>(
        &mut self,
        ciphertext: &[[u8; B]; N],
    ) -> Result<[[u8; B]; N], SymmetricCipherError> {
        let mut pt = [[0u8; B]; N];
        self.do_decrypt_blocks_out(ciphertext, &mut pt)?;
        Ok(pt)
    }
    fn do_decrypt_blocks_out<const N: usize>(
        &mut self,
        ciphertext: &[[u8; B]; N],
        plaintext: &mut [[u8; B]; N],
    ) -> Result<usize, SymmetricCipherError> {
        for (c, p) in ciphertext.iter().zip(plaintext.iter_mut()) {
            for i in 0..B {
                p[i] = c[i] ^ self.chain[i] ^ self.key[i];
            }
            self.chain = *c;
        }
        Ok(N * B)
    }
}

type Enc = PaddedEncryptor<ToyCbc, PKCS7, B, B, B>;
type Dec = PaddedDecryptor<ToyCbc, PKCS7, B, B, B>;

fn key() -> KeyMaterial<B> {
    KeyMaterial::<B>::from_bytes_as_type(&[0x5a; B], KeyType::SymmetricCipherKey).unwrap()
}

fn msg(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + 3) as u8).collect()
}

#[test]
fn toy_cipher_passes_core_test_framework() {
    TestFrameworkBlockCipher::new().test::<B, B, B, ToyCbc, ToyCbc>();
}

#[test]
fn one_shot_roundtrip_all_lengths() {
    let key = key();
    for len in 0..=3 * B + 1 {
        let pt = msg(len);
        let mut ct = vec![0u8; Enc::encrypt_out_len(len)];
        let (iv, n) = Enc::encrypt_out(&key, &pt, &mut ct).unwrap();
        assert_eq!(n, ct.len());
        assert_eq!(n, (len / B + 1) * B, "always one extra padding block");

        let mut out = vec![0u8; Dec::decrypt_out_max_len(n)];
        let m = Dec::decrypt_out(&key, &iv, &ct[..n], &mut out).unwrap();
        assert_eq!(&out[..m], &pt[..]);
    }
}

#[test]
fn streaming_matches_one_shot_for_every_chunking() {
    let key = key();
    let len = 5 * B + 3;
    let pt = msg(len);

    for chunk in [1usize, 2, 3, 7, 8, 9, 15, 16, 17, len] {
        // encrypt in chunks
        let (mut enc, iv) = Enc::new(&key).unwrap();
        let mut ct = Vec::new();
        for piece in pt.chunks(chunk) {
            let expect = enc.update_out_len(piece.len());
            let mut buf = vec![0u8; expect];
            let n = enc.do_update_out(piece, &mut buf).unwrap();
            assert_eq!(n, expect, "update_out_len must be exact");
            ct.extend_from_slice(&buf[..n]);
        }
        let last = enc.do_final().unwrap();
        ct.extend_from_slice(&last);
        assert_eq!(ct.len(), Enc::encrypt_out_len(len));

        // one-shot decrypt
        let mut out = vec![0u8; Dec::decrypt_out_max_len(ct.len())];
        let m = Dec::decrypt_out(&key, &iv, &ct, &mut out).unwrap();
        assert_eq!(&out[..m], &pt[..], "chunk {chunk}");

        // decrypt in the same chunks
        let mut dec = Dec::new(&key, &iv).unwrap();
        let mut rec = Vec::new();
        for piece in ct.chunks(chunk) {
            let expect = dec.update_out_len(piece.len());
            let mut buf = vec![0u8; expect];
            let n = dec.do_update_out(piece, &mut buf).unwrap();
            assert_eq!(n, expect, "update_out_len must be exact (decrypt)");
            rec.extend_from_slice(&buf[..n]);
        }
        let (block, data_len) = dec.do_final().unwrap();
        rec.extend_from_slice(&block[..data_len]);
        assert_eq!(rec, pt, "chunk {chunk}");
    }
}

#[test]
fn decryptor_lags_by_exactly_one_block() {
    let key = key();
    let (iv, ct) = {
        let mut ct = vec![0u8; Enc::encrypt_out_len(2 * B)];
        let (iv, _) = Enc::encrypt_out(&key, &msg(2 * B), &mut ct).unwrap();
        (iv, ct)
    };
    assert_eq!(ct.len(), 3 * B);
    let mut dec = Dec::new(&key, &iv).unwrap();
    let mut out = [0u8; 3 * B];
    // first block: nothing can be released yet
    assert_eq!(dec.update_out_len(B), 0);
    assert_eq!(dec.do_update_out(&ct[..B], &mut out).unwrap(), 0);
    // second block: releases the first
    assert_eq!(dec.update_out_len(B), B);
    assert_eq!(dec.do_update_out(&ct[B..2 * B], &mut out).unwrap(), B);
    // third block: releases the second
    assert_eq!(dec.do_update_out(&ct[2 * B..], &mut out[B..]).unwrap(), B);
    let (last, n) = dec.do_final().unwrap();
    assert_eq!(n, 0, "block-aligned plaintext => final block is all padding");
    assert_eq!(&out[..2 * B], &msg(2 * B)[..]);
    let _ = last;
}

#[test]
fn final_out_variants() {
    let key = key();
    let (mut enc, iv) = Enc::new(&key).unwrap();
    let mut ct = [0u8; 2 * B];
    let n = enc.do_update_out(&msg(B + 2), &mut ct).unwrap();
    assert_eq!(n, B);
    let mut last = [0u8; B];
    assert_eq!(enc.do_final_out(&mut last).unwrap(), B);
    ct[B..].copy_from_slice(&last);

    let mut dec = Dec::new(&key, &iv).unwrap();
    let mut out = [0u8; B];
    assert_eq!(dec.do_update_out(&ct, &mut out).unwrap(), B);
    let mut last_pt = [0u8; B];
    let data_len = dec.do_final_out(&mut last_pt).unwrap();
    assert_eq!(data_len, 2);
    let mut rec = out.to_vec();
    rec.extend_from_slice(&last_pt[..data_len]);
    assert_eq!(rec, msg(B + 2));
}

#[test]
fn tampered_final_block_is_rejected() {
    let key = key();
    for len in [0, 1, B - 1, B, B + 5] {
        let mut ct = vec![0u8; Enc::encrypt_out_len(len)];
        let (iv, n) = Enc::encrypt_out(&key, &msg(len), &mut ct).unwrap();
        // flipping the low bit of the final byte corrupts the PKCS7 length byte
        ct[n - 1] ^= 0x01;
        let mut out = vec![0u8; n];
        match Dec::decrypt_out(&key, &iv, &ct, &mut out) {
            Err(SymmetricCipherError::PaddingError(PaddingError::InvalidPadding)) => {}
            other => panic!("len {len}: expected InvalidPadding, got {other:?}"),
        }
    }
}

#[test]
fn malformed_ciphertext_lengths_are_rejected() {
    let key = key();
    let iv = [0u8; B];
    let mut out = [0u8; 4 * B];

    // empty
    assert!(matches!(
        Dec::decrypt_out(&key, &iv, &[], &mut out),
        Err(SymmetricCipherError::DecryptionFailed)
    ));
    // not a multiple of the block length
    assert!(matches!(
        Dec::decrypt_out(&key, &iv, &[0u8; B + 1], &mut out),
        Err(SymmetricCipherError::DecryptionFailed)
    ));
    // streaming: partial trailing block at final
    let mut dec = Dec::new(&key, &iv).unwrap();
    dec.do_update_out(&[0u8; B + 3], &mut out).unwrap();
    assert!(matches!(dec.do_final(), Err(SymmetricCipherError::DecryptionFailed)));
    // streaming: nothing fed at all
    let dec = Dec::new(&key, &iv).unwrap();
    assert!(matches!(dec.do_final(), Err(SymmetricCipherError::DecryptionFailed)));
}

#[test]
fn output_buffer_too_small_reports_required_length() {
    let key = key();
    let pt = msg(2 * B + 1);

    let mut small = [0u8; 2 * B];
    match Enc::encrypt_out(&key, &pt, &mut small) {
        Err(SymmetricCipherError::IncorrectOutputBufferLength(_, need)) => assert_eq!(need, 3 * B),
        other => panic!("{other:?}"),
    }

    let (mut enc, iv) = Enc::new(&key).unwrap();
    let mut tiny = [0u8; B - 1];
    match enc.do_update_out(&pt, &mut tiny) {
        Err(SymmetricCipherError::IncorrectOutputBufferLength(_, need)) => assert_eq!(need, 2 * B),
        other => panic!("{other:?}"),
    }
    drop(enc);

    let ct = [0u8; 3 * B];
    let mut small = [0u8; 3 * B - 2];
    match Dec::decrypt_out(&key, &iv, &ct, &mut small) {
        Err(SymmetricCipherError::IncorrectOutputBufferLength(_, need)) => {
            assert_eq!(need, 3 * B - 1)
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn wrong_key_type_is_rejected_by_adapters() {
    let mac_key = KeyMaterial::<B>::from_bytes_as_type(&[1u8; B], KeyType::MACKey).unwrap();
    assert!(matches!(Enc::new(&mac_key), Err(SymmetricCipherError::KeyMaterialError(_))));
    assert!(matches!(
        Dec::new(&mac_key, &[0u8; B]),
        Err(SymmetricCipherError::KeyMaterialError(_))
    ));
}
