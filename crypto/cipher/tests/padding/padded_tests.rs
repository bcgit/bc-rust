//! Tests for PaddedBlockCipherEncryptor / PaddedBlockCipherDecryptor, through the key path:
//! `CBC<PKCS7>` and `CBC<NoPadding>` over the toy permutation in `common/toy_block_cipher.rs`.
//! They exercise every code path of the adapters: IV generation, chaining state across calls,
//! the one-block lag on decryption, and the alignment check `NoPadding` turns the adapters into.

#[path = "../common/toy_block_cipher.rs"]
mod toy_block_cipher;
#[path = "../common/toy_key.rs"]
#[allow(dead_code)]
mod toy_key;

use bouncycastle_cipher::modes::{Blocks, CBC, ModeNames};
use bouncycastle_cipher::padding::{NoPadding, PKCS7};
use bouncycastle_core::errors::{PaddingError, SymmetricCipherError};
use bouncycastle_core::hazmat::Mode;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{
    BlockEncryptionKey, FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle_core::traits::{
    BlockCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_core_test_framework::block_cipher::TestFrameworkBlockCipher;
use bouncycastle_core_test_framework::from_key_material::TestFrameworkFromKeyMaterial;
use bouncycastle_core_test_framework::symmetric_ciphers::TestFrameworkSymmetricCipher;
use toy_block_cipher::{TOY_BLOCK_LEN, ToyBlockCipher};
use toy_key::{ToyKey, os_rng};

const B: usize = TOY_BLOCK_LEN;

type Key = ToyKey<ToyBlockCipher, CBC<PKCS7>>;
type Enc<'k> = <Key as SymmetricEncryptionKey<B, B, B>>::Encryptor<'k>;
type Dec<'k> = <Key as SymmetricDecryptionKey<B, B, B>>::Decryptor<'k>;
/// The same adapters over `NoPadding`: an alignment check rather than a padding scheme.
type KeyNP = ToyKey<ToyBlockCipher, CBC<NoPadding>>;
type EncNP<'k> = <KeyNP as SymmetricEncryptionKey<B, B, B>>::Encryptor<'k>;
type DecNP<'k> = <KeyNP as SymmetricDecryptionKey<B, B, B>>::Decryptor<'k>;

fn material() -> KeyMaterial<B> {
    KeyMaterial::<B>::from_bytes_as_type(&[0x5a; B], KeyType::SymmetricCipherKey).unwrap()
}

fn key_for<M: Mode<ToyBlockCipher>>() -> ToyKey<ToyBlockCipher, M> {
    ToyKey::from_key_material(&material()).expect("the toy key")
}

fn key() -> Key {
    key_for()
}

fn key_np() -> KeyNP {
    key_for()
}

fn msg(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + 3) as u8).collect()
}

#[test]
fn toy_cipher_passes_core_test_framework() {
    TestFrameworkBlockCipher::new()
        .test_key::<B, B, B, _>(&key_for::<CBC<Blocks>>(), &mut os_rng());
}

/// The padded adapters are what the symmetric key path hands out for a block mode, so this is
/// also what exercises the role traits' provided one-shots over a mode with a final block.
#[test]
fn padded_adapters_pass_the_symmetric_cipher_framework() {
    TestFrameworkSymmetricCipher::new().test_key::<B, B, B, _>(&key(), &mut os_rng());
}

/// The construction suite for both keys: the type, binding and strength policy of
/// `from_key_material`.
#[test]
fn the_keys_enforce_the_material_policy() {
    let framework = TestFrameworkFromKeyMaterial::new();
    framework.test::<B, Key>(ToyBlockCipher::CBC_ALG_NAME, SecurityStrength::_128bit);
    framework.test::<B, KeyNP>(ToyBlockCipher::CBC_ALG_NAME, SecurityStrength::_128bit);
}

#[test]
fn one_shot_roundtrip_all_lengths() {
    let key = key();
    for len in 0..=3 * B + 1 {
        let pt = msg(len);
        let mut ct = vec![0u8; Enc::encrypt_out_len(len)];
        let (n, iv) = key.encrypt_out(&mut os_rng(), &pt, &mut ct).unwrap();
        assert_eq!(n, ct.len());
        assert_eq!(n, (len / B + 1) * B, "always one extra padding block");

        let mut out = vec![0u8; Dec::decrypt_out_len(n)];
        let m = key.decrypt_out(&iv, &ct[..n], &mut out).unwrap();
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
        let (mut enc, iv) = key.create_encryptor(&mut os_rng()).unwrap();
        let mut ct = Vec::new();
        for piece in pt.chunks(chunk) {
            let expect = enc.do_encrypt_out_len(piece.len());
            let mut buf = vec![0u8; expect];
            let n = enc.do_encrypt_out(piece, &mut buf).unwrap();
            assert_eq!(n, expect, "update_out_len must be exact");
            ct.extend_from_slice(&buf[..n]);
        }
        let (last, last_len) = enc.do_encrypt_final().unwrap();
        assert_eq!(last_len, B, "PKCS7 always emits a final block");
        ct.extend_from_slice(&last[..last_len]);
        assert_eq!(ct.len(), Enc::encrypt_out_len(len));

        // one-shot decrypt
        let mut out = vec![0u8; Dec::decrypt_out_len(ct.len())];
        let m = key.decrypt_out(&iv, &ct, &mut out).unwrap();
        assert_eq!(&out[..m], &pt[..], "chunk {chunk}");

        // decrypt in the same chunks
        let mut dec = key.create_decryptor(&iv);
        let mut rec = Vec::new();
        for piece in ct.chunks(chunk) {
            let expect = dec.do_decrypt_out_len(piece.len());
            let mut buf = vec![0u8; expect];
            let n = dec.do_decrypt_out(piece, &mut buf).unwrap();
            assert_eq!(n, expect, "update_out_len must be exact (decrypt)");
            rec.extend_from_slice(&buf[..n]);
        }
        let (block, data_len) = dec.do_decrypt_final().unwrap();
        rec.extend_from_slice(&block[..data_len]);
        assert_eq!(rec, pt, "chunk {chunk}");
    }
}

#[test]
fn decryptor_lags_by_exactly_one_block() {
    let key = key();
    let (iv, ct) = {
        let mut ct = vec![0u8; Enc::encrypt_out_len(2 * B)];
        let (_, iv) = key.encrypt_out(&mut os_rng(), &msg(2 * B), &mut ct).unwrap();
        (iv, ct)
    };
    assert_eq!(ct.len(), 3 * B);
    let mut dec = key.create_decryptor(&iv);
    let mut out = [0u8; 3 * B];
    // first block: nothing can be released yet
    assert_eq!(dec.do_decrypt_out_len(B), 0);
    assert_eq!(dec.do_decrypt_out(&ct[..B], &mut out).unwrap(), 0);
    // second block: releases the first
    assert_eq!(dec.do_decrypt_out_len(B), B);
    assert_eq!(dec.do_decrypt_out(&ct[B..2 * B], &mut out).unwrap(), B);
    // third block: releases the second
    assert_eq!(dec.do_decrypt_out(&ct[2 * B..], &mut out[B..]).unwrap(), B);
    let (last, n) = dec.do_decrypt_final().unwrap();
    assert_eq!(n, 0, "block-aligned plaintext => final block is all padding");
    assert_eq!(&out[..2 * B], &msg(2 * B)[..]);
    let _ = last;
}

#[test]
fn final_out_variants() {
    let key = key();
    let (mut enc, iv) = key.create_encryptor(&mut os_rng()).unwrap();
    let mut ct = [0u8; 2 * B];
    let n = enc.do_encrypt_out(&msg(B + 2), &mut ct).unwrap();
    assert_eq!(n, B);
    let mut last = [0u8; B];
    assert_eq!(enc.do_encrypt_final_out(&mut last).unwrap(), B);
    ct[B..].copy_from_slice(&last);

    let mut dec = key.create_decryptor(&iv);
    let mut out = [0u8; B];
    assert_eq!(dec.do_decrypt_out(&ct, &mut out).unwrap(), B);
    let mut last_pt = [0u8; B];
    let data_len = dec.do_decrypt_final_out(&mut last_pt).unwrap();
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
        let (n, iv) = key.encrypt_out(&mut os_rng(), &msg(len), &mut ct).unwrap();
        // flipping the low bit of the final byte corrupts the PKCS7 length byte
        ct[n - 1] ^= 0x01;
        // Pre-filled with a non-zero byte, so a buffer the decryptor never wrote is not mistaken
        // for one it zeroized. At `B + 5` the first block has been decrypted into `out` by the
        // time the padding fails, and `decrypt_out` must wipe it.
        let mut out = vec![0xEEu8; n];
        match key.decrypt_out(&iv, &ct, &mut out) {
            Err(SymmetricCipherError::PaddingError(PaddingError::InvalidPadding)) => {}
            other => panic!("len {len}: expected InvalidPadding, got {other:?}"),
        }
        assert!(out.iter().all(|&b| b == 0), "len {len}: a failed decrypt must zeroize `out`");
    }
}

#[test]
fn malformed_ciphertext_lengths_are_rejected() {
    let key = key();
    let iv = [0u8; B];
    let mut out = [0u8; 4 * B];

    // empty
    assert!(matches!(
        key.decrypt_out(&iv, &[], &mut out),
        Err(SymmetricCipherError::DecryptionFailed)
    ));
    // not a multiple of the block length
    assert!(matches!(
        key.decrypt_out(&iv, &[0u8; B + 1], &mut out),
        Err(SymmetricCipherError::DataNotBlockAligned)
    ));
    // streaming: partial trailing block at final
    let mut dec = key.create_decryptor(&iv);
    dec.do_decrypt_out(&[0u8; B + 3], &mut out).unwrap();
    assert!(matches!(dec.do_decrypt_final(), Err(SymmetricCipherError::DataNotBlockAligned)));
    // streaming: nothing fed at all
    let dec = key.create_decryptor(&iv);
    assert!(matches!(dec.do_decrypt_final(), Err(SymmetricCipherError::DecryptionFailed)));
}

#[test]
fn output_buffer_too_small_reports_required_length() {
    let key = key();
    let pt = msg(2 * B + 1);

    let mut small = [0u8; 2 * B];
    match key.encrypt_out(&mut os_rng(), &pt, &mut small) {
        Err(SymmetricCipherError::OutputBufferTooSmall(need)) => assert_eq!(need, 3 * B),
        other => panic!("{other:?}"),
    }

    let (mut enc, iv) = key.create_encryptor(&mut os_rng()).unwrap();
    let mut tiny = [0u8; B - 1];
    match enc.do_encrypt_out(&pt, &mut tiny) {
        Err(SymmetricCipherError::OutputBufferTooSmall(need)) => assert_eq!(need, 2 * B),
        other => panic!("{other:?}"),
    }
    drop(enc);

    let ct = [0u8; 3 * B];
    let mut small = [0u8; 3 * B - 2];
    match key.decrypt_out(&iv, &ct, &mut small) {
        Err(SymmetricCipherError::OutputBufferTooSmall(need)) => {
            assert_eq!(need, 3 * B - 1)
        }
        other => panic!("{other:?}"),
    }
}

// ---- NoPadding through the adapters --------------------------------------------------------

/// With `NoPadding` the adapters enforce alignment: the framework is told that only multiples of
/// the block length are accepted, and it asserts that every other length is refused with a
/// `PaddingError`, at `encrypt_out` and at a streaming `do_encrypt_final`.
#[test]
fn no_padding_adapters_pass_the_symmetric_cipher_framework() {
    let mut framework = TestFrameworkSymmetricCipher::new();
    framework.required_alignment = B;
    framework.test_key::<B, B, B, _>(&key_np(), &mut os_rng());
}

/// An aligned message passes through with its length unchanged -- no final block is added -- and the
/// ciphertext is exactly what the bare mode produces: NoPadding is a check, not a transformation.
#[test]
fn no_padding_adds_nothing_to_aligned_data() {
    let key_np = key_np();
    for blocks in 0..=4usize {
        let len = blocks * B;
        let pt = msg(len);
        assert_eq!(EncNP::encrypt_out_len(len), len);
        assert_eq!(DecNP::decrypt_out_len(len), len);

        let mut ct = vec![0u8; len];
        let (n, iv) = key_np.encrypt_out(&mut os_rng(), &pt, &mut ct).unwrap();
        assert_eq!(n, len, "{blocks} blocks: output length equals input length");

        // Byte for byte the bare cipher's output under the same IV.
        let mut bare = pt.clone();
        let key = key_for::<CBC<Blocks>>();
        let (mut enc, _) = key.create_encryptor(&mut FixedSeedRNG::<B>::new(iv)).unwrap();
        let (blocks_mut, _) = bare.as_chunks_mut::<B>();
        enc.do_encrypt_blocks_inplace(blocks_mut).unwrap();
        assert_eq!(ct, bare, "{blocks} blocks: the adapter must not alter the ciphertext");

        let mut out = vec![0u8; len];
        let m = key_np.decrypt_out(&iv, &ct, &mut out).unwrap();
        assert_eq!(&out[..m], &pt[..], "{blocks} blocks: round trip");

        // Streaming: do_encrypt_final reports zero output bytes.
        let (mut enc, _) = key_np.create_encryptor(&mut os_rng()).unwrap();
        let mut buf = vec![0u8; enc.do_encrypt_out_len(len)];
        assert_eq!(enc.do_encrypt_out(&pt, &mut buf).unwrap(), len);
        let (_, last_len) = enc.do_encrypt_final().unwrap();
        assert_eq!(last_len, 0, "{blocks} blocks: no final block");
    }
}

/// An unaligned message is refused with `DataNotBlockAligned`, from the one-shot and from a
/// streaming `do_encrypt_final`, and nothing is written for the final block.
#[test]
fn no_padding_refuses_unaligned_data() {
    let key_np = key_np();
    for len in [1usize, B - 1, B + 1, 2 * B + 3, 3 * B - 1] {
        let pt = msg(len);
        let mut ct = vec![0u8; len + B];
        assert!(
            matches!(
                key_np.encrypt_out(&mut os_rng(), &pt, &mut ct),
                Err(SymmetricCipherError::DataNotBlockAligned)
            ),
            "len {len}: one-shot must refuse an unaligned message"
        );

        let (mut enc, _) = key_np.create_encryptor(&mut os_rng()).unwrap();
        let whole = len / B * B;
        let mut buf = vec![0u8; whole];
        assert_eq!(enc.do_encrypt_out(&pt, &mut buf).unwrap(), whole, "whole blocks still stream");
        assert!(
            matches!(enc.do_encrypt_final(), Err(SymmetricCipherError::DataNotBlockAligned)),
            "len {len}: do_encrypt_final must refuse the buffered partial block"
        );
    }
}

/// On the decrypt side, an empty ciphertext is the empty message (there is no padding block to
/// demand), and an unaligned ciphertext is still malformed.
#[test]
fn no_padding_decryptor_accepts_empty_and_rejects_unaligned() {
    let key_np = key_np();
    let iv = [0x11u8; B];
    let mut out = [0u8; 0];
    assert_eq!(key_np.decrypt_out(&iv, &[], &mut out).unwrap(), 0);
    let dec = key_np.create_decryptor(&iv);
    assert_eq!(dec.do_decrypt_final().unwrap().1, 0);

    for len in [1usize, B - 1, B + 1, 2 * B + 5] {
        let mut out = vec![0u8; len];
        assert!(
            matches!(
                key_np.decrypt_out(&iv, &msg(len), &mut out),
                Err(SymmetricCipherError::DataNotBlockAligned)
            ),
            "len {len}: an unaligned ciphertext is malformed"
        );
    }
}
