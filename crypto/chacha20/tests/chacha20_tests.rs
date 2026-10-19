use bouncycastle_chacha20::ChaCha20;
use bouncycastle_chacha20::hazmat::ChaCha20KeyStream;
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::hazmat::KeyStream;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{
    StreamCipherDecryptor, StreamCipherEncryptor, SuspendableKeyed, SymmetricCipherDecryptor,
    SymmetricCipherEncryptor,
};
use bouncycastle_core_test_framework::key_stream::TestFrameworkKeyStream;
use bouncycastle_core_test_framework::suspendable_state::TestFrameworkSuspendableKeyedState;
use bouncycastle_core_test_framework::symmetric_ciphers::{
    TestFrameworkStreamCipher, TestFrameworkSymmetricCipher,
};

fn key() -> KeyMaterial<32> {
    KeyMaterial::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey).unwrap()
}

fn at(nonce: &[u8; 12], counter: u32) -> ChaCha20<Encrypting> {
    ChaCha20::from_keystream(ChaCha20KeyStream::start_at(&key(), nonce, counter).unwrap())
}

#[test]
fn core_stream_and_symmetric_contracts() {
    TestFrameworkStreamCipher::new().test::<32, 12, ChaCha20<Encrypting>, ChaCha20<Decrypting>>();
    TestFrameworkSymmetricCipher::new()
        .test_encryptor_decryptor::<32, 12, 0, ChaCha20<Encrypting>, ChaCha20<Decrypting>>();
    TestFrameworkKeyStream::new().test::<32, 12, 64, ChaCha20KeyStream>();
}

#[test]
fn counter_exhaustion_is_atomic_and_retains_partial_blocks() {
    for used in [0, 1, 31, 63, 64] {
        let nonce = [7; 12];
        let mut reference = [0x5a; 64];
        at(&nonce, u32::MAX).do_encrypt(&mut reference).unwrap();
        let mut cipher = at(&nonce, u32::MAX);
        let mut actual = [0x5a; 64];
        cipher.do_encrypt(&mut actual[..used]).unwrap();

        let mut too_long = vec![0xa5; 65 - used];
        assert!(matches!(
            cipher.do_encrypt(&mut too_long),
            Err(SymmetricCipherError::DataLimitExceeded)
        ));
        assert!(too_long.iter().all(|&b| b == 0xa5));
        cipher.do_encrypt(&mut actual[used..]).unwrap();
        assert_eq!(actual, reference);
        assert_eq!(cipher.keystream().remaining_blocks(), 0);
        assert_eq!(cipher.do_encrypt(&mut []).unwrap(), 0);
        assert!(matches!(
            cipher.do_encrypt(&mut [0]),
            Err(SymmetricCipherError::DataLimitExceeded)
        ));
    }
}

#[test]
fn last_two_blocks_work_in_arbitrary_chunks() {
    let nonce = [9; 12];
    let mut expected = [0u8; 128];
    at(&nonce, u32::MAX - 1).do_encrypt(&mut expected).unwrap();
    for chunk in [1, 3, 63, 64, 65, 127] {
        let mut cipher = at(&nonce, u32::MAX - 1);
        let mut out = [0u8; 128];
        for bytes in out.chunks_mut(chunk) {
            cipher.do_encrypt(bytes).unwrap();
        }
        assert_eq!(out, expected);
        assert_eq!(cipher.keystream().remaining_blocks(), 0);
    }
    assert_eq!(ChaCha20KeyStream::new(&key(), &nonce).unwrap().remaining_blocks(), 1u64 << 32);
    assert_eq!(
        ChaCha20KeyStream::start_at(&key(), &nonce, 1).unwrap().remaining_blocks(),
        u32::MAX as u64
    );
}

#[test]
fn start_at_matches_new_after_discarding_blocks() {
    let nonce = [3; 12];
    let mut from_new =
        ChaCha20::<Encrypting>::from_keystream(ChaCha20KeyStream::new(&key(), &nonce).unwrap());
    from_new.do_encrypt(&mut [0u8; 128]).unwrap();
    let mut a = [0x42u8; 100];
    let mut b = a;
    from_new.do_encrypt(&mut a).unwrap();
    at(&nonce, 2).do_encrypt(&mut b).unwrap();
    assert_eq!(a, b);
}

#[test]
fn key_capacity_does_not_replace_key_length() {
    for len in 0..32 {
        let mut key = key();
        key.set_key_len(len).unwrap();
        assert!(matches!(
            ChaCha20KeyStream::start_at(&key, &[0; 12], 0),
            Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::InvalidLength))
        ));
        assert!(matches!(
            ChaCha20::<Decrypting>::do_decrypt_init(&key, &[0; 12]),
            Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::InvalidLength))
        ));
    }
}

/// Part of a message, then suspend a clone and resume it with the re-supplied key: both must
/// finish identically, mid-block and at a block boundary, in both directions.
#[test]
fn suspend_and_resume_continues_the_keystream() {
    const N: usize = ChaCha20::<Encrypting>::SUSPENDED_STATE_LEN;
    let key = key();
    for first in [0, 1, 63, 64, 65] {
        let (mut enc, nonce) = ChaCha20::<Encrypting>::do_encrypt_init(&key).unwrap();
        let mut ciphertext = vec![0x5au8; 200];
        enc.do_encrypt(&mut ciphertext[..first]).unwrap();
        TestFrameworkSuspendableKeyedState::new().test::<N, _>(&enc, &key);
        let state: [u8; N] = enc.clone().suspend();
        let mut resumed = ChaCha20::<Encrypting>::from_suspended(state, &key).unwrap();
        let mut rest = ciphertext[first..].to_vec();
        enc.do_encrypt(&mut ciphertext[first..]).unwrap();
        resumed.do_encrypt(&mut rest).unwrap();
        assert_eq!(rest, ciphertext[first..]);

        let mut dec = ChaCha20::<Decrypting>::do_decrypt_init(&key, &nonce).unwrap();
        dec.do_decrypt(&mut ciphertext[..first]).unwrap();
        const M: usize = ChaCha20::<Decrypting>::SUSPENDED_STATE_LEN;
        TestFrameworkSuspendableKeyedState::new().test::<M, _>(&dec, &key);
        let state: [u8; M] = dec.suspend();
        let mut resumed = ChaCha20::<Decrypting>::from_suspended(state, &key).unwrap();
        resumed.do_decrypt(&mut ciphertext[first..]).unwrap();
        assert_eq!(ciphertext, vec![0x5au8; 200]);
    }
}

/// A resumed state carrying a counter past `2^32` is not one this type writes, and a resumed
/// exhausted keystream stays exhausted.
#[test]
fn resumed_counter_is_bounded() {
    const N: usize = ChaCha20::<Encrypting>::SUSPENDED_STATE_LEN;
    let mut cipher = at(&[1; 12], u32::MAX);
    cipher.do_encrypt(&mut [0u8; 64]).unwrap();
    let state: [u8; N] = cipher.suspend();
    let mut resumed = ChaCha20::<Encrypting>::from_suspended(state, &key()).unwrap();
    assert!(resumed.do_encrypt(&mut [0]).is_err());

    // Layout: version header (3), nonce (12), next counter (8, little-endian), pending block, used.
    let mut past = state;
    past[3 + 12..3 + 20].copy_from_slice(&((1u64 << 32) + 1).to_le_bytes());
    assert!(ChaCha20::<Encrypting>::from_suspended(past, &key()).is_err());

    let wrong = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::MACKey).unwrap();
    assert!(ChaCha20::<Encrypting>::from_suspended(state, &wrong).is_err());
}
