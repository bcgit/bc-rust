use bouncycastle_chacha20::hazmat::{ChaCha20KeyState, ChaCha20KeyStream};
use bouncycastle_chacha20::{ChaCha20, ChaCha20Key};
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::hazmat::KeyStream;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{
    FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle_core::traits::{
    Algorithm, StreamCipherDecryptor, StreamCipherEncryptor, SuspendableKeyed,
};
use bouncycastle_core_test_framework::from_key_material::TestFrameworkFromKeyMaterial;
use bouncycastle_core_test_framework::key_stream::TestFrameworkKeyStream;
use bouncycastle_core_test_framework::suspendable_state::TestFrameworkSuspendableKeyedState;
use bouncycastle_core_test_framework::symmetric_ciphers::{
    TestFrameworkStreamCipher, TestFrameworkSymmetricCipher,
};
use bouncycastle_rng::HashDRBG_SHA512;

fn material() -> KeyMaterial<32> {
    KeyMaterial::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey).unwrap()
}

fn key() -> ChaCha20Key {
    ChaCha20Key::from_key_material(&material()).unwrap()
}

fn state() -> ChaCha20KeyState {
    ChaCha20KeyState::new(&material()).unwrap()
}

fn at<'k>(state: &'k ChaCha20KeyState, nonce: &[u8; 12], counter: u32) -> ChaCha20<'k, Encrypting> {
    ChaCha20::from_keystream(ChaCha20KeyStream::start_at(state, nonce, counter))
}

#[test]
fn core_stream_and_symmetric_contracts() {
    let key = key();
    let mut rng = HashDRBG_SHA512::new_from_os();
    TestFrameworkStreamCipher::new().test_key::<32, 12, ChaCha20Key>(&key, &mut rng);
    TestFrameworkSymmetricCipher::new().test_key::<32, 12, 0, ChaCha20Key>(&key, &mut rng);
    let state = state();
    TestFrameworkKeyStream::new()
        .test::<12, 64, _>(|nonce| ChaCha20KeyStream::start_at(&state, nonce, 0));
}

/// The key's construction suite: the type and strength policy of `from_key_material`.
#[test]
fn the_key_enforces_the_material_policy() {
    TestFrameworkFromKeyMaterial::new()
        .test::<32, ChaCha20Key>(ChaCha20KeyStream::ALG_NAME, SecurityStrength::_256bit);
}

#[test]
fn counter_exhaustion_is_atomic_and_retains_partial_blocks() {
    let state = state();
    for used in [0, 1, 31, 63, 64] {
        let nonce = [7; 12];
        let mut reference = [0x5a; 64];
        at(&state, &nonce, u32::MAX).do_encrypt_inplace(&mut reference).unwrap();
        let mut cipher = at(&state, &nonce, u32::MAX);
        let mut actual = [0x5a; 64];
        cipher.do_encrypt_inplace(&mut actual[..used]).unwrap();

        let mut too_long = vec![0xa5; 65 - used];
        assert!(matches!(
            cipher.do_encrypt_inplace(&mut too_long),
            Err(SymmetricCipherError::DataLimitExceeded)
        ));
        assert!(too_long.iter().all(|&b| b == 0xa5));
        cipher.do_encrypt_inplace(&mut actual[used..]).unwrap();
        assert_eq!(actual, reference);
        assert_eq!(cipher.keystream().remaining_blocks(), 0);
        assert_eq!(cipher.do_encrypt_inplace(&mut []).unwrap(), 0);
        assert!(matches!(
            cipher.do_encrypt_inplace(&mut [0]),
            Err(SymmetricCipherError::DataLimitExceeded)
        ));
    }
}

#[test]
fn last_two_blocks_work_in_arbitrary_chunks() {
    let state = state();
    let nonce = [9; 12];
    let mut expected = [0u8; 128];
    at(&state, &nonce, u32::MAX - 1).do_encrypt_inplace(&mut expected).unwrap();
    for chunk in [1, 3, 63, 64, 65, 127] {
        let mut cipher = at(&state, &nonce, u32::MAX - 1);
        let mut out = [0u8; 128];
        for bytes in out.chunks_mut(chunk) {
            cipher.do_encrypt_inplace(bytes).unwrap();
        }
        assert_eq!(out, expected);
        assert_eq!(cipher.keystream().remaining_blocks(), 0);
    }
    assert_eq!(key().create_decryptor(&nonce).keystream().remaining_blocks(), 1u64 << 32);
    assert_eq!(ChaCha20KeyStream::start_at(&state, &nonce, 1).remaining_blocks(), u32::MAX as u64);
}

/// The key's workers start at block counter 0: two blocks in, they match a keystream started at
/// counter 2.
#[test]
fn start_at_matches_the_key_after_discarding_blocks() {
    let nonce = [3; 12];
    let key = key();
    let state = state();
    let mut from_key = key.create_decryptor(&nonce);
    from_key.do_decrypt_inplace(&mut [0u8; 128]).unwrap();
    let mut a = [0x42u8; 100];
    let mut b = a;
    from_key.do_decrypt_inplace(&mut a).unwrap();
    at(&state, &nonce, 2).do_encrypt_inplace(&mut b).unwrap();
    assert_eq!(a, b);
}

#[test]
fn key_capacity_does_not_replace_key_length() {
    for len in 0..32 {
        let mut short = material();
        short.set_key_len(len).unwrap();
        assert!(matches!(
            ChaCha20KeyState::new(&short),
            Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::InvalidLength))
        ));
        assert!(matches!(
            ChaCha20Key::from_key_material(&short),
            Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::InvalidLength))
        ));
    }
}

/// Part of a message, then suspend a clone and resume it over the key it was made from: both
/// must finish identically, mid-block and at a block boundary, in both directions.
#[test]
fn suspend_and_resume_continues_the_keystream() {
    const N: usize = ChaCha20::<'static, Encrypting>::SUSPENDED_STATE_LEN;
    let key = key();
    let mut rng = HashDRBG_SHA512::new_from_os();
    for first in [0, 1, 63, 64, 65] {
        let (mut enc, nonce) = key.create_encryptor(&mut rng).unwrap();
        let mut ciphertext = vec![0x5au8; 200];
        enc.do_encrypt_inplace(&mut ciphertext[..first]).unwrap();
        TestFrameworkSuspendableKeyedState::new().test::<N, _>(&enc, &key);
        let state: [u8; N] = enc.clone().suspend();
        let mut resumed = ChaCha20::<Encrypting>::from_suspended(state, &key).unwrap();
        let mut rest = ciphertext[first..].to_vec();
        enc.do_encrypt_inplace(&mut ciphertext[first..]).unwrap();
        resumed.do_encrypt_inplace(&mut rest).unwrap();
        assert_eq!(rest, ciphertext[first..]);

        let mut dec = key.create_decryptor(&nonce);
        dec.do_decrypt_inplace(&mut ciphertext[..first]).unwrap();
        const M: usize = ChaCha20::<'static, Decrypting>::SUSPENDED_STATE_LEN;
        TestFrameworkSuspendableKeyedState::new().test::<M, _>(&dec, &key);
        let state: [u8; M] = dec.suspend();
        let mut resumed = ChaCha20::<Decrypting>::from_suspended(state, &key).unwrap();
        resumed.do_decrypt_inplace(&mut ciphertext[first..]).unwrap();
        assert_eq!(ciphertext, vec![0x5au8; 200]);
    }
}

/// The suspended layout is frozen. After the version header: the nonce, the next block counter
/// (`u64`, little-endian), the pending keystream block, and how much of it is used (`u64`,
/// little-endian). Here 70 bytes in, block 0 is spent, block 1 is pending with 6 bytes used, and
/// the next counter is 2.
#[test]
fn the_suspended_layout_is_frozen() {
    const N: usize = ChaCha20::<'static, Decrypting>::SUSPENDED_STATE_LEN;
    let key = key();
    let nonce = [0x24; 12];
    let mut keystream = [0u8; 192];
    key.create_decryptor(&nonce).do_decrypt_inplace(&mut keystream).unwrap();

    let mut dec = key.create_decryptor(&nonce);
    dec.do_decrypt_inplace(&mut [0u8; 70]).unwrap();
    let state: [u8; N] = dec.suspend();
    let mut expected = nonce.to_vec();
    expected.extend_from_slice(&2u64.to_le_bytes());
    expected.extend_from_slice(&keystream[64..128]);
    expected.extend_from_slice(&6u64.to_le_bytes());
    assert_eq!(state[3..], expected[..]);

    let mut resumed = ChaCha20::<Decrypting>::from_suspended(state, &key).unwrap();
    let mut rest = [0u8; 122];
    resumed.do_decrypt_inplace(&mut rest).unwrap();
    assert_eq!(rest, keystream[70..]);
}

/// A resumed state carrying a counter past `2^32` is not one this type writes, and a resumed
/// exhausted keystream stays exhausted.
#[test]
fn resumed_counter_is_bounded() {
    const N: usize = ChaCha20::<'static, Encrypting>::SUSPENDED_STATE_LEN;
    let key = key();
    let key_state = state();
    let mut cipher = at(&key_state, &[1; 12], u32::MAX);
    cipher.do_encrypt_inplace(&mut [0u8; 64]).unwrap();
    let state: [u8; N] = cipher.suspend();
    let mut resumed = ChaCha20::<Encrypting>::from_suspended(state, &key).unwrap();
    assert!(resumed.do_encrypt_inplace(&mut [0]).is_err());

    // Layout: version header (3), nonce (12), next counter (8, little-endian), pending block, used.
    let mut past = state;
    past[3 + 12..3 + 20].copy_from_slice(&((1u64 << 32) + 1).to_le_bytes());
    assert!(ChaCha20::<Encrypting>::from_suspended(past, &key).is_err());
}

/// The figures in the crate docs' Memory Usage table.
#[cfg(target_pointer_width = "64")]
#[test]
fn sizes_match_the_documented_memory_table() {
    use core::mem::size_of;
    assert_eq!(size_of::<ChaCha20Key>(), 32);
    assert_eq!(size_of::<ChaCha20KeyStream<'static>>(), 32);
    assert_eq!(size_of::<ChaCha20<'static, Encrypting>>(), 104);
    assert_eq!(size_of::<ChaCha20<'static, Decrypting>>(), 104);
    assert_eq!(ChaCha20::<'static, Encrypting>::SUSPENDED_STATE_LEN, 95);
}
