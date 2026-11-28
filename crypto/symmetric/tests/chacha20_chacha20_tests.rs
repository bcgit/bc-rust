use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::hazmat::KeyStream;
use bouncycastle_core::hex;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{
    FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle_core::traits::{
    Algorithm, SeekableStreamCipher, StreamCipherDecryptor, StreamCipherEncryptor,
};
use bouncycastle_core_test_framework::from_key_material::TestFrameworkFromKeyMaterial;
use bouncycastle_core_test_framework::key_stream::TestFrameworkKeyStream;
use bouncycastle_core_test_framework::symmetric_ciphers::{
    TestFrameworkSeekableStreamCipher, TestFrameworkStreamCipher, TestFrameworkSymmetricCipher,
};
use bouncycastle_rng::HashDRBG_SHA512;
use bouncycastle_symmetric::chacha20::hazmat::{ChaCha20KeyStream, keystream_at};
use bouncycastle_symmetric::chacha20::{ChaCha20, ChaCha20Key};
use bouncycastle_symmetric::stream::hazmat::stream_cipher_over;
use bouncycastle_symmetric::{Decrypting, Encrypting};

fn material() -> KeyMaterial<32> {
    KeyMaterial::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey).unwrap()
}

fn key() -> ChaCha20Key {
    ChaCha20Key::from_key_material(&material()).unwrap()
}

fn at<'k>(key: &'k ChaCha20Key, nonce: &[u8; 12], counter: u32) -> ChaCha20<'k, Encrypting> {
    stream_cipher_over(keystream_at(key, nonce, counter))
}

#[test]
fn core_stream_and_symmetric_contracts() {
    let key = key();
    let mut rng = HashDRBG_SHA512::new_from_os();
    TestFrameworkStreamCipher::new().test_key::<32, 12, ChaCha20Key>(&key, &mut rng);
    TestFrameworkSymmetricCipher::new().test_key::<32, 12, 0, ChaCha20Key>(&key, &mut rng);
    TestFrameworkKeyStream::new().test::<12, 64, _>(|nonce| keystream_at(&key, nonce, 0));
    // RFC 8439 Sec 2.4: 2^32 counter values of one 64-byte block each.
    TestFrameworkSeekableStreamCipher::new().test_key::<32, 12, ChaCha20Key>(&key, 64 << 32);
}

/// RFC 8439 Sec 2.4.2, whose initial counter is 1, from a key's workers, which start at counter
/// 0: `seek_to(64)` reaches it, in both directions.
#[test]
fn rfc8439_2_4_2_is_reached_by_seeking_one_block() {
    let bytes: [u8; 32] =
        hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap()
            .try_into()
            .unwrap();
    let key = ChaCha20Key::from_key_material(
        &KeyMaterial::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).unwrap(),
    )
    .unwrap();
    let nonce: [u8; 12] = hex::decode("000000000000004a00000000").unwrap().try_into().unwrap();
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let ciphertext = hex::decode(concat!(
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b",
        "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8",
        "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736",
        "5af90bbf74a35be6b40b8eedf2785e42874d",
    ))
    .unwrap();

    let mut enc = key.create_encryptor_nonce(&nonce);
    enc.seek_to(64).unwrap();
    let mut data = *plaintext;
    enc.do_encrypt_inplace(&mut data).unwrap();
    assert_eq!(&data[..], &ciphertext[..]);
    assert_eq!(enc.position(), 64 + 114);

    let mut dec = key.create_decryptor(&nonce);
    dec.seek_to(64).unwrap();
    dec.do_decrypt_inplace(&mut data).unwrap();
    assert_eq!(&data, plaintext);

    // A worker over `keystream_at(.., 1)` is at that position already.
    assert_eq!(at(&key, &nonce, 1).position(), 64);
}

/// The last valid position is the start of the block past counter `2^32 - 1`: the block at
/// `2^38 - 64` is that counter's, and one byte past the end is refused, leaving the worker usable.
#[test]
fn seeking_stops_at_the_end_of_the_counter() {
    let key = key();
    let nonce = [5; 12];
    let mut expected = [0u8; 64];
    at(&key, &nonce, u32::MAX).do_encrypt_inplace(&mut expected).unwrap();

    let mut enc = key.create_encryptor_nonce(&nonce);
    enc.seek_to((1 << 38) - 64).unwrap();
    let mut last = [0u8; 64];
    enc.do_encrypt_inplace(&mut last).unwrap();
    assert_eq!(last, expected);
    assert_eq!(enc.position(), 1 << 38);
    assert_eq!(enc.keystream().remaining_blocks(), 0);

    assert!(matches!(enc.seek_to((1 << 38) + 1), Err(SymmetricCipherError::DataLimitExceeded)));
    assert_eq!(enc.position(), 1 << 38);
    enc.seek_to(1 << 38).unwrap();
    enc.seek_to((1 << 38) - 1).unwrap();
    let mut one = [0u8; 1];
    enc.do_encrypt_inplace(&mut one).unwrap();
    assert_eq!(one[0], expected[63]);
}

/// A worker started at counter 1 cannot seek back into block 0, which ChaCha20-Poly1305 keeps
/// for its one-time key (RFC 8439 Sec 2.6.1); a refused seek leaves it where it was, and it can
/// seek anywhere from its start onwards, backwards included.
#[test]
fn seeking_stops_at_the_starting_block() {
    let key = key();
    let nonce = [6; 12];
    let mut expected = [0u8; 70];
    at(&key, &nonce, 1).do_encrypt_inplace(&mut expected).unwrap();

    let mut enc = at(&key, &nonce, 1);
    let mut head = [0u8; 3];
    enc.do_encrypt_inplace(&mut head).unwrap();
    for position in [0, 1, 63] {
        assert!(matches!(enc.seek_to(position), Err(SymmetricCipherError::DataLimitExceeded)));
        assert_eq!(enc.position(), 67);
    }
    let mut next = [0u8; 2];
    enc.do_encrypt_inplace(&mut next).unwrap();
    assert_eq!(next, expected[3..5]);

    enc.seek_to(64).unwrap();
    let mut again = [0u8; 70];
    enc.do_encrypt_inplace(&mut again).unwrap();
    assert_eq!(again, expected);
}

/// The key's construction suite: the type and strength policy of `from_key_material`.
#[test]
fn the_key_enforces_the_material_policy() {
    TestFrameworkFromKeyMaterial::new()
        .test::<32, ChaCha20Key>(ChaCha20KeyStream::ALG_NAME, SecurityStrength::_256bit);
}

#[test]
fn counter_exhaustion_is_atomic_and_retains_partial_blocks() {
    let key = key();
    for used in [0, 1, 31, 63, 64] {
        let nonce = [7; 12];
        let mut reference = [0x5a; 64];
        at(&key, &nonce, u32::MAX).do_encrypt_inplace(&mut reference).unwrap();
        let mut cipher = at(&key, &nonce, u32::MAX);
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
    let key = key();
    let nonce = [9; 12];
    let mut expected = [0u8; 128];
    at(&key, &nonce, u32::MAX - 1).do_encrypt_inplace(&mut expected).unwrap();
    for chunk in [1, 3, 63, 64, 65, 127] {
        let mut cipher = at(&key, &nonce, u32::MAX - 1);
        let mut out = [0u8; 128];
        for bytes in out.chunks_mut(chunk) {
            cipher.do_encrypt_inplace(bytes).unwrap();
        }
        assert_eq!(out, expected);
        assert_eq!(cipher.keystream().remaining_blocks(), 0);
    }
    assert_eq!(key.create_decryptor(&nonce).keystream().remaining_blocks(), 1u64 << 32);
    assert_eq!(keystream_at(&key, &nonce, 1).remaining_blocks(), u32::MAX as u64);
}

/// The raw keystream run to its last counter value has nothing left, and a stream cipher made
/// over it refuses more data rather than carrying on.
#[test]
fn a_keystream_at_its_last_counter_has_no_blocks_left() {
    let key = key();
    let mut ks = keystream_at(&key, &[7; 12], u32::MAX);
    ks.apply_blocks(&mut [[0u8; 64]; 1]);
    assert_eq!(ks.remaining_blocks(), 0);
    assert!(matches!(
        stream_cipher_over::<_, Encrypting, 12, 64>(ks).do_encrypt_inplace(&mut [0u8; 1]),
        Err(SymmetricCipherError::DataLimitExceeded)
    ));
}

/// Past the last counter value the raw keystream panics, as the trait allows, rather than
/// wrapping word 12 to 0 and repeating the keystream; in release builds too.
#[test]
#[should_panic(expected = "the caller checks remaining_blocks")]
fn applying_blocks_past_the_last_counter_panics() {
    let key = key();
    let mut ks = keystream_at(&key, &[7; 12], u32::MAX);
    ks.apply_blocks(&mut [[0u8; 64]; 2]);
}

/// The key's workers start at block counter 0: two blocks in, they match a keystream started at
/// counter 2.
#[test]
fn keystream_at_matches_the_key_after_discarding_blocks() {
    let nonce = [3; 12];
    let key = key();
    let mut from_key = key.create_decryptor(&nonce);
    from_key.do_decrypt_inplace(&mut [0u8; 128]).unwrap();
    let mut a = [0x42u8; 100];
    let mut b = a;
    from_key.do_decrypt_inplace(&mut a).unwrap();
    at(&key, &nonce, 2).do_encrypt_inplace(&mut b).unwrap();
    assert_eq!(a, b);
}

#[test]
fn key_capacity_does_not_replace_key_length() {
    for len in 0..32 {
        let mut short = material();
        short.set_key_len(len).unwrap();
        assert!(matches!(
            ChaCha20Key::from_key_material(&short),
            Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::InvalidLength))
        ));
    }
}

/// The figures in the module docs' Memory Usage table.
#[cfg(target_pointer_width = "64")]
#[test]
fn sizes_match_the_documented_memory_table() {
    use core::mem::size_of;
    assert_eq!(size_of::<ChaCha20Key>(), 32);
    assert_eq!(size_of::<ChaCha20KeyStream<'static>>(), 32);
    assert_eq!(size_of::<ChaCha20<'static, Encrypting>>(), 104);
    assert_eq!(size_of::<ChaCha20<'static, Decrypting>>(), 104);
}

/// Equality is over the key words, so it follows the material: the same bytes compare equal, as
/// does a clone, and a single flipped bit does not. Keys have no `Debug`, hence `assert!` over `==`.
#[test]
fn keys_compare_equal_exactly_when_their_material_does() {
    let key = key();
    assert!(key == key.clone());
    assert!(key == ChaCha20Key::from_key_material(&material()).unwrap());
    let mut flipped = [0x42u8; 32];
    flipped[31] ^= 1;
    let other =
        KeyMaterial::<32>::from_bytes_as_type(&flipped, KeyType::SymmetricCipherKey).unwrap();
    assert!(key != ChaCha20Key::from_key_material(&other).unwrap());
}
