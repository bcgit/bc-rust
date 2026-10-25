//! Tests for the stream-mode aliases `SM4_CFB`, `SM4_CFB8` and `SM4_CTR`, through the keys that
//! hand them out.
//!
//! The aliases are only type aliases, so what is worth testing is that they behave as the mode
//! they claim to be: the direction selects the encryptor or the decryptor, the init data is the
//! length the mode defines, and the three modes are distinct from each other and from CBC. The
//! known-answer coverage is in `stream_mode_tests.rs`, which type each alias resolves to is
//! pinned in `alg_name_tests.rs`, and the modes themselves are tested in their own right in
//! `bouncycastle_cipher::modes`; this checks the wiring between them.

use bouncycastle_cipher::modes::{CFB, CFB8, CTR};
use bouncycastle_core::hazmat::Mode;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{
    FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle_core::traits::{StreamCipherDecryptor, StreamCipherEncryptor};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_rng::HashDRBG_SHA512;
use bouncycastle_sm4::hazmat::SM4Internal;
use bouncycastle_sm4::{BLOCK_LEN, CTR_NONCE_LEN, KEY_LEN, SM4Key};

fn material() -> KeyMaterial<KEY_LEN> {
    let bytes: [u8; KEY_LEN] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    KeyMaterial::<KEY_LEN>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
        .expect("a valid key")
}

fn key<M: Mode<SM4Internal>>() -> SM4Key<M> {
    SM4Key::from_key_material(&material()).expect("a valid key")
}

fn rng() -> HashDRBG_SHA512 {
    HashDRBG_SHA512::new_from_os()
}

/// Deterministic filler, so nothing here depends on an RNG.
fn filler(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state >> 24) as u8
        })
        .collect()
}

/// Every stream-mode key round-trips at any length, with the ciphertext exactly as long as the
/// plaintext -- the property that separates these three from the CBC key, which pads.
#[test]
fn every_stream_key_round_trips_at_any_length() {
    fn check<'k, const INIT_DATA_LEN: usize, K>(name: &str, key: &'k K)
    where
        K: SymmetricEncryptionKey<KEY_LEN, INIT_DATA_LEN, 0>
            + SymmetricDecryptionKey<KEY_LEN, INIT_DATA_LEN, 0>,
        K::Encryptor<'k>: StreamCipherEncryptor<INIT_DATA_LEN>,
        K::Decryptor<'k>: StreamCipherDecryptor<INIT_DATA_LEN>,
    {
        for len in [0usize, 1, 15, 16, 17, 64, 257] {
            let plaintext = filler(len, len as u32);
            let mut data = plaintext.clone();

            let (written, init) = key.encrypt_inplace(&mut rng(), &mut data).expect("encryption");
            assert_eq!(written, len, "{name}, len {len}: bytes written");
            assert_eq!(data.len(), len, "{name}, len {len}: no padding is added");
            assert_eq!(init.len(), INIT_DATA_LEN, "{name}: init data length");

            let read = key.decrypt_inplace(&init, &mut data).expect("decryption");
            assert_eq!(read, len, "{name}, len {len}: bytes read");
            assert_eq!(data, plaintext, "{name}, len {len}: round trip");
        }
    }

    check::<16, _>("SM4_CFB", &key::<CFB>());
    check::<16, _>("SM4_CFB8", &key::<CFB8>());
    check::<12, _>("SM4_CTR", &key::<CTR>());
}

/// Streaming in arbitrary pieces gives the same answer as one call: a sequence of calls must be
/// equivalent to one over the concatenation, whatever the chunking.
#[test]
fn chunking_does_not_change_the_ciphertext() {
    fn check<'k, const INIT_DATA_LEN: usize, K>(name: &str, key: &'k K)
    where
        K: SymmetricEncryptionKey<KEY_LEN, INIT_DATA_LEN, 0>
            + SymmetricDecryptionKey<KEY_LEN, INIT_DATA_LEN, 0>,
        K::Encryptor<'k>: StreamCipherEncryptor<INIT_DATA_LEN>,
        K::Decryptor<'k>: StreamCipherDecryptor<INIT_DATA_LEN>,
    {
        let plaintext = filler(100, 99);
        let mut whole = plaintext.clone();
        let (_, init) = key.encrypt_inplace(&mut rng(), &mut whole).expect("encryption");

        for chunk in [1usize, 3, 7, 16, 33] {
            let mut dec = key.create_decryptor(&init);
            let mut data = whole.clone();
            for piece in data.chunks_mut(chunk) {
                dec.do_decrypt_inplace(piece).expect("decryption");
            }
            assert_eq!(data, plaintext, "{name}: {chunk}-byte pieces should decrypt the same");
        }
    }

    check::<16, _>("SM4_CFB", &key::<CFB>());
    check::<16, _>("SM4_CFB8", &key::<CFB8>());
    check::<12, _>("SM4_CTR", &key::<CTR>());
}

/// A fresh IV or nonce per encryption, so the same plaintext gives different ciphertext. For CTR
/// this is the whole security argument: a repeated nonce leaks the XOR of the two messages.
#[test]
fn each_encryption_gets_fresh_init_data() {
    fn check<'k, const INIT_DATA_LEN: usize, K>(name: &str, key: &'k K)
    where
        K: SymmetricEncryptionKey<KEY_LEN, INIT_DATA_LEN, 0>
            + SymmetricDecryptionKey<KEY_LEN, INIT_DATA_LEN, 0>,
        K::Encryptor<'k>: StreamCipherEncryptor<INIT_DATA_LEN>,
        K::Decryptor<'k>: StreamCipherDecryptor<INIT_DATA_LEN>,
    {
        let plaintext = [0x77u8; 32];
        let mut rng = rng();
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..16 {
            let mut data = plaintext;
            let (_, init) = key.encrypt_inplace(&mut rng, &mut data).expect("encryption");
            assert!(seen.insert(init.to_vec()), "{name}: init data repeated across encryptions");
            key.decrypt_inplace(&init, &mut data).expect("decryption");
            assert_eq!(data, plaintext, "{name}: round trip");
        }
    }

    check::<16, _>("SM4_CFB", &key::<CFB>());
    check::<16, _>("SM4_CFB8", &key::<CFB8>());
    check::<12, _>("SM4_CTR", &key::<CTR>());
}

/// CFB128 and CFB8 are different, non-interoperable modes. Under the same key and IV their first
/// bytes agree -- both are `P_1 xor MSB_8(O_1)` of the same first output block -- and everything
/// after that diverges, because CFB8 re-enciphers after every byte while CFB128 waits for a block.
#[test]
fn cfb128_and_cfb8_are_not_interchangeable() {
    let iv = [0x0Au8; BLOCK_LEN];
    let plaintext = filler(32, 12_345);

    let cfb_key = key::<CFB>();
    let mut as_cfb = plaintext.clone();
    let (mut enc, got) =
        cfb_key.create_encryptor(&mut FixedSeedRNG::<BLOCK_LEN>::new(iv)).expect("CFB128 init");
    assert_eq!(got, iv, "the pinned RNG should produce the chosen IV");
    enc.do_encrypt_inplace(&mut as_cfb).expect("CFB128");

    let cfb8_key = key::<CFB8>();
    let mut as_cfb8 = plaintext.clone();
    let (mut enc8, got8) =
        cfb8_key.create_encryptor(&mut FixedSeedRNG::<BLOCK_LEN>::new(iv)).expect("CFB8 init");
    assert_eq!(got8, iv);
    enc8.do_encrypt_inplace(&mut as_cfb8).expect("CFB8");

    assert_eq!(as_cfb[0], as_cfb8[0], "both take MSB_8 of the same first output block");
    assert_ne!(as_cfb[1..], as_cfb8[1..], "and diverge from the second byte on");
}

/// CTR is not CFB either, and its init data is shorter: 12 bytes against 16.
#[test]
fn ctr_is_not_cfb() {
    let plaintext = filler(32, 999);

    let mut as_ctr = plaintext.clone();
    let (_, nonce) = key::<CTR>().encrypt_inplace(&mut rng(), &mut as_ctr).expect("CTR");
    assert_eq!(nonce.len(), CTR_NONCE_LEN);

    let cfb_key = key::<CFB>();
    let mut as_cfb = plaintext.clone();
    let (_, iv) = cfb_key.encrypt_inplace(&mut rng(), &mut as_cfb).expect("CFB128");
    assert_eq!(iv.len(), BLOCK_LEN);

    // A CFB decryptor handed a CTR ciphertext cannot recover the plaintext.
    let mut misread = as_ctr.clone();
    let mut iv_from_nonce = [0u8; BLOCK_LEN];
    iv_from_nonce[..CTR_NONCE_LEN].copy_from_slice(&nonce);
    cfb_key.decrypt_inplace(&iv_from_nonce, &mut misread).expect("decryption runs");
    assert_ne!(misread, plaintext, "CFB must not decrypt a CTR ciphertext");
}
