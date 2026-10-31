//! Tests for the stream-mode keys `Camellia_CFB_*`, `Camellia_CFB8_*` and `Camellia_CTR_*`.
//!
//! The aliases are only type aliases, so what is worth testing is that they name the right types
//! and behave as the mode they claim to be: the direction selects the encryptor or the decryptor,
//! the init data is the length the mode defines, and the three modes are distinct from each other.
//! The known-answer coverage is in `stream_mode_tests.rs`, and the modes themselves are tested in
//! their own right in `bouncycastle_cipher::modes`; this checks the wiring between them.

use bouncycastle_camellia::hazmat::{
    Camellia128Internal, Camellia192Internal, Camellia256Internal,
};
use bouncycastle_camellia::{
    BLOCK_LEN, CTR_NONCE_LEN, Camellia128Key, Camellia192Key, Camellia256Key,
};
use bouncycastle_cipher::modes::{CFB, CFB8, CTR};
use bouncycastle_core::hazmat::Mode;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{
    FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle_core::traits::{StreamCipherDecryptor, StreamCipherEncryptor};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_rng::HashDRBG_SHA512;

fn material<const N: usize>() -> KeyMaterial<N> {
    let bytes: [u8; N] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).expect("a valid key")
}

fn key128<M: Mode<Camellia128Internal>>() -> Camellia128Key<M> {
    Camellia128Key::from_key_material(&material::<16>()).expect("a valid key")
}
fn key192<M: Mode<Camellia192Internal>>() -> Camellia192Key<M> {
    Camellia192Key::from_key_material(&material::<24>()).expect("a valid key")
}
fn key256<M: Mode<Camellia256Internal>>() -> Camellia256Key<M> {
    Camellia256Key::from_key_material(&material::<32>()).expect("a valid key")
}

fn rng() -> HashDRBG_SHA512 {
    HashDRBG_SHA512::new_from_os()
}

/// Deterministic pseudo-random bytes, so the tests do not depend on an RNG.
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
/// plaintext -- the property that separates these nine from the CBC keys, which pad.
#[test]
fn every_stream_key_round_trips_at_any_length() {
    fn check<'k, const KEY_LEN: usize, const INIT_DATA_LEN: usize, K>(name: &str, key: &'k K)
    where
        K: SymmetricEncryptionKey<KEY_LEN, INIT_DATA_LEN, 0>
            + SymmetricDecryptionKey<KEY_LEN, INIT_DATA_LEN, 0>,
        K::Encryptor<'k>: StreamCipherEncryptor<INIT_DATA_LEN>,
        K::Decryptor<'k>: StreamCipherDecryptor<INIT_DATA_LEN>,
    {
        for len in [0usize, 1, 15, 16, 17, 64, 257] {
            let plaintext = filler(len, len as u32);
            let mut data = plaintext.clone();

            let (_, init) = key.encrypt_inplace(&mut rng(), &mut data).expect("encryption");
            assert_eq!(data.len(), len, "{name}, len {len}: no padding is added");
            assert_eq!(init.len(), INIT_DATA_LEN, "{name}: init data length");

            key.decrypt_inplace(&init, &mut data).expect("decryption");
            assert_eq!(data, plaintext, "{name}, len {len}: round trip");
        }
    }

    check::<16, 16, _>("Camellia_CFB_128", &key128::<CFB>());
    check::<24, 16, _>("Camellia_CFB_192", &key192::<CFB>());
    check::<32, 16, _>("Camellia_CFB_256", &key256::<CFB>());
    check::<16, 16, _>("Camellia_CFB8_128", &key128::<CFB8>());
    check::<24, 16, _>("Camellia_CFB8_192", &key192::<CFB8>());
    check::<32, 16, _>("Camellia_CFB8_256", &key256::<CFB8>());
    check::<16, 12, _>("Camellia_CTR_128", &key128::<CTR>());
    check::<24, 12, _>("Camellia_CTR_192", &key192::<CTR>());
    check::<32, 12, _>("Camellia_CTR_256", &key256::<CTR>());
}

/// Streaming in arbitrary pieces gives the same answer as one call: a sequence of calls must be
/// equivalent to one over the concatenation, whatever the chunking.
#[test]
fn chunking_does_not_change_the_ciphertext() {
    fn check<'k, const KEY_LEN: usize, const INIT_DATA_LEN: usize, K>(name: &str, key: &'k K)
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

    check::<16, 16, _>("Camellia_CFB_128", &key128::<CFB>());
    check::<24, 16, _>("Camellia_CFB8_192", &key192::<CFB8>());
    check::<32, 12, _>("Camellia_CTR_256", &key256::<CTR>());
}

/// A fresh IV or nonce per encryption, so the same plaintext gives different ciphertext. For CTR
/// this is the whole security argument: a repeated nonce leaks the XOR of the two messages.
#[test]
fn each_encryption_gets_fresh_init_data() {
    fn check<'k, const INIT_DATA_LEN: usize, K>(name: &str, key: &'k K)
    where
        K: SymmetricEncryptionKey<16, INIT_DATA_LEN, 0>
            + SymmetricDecryptionKey<16, INIT_DATA_LEN, 0>,
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

    check::<16, _>("Camellia_CFB_128", &key128::<CFB>());
    check::<16, _>("Camellia_CFB8_128", &key128::<CFB8>());
    check::<12, _>("Camellia_CTR_128", &key128::<CTR>());
}

/// CFB128 and CFB8 are different, non-interoperable modes. Under the same key and IV their first
/// bytes agree -- both are `P_1 XOR MSB_8(O_1)` of the same first output block -- and everything
/// after that diverges, because CFB8 re-enciphers after every byte while CFB128 waits for a block.
#[test]
fn cfb128_and_cfb8_are_not_interchangeable() {
    let iv = [0x0Au8; BLOCK_LEN];
    let plaintext = filler(32, 12_345);

    let cfb_key = key128::<CFB>();
    let mut as_cfb = plaintext.clone();
    let (mut enc, got) =
        cfb_key.create_encryptor(&mut FixedSeedRNG::<BLOCK_LEN>::new(iv)).expect("CFB128 init");
    assert_eq!(got, iv, "the pinned RNG should produce the chosen IV");
    enc.do_encrypt_inplace(&mut as_cfb).expect("CFB128");

    let cfb8_key = key128::<CFB8>();
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
    let (_, nonce) = key128::<CTR>().encrypt_inplace(&mut rng(), &mut as_ctr).unwrap();
    assert_eq!(nonce.len(), CTR_NONCE_LEN);

    let cfb_key = key128::<CFB>();
    let mut as_cfb = plaintext.clone();
    let (_, iv) = cfb_key.encrypt_inplace(&mut rng(), &mut as_cfb).unwrap();
    assert_eq!(iv.len(), BLOCK_LEN);

    // A CFB decryptor handed a CTR ciphertext cannot recover the plaintext.
    let mut misread = as_ctr.clone();
    let mut iv_from_nonce = [0u8; BLOCK_LEN];
    iv_from_nonce[..CTR_NONCE_LEN].copy_from_slice(&nonce);
    cfb_key.decrypt_inplace(&iv_from_nonce, &mut misread).expect("decryption runs");
    assert_ne!(misread, plaintext, "CFB must not decrypt a CTR ciphertext");
}
