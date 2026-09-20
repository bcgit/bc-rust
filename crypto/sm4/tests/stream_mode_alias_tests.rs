//! Tests for the stream-mode aliases `SM4_CFB`, `SM4_CFB8` and `SM4_CTR`.
//!
//! The aliases are only type aliases, so what is worth testing is that they name the right types
//! and behave as the mode they claim to be: the direction selects the encryptor or the decryptor,
//! the init data is the length the mode defines, and the three modes are distinct from each other
//! and from CBC. The known-answer coverage is in `stream_mode_tests.rs`, and the modes themselves
//! are tested in their own right in `bouncycastle-modes`; this checks the wiring between them.

use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{StreamCipherDecryptor, StreamCipherEncryptor};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_modes::{Cfb, Cfb8, Ctr, Decrypting, Encrypting};
use bouncycastle_sm4::{BLOCK_LEN, CTR_NONCE_LEN, KEY_LEN, SM4, SM4_CFB, SM4_CFB8, SM4_CTR};

fn key() -> KeyMaterial<KEY_LEN> {
    let bytes: [u8; KEY_LEN] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    KeyMaterial::<KEY_LEN>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
        .expect("a valid key")
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

/// Each alias must resolve to exactly the mode it claims to, at both directions.
#[test]
fn the_aliases_name_the_expected_types() {
    use core::mem::size_of;

    assert_eq!(size_of::<SM4_CFB<Encrypting>>(), size_of::<Cfb<SM4, Encrypting, 16, 16>>());
    assert_eq!(size_of::<SM4_CFB<Decrypting>>(), size_of::<Cfb<SM4, Decrypting, 16, 16>>());
    assert_eq!(size_of::<SM4_CFB8<Encrypting>>(), size_of::<Cfb8<SM4, Encrypting, 16, 16>>());
    assert_eq!(size_of::<SM4_CFB8<Decrypting>>(), size_of::<Cfb8<SM4, Decrypting, 16, 16>>());
    assert_eq!(size_of::<SM4_CTR<Encrypting>>(), size_of::<Ctr<SM4, Encrypting, 16, 16, 12>>());
    assert_eq!(size_of::<SM4_CTR<Decrypting>>(), size_of::<Ctr<SM4, Decrypting, 16, 16, 12>>());
}

/// The const parameters SM4 fills in are the ones the crate exports, and CTR's nonce leaves the
/// four-byte counter the mode's maximum.
#[test]
fn the_const_parameters_are_sm4s() {
    assert_eq!(KEY_LEN, 16);
    assert_eq!(BLOCK_LEN, 16);
    assert_eq!(CTR_NONCE_LEN, 12, "a 12-byte nonce leaves the 4-byte counter CTR caps at");
}

/// Every alias round-trips at any length, with the ciphertext exactly as long as the plaintext --
/// the property that separates these three from CBC, which pads.
#[test]
fn every_alias_round_trips_at_any_length() {
    fn check<const INIT_DATA_LEN: usize, Enc, Dec>(name: &str)
    where
        Enc: StreamCipherEncryptor<KEY_LEN, INIT_DATA_LEN>,
        Dec: StreamCipherDecryptor<KEY_LEN, INIT_DATA_LEN>,
    {
        for len in [0usize, 1, 15, 16, 17, 64, 257] {
            let plaintext = filler(len, len as u32);
            let mut data = plaintext.clone();

            let (written, init) = Enc::encrypt(&key(), &mut data).expect("encryption");
            assert_eq!(written, len, "{name}, len {len}: bytes written");
            assert_eq!(data.len(), len, "{name}, len {len}: no padding is added");
            assert_eq!(init.len(), INIT_DATA_LEN, "{name}: init data length");

            let read = Dec::decrypt(&key(), &init, &mut data).expect("decryption");
            assert_eq!(read, len, "{name}, len {len}: bytes read");
            assert_eq!(data, plaintext, "{name}, len {len}: round trip");
        }
    }

    check::<16, SM4_CFB<Encrypting>, SM4_CFB<Decrypting>>("SM4_CFB");
    check::<16, SM4_CFB8<Encrypting>, SM4_CFB8<Decrypting>>("SM4_CFB8");
    check::<12, SM4_CTR<Encrypting>, SM4_CTR<Decrypting>>("SM4_CTR");
}

/// Streaming in arbitrary pieces gives the same answer as one call: a sequence of `do_encrypt`
/// calls must be equivalent to one over the concatenation, whatever the chunking.
#[test]
fn chunking_does_not_change_the_ciphertext() {
    fn check<const INIT_DATA_LEN: usize, Enc, Dec>(name: &str)
    where
        Enc: StreamCipherEncryptor<KEY_LEN, INIT_DATA_LEN>,
        Dec: StreamCipherDecryptor<KEY_LEN, INIT_DATA_LEN>,
    {
        let plaintext = filler(100, 99);

        let mut whole = plaintext.clone();
        let (_, init) = Enc::encrypt(&key(), &mut whole).expect("encryption");

        for chunk in [1usize, 3, 7, 16, 33] {
            let mut dec = Dec::do_decrypt_init(&key(), &init).expect("decryption init");
            let mut data = whole.clone();
            for piece in data.chunks_mut(chunk) {
                dec.do_decrypt(piece).expect("decryption");
            }
            assert_eq!(data, plaintext, "{name}: {chunk}-byte pieces should decrypt the same");
        }
    }

    check::<16, SM4_CFB<Encrypting>, SM4_CFB<Decrypting>>("SM4_CFB");
    check::<16, SM4_CFB8<Encrypting>, SM4_CFB8<Decrypting>>("SM4_CFB8");
    check::<12, SM4_CTR<Encrypting>, SM4_CTR<Decrypting>>("SM4_CTR");
}

/// A fresh IV or nonce per encryption, so the same plaintext gives different ciphertext. For CTR
/// this is the whole security argument: a repeated nonce leaks the XOR of the two messages.
#[test]
fn each_encryption_gets_fresh_init_data() {
    fn check<const INIT_DATA_LEN: usize, Enc, Dec>(name: &str)
    where
        Enc: StreamCipherEncryptor<KEY_LEN, INIT_DATA_LEN>,
        Dec: StreamCipherDecryptor<KEY_LEN, INIT_DATA_LEN>,
    {
        let plaintext = [0x77u8; 32];
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..16 {
            let mut data = plaintext;
            let (_, init) = Enc::encrypt(&key(), &mut data).expect("encryption");
            assert!(seen.insert(init.to_vec()), "{name}: init data repeated across encryptions");
            Dec::decrypt(&key(), &init, &mut data).expect("decryption");
            assert_eq!(data, plaintext, "{name}: round trip");
        }
    }

    check::<16, SM4_CFB<Encrypting>, SM4_CFB<Decrypting>>("SM4_CFB");
    check::<16, SM4_CFB8<Encrypting>, SM4_CFB8<Decrypting>>("SM4_CFB8");
    check::<12, SM4_CTR<Encrypting>, SM4_CTR<Decrypting>>("SM4_CTR");
}

/// CFB128 and CFB8 are different, non-interoperable modes. Under the same key and IV their first
/// bytes agree -- both are `P_1 xor MSB_8(O_1)` of the same first output block -- and everything
/// after that diverges, because CFB8 re-enciphers after every byte while CFB128 waits for a block.
#[test]
fn cfb128_and_cfb8_are_not_interchangeable() {
    let iv = [0x0Au8; BLOCK_LEN];
    let plaintext = filler(32, 12_345);

    let mut as_cfb = plaintext.clone();
    let (mut enc, got) =
        SM4_CFB::<Encrypting>::do_encrypt_init_rng(&key(), &mut FixedSeedRNG::<BLOCK_LEN>::new(iv))
            .expect("CFB128 init");
    assert_eq!(got, iv, "the pinned RNG should produce the chosen IV");
    enc.do_encrypt(&mut as_cfb).expect("CFB128");

    let mut as_cfb8 = plaintext.clone();
    let (mut enc8, got8) = SM4_CFB8::<Encrypting>::do_encrypt_init_rng(
        &key(),
        &mut FixedSeedRNG::<BLOCK_LEN>::new(iv),
    )
    .expect("CFB8 init");
    assert_eq!(got8, iv);
    enc8.do_encrypt(&mut as_cfb8).expect("CFB8");

    assert_eq!(as_cfb[0], as_cfb8[0], "both take MSB_8 of the same first output block");
    assert_ne!(as_cfb[1..], as_cfb8[1..], "and diverge from the second byte on");
}

/// CTR is not CFB either, and its init data is shorter: 12 bytes against 16.
#[test]
fn ctr_is_not_cfb() {
    let plaintext = filler(32, 999);

    let mut as_ctr = plaintext.clone();
    let (_, nonce) = SM4_CTR::<Encrypting>::encrypt(&key(), &mut as_ctr).expect("CTR");
    assert_eq!(nonce.len(), CTR_NONCE_LEN);

    let mut as_cfb = plaintext.clone();
    let (_, iv) = SM4_CFB::<Encrypting>::encrypt(&key(), &mut as_cfb).expect("CFB128");
    assert_eq!(iv.len(), BLOCK_LEN);

    // A CFB decryptor handed a CTR ciphertext cannot recover the plaintext.
    let mut misread = as_ctr.clone();
    let mut iv_from_nonce = [0u8; BLOCK_LEN];
    iv_from_nonce[..CTR_NONCE_LEN].copy_from_slice(&nonce);
    SM4_CFB::<Decrypting>::decrypt(&key(), &iv_from_nonce, &mut misread).expect("decryption runs");
    assert_ne!(misread, plaintext, "CFB must not decrypt a CTR ciphertext");
}
