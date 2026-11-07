//! CFB, CFB8 and CTR through the key: the direction selects the encryptor or the decryptor, the
//! init data is the length the mode defines, and the three modes are distinct from each other.
//! The modes are tested in their own right in `bouncycastle_cipher::modes`; this is the wiring.

use crate::Permutation;
use crate::material::{filler, material, rng};
use bouncycastle_cipher::BlockCipherKey;
use bouncycastle_cipher::modes::{CFB, CFB8, CTR};
use bouncycastle_core::hazmat::Mode;
use bouncycastle_core::symmetric_key::{
    FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle_core::traits::{StreamCipherDecryptor, StreamCipherEncryptor};
use bouncycastle_rng::FixedSeedRNG;

const BLOCK_LEN: usize = 16;
const CTR_NONCE_LEN: usize = 12;

fn key<P: Permutation<KEY_LEN>, M: Mode<P>, const KEY_LEN: usize>() -> BlockCipherKey<P, M> {
    BlockCipherKey::from_key_material(&material::<KEY_LEN>()).expect("a valid key")
}

fn round_trips_one<'k, const KEY_LEN: usize, const INIT_DATA_LEN: usize, K>(name: &str, key: &'k K)
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

/// Every stream-mode key round-trips at any length, with the ciphertext exactly as long as the
/// plaintext -- the property that separates these from the CBC keys, which pad. `name` labels a
/// failure.
pub fn round_trips_at_any_length<P: Permutation<KEY_LEN>, const KEY_LEN: usize>(name: &str) {
    round_trips_one::<KEY_LEN, BLOCK_LEN, _>(&format!("{name} CFB"), &key::<P, CFB, KEY_LEN>());
    round_trips_one::<KEY_LEN, BLOCK_LEN, _>(&format!("{name} CFB8"), &key::<P, CFB8, KEY_LEN>());
    round_trips_one::<KEY_LEN, CTR_NONCE_LEN, _>(&format!("{name} CTR"), &key::<P, CTR, KEY_LEN>());
}

fn chunking_one<'k, const KEY_LEN: usize, const INIT_DATA_LEN: usize, K>(name: &str, key: &'k K)
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

/// Streaming in arbitrary pieces gives the same answer as one call, whatever the chunking.
pub fn chunking_does_not_change_the_ciphertext<P: Permutation<KEY_LEN>, const KEY_LEN: usize>(
    name: &str,
) {
    chunking_one::<KEY_LEN, BLOCK_LEN, _>(&format!("{name} CFB"), &key::<P, CFB, KEY_LEN>());
    chunking_one::<KEY_LEN, BLOCK_LEN, _>(&format!("{name} CFB8"), &key::<P, CFB8, KEY_LEN>());
    chunking_one::<KEY_LEN, CTR_NONCE_LEN, _>(&format!("{name} CTR"), &key::<P, CTR, KEY_LEN>());
}

fn fresh_one<'k, const KEY_LEN: usize, const INIT_DATA_LEN: usize, K>(name: &str, key: &'k K)
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

/// A fresh IV or nonce per encryption, so the same plaintext gives different ciphertext. For CTR
/// this is the whole security argument: a repeated nonce leaks the XOR of the two messages.
pub fn each_encryption_gets_fresh_init_data<P: Permutation<KEY_LEN>, const KEY_LEN: usize>(
    name: &str,
) {
    fresh_one::<KEY_LEN, BLOCK_LEN, _>(&format!("{name} CFB"), &key::<P, CFB, KEY_LEN>());
    fresh_one::<KEY_LEN, BLOCK_LEN, _>(&format!("{name} CFB8"), &key::<P, CFB8, KEY_LEN>());
    fresh_one::<KEY_LEN, CTR_NONCE_LEN, _>(&format!("{name} CTR"), &key::<P, CTR, KEY_LEN>());
}

/// CFB128 and CFB8 are different, non-interoperable modes. Under the same key and IV their first
/// bytes agree -- both are `P_1 XOR MSB_8(O_1)` of the same first output block -- and everything
/// after that diverges, because CFB8 re-enciphers after every byte while CFB128 waits for a block.
pub fn cfb128_and_cfb8_are_not_interchangeable<P: Permutation<KEY_LEN>, const KEY_LEN: usize>() {
    let iv = [0x0Au8; BLOCK_LEN];
    let plaintext = filler(32, 12_345);

    let cfb_key = key::<P, CFB, KEY_LEN>();
    let mut as_cfb = plaintext.clone();
    let (mut enc, got) = cfb_key.create_encryptor(&mut FixedSeedRNG::new(iv)).expect("CFB128 init");
    assert_eq!(got, iv, "the pinned RNG should produce the chosen IV");
    enc.do_encrypt_inplace(&mut as_cfb).expect("CFB128");

    let cfb8_key = key::<P, CFB8, KEY_LEN>();
    let mut as_cfb8 = plaintext.clone();
    let (mut enc8, got8) =
        cfb8_key.create_encryptor(&mut FixedSeedRNG::new(iv)).expect("CFB8 init");
    assert_eq!(got8, iv);
    enc8.do_encrypt_inplace(&mut as_cfb8).expect("CFB8");

    assert_eq!(as_cfb[0], as_cfb8[0], "both take MSB_8 of the same first output block");
    assert_ne!(as_cfb[1..], as_cfb8[1..], "and diverge from the second byte on");
}

/// CTR is not CFB either, and its init data is shorter: 12 bytes against 16.
pub fn ctr_is_not_cfb<P: Permutation<KEY_LEN>, const KEY_LEN: usize>() {
    let plaintext = filler(32, 999);

    let mut as_ctr = plaintext.clone();
    let (_, nonce) = key::<P, CTR, KEY_LEN>().encrypt_inplace(&mut rng(), &mut as_ctr).unwrap();
    assert_eq!(nonce.len(), CTR_NONCE_LEN);

    let cfb_key = key::<P, CFB, KEY_LEN>();
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
