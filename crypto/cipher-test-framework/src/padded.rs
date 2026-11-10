//! Padded CBC through the key: the aliases are only type aliases, so what is worth checking is
//! that both parameters select -- the direction picks the encryptor or the decryptor, and the
//! padding scheme changes the behaviour. The mode and the padding layer are tested in
//! `bouncycastle-cipher`; this is the wiring between them and the key.

use crate::Permutation;
use crate::material::{material, rng};
use bouncycastle_cipher::BlockCipherKey;
use bouncycastle_cipher::modes::CBC;
use bouncycastle_cipher::padding::{NoPadding, PKCS7};
use bouncycastle_core::symmetric_key::{
    FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey,
};

const BLOCK_LEN: usize = 16;

fn pkcs7<P: Permutation<KEY_LEN>, const KEY_LEN: usize>() -> BlockCipherKey<P, CBC<PKCS7>> {
    BlockCipherKey::from_key_material(&material::<KEY_LEN>()).unwrap()
}

fn nopad<P: Permutation<KEY_LEN>, const KEY_LEN: usize>() -> BlockCipherKey<P, CBC<NoPadding>> {
    BlockCipherKey::from_key_material(&material::<KEY_LEN>()).unwrap()
}

/// Round trips at lengths that need padding and lengths that do not; `name` labels a failure.
pub fn round_trips<P: Permutation<KEY_LEN>, const KEY_LEN: usize>(name: &str) {
    let key = pkcs7::<P, KEY_LEN>();
    for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 127, 128] {
        let plaintext: Vec<u8> = (0..len).map(|i| (i * 11 + 3) as u8).collect();
        let (iv, ciphertext) = key.encrypt(&mut rng(), &plaintext).expect("encryption");
        assert_eq!(iv.len(), BLOCK_LEN);
        assert_eq!(
            ciphertext.len(),
            (len / BLOCK_LEN + 1) * BLOCK_LEN,
            "{name}, len {len}: PKCS7 pads up to the next whole block"
        );
        let recovered = key.decrypt(&iv, &ciphertext).expect("decryption");
        assert_eq!(recovered, plaintext, "{name}, len {len}: round trip");
    }
}

/// The padding parameter selects the scheme, and a ciphertext made under one scheme does not
/// decrypt cleanly under the other.
pub fn padding_selects_the_scheme<P: Permutation<KEY_LEN>, const KEY_LEN: usize>() {
    let pkcs7_key = pkcs7::<P, KEY_LEN>();
    let nopad_key = nopad::<P, KEY_LEN>();

    // A whole block: both schemes accept it, and they disagree about the length.
    let aligned = [0x5Au8; BLOCK_LEN];
    let (iv, pkcs7) = pkcs7_key.encrypt(&mut rng(), &aligned).expect("PKCS7 accepts it");
    let (_, nopad) = nopad_key.encrypt(&mut rng(), &aligned).expect("NoPadding accepts it");
    assert_eq!(pkcs7.len(), 32, "PKCS7 adds a whole block of padding to aligned data");
    assert_eq!(nopad.len(), 16, "NoPadding adds nothing");

    // Five bytes: PKCS7 pads it, NoPadding refuses rather than silently padding.
    assert!(pkcs7_key.encrypt(&mut rng(), b"hello").is_ok(), "PKCS7 pads a partial block");
    assert!(nopad_key.encrypt(&mut rng(), b"hello").is_err(), "NoPadding must refuse it");

    // NoPadding hands back the padding block as if it were data: the silent mismatch the type
    // parameter is there to prevent.
    let as_nopad = nopad_key.decrypt(&iv, &pkcs7).expect("NoPadding cannot tell");
    assert_ne!(as_nopad, aligned);
    assert_eq!(as_nopad.len(), 32, "it keeps the padding block as data");
    assert_eq!(pkcs7_key.decrypt(&iv, &pkcs7).expect("decryption"), aligned);
}

/// The IV is drawn per encryption, so the same plaintext gives different ciphertext.
pub fn fresh_iv<P: Permutation<KEY_LEN>, const KEY_LEN: usize>() {
    let key = pkcs7::<P, KEY_LEN>();
    let mut rng = rng();
    let plaintext = [0x77u8; 32];
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..16 {
        let (iv, ct) = key.encrypt(&mut rng, &plaintext).unwrap();
        assert!(seen.insert(iv), "IV repeated across encryptions");
        assert_eq!(key.decrypt(&iv, &ct).unwrap(), plaintext);
    }
}
