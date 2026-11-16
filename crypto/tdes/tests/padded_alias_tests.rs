//! The padded CBC and ECB modes through a three-key TDEA key.
//!
//! The aliases are only type aliases, so what is worth testing is that both parameters actually
//! select: the direction picks the encryptor or the decryptor, and the padding scheme changes the
//! behaviour rather than being decorative. The mode and the padding layer are tested in
//! `bouncycastle-cipher`; this checks the wiring between them and the 8-byte block, through the
//! key that hands the aliases out. Which type each alias resolves to is pinned in
//! `alg_name_tests.rs`.

use bouncycastle_cipher::modes::CBC;
use bouncycastle_cipher::modes::hazmat::ecb::ECB;
use bouncycastle_cipher::padding::{NoPadding, PKCS7};
use bouncycastle_core::hazmat::Mode;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{
    FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle_rng::HashDRBG_SHA512;
use bouncycastle_tdes::hazmat::TDESInternal;
use bouncycastle_tdes::{BLOCK_LEN, KEY_LEN, TDES3Key};

fn material() -> KeyMaterial<KEY_LEN> {
    // Three distinct component keys, none of them weak.
    let bytes: [u8; KEY_LEN] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    KeyMaterial::<KEY_LEN>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
        .expect("a valid key")
}

fn key_for<M: Mode<TDESInternal>>() -> TDES3Key<M> {
    TDES3Key::from_key_material(&material()).expect("a valid key bundle")
}

fn rng() -> HashDRBG_SHA512 {
    HashDRBG_SHA512::new_from_os()
}

#[test]
fn round_trips_at_every_alignment() {
    fn check<const IV_LEN: usize, M>(name: &str)
    where
        M: Mode<TDESInternal>,
        TDES3Key<M>: SymmetricEncryptionKey<KEY_LEN, IV_LEN, BLOCK_LEN>
            + SymmetricDecryptionKey<KEY_LEN, IV_LEN, BLOCK_LEN>,
    {
        let key = key_for::<M>();
        for len in [0usize, 1, 7, 8, 9, 15, 16, 17, 63, 64] {
            let plaintext: Vec<u8> = (0..len).map(|i| (i * 11 + 3) as u8).collect();
            let (iv, ciphertext) = key.encrypt(&mut rng(), &plaintext).expect("encryption");
            assert_eq!(iv.len(), IV_LEN);

            // PKCS#7 always adds at least one byte, and rounds up to a whole 8-byte block.
            assert_eq!(
                ciphertext.len(),
                (len / BLOCK_LEN + 1) * BLOCK_LEN,
                "{name}, len {len}: PKCS7 pads up to the next whole block"
            );

            let recovered = key.decrypt(&iv, &ciphertext).expect("decryption");
            assert_eq!(recovered, plaintext, "{name}, len {len}: round trip");
        }
    }

    check::<BLOCK_LEN, CBC<PKCS7>>("CBC");
    check::<0, ECB<PKCS7>>("ECB");
}

#[test]
fn the_padding_parameter_selects_the_scheme() {
    fn check<const IV_LEN: usize, Pkcs7Mode, NoPadMode>(name: &str)
    where
        Pkcs7Mode: Mode<TDESInternal>,
        NoPadMode: Mode<TDESInternal>,
        TDES3Key<Pkcs7Mode>: SymmetricEncryptionKey<KEY_LEN, IV_LEN, BLOCK_LEN>,
        TDES3Key<NoPadMode>: SymmetricEncryptionKey<KEY_LEN, IV_LEN, BLOCK_LEN>,
    {
        let pkcs7_key = key_for::<Pkcs7Mode>();
        let nopad_key = key_for::<NoPadMode>();

        // A whole block: both schemes accept it, and they disagree about the length.
        let aligned = [0x5Au8; BLOCK_LEN];
        let (_, pkcs7) = pkcs7_key.encrypt(&mut rng(), &aligned).expect("PKCS7 accepts it");
        let (_, nopad) = nopad_key.encrypt(&mut rng(), &aligned).expect("NoPadding accepts it");
        assert_eq!(pkcs7.len(), 16, "{name}: PKCS7 adds a whole block of padding to aligned data");
        assert_eq!(nopad.len(), 8, "{name}: NoPadding adds nothing");

        // Five bytes: PKCS7 pads it, NoPadding refuses rather than silently padding.
        let unaligned = b"hello";
        assert!(pkcs7_key.encrypt(&mut rng(), unaligned).is_ok(), "{name}: PKCS7 pads it");
        assert!(
            nopad_key.encrypt(&mut rng(), unaligned).is_err(),
            "{name}: NoPadding must refuse a message that is not a whole number of blocks"
        );
    }

    check::<BLOCK_LEN, CBC<PKCS7>, CBC<NoPadding>>("CBC");
    check::<0, ECB<PKCS7>, ECB<NoPadding>>("ECB");
}

#[test]
fn the_two_schemes_are_not_interchangeable() {
    let aligned = [0x5Au8; BLOCK_LEN];
    let (iv, pkcs7) = key_for::<CBC<PKCS7>>().encrypt(&mut rng(), &aligned).expect("encryption");

    // NoPadding will hand back the padded block as if it were data, so it "succeeds" with the
    // wrong answer -- exactly the silent mismatch the type parameter is there to prevent.
    let as_nopad = key_for::<CBC<NoPadding>>()
        .decrypt(&iv, &pkcs7)
        .expect("NoPadding cannot tell that the trailing block is padding");
    assert_ne!(as_nopad, aligned, "the recovered data must not match the original");
    assert_eq!(as_nopad.len(), 16, "it keeps the padding block as data");

    // ...and the matching scheme gets it right.
    let correct = key_for::<CBC<PKCS7>>().decrypt(&iv, &pkcs7).expect("decryption");
    assert_eq!(correct, aligned);
}

#[test]
fn each_cbc_encryption_gets_a_fresh_iv() {
    let key = key_for::<CBC<PKCS7>>();
    let mut rng = rng();
    let plaintext = [0x77u8; 16];
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..16 {
        let (iv, ct) = key.encrypt(&mut rng, &plaintext).unwrap();
        assert!(seen.insert(iv), "IV repeated across encryptions");
        let back = key.decrypt(&iv, &ct).unwrap();
        assert_eq!(back, plaintext);
    }
}

#[test]
fn ecb_has_no_iv() {
    let key = key_for::<ECB<PKCS7>>();
    let (no_iv, ciphertext) = key.encrypt(&mut rng(), b"hello").expect("encryption");
    assert_eq!(no_iv, [0u8; 0], "ECB has no IV, so the init data is empty");
    assert_eq!(ciphertext.len(), 8, "five bytes padded to one block, nothing prepended");

    let recovered = key.decrypt(&no_iv, &ciphertext).unwrap();
    assert_eq!(recovered, b"hello");
}

#[test]
fn padding_does_not_hide_the_ecb_codebook_property() {
    // Two identical blocks give two identical ciphertext blocks.
    let (_, ciphertext) = key_for::<ECB<NoPadding>>().encrypt(&mut rng(), &[0x5Au8; 16]).unwrap();
    assert_eq!(ciphertext[..8], ciphertext[8..], "ECB is a codebook, padded or not");

    // ...and encryption is deterministic, there being no IV to vary.
    let key = key_for::<ECB<PKCS7>>();
    let (_, a) = key.encrypt(&mut rng(), b"hello").unwrap();
    let (_, b) = key.encrypt(&mut rng(), b"hello").unwrap();
    assert_eq!(a, b, "the same message encrypts the same way every time");
}
