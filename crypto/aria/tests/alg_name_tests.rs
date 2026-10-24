//! What each public ARIA alias is: the algorithm it reports and the type it resolves to.
//!
//! Each alias reports its own algorithm through `Algorithm`, not the engine it is built on:
//! `ARIA_CBC_128` is `"ARIA_CBC_128"`, while `ARIA128Internal` stays `"ARIA-128"`. The strength
//! is the key's. The direction and the padding are type parameters of one algorithm, not
//! different algorithms, so every combination of them must report the same name.

use bouncycastle_aria::hazmat::{ARIA128Internal, ARIA192Internal, ARIA256Internal};
use bouncycastle_aria::{
    ARIA_CBC_128, ARIA_CBC_192, ARIA_CBC_256, ARIA_CFB_128, ARIA_CFB_192, ARIA_CFB_256,
    ARIA_CFB8_128, ARIA_CFB8_192, ARIA_CFB8_256, ARIA_CTR_128, ARIA_CTR_192, ARIA_CTR_256,
    ARIA128Key, BLOCK_LEN, CTR_NONCE_LEN,
};
use bouncycastle_cipher::modes::{CBC, CFB, CFB8, CTR, Cbc, Cfb, Cfb8, Ctr};
use bouncycastle_cipher::padding::{
    NoPadding, PKCS7, PaddedBlockCipherDecryptor, PaddedBlockCipherEncryptor,
};
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{
    FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle_core::traits::Algorithm;
use bouncycastle_rng::HashDRBG_SHA512;
use core::mem::size_of;

/// Both directions of one algorithm report `name` and `strength`.
fn check<Enc: Algorithm, Dec: Algorithm>(name: &str, strength: SecurityStrength) {
    assert_eq!(Enc::ALG_NAME, name);
    assert_eq!(Dec::ALG_NAME, name);
    assert_eq!(Enc::MAX_SECURITY_STRENGTH, strength, "{name}");
    assert_eq!(Dec::MAX_SECURITY_STRENGTH, strength, "{name}");
}

#[test]
fn cbc() {
    use SecurityStrength::*;
    check::<ARIA_CBC_128<'_, Encrypting, PKCS7>, ARIA_CBC_128<'_, Decrypting, PKCS7>>(
        "ARIA_CBC_128", _128bit,
    );
    check::<ARIA_CBC_128<'_, Encrypting, NoPadding>, ARIA_CBC_128<'_, Decrypting, NoPadding>>(
        "ARIA_CBC_128", _128bit,
    );
    check::<ARIA_CBC_192<'_, Encrypting, PKCS7>, ARIA_CBC_192<'_, Decrypting, PKCS7>>(
        "ARIA_CBC_192", _192bit,
    );
    check::<ARIA_CBC_256<'_, Encrypting, PKCS7>, ARIA_CBC_256<'_, Decrypting, PKCS7>>(
        "ARIA_CBC_256", _256bit,
    );
}

#[test]
fn cfb_cfb8_ctr() {
    use SecurityStrength::*;
    check::<ARIA_CFB_128<'_, Encrypting>, ARIA_CFB_128<'_, Decrypting>>("ARIA_CFB_128", _128bit);
    check::<ARIA_CFB_192<'_, Encrypting>, ARIA_CFB_192<'_, Decrypting>>("ARIA_CFB_192", _192bit);
    check::<ARIA_CFB_256<'_, Encrypting>, ARIA_CFB_256<'_, Decrypting>>("ARIA_CFB_256", _256bit);
    check::<ARIA_CFB8_128<'_, Encrypting>, ARIA_CFB8_128<'_, Decrypting>>("ARIA_CFB8_128", _128bit);
    check::<ARIA_CFB8_192<'_, Encrypting>, ARIA_CFB8_192<'_, Decrypting>>("ARIA_CFB8_192", _192bit);
    check::<ARIA_CFB8_256<'_, Encrypting>, ARIA_CFB8_256<'_, Decrypting>>("ARIA_CFB8_256", _256bit);
    check::<ARIA_CTR_128<'_, Encrypting>, ARIA_CTR_128<'_, Decrypting>>("ARIA_CTR_128", _128bit);
    check::<ARIA_CTR_192<'_, Encrypting>, ARIA_CTR_192<'_, Decrypting>>("ARIA_CTR_192", _192bit);
    check::<ARIA_CTR_256<'_, Encrypting>, ARIA_CTR_256<'_, Decrypting>>("ARIA_CTR_256", _256bit);
}

#[test]
fn the_engines_keep_their_own_names() {
    assert_eq!(ARIA128Internal::ALG_NAME, "ARIA-128");
    assert_eq!(ARIA192Internal::ALG_NAME, "ARIA-192");
    assert_eq!(ARIA256Internal::ALG_NAME, "ARIA-256");
    assert_eq!(ARIA128Internal::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);
    assert_eq!(ARIA192Internal::MAX_SECURITY_STRENGTH, SecurityStrength::_192bit);
    assert_eq!(ARIA256Internal::MAX_SECURITY_STRENGTH, SecurityStrength::_256bit);
}

/// The aliases must resolve to exactly the types they claim to, at both directions, and be what
/// the keys hand out. A type alias that quietly resolved to something else would still compile
/// everywhere it is used, so this pins the projection by asserting the layouts coincide with the
/// fully spelled-out types.
#[test]
fn the_aliases_name_the_expected_types() {
    assert_eq!(
        size_of::<ARIA_CBC_128<'_, Encrypting, PKCS7>>(),
        size_of::<
            PaddedBlockCipherEncryptor<
                Cbc<'_, ARIA128Internal, Encrypting, BLOCK_LEN>,
                PKCS7,
                BLOCK_LEN,
                BLOCK_LEN,
            >,
        >()
    );
    assert_eq!(
        size_of::<ARIA_CBC_192<'_, Decrypting, PKCS7>>(),
        size_of::<
            PaddedBlockCipherDecryptor<
                Cbc<'_, ARIA192Internal, Decrypting, BLOCK_LEN>,
                PKCS7,
                BLOCK_LEN,
                BLOCK_LEN,
            >,
        >()
    );
    assert_eq!(
        size_of::<ARIA_CBC_256<'_, Encrypting, NoPadding>>(),
        size_of::<
            PaddedBlockCipherEncryptor<
                Cbc<'_, ARIA256Internal, Encrypting, BLOCK_LEN>,
                NoPadding,
                BLOCK_LEN,
                BLOCK_LEN,
            >,
        >()
    );
    // The two directions are genuinely different types, so the encryptor and the decryptor do not
    // have to agree in size -- and here they do not, which is itself evidence the projection
    // selected two different adapters rather than one.
    assert_ne!(
        size_of::<ARIA_CBC_128<'_, Encrypting, PKCS7>>(),
        size_of::<ARIA_CBC_128<'_, Decrypting, PKCS7>>()
    );

    assert_eq!(
        size_of::<ARIA_CFB_128<'_, Encrypting>>(),
        size_of::<Cfb<'_, ARIA128Internal, Encrypting, BLOCK_LEN>>()
    );
    assert_eq!(
        size_of::<ARIA_CFB_192<'_, Decrypting>>(),
        size_of::<Cfb<'_, ARIA192Internal, Decrypting, BLOCK_LEN>>()
    );
    assert_eq!(
        size_of::<ARIA_CFB_256<'_, Encrypting>>(),
        size_of::<Cfb<'_, ARIA256Internal, Encrypting, BLOCK_LEN>>()
    );
    assert_eq!(
        size_of::<ARIA_CFB8_128<'_, Encrypting>>(),
        size_of::<Cfb8<'_, ARIA128Internal, Encrypting, BLOCK_LEN>>()
    );
    assert_eq!(
        size_of::<ARIA_CFB8_192<'_, Decrypting>>(),
        size_of::<Cfb8<'_, ARIA192Internal, Decrypting, BLOCK_LEN>>()
    );
    assert_eq!(
        size_of::<ARIA_CFB8_256<'_, Encrypting>>(),
        size_of::<Cfb8<'_, ARIA256Internal, Encrypting, BLOCK_LEN>>()
    );
    assert_eq!(
        size_of::<ARIA_CTR_128<'_, Encrypting>>(),
        size_of::<Ctr<'_, ARIA128Internal, Encrypting, BLOCK_LEN, CTR_NONCE_LEN>>()
    );
    assert_eq!(
        size_of::<ARIA_CTR_192<'_, Decrypting>>(),
        size_of::<Ctr<'_, ARIA192Internal, Decrypting, BLOCK_LEN, CTR_NONCE_LEN>>()
    );
    assert_eq!(
        size_of::<ARIA_CTR_256<'_, Encrypting>>(),
        size_of::<Ctr<'_, ARIA256Internal, Encrypting, BLOCK_LEN, CTR_NONCE_LEN>>()
    );

    // ...and the key hands out exactly those types.
    let bytes: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    let material =
        KeyMaterial::<16>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).unwrap();
    let mut rng = HashDRBG_SHA512::new_from_os();
    let key = ARIA128Key::<CBC<PKCS7>>::from_key_material(&material).unwrap();
    let (enc, iv) = key.create_encryptor(&mut rng).unwrap();
    let _: ARIA_CBC_128<'_, Encrypting, PKCS7> = enc;
    let _: ARIA_CBC_128<'_, Decrypting, PKCS7> = key.create_decryptor(&iv);
    let key = ARIA128Key::<CFB>::from_key_material(&material).unwrap();
    let _: ARIA_CFB_128<'_, Encrypting> = key.create_encryptor(&mut rng).unwrap().0;
    let key = ARIA128Key::<CFB8>::from_key_material(&material).unwrap();
    let _: ARIA_CFB8_128<'_, Encrypting> = key.create_encryptor(&mut rng).unwrap().0;
    let key = ARIA128Key::<CTR>::from_key_material(&material).unwrap();
    let (enc, nonce) = key.create_encryptor(&mut rng).unwrap();
    let _: ARIA_CTR_128<'_, Encrypting> = enc;
    let _: ARIA_CTR_128<'_, Decrypting> = key.create_decryptor(&nonce);
}

/// The const parameters are ARIA's, and CTR's nonce leaves the four-byte counter the mode caps at.
#[test]
fn the_const_parameters_are_arias() {
    assert_eq!(BLOCK_LEN, 16);
    assert_eq!(CTR_NONCE_LEN, 12, "a 12-byte nonce leaves the 4-byte counter CTR caps at");
}
