//! What each public SM4 alias is: the algorithm it reports and the type it resolves to.
//!
//! Each alias reports its own algorithm through `Algorithm`, not the engine it is built on:
//! `SM4_CBC` is `"SM4_CBC"`, while `SM4Internal` stays `"SM4"`. The strength is the key's. The
//! direction and the padding are type parameters of one algorithm, not different algorithms, so
//! every combination of them must report the same name.

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
use bouncycastle_sm4::hazmat::SM4Internal;
use bouncycastle_sm4::{
    BLOCK_LEN, CTR_NONCE_LEN, KEY_LEN, SM4_CBC, SM4_CFB, SM4_CFB8, SM4_CTR, SM4Key,
};
use core::mem::size_of;

/// Both directions of one algorithm report `name` at the 128-bit strength.
fn check<Enc: Algorithm, Dec: Algorithm>(name: &str) {
    assert_eq!(Enc::ALG_NAME, name);
    assert_eq!(Dec::ALG_NAME, name);
    assert_eq!(Enc::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit, "{name}");
    assert_eq!(Dec::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit, "{name}");
}

#[test]
fn cbc() {
    check::<SM4_CBC<'_, Encrypting, PKCS7>, SM4_CBC<'_, Decrypting, PKCS7>>("SM4_CBC");
    check::<SM4_CBC<'_, Encrypting, NoPadding>, SM4_CBC<'_, Decrypting, NoPadding>>("SM4_CBC");
}

#[test]
fn cfb_cfb8_ctr() {
    check::<SM4_CFB<'_, Encrypting>, SM4_CFB<'_, Decrypting>>("SM4_CFB");
    check::<SM4_CFB8<'_, Encrypting>, SM4_CFB8<'_, Decrypting>>("SM4_CFB8");
    check::<SM4_CTR<'_, Encrypting>, SM4_CTR<'_, Decrypting>>("SM4_CTR");
}

#[test]
fn the_engine_keeps_its_own_name() {
    assert_eq!(SM4Internal::ALG_NAME, "SM4");
    assert_eq!(SM4Internal::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);
}

/// The aliases must resolve to exactly the types they claim to, at both directions, and be what
/// the key hands out. A type alias that quietly resolved to something else would still compile
/// everywhere it is used, so this pins the projection by asserting the layouts coincide with the
/// fully spelled-out types.
#[test]
fn the_aliases_name_the_expected_types() {
    assert_eq!(
        size_of::<SM4_CBC<'_, Encrypting, PKCS7>>(),
        size_of::<
            PaddedBlockCipherEncryptor<
                Cbc<'_, SM4Internal, Encrypting, BLOCK_LEN>,
                PKCS7,
                BLOCK_LEN,
                BLOCK_LEN,
            >,
        >()
    );
    assert_eq!(
        size_of::<SM4_CBC<'_, Decrypting, PKCS7>>(),
        size_of::<
            PaddedBlockCipherDecryptor<
                Cbc<'_, SM4Internal, Decrypting, BLOCK_LEN>,
                PKCS7,
                BLOCK_LEN,
                BLOCK_LEN,
            >,
        >()
    );
    assert_eq!(
        size_of::<SM4_CBC<'_, Encrypting, NoPadding>>(),
        size_of::<
            PaddedBlockCipherEncryptor<
                Cbc<'_, SM4Internal, Encrypting, BLOCK_LEN>,
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
        size_of::<SM4_CBC<'_, Encrypting, PKCS7>>(),
        size_of::<SM4_CBC<'_, Decrypting, PKCS7>>()
    );

    assert_eq!(
        size_of::<SM4_CFB<'_, Encrypting>>(),
        size_of::<Cfb<'_, SM4Internal, Encrypting, BLOCK_LEN>>()
    );
    assert_eq!(
        size_of::<SM4_CFB<'_, Decrypting>>(),
        size_of::<Cfb<'_, SM4Internal, Decrypting, BLOCK_LEN>>()
    );
    assert_eq!(
        size_of::<SM4_CFB8<'_, Encrypting>>(),
        size_of::<Cfb8<'_, SM4Internal, Encrypting, BLOCK_LEN>>()
    );
    assert_eq!(
        size_of::<SM4_CFB8<'_, Decrypting>>(),
        size_of::<Cfb8<'_, SM4Internal, Decrypting, BLOCK_LEN>>()
    );
    assert_eq!(
        size_of::<SM4_CTR<'_, Encrypting>>(),
        size_of::<Ctr<'_, SM4Internal, Encrypting, BLOCK_LEN, CTR_NONCE_LEN>>()
    );
    assert_eq!(
        size_of::<SM4_CTR<'_, Decrypting>>(),
        size_of::<Ctr<'_, SM4Internal, Decrypting, BLOCK_LEN, CTR_NONCE_LEN>>()
    );

    // ...and the key hands out exactly those types.
    let bytes: [u8; KEY_LEN] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    let material =
        KeyMaterial::<KEY_LEN>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).unwrap();
    let mut rng = HashDRBG_SHA512::new_from_os();
    let key = SM4Key::<CBC<PKCS7>>::from_key_material(&material).unwrap();
    let (enc, iv) = key.create_encryptor(&mut rng).unwrap();
    let _: SM4_CBC<'_, Encrypting, PKCS7> = enc;
    let _: SM4_CBC<'_, Decrypting, PKCS7> = key.create_decryptor(&iv);
    let key = SM4Key::<CFB>::from_key_material(&material).unwrap();
    let _: SM4_CFB<'_, Encrypting> = key.create_encryptor(&mut rng).unwrap().0;
    let key = SM4Key::<CFB8>::from_key_material(&material).unwrap();
    let _: SM4_CFB8<'_, Encrypting> = key.create_encryptor(&mut rng).unwrap().0;
    let key = SM4Key::<CTR>::from_key_material(&material).unwrap();
    let (enc, nonce) = key.create_encryptor(&mut rng).unwrap();
    let _: SM4_CTR<'_, Encrypting> = enc;
    let _: SM4_CTR<'_, Decrypting> = key.create_decryptor(&nonce);
}

/// The const parameters SM4 fills in are the ones the crate exports, and CTR's nonce leaves the
/// four-byte counter the mode's maximum.
#[test]
fn the_const_parameters_are_sm4s() {
    assert_eq!(KEY_LEN, 16);
    assert_eq!(BLOCK_LEN, 16);
    assert_eq!(CTR_NONCE_LEN, 12, "a 12-byte nonce leaves the 4-byte counter CTR caps at");
}
