//! What each public Camellia alias is: the algorithm it reports and the type it resolves to.
//!
//! Each alias reports its own algorithm through `Algorithm`, not the engine it is built on:
//! `Camellia_CBC_128` is `"Camellia_CBC_128"`, while `Camellia128Internal` stays
//! `"Camellia-128"`. The strength is the key's. The direction and the padding are type parameters
//! of one algorithm, not different algorithms, so every combination of them must report the same
//! name.

use bouncycastle_camellia::hazmat::{
    Camellia128Internal, Camellia192Internal, Camellia256Internal,
};
use bouncycastle_camellia::{
    BLOCK_LEN, CTR_NONCE_LEN, Camellia_CBC_128, Camellia_CBC_192, Camellia_CBC_256,
    Camellia_CFB_128, Camellia_CFB_192, Camellia_CFB_256, Camellia_CFB8_128, Camellia_CFB8_192,
    Camellia_CFB8_256, Camellia_CTR_128, Camellia_CTR_192, Camellia_CTR_256, Camellia128Key, LANES,
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
    check::<Camellia_CBC_128<'_, Encrypting, PKCS7>, Camellia_CBC_128<'_, Decrypting, PKCS7>>(
        "Camellia_CBC_128", _128bit,
    );
    type NoPadEnc<'k> = Camellia_CBC_128<'k, Encrypting, NoPadding>;
    type NoPadDec<'k> = Camellia_CBC_128<'k, Decrypting, NoPadding>;
    check::<NoPadEnc<'_>, NoPadDec<'_>>("Camellia_CBC_128", _128bit);
    check::<Camellia_CBC_192<'_, Encrypting, PKCS7>, Camellia_CBC_192<'_, Decrypting, PKCS7>>(
        "Camellia_CBC_192", _192bit,
    );
    check::<Camellia_CBC_256<'_, Encrypting, PKCS7>, Camellia_CBC_256<'_, Decrypting, PKCS7>>(
        "Camellia_CBC_256", _256bit,
    );
}

#[test]
fn cfb_cfb8_ctr() {
    use SecurityStrength::*;
    check::<Camellia_CFB_128<'_, Encrypting>, Camellia_CFB_128<'_, Decrypting>>(
        "Camellia_CFB_128", _128bit,
    );
    check::<Camellia_CFB_192<'_, Encrypting>, Camellia_CFB_192<'_, Decrypting>>(
        "Camellia_CFB_192", _192bit,
    );
    check::<Camellia_CFB_256<'_, Encrypting>, Camellia_CFB_256<'_, Decrypting>>(
        "Camellia_CFB_256", _256bit,
    );
    check::<Camellia_CFB8_128<'_, Encrypting>, Camellia_CFB8_128<'_, Decrypting>>(
        "Camellia_CFB8_128", _128bit,
    );
    check::<Camellia_CFB8_192<'_, Encrypting>, Camellia_CFB8_192<'_, Decrypting>>(
        "Camellia_CFB8_192", _192bit,
    );
    check::<Camellia_CFB8_256<'_, Encrypting>, Camellia_CFB8_256<'_, Decrypting>>(
        "Camellia_CFB8_256", _256bit,
    );
    check::<Camellia_CTR_128<'_, Encrypting>, Camellia_CTR_128<'_, Decrypting>>(
        "Camellia_CTR_128", _128bit,
    );
    check::<Camellia_CTR_192<'_, Encrypting>, Camellia_CTR_192<'_, Decrypting>>(
        "Camellia_CTR_192", _192bit,
    );
    check::<Camellia_CTR_256<'_, Encrypting>, Camellia_CTR_256<'_, Decrypting>>(
        "Camellia_CTR_256", _256bit,
    );
}

#[test]
fn the_engines_keep_their_own_names() {
    assert_eq!(Camellia128Internal::ALG_NAME, "Camellia-128");
    assert_eq!(Camellia192Internal::ALG_NAME, "Camellia-192");
    assert_eq!(Camellia256Internal::ALG_NAME, "Camellia-256");
    assert_eq!(Camellia128Internal::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);
    assert_eq!(Camellia192Internal::MAX_SECURITY_STRENGTH, SecurityStrength::_192bit);
    assert_eq!(Camellia256Internal::MAX_SECURITY_STRENGTH, SecurityStrength::_256bit);
}

/// The aliases must resolve to exactly the types they claim to, at both directions, and be what
/// the keys hand out. A type alias that quietly resolved to something else would still compile
/// everywhere it is used, so this pins the projection by asserting the layouts coincide with the
/// fully spelled-out types.
#[test]
fn the_aliases_name_the_expected_types() {
    assert_eq!(
        size_of::<Camellia_CBC_128<'_, Encrypting, PKCS7>>(),
        size_of::<
            PaddedBlockCipherEncryptor<
                Cbc<'_, Camellia128Internal, Encrypting, BLOCK_LEN>,
                PKCS7,
                BLOCK_LEN,
                BLOCK_LEN,
            >,
        >()
    );
    assert_eq!(
        size_of::<Camellia_CBC_192<'_, Decrypting, PKCS7>>(),
        size_of::<
            PaddedBlockCipherDecryptor<
                Cbc<'_, Camellia192Internal, Decrypting, BLOCK_LEN>,
                PKCS7,
                BLOCK_LEN,
                BLOCK_LEN,
            >,
        >()
    );
    assert_eq!(
        size_of::<Camellia_CBC_256<'_, Encrypting, NoPadding>>(),
        size_of::<
            PaddedBlockCipherEncryptor<
                Cbc<'_, Camellia256Internal, Encrypting, BLOCK_LEN>,
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
        size_of::<Camellia_CBC_128<'_, Encrypting, PKCS7>>(),
        size_of::<Camellia_CBC_128<'_, Decrypting, PKCS7>>()
    );

    assert_eq!(
        size_of::<Camellia_CFB_128<'_, Encrypting>>(),
        size_of::<Cfb<'_, Camellia128Internal, Encrypting, BLOCK_LEN>>()
    );
    assert_eq!(
        size_of::<Camellia_CFB_192<'_, Decrypting>>(),
        size_of::<Cfb<'_, Camellia192Internal, Decrypting, BLOCK_LEN>>()
    );
    assert_eq!(
        size_of::<Camellia_CFB_256<'_, Encrypting>>(),
        size_of::<Cfb<'_, Camellia256Internal, Encrypting, BLOCK_LEN>>()
    );
    assert_eq!(
        size_of::<Camellia_CFB8_128<'_, Encrypting>>(),
        size_of::<Cfb8<'_, Camellia128Internal, Encrypting, BLOCK_LEN>>()
    );
    assert_eq!(
        size_of::<Camellia_CFB8_192<'_, Decrypting>>(),
        size_of::<Cfb8<'_, Camellia192Internal, Decrypting, BLOCK_LEN>>()
    );
    assert_eq!(
        size_of::<Camellia_CFB8_256<'_, Encrypting>>(),
        size_of::<Cfb8<'_, Camellia256Internal, Encrypting, BLOCK_LEN>>()
    );
    assert_eq!(
        size_of::<Camellia_CTR_128<'_, Encrypting>>(),
        size_of::<Ctr<'_, Camellia128Internal, Encrypting, BLOCK_LEN, CTR_NONCE_LEN>>()
    );
    assert_eq!(
        size_of::<Camellia_CTR_192<'_, Decrypting>>(),
        size_of::<Ctr<'_, Camellia192Internal, Decrypting, BLOCK_LEN, CTR_NONCE_LEN>>()
    );
    assert_eq!(
        size_of::<Camellia_CTR_256<'_, Encrypting>>(),
        size_of::<Ctr<'_, Camellia256Internal, Encrypting, BLOCK_LEN, CTR_NONCE_LEN>>()
    );

    // ...and the key hands out exactly those types.
    let bytes: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    let material =
        KeyMaterial::<16>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).unwrap();
    let mut rng = HashDRBG_SHA512::new_from_os();
    let key = Camellia128Key::<CBC<PKCS7>>::from_key_material(&material).unwrap();
    let (enc, iv) = key.create_encryptor(&mut rng).unwrap();
    let _: Camellia_CBC_128<'_, Encrypting, PKCS7> = enc;
    let _: Camellia_CBC_128<'_, Decrypting, PKCS7> = key.create_decryptor(&iv);
    let key = Camellia128Key::<CFB>::from_key_material(&material).unwrap();
    let _: Camellia_CFB_128<'_, Encrypting> = key.create_encryptor(&mut rng).unwrap().0;
    let key = Camellia128Key::<CFB8>::from_key_material(&material).unwrap();
    let _: Camellia_CFB8_128<'_, Encrypting> = key.create_encryptor(&mut rng).unwrap().0;
    let key = Camellia128Key::<CTR>::from_key_material(&material).unwrap();
    let (enc, nonce) = key.create_encryptor(&mut rng).unwrap();
    let _: Camellia_CTR_128<'_, Encrypting> = enc;
    let _: Camellia_CTR_128<'_, Decrypting> = key.create_decryptor(&nonce);
}

/// The const parameters are Camellia's, CTR's nonce leaves the four-byte counter the mode caps
/// at, and four lanes of eight-byte F-function inputs fill the 32 byte positions of the `u32`
/// planes.
#[test]
fn the_const_parameters_are_camellias() {
    assert_eq!(BLOCK_LEN, 16);
    assert_eq!(CTR_NONCE_LEN, 12, "a 12-byte nonce leaves the 4-byte counter CTR caps at");
    assert_eq!(LANES * 8, 32, "four lanes of one F-function input each fill the circuit");
}

/// The engines are exactly their subkeys, the sizes the crate docs quote: 26 or 34 subkeys of 64
/// bits and nothing else, no direction flag, no round counter, no initialised marker.
#[test]
fn the_engines_are_exactly_their_subkeys() {
    assert_eq!(size_of::<Camellia128Internal>(), 208);
    assert_eq!(size_of::<Camellia192Internal>(), 272);
    assert_eq!(size_of::<Camellia256Internal>(), 272);
}
