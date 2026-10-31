//! What each public AES alias is: the algorithm it reports and the type it resolves to.
//!
//! The direction and the padding are type parameters of one algorithm, not different algorithms,
//! so every combination of them must report the same name, and so must every CCM frame.

use bouncycastle_aes::hazmat::{AES_ECB_128, AES_ECB_192, AES_ECB_256, AES128Internal};
use bouncycastle_aes::{
    AES_CBC_128, AES_CBC_192, AES_CBC_256, AES_CCM_128, AES_CCM_192, AES_CCM_256, AES_CFB_128,
    AES_CFB_192, AES_CFB_256, AES_CFB8_128, AES_CFB8_192, AES_CFB8_256, AES_CMAC_128, AES_CMAC_192,
    AES_CMAC_256, AES_CTR_128, AES_CTR_192, AES_CTR_256, AES_GCM_128, AES_GCM_192, AES_GCM_256,
    AES_GMAC_128, AES_GMAC_192, AES_GMAC_256, AES128Key, CCM_NONCE_LEN, CCM_TAG_LEN,
};
use bouncycastle_cipher::modes::hazmat::ecb::{ECB, Ecb};
use bouncycastle_cipher::modes::{CBC, Cbc, Gcm};
use bouncycastle_cipher::padding::{
    NoPadding, PKCS7, PaddedBlockCipherDecryptor, PaddedBlockCipherEncryptor,
};
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::hazmat::Mode;
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
    type Enc<'k> = AES_CBC_128<'k, Encrypting, NoPadding>;
    assert_eq!(Enc::ALG_NAME, "AES_CBC_128");
    assert_eq!(Enc::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);

    use SecurityStrength::*;
    check::<AES_CBC_128<'_, Encrypting, NoPadding>, AES_CBC_128<'_, Decrypting, NoPadding>>(
        "AES_CBC_128", _128bit,
    );
    check::<AES_CBC_128<'_, Encrypting, PKCS7>, AES_CBC_128<'_, Decrypting, PKCS7>>(
        "AES_CBC_128", _128bit,
    );
    check::<AES_CBC_192<'_, Encrypting, NoPadding>, AES_CBC_192<'_, Decrypting, NoPadding>>(
        "AES_CBC_192", _192bit,
    );
    check::<AES_CBC_192<'_, Encrypting, PKCS7>, AES_CBC_192<'_, Decrypting, PKCS7>>(
        "AES_CBC_192", _192bit,
    );
    check::<AES_CBC_256<'_, Encrypting, NoPadding>, AES_CBC_256<'_, Decrypting, NoPadding>>(
        "AES_CBC_256", _256bit,
    );
    check::<AES_CBC_256<'_, Encrypting, PKCS7>, AES_CBC_256<'_, Decrypting, PKCS7>>(
        "AES_CBC_256", _256bit,
    );
}

#[test]
fn ecb() {
    use SecurityStrength::*;
    check::<AES_ECB_128<'_, Encrypting, NoPadding>, AES_ECB_128<'_, Decrypting, NoPadding>>(
        "AES_ECB_128", _128bit,
    );
    check::<AES_ECB_128<'_, Encrypting, PKCS7>, AES_ECB_128<'_, Decrypting, PKCS7>>(
        "AES_ECB_128", _128bit,
    );
    check::<AES_ECB_192<'_, Encrypting, NoPadding>, AES_ECB_192<'_, Decrypting, NoPadding>>(
        "AES_ECB_192", _192bit,
    );
    check::<AES_ECB_192<'_, Encrypting, PKCS7>, AES_ECB_192<'_, Decrypting, PKCS7>>(
        "AES_ECB_192", _192bit,
    );
    check::<AES_ECB_256<'_, Encrypting, NoPadding>, AES_ECB_256<'_, Decrypting, NoPadding>>(
        "AES_ECB_256", _256bit,
    );
    check::<AES_ECB_256<'_, Encrypting, PKCS7>, AES_ECB_256<'_, Decrypting, PKCS7>>(
        "AES_ECB_256", _256bit,
    );
}

#[test]
fn cfb_cfb8_ctr() {
    use SecurityStrength::*;
    check::<AES_CFB_128<'_, Encrypting>, AES_CFB_128<'_, Decrypting>>("AES_CFB_128", _128bit);
    check::<AES_CFB_192<'_, Encrypting>, AES_CFB_192<'_, Decrypting>>("AES_CFB_192", _192bit);
    check::<AES_CFB_256<'_, Encrypting>, AES_CFB_256<'_, Decrypting>>("AES_CFB_256", _256bit);

    check::<AES_CFB8_128<'_, Encrypting>, AES_CFB8_128<'_, Decrypting>>("AES_CFB8_128", _128bit);
    check::<AES_CFB8_192<'_, Encrypting>, AES_CFB8_192<'_, Decrypting>>("AES_CFB8_192", _192bit);
    check::<AES_CFB8_256<'_, Encrypting>, AES_CFB8_256<'_, Decrypting>>("AES_CFB8_256", _256bit);

    check::<AES_CTR_128<'_, Encrypting>, AES_CTR_128<'_, Decrypting>>("AES_CTR_128", _128bit);
    check::<AES_CTR_192<'_, Encrypting>, AES_CTR_192<'_, Decrypting>>("AES_CTR_192", _192bit);
    check::<AES_CTR_256<'_, Encrypting>, AES_CTR_256<'_, Decrypting>>("AES_CTR_256", _256bit);
}

#[test]
fn gcm() {
    type Enc<'k> = AES_GCM_128<'k, Encrypting>;
    assert_eq!(Enc::ALG_NAME, "AES_GCM_128");
    assert_eq!(Enc::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);

    use SecurityStrength::*;
    check::<AES_GCM_128<'_, Encrypting>, AES_GCM_128<'_, Decrypting>>("AES_GCM_128", _128bit);
    check::<AES_GCM_192<'_, Encrypting>, AES_GCM_192<'_, Decrypting>>("AES_GCM_192", _192bit);
    check::<AES_GCM_256<'_, Encrypting>, AES_GCM_256<'_, Decrypting>>("AES_GCM_256", _256bit);
}

#[test]
fn ccm() {
    use SecurityStrength::*;
    const N: usize = CCM_NONCE_LEN;
    const T: usize = CCM_TAG_LEN;
    // The nonce and tag lengths are parameters too, not part of the name.
    check::<AES_CCM_128<'_, Encrypting, 7, 4, 16, 32>, AES_CCM_128<'_, Decrypting, 7, 4, 16, 32>>(
        "AES_CCM_128", _128bit,
    );
    check::<AES_CCM_128<'_, Encrypting, N, T, 16, 32>, AES_CCM_128<'_, Decrypting, N, T, 16, 32>>(
        "AES_CCM_128", _128bit,
    );
    check::<AES_CCM_192<'_, Encrypting, N, T, 16, 32>, AES_CCM_192<'_, Decrypting, N, T, 16, 32>>(
        "AES_CCM_192", _192bit,
    );
    check::<AES_CCM_256<'_, Encrypting, N, T, 16, 32>, AES_CCM_256<'_, Decrypting, N, T, 16, 32>>(
        "AES_CCM_256", _256bit,
    );
}

#[test]
fn gmac() {
    use SecurityStrength::*;
    check::<AES_GMAC_128<'_, Encrypting>, AES_GMAC_128<'_, Decrypting>>("AES_GMAC_128", _128bit);
    check::<AES_GMAC_192<'_, Encrypting>, AES_GMAC_192<'_, Decrypting>>("AES_GMAC_192", _192bit);
    check::<AES_GMAC_256<'_, Encrypting>, AES_GMAC_256<'_, Decrypting>>("AES_GMAC_256", _256bit);
}

#[test]
fn cmac() {
    use SecurityStrength::*;
    assert_eq!(
        (AES_CMAC_128::ALG_NAME, AES_CMAC_128::MAX_SECURITY_STRENGTH),
        ("AES_CMAC_128", _128bit)
    );
    assert_eq!(
        (AES_CMAC_192::ALG_NAME, AES_CMAC_192::MAX_SECURITY_STRENGTH),
        ("AES_CMAC_192", _192bit)
    );
    assert_eq!(
        (AES_CMAC_256::ALG_NAME, AES_CMAC_256::MAX_SECURITY_STRENGTH),
        ("AES_CMAC_256", _256bit)
    );
}

fn key_for<M: Mode<AES128Internal>>() -> AES128Key<M> {
    let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
        .expect("a 16-byte symmetric cipher key");
    AES128Key::from_key_material(&key).expect("a valid key")
}

/// The aliases must resolve to exactly the types they claim to, at both directions, and be what
/// the keys hand out.
///
/// A type alias that quietly resolved to something else -- the wrong padding, the wrong direction,
/// the wrong key length -- would still compile everywhere it is used, so this pins the projection
/// itself by asserting the layouts coincide with the fully spelled-out types. ECB's projection
/// carries `INIT_DATA_LEN = 0` where CBC's carries 16.
#[test]
fn the_aliases_name_the_expected_types() {
    assert_eq!(
        size_of::<AES_CBC_128<'_, Encrypting, PKCS7>>(),
        size_of::<PaddedBlockCipherEncryptor<Cbc<'_, AES128Internal, Encrypting, 16>, PKCS7, 16, 16>>(
        )
    );
    assert_eq!(
        size_of::<AES_CBC_128<'_, Decrypting, PKCS7>>(),
        size_of::<PaddedBlockCipherDecryptor<Cbc<'_, AES128Internal, Decrypting, 16>, PKCS7, 16, 16>>(
        )
    );
    // The two directions are genuinely different types, so the encryptor and the decryptor do not
    // have to agree in size -- and here they do not, which is itself evidence the projection
    // selected two different adapters rather than one.
    assert_ne!(
        size_of::<AES_CBC_128<'_, Encrypting, PKCS7>>(),
        size_of::<AES_CBC_128<'_, Decrypting, PKCS7>>()
    );

    assert_eq!(
        size_of::<AES_ECB_128<'_, Encrypting, PKCS7>>(),
        size_of::<PaddedBlockCipherEncryptor<Ecb<'_, AES128Internal, Encrypting, 16>, PKCS7, 0, 16>>(
        )
    );
    assert_eq!(
        size_of::<AES_ECB_128<'_, Decrypting, PKCS7>>(),
        size_of::<PaddedBlockCipherDecryptor<Ecb<'_, AES128Internal, Decrypting, 16>, PKCS7, 0, 16>>(
        )
    );

    assert_eq!(
        size_of::<AES_GCM_128<'_, Encrypting>>(),
        size_of::<Gcm<'_, AES128Internal, Encrypting, 16>>()
    );
    assert_eq!(
        size_of::<AES_GCM_128<'_, Decrypting>>(),
        size_of::<Gcm<'_, AES128Internal, Decrypting, 16>>()
    );

    // ...and the keys hand out exactly those types.
    let mut rng = HashDRBG_SHA512::new_from_os();
    let key = key_for::<CBC<PKCS7>>();
    let (enc, iv) = key.create_encryptor(&mut rng).unwrap();
    let _: AES_CBC_128<'_, Encrypting, PKCS7> = enc;
    let _: AES_CBC_128<'_, Decrypting, PKCS7> = key.create_decryptor(&iv);
    let key = key_for::<ECB<PKCS7>>();
    let (enc, no_iv) = key.create_encryptor(&mut rng).unwrap();
    let _: AES_ECB_128<'_, Encrypting, PKCS7> = enc;
    let _: AES_ECB_128<'_, Decrypting, PKCS7> = key.create_decryptor(&no_iv);
}
