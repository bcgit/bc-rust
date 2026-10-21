//! Each public AES alias reports its own algorithm through `Algorithm`, not the AES permutation it
//! is built on: `AES_GCM_128` is `"AES_GCM_128"`, while `AES128Internal` stays `"AES-128"`. The
//! strength is the key's, so it is the same for every mode at a key size.
//!
//! The direction and the padding are type parameters of one algorithm, not different algorithms,
//! so every combination of them must report the same name, and so must every CCM frame.

use bouncycastle_aes::hazmat::{AES_ECB_128, AES_ECB_192, AES_ECB_256};
use bouncycastle_aes::{
    AES_CBC_128, AES_CBC_192, AES_CBC_256, AES_CCM_128, AES_CCM_192, AES_CCM_256, AES_CFB_128,
    AES_CFB_192, AES_CFB_256, AES_CFB8_128, AES_CFB8_192, AES_CFB8_256, AES_CMAC_128, AES_CMAC_192,
    AES_CMAC_256, AES_CTR_128, AES_CTR_192, AES_CTR_256, AES_GCM_128, AES_GCM_192, AES_GCM_256,
    AES_GMAC_128, AES_GMAC_192, AES_GMAC_256, CCM_NONCE_LEN, CCM_TAG_LEN,
};
use bouncycastle_cipher::padding::{NoPadding, PKCS7};
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::Algorithm;

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
