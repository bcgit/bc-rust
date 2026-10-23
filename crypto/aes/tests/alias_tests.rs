//! What each public AES alias is: the algorithm it reports and the type it resolves to.
//!
//! Each alias reports its own algorithm through `Algorithm`, not the AES permutation it is built
//! on: `AES_GCM_128` is `"AES_GCM_128"`, while `AES128Internal` stays `"AES-128"`. The strength is
//! the key's, so it is the same for every mode at a key size. The direction and the padding are
//! type parameters of one algorithm, not different algorithms, so every combination of them must
//! report the same name. So must the `AES_CCM_*_Packet` aliases, which are a second API onto the
//! same mode rather than another algorithm.

use bouncycastle_aes::hazmat::{AES_ECB_128, AES_ECB_192, AES_ECB_256, AES128Internal};
use bouncycastle_aes::{
    AES_CBC_128, AES_CBC_192, AES_CBC_256, AES_CCM_128, AES_CCM_128_Packet, AES_CCM_192,
    AES_CCM_192_Packet, AES_CCM_256, AES_CCM_256_Packet, AES_CFB_128, AES_CFB_192, AES_CFB_256,
    AES_CFB8_128, AES_CFB8_192, AES_CFB8_256, AES_CTR_128, AES_CTR_192, AES_CTR_256, AES_GCM_128,
    AES_GCM_192, AES_GCM_256, CCM_NONCE_LEN, CCM_TAG_LEN,
};
use bouncycastle_cipher::modes::hazmat::ecb::Ecb;
use bouncycastle_cipher::modes::{Cbc, Gcm};
use bouncycastle_cipher::padding::{
    NoPadding, PKCS7, PaddedBlockCipherDecryptor, PaddedBlockCipherEncryptor,
};
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::Algorithm;
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
    check::<AES_CBC_128<Encrypting, NoPadding>, AES_CBC_128<Decrypting, NoPadding>>(
        "AES_CBC_128", _128bit,
    );
    check::<AES_CBC_128<Encrypting, PKCS7>, AES_CBC_128<Decrypting, PKCS7>>("AES_CBC_128", _128bit);
    check::<AES_CBC_192<Encrypting, NoPadding>, AES_CBC_192<Decrypting, NoPadding>>(
        "AES_CBC_192", _192bit,
    );
    check::<AES_CBC_192<Encrypting, PKCS7>, AES_CBC_192<Decrypting, PKCS7>>("AES_CBC_192", _192bit);
    check::<AES_CBC_256<Encrypting, NoPadding>, AES_CBC_256<Decrypting, NoPadding>>(
        "AES_CBC_256", _256bit,
    );
    check::<AES_CBC_256<Encrypting, PKCS7>, AES_CBC_256<Decrypting, PKCS7>>("AES_CBC_256", _256bit);
}

#[test]
fn ecb() {
    use SecurityStrength::*;
    check::<AES_ECB_128<Encrypting, NoPadding>, AES_ECB_128<Decrypting, NoPadding>>(
        "AES_ECB_128", _128bit,
    );
    check::<AES_ECB_128<Encrypting, PKCS7>, AES_ECB_128<Decrypting, PKCS7>>("AES_ECB_128", _128bit);
    check::<AES_ECB_192<Encrypting, NoPadding>, AES_ECB_192<Decrypting, NoPadding>>(
        "AES_ECB_192", _192bit,
    );
    check::<AES_ECB_192<Encrypting, PKCS7>, AES_ECB_192<Decrypting, PKCS7>>("AES_ECB_192", _192bit);
    check::<AES_ECB_256<Encrypting, NoPadding>, AES_ECB_256<Decrypting, NoPadding>>(
        "AES_ECB_256", _256bit,
    );
    check::<AES_ECB_256<Encrypting, PKCS7>, AES_ECB_256<Decrypting, PKCS7>>("AES_ECB_256", _256bit);
}

#[test]
fn cfb_cfb8_ctr() {
    use SecurityStrength::*;
    check::<AES_CFB_128<Encrypting>, AES_CFB_128<Decrypting>>("AES_CFB_128", _128bit);
    check::<AES_CFB_192<Encrypting>, AES_CFB_192<Decrypting>>("AES_CFB_192", _192bit);
    check::<AES_CFB_256<Encrypting>, AES_CFB_256<Decrypting>>("AES_CFB_256", _256bit);

    check::<AES_CFB8_128<Encrypting>, AES_CFB8_128<Decrypting>>("AES_CFB8_128", _128bit);
    check::<AES_CFB8_192<Encrypting>, AES_CFB8_192<Decrypting>>("AES_CFB8_192", _192bit);
    check::<AES_CFB8_256<Encrypting>, AES_CFB8_256<Decrypting>>("AES_CFB8_256", _256bit);

    check::<AES_CTR_128<Encrypting>, AES_CTR_128<Decrypting>>("AES_CTR_128", _128bit);
    check::<AES_CTR_192<Encrypting>, AES_CTR_192<Decrypting>>("AES_CTR_192", _192bit);
    check::<AES_CTR_256<Encrypting>, AES_CTR_256<Decrypting>>("AES_CTR_256", _256bit);
}

#[test]
fn gcm() {
    use SecurityStrength::*;
    check::<AES_GCM_128<Encrypting>, AES_GCM_128<Decrypting>>("AES_GCM_128", _128bit);
    check::<AES_GCM_192<Encrypting>, AES_GCM_192<Decrypting>>("AES_GCM_192", _192bit);
    check::<AES_GCM_256<Encrypting>, AES_GCM_256<Decrypting>>("AES_GCM_256", _256bit);
}

#[test]
fn ccm() {
    use SecurityStrength::*;
    const N: usize = CCM_NONCE_LEN;
    const T: usize = CCM_TAG_LEN;
    check::<AES_CCM_128_Packet<Encrypting, N, T>, AES_CCM_128_Packet<Decrypting, N, T>>(
        "AES_CCM_128", _128bit,
    );
    check::<AES_CCM_192_Packet<Encrypting, N, T>, AES_CCM_192_Packet<Decrypting, N, T>>(
        "AES_CCM_192", _192bit,
    );
    check::<AES_CCM_256_Packet<Encrypting, N, T>, AES_CCM_256_Packet<Decrypting, N, T>>(
        "AES_CCM_256", _256bit,
    );
    // The nonce and tag lengths are parameters too, not part of the name.
    check::<AES_CCM_128_Packet<Encrypting, 7, 4>, AES_CCM_128_Packet<Decrypting, 7, 4>>(
        "AES_CCM_128", _128bit,
    );

    check::<AES_CCM_128<Encrypting, N, T, 16, 32>, AES_CCM_128<Decrypting, N, T, 16, 32>>(
        "AES_CCM_128", _128bit,
    );
    check::<AES_CCM_192<Encrypting, N, T, 16, 32>, AES_CCM_192<Decrypting, N, T, 16, 32>>(
        "AES_CCM_192", _192bit,
    );
    check::<AES_CCM_256<Encrypting, N, T, 16, 32>, AES_CCM_256<Decrypting, N, T, 16, 32>>(
        "AES_CCM_256", _256bit,
    );
}

/// The aliases must resolve to exactly the types they claim to, at both directions.
///
/// A type alias that quietly resolved to something else -- the wrong padding, the wrong direction,
/// the wrong key length -- would still compile everywhere it is used, so this pins the projection
/// itself by asserting the layouts coincide with the fully spelled-out types. ECB's projection
/// carries `INIT_DATA_LEN = 0` where CBC's carries 16.
#[test]
fn the_aliases_name_the_expected_types() {
    assert_eq!(
        size_of::<AES_CBC_128<Encrypting, PKCS7>>(),
        size_of::<
            PaddedBlockCipherEncryptor<Cbc<AES128Internal, Encrypting, 16, 16>, PKCS7, 16, 16, 16>,
        >()
    );
    assert_eq!(
        size_of::<AES_CBC_128<Decrypting, PKCS7>>(),
        size_of::<
            PaddedBlockCipherDecryptor<Cbc<AES128Internal, Decrypting, 16, 16>, PKCS7, 16, 16, 16>,
        >()
    );
    // The two directions are genuinely different types, so the encryptor and the decryptor do not
    // have to agree in size -- and here they do not, which is itself evidence the projection
    // selected two different adapters rather than one.
    assert_ne!(
        size_of::<AES_CBC_128<Encrypting, PKCS7>>(),
        size_of::<AES_CBC_128<Decrypting, PKCS7>>()
    );

    assert_eq!(
        size_of::<AES_ECB_128<Encrypting, PKCS7>>(),
        size_of::<
            PaddedBlockCipherEncryptor<Ecb<AES128Internal, Encrypting, 16, 16>, PKCS7, 16, 0, 16>,
        >()
    );
    assert_eq!(
        size_of::<AES_ECB_128<Decrypting, PKCS7>>(),
        size_of::<
            PaddedBlockCipherDecryptor<Ecb<AES128Internal, Decrypting, 16, 16>, PKCS7, 16, 0, 16>,
        >()
    );

    assert_eq!(
        size_of::<AES_GCM_128<Encrypting>>(),
        size_of::<Gcm<AES128Internal, Encrypting, 16, 16>>()
    );
    assert_eq!(
        size_of::<AES_GCM_128<Decrypting>>(),
        size_of::<Gcm<AES128Internal, Decrypting, 16, 16>>()
    );
}
