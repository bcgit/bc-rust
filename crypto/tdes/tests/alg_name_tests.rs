//! What each public TDES alias is: the algorithm it reports and the type it resolves to.
//!
//! Each alias reports its own algorithm through `Algorithm`, not the engine it is built on:
//! `TDES_CBC` is `"TDES_CBC"`, while `TDESInternal` stays `"TDES"`. The strength is the key's:
//! 112 bits for three-key TDEA, and none at all for two-key. The direction and the padding are
//! type parameters of one algorithm, not different algorithms, so every combination of them must
//! report the same name.

use bouncycastle_cipher::modes::hazmat::ecb::{ECB, Ecb};
use bouncycastle_cipher::modes::{CBC, Cbc, Cfb, Cfb8, Ctr};
use bouncycastle_cipher::padding::{
    NoPadding, PKCS7, PaddedBlockCipherDecryptor, PaddedBlockCipherEncryptor,
};
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::hazmat::{ElectronicCodeBook, Mode};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{
    FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle_core::traits::Algorithm;
use bouncycastle_rng::HashDRBG_SHA512;
use bouncycastle_tdes::hazmat::{TDES_ECB, TDES2_ECB, TDES2Internal, TDESInternal};
use bouncycastle_tdes::{
    BLOCK_LEN, CTR_NONCE_LEN, KEY_LEN, KEY_LEN_2KEY, TDES_CBC, TDES_CFB, TDES_CFB8, TDES_CTR,
    TDES2_CBC, TDES2_CFB, TDES2_CFB8, TDES2_CTR, TDES3Key,
};
use core::mem::size_of;

/// Both directions of one algorithm report `name` and `strength`.
fn check<Enc: Algorithm, Dec: Algorithm>(name: &str, strength: SecurityStrength) {
    assert_eq!(Enc::ALG_NAME, name);
    assert_eq!(Dec::ALG_NAME, name);
    assert_eq!(Enc::MAX_SECURITY_STRENGTH, strength, "{name}");
    assert_eq!(Dec::MAX_SECURITY_STRENGTH, strength, "{name}");
}

/// The one direction a two-key alias has.
fn check_decrypting<Dec: Algorithm>(name: &str) {
    assert_eq!(Dec::ALG_NAME, name);
    assert_eq!(Dec::MAX_SECURITY_STRENGTH, SecurityStrength::None, "{name}");
}

#[test]
fn cbc() {
    use SecurityStrength::*;
    check::<TDES_CBC<'_, Encrypting, NoPadding>, TDES_CBC<'_, Decrypting, NoPadding>>(
        "TDES_CBC", _112bit,
    );
    check::<TDES_CBC<'_, Encrypting, PKCS7>, TDES_CBC<'_, Decrypting, PKCS7>>("TDES_CBC", _112bit);
    check_decrypting::<TDES2_CBC<'_, NoPadding>>("TDES2_CBC");
    check_decrypting::<TDES2_CBC<'_, PKCS7>>("TDES2_CBC");
}

#[test]
fn ecb() {
    use SecurityStrength::*;
    check::<TDES_ECB<'_, Encrypting, NoPadding>, TDES_ECB<'_, Decrypting, NoPadding>>(
        "TDES_ECB", _112bit,
    );
    check::<TDES_ECB<'_, Encrypting, PKCS7>, TDES_ECB<'_, Decrypting, PKCS7>>("TDES_ECB", _112bit);
    check_decrypting::<TDES2_ECB<'_, NoPadding>>("TDES2_ECB");
    check_decrypting::<TDES2_ECB<'_, PKCS7>>("TDES2_ECB");
}

#[test]
fn cfb_cfb8_ctr() {
    use SecurityStrength::*;
    check::<TDES_CFB<'_, Encrypting>, TDES_CFB<'_, Decrypting>>("TDES_CFB", _112bit);
    check::<TDES_CFB8<'_, Encrypting>, TDES_CFB8<'_, Decrypting>>("TDES_CFB8", _112bit);
    check::<TDES_CTR<'_, Encrypting>, TDES_CTR<'_, Decrypting>>("TDES_CTR", _112bit);
    check_decrypting::<TDES2_CFB<'_>>("TDES2_CFB");
    check_decrypting::<TDES2_CFB8<'_>>("TDES2_CFB8");
    check_decrypting::<TDES2_CTR<'_>>("TDES2_CTR");
}

#[test]
fn the_engines_keep_their_own_names() {
    assert_eq!(TDESInternal::ALG_NAME, "TDES");
    assert_eq!(TDESInternal::MAX_SECURITY_STRENGTH, SecurityStrength::_112bit);
    assert_eq!(TDES2Internal::ALG_NAME, "TDES-2KEY");
    assert_eq!(TDES2Internal::MAX_SECURITY_STRENGTH, SecurityStrength::None);
}

/// Three-key TDEA may encrypt; two-key TDEA may not (SP 800-131A Rev 2 Table 1), which is the
/// gate the modes check at compile time.
#[test]
fn only_the_three_key_engine_is_approved_for_encryption() {
    assert!(<TDESInternal as ElectronicCodeBook<KEY_LEN, BLOCK_LEN>>::ENCRYPTION_APPROVED);
    assert!(!<TDES2Internal as ElectronicCodeBook<KEY_LEN_2KEY, BLOCK_LEN>>::ENCRYPTION_APPROVED);
}

/// The engines are exactly their packed schedules, the sizes the crate docs quote: sixteen
/// two-word round keys per DEA key, three or two keys, and nothing else.
#[test]
fn the_engines_are_exactly_their_schedules() {
    assert_eq!(size_of::<TDESInternal>(), 3 * 16 * 2 * 4);
    assert_eq!(size_of::<TDES2Internal>(), 2 * 16 * 2 * 4);
}

fn key_for<M: Mode<TDESInternal>>() -> TDES3Key<M> {
    let bytes: [u8; KEY_LEN] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    let key = KeyMaterial::<KEY_LEN>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
        .expect("a 24-byte symmetric cipher key");
    TDES3Key::from_key_material(&key).expect("a valid key bundle")
}

/// The aliases must resolve to exactly the types they claim to, at both directions, and be what
/// the keys hand out.
///
/// A type alias that quietly resolved to something else -- the wrong padding, the wrong direction,
/// the wrong block length -- would still compile everywhere it is used, so this pins the projection
/// itself by asserting the layouts coincide with the fully spelled-out types. ECB's projection
/// carries `INIT_DATA_LEN = 0` where CBC's carries 8.
#[test]
fn the_aliases_name_the_expected_types() {
    assert_eq!(
        size_of::<TDES_CBC<'_, Encrypting, PKCS7>>(),
        size_of::<
            PaddedBlockCipherEncryptor<
                Cbc<'_, TDESInternal, Encrypting, BLOCK_LEN>,
                PKCS7,
                BLOCK_LEN,
                BLOCK_LEN,
            >,
        >()
    );
    assert_eq!(
        size_of::<TDES_CBC<'_, Decrypting, PKCS7>>(),
        size_of::<
            PaddedBlockCipherDecryptor<
                Cbc<'_, TDESInternal, Decrypting, BLOCK_LEN>,
                PKCS7,
                BLOCK_LEN,
                BLOCK_LEN,
            >,
        >()
    );
    // The two directions are genuinely different types, so the encryptor and the decryptor do not
    // have to agree in size -- and here they do not, which is itself evidence the projection
    // selected two different adapters rather than one.
    assert_ne!(
        size_of::<TDES_CBC<'_, Encrypting, PKCS7>>(),
        size_of::<TDES_CBC<'_, Decrypting, PKCS7>>()
    );

    assert_eq!(
        size_of::<TDES_ECB<'_, Encrypting, PKCS7>>(),
        size_of::<
            PaddedBlockCipherEncryptor<
                Ecb<'_, TDESInternal, Encrypting, BLOCK_LEN>,
                PKCS7,
                0,
                BLOCK_LEN,
            >,
        >()
    );
    assert_eq!(
        size_of::<TDES_ECB<'_, Decrypting, PKCS7>>(),
        size_of::<
            PaddedBlockCipherDecryptor<
                Ecb<'_, TDESInternal, Decrypting, BLOCK_LEN>,
                PKCS7,
                0,
                BLOCK_LEN,
            >,
        >()
    );

    assert_eq!(
        size_of::<TDES_CFB<'_, Encrypting>>(),
        size_of::<Cfb<'_, TDESInternal, Encrypting, BLOCK_LEN>>()
    );
    assert_eq!(
        size_of::<TDES_CFB8<'_, Decrypting>>(),
        size_of::<Cfb8<'_, TDESInternal, Decrypting, BLOCK_LEN>>()
    );
    assert_eq!(
        size_of::<TDES_CTR<'_, Encrypting>>(),
        size_of::<Ctr<'_, TDESInternal, Encrypting, BLOCK_LEN, CTR_NONCE_LEN>>()
    );

    // ...and the key hands out exactly those types.
    let mut rng = HashDRBG_SHA512::new_from_os();
    let key = key_for::<CBC<PKCS7>>();
    let (enc, iv) = key.create_encryptor(&mut rng).unwrap();
    let _: TDES_CBC<'_, Encrypting, PKCS7> = enc;
    let _: TDES_CBC<'_, Decrypting, PKCS7> = key.create_decryptor(&iv);
    let key = key_for::<ECB<PKCS7>>();
    let (enc, no_iv) = key.create_encryptor(&mut rng).unwrap();
    let _: TDES_ECB<'_, Encrypting, PKCS7> = enc;
    let _: TDES_ECB<'_, Decrypting, PKCS7> = key.create_decryptor(&no_iv);
}
