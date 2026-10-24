//! `AES*Key<GMAC>`: the key object holding `H`, and the pair it hands out producing exactly what
//! `Gmac::new` and `AES_GCM_*` over AAD alone produce from the same bytes.

use bouncycastle_aes::hazmat::{AES128Internal, AES192Internal};
use bouncycastle_aes::{
    AES_GCM_128, AES_GMAC_128, AES_GMAC_192, AES_GMAC_256, AES128Key, AES192Key, AES256Key,
};
use bouncycastle_cipher::modes::{GCM, GCM_NONCE_LEN, GMAC, GcmKeyState, Gmac};
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::FromKeyMaterial;
use bouncycastle_core::traits::AEADCipherEncryptor;
use bouncycastle_core_test_framework::FixedSeedRNG;

const NONCE: [u8; GCM_NONCE_LEN] = [0x5A; GCM_NONCE_LEN];
const MSG: &[u8] = b"The quick brown fox jumps over the lazy dog";

fn material<const N: usize>(fill: u8, key_type: KeyType) -> KeyMaterial<N> {
    KeyMaterial::<N>::from_bytes_as_type(&[fill; N], key_type).expect("key material")
}

fn rng() -> FixedSeedRNG<GCM_NONCE_LEN> {
    FixedSeedRNG::new(NONCE)
}

/// The key object, the material constructor and GCM over AAD alone give one tag, at every key
/// length and through both generator constructors.
#[test]
fn the_key_and_the_other_routes_agree_at_every_key_length() {
    macro_rules! agree {
        ($key:ty, $alias:ident, $klen:literal, $fill:literal) => {{
            let mac_key = material::<$klen>($fill, KeyType::MACKey);
            let key = <$key>::from_key_material(&mac_key).unwrap();
            let (gen_, nonce) = key.create_generator(&mut rng()).unwrap();
            assert_eq!(nonce, NONCE);
            let tag = gen_.mac(MSG);
            assert_eq!(
                key.create_generator_nonce(&NONCE).mac(MSG),
                tag,
                "{} supplied nonce",
                $klen
            );
            assert_eq!(
                $alias::<Encrypting>::new_nonce(&mac_key, &NONCE).unwrap().mac(MSG),
                tag,
                "{} Gmac::new_nonce",
                $klen
            );
            let (gen_, nonce) = $alias::<Encrypting>::new(&mac_key, &mut rng()).unwrap();
            assert_eq!((nonce, gen_.mac(MSG)), (NONCE, tag), "{} Gmac::new", $klen);
            assert!(key.create_verifier(&NONCE).verify(MSG, &tag));
            assert!(!key.create_verifier(&NONCE).verify(b"another message", &tag));
            assert!($alias::<Decrypting>::new(&mac_key, &NONCE).unwrap().verify(MSG, &tag));
            tag
        }};
    }
    let tag128 = agree!(AES128Key<GMAC>, AES_GMAC_128, 16, 0x11);
    agree!(AES192Key<GMAC>, AES_GMAC_192, 24, 0x22);
    agree!(AES256Key<GMAC>, AES_GMAC_256, 32, 0x33);

    // And GCM over the same bytes as a cipher key, with the message as AAD and no payload.
    let (nonce, _, from_gcm) = AES_GCM_128::<Encrypting>::encrypt_detached_rng_out(
        &material::<16>(0x11, KeyType::SymmetricCipherKey),
        &mut rng(),
        MSG,
        &[],
        &mut [],
    )
    .unwrap();
    assert_eq!((nonce, from_gcm), (NONCE, tag128));
}

/// A 96-bit-tag key gives the 128-bit tag's prefix.
#[test]
fn a_shorter_tag_is_the_prefix() {
    let k = material::<16>(0x44, KeyType::MACKey);
    let full =
        AES128Key::<GMAC>::from_key_material(&k).unwrap().create_generator_nonce(&NONCE).mac(MSG);
    let short = AES128Key::<GMAC<12>>::from_key_material(&k).unwrap();
    assert_eq!(short.create_generator_nonce(&NONCE).mac(MSG)[..], full[..12]);
    assert!(short.create_verifier(&NONCE).verify(MSG, full[..12].try_into().unwrap()));
}

/// Workers from one key are independent of each other and leave the key as it was.
#[test]
fn several_workers_from_one_key_are_independent_and_the_key_is_unchanged() {
    let key = AES256Key::<GMAC>::from_key_material(&material::<32>(0x55, KeyType::MACKey)).unwrap();
    let expected = key.create_generator_nonce(&NONCE).mac(MSG);

    let mut a = key.create_generator_nonce(&NONCE);
    let mut b = key.create_generator_nonce(&NONCE);
    let mut v = key.create_verifier(&NONCE);
    a.do_update(&MSG[..10]);
    b.do_update(&MSG[..20]);
    v.do_update(&MSG[..30]);
    a.do_update(&MSG[10..]);
    v.do_update(&MSG[30..]);
    b.do_update(&MSG[20..]);
    assert_eq!(b.do_final(), expected);
    assert!(v.do_verify_final(&expected));
    assert_eq!(a.do_final(), expected);
    assert_eq!(key.create_generator_nonce(&NONCE).mac(MSG), expected);
}

/// Two draws from one RNG are two nonces, and so two tags.
#[test]
fn a_fresh_nonce_per_generator() {
    let key = AES128Key::<GMAC>::from_key_material(&material::<16>(0x66, KeyType::MACKey)).unwrap();
    let mut rng = FixedSeedRNG::<64>::new(core::array::from_fn(|i| i as u8));
    let (g1, n1) = key.create_generator(&mut rng).unwrap();
    let (g2, n2) = key.create_generator(&mut rng).unwrap();
    assert_ne!(n1, n2);
    assert_ne!(g1.mac(MSG), g2.mac(MSG));
}

/// A GMAC key is `MACKey` material: a cipher key is refused, and the same bytes tagged `MACKey`
/// are refused by the GCM key, so one key cannot be both.
#[test]
fn a_cipher_key_is_refused_and_a_mac_key_is_not_a_gcm_key() {
    let cipher_key = material::<16>(0x77, KeyType::SymmetricCipherKey);
    assert!(matches!(
        AES128Key::<GMAC>::from_key_material(&cipher_key),
        Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_)))
    ));
    let mac_key = material::<16>(0x77, KeyType::MACKey);
    assert!(matches!(
        AES128Key::<GCM>::from_key_material(&mac_key),
        Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_)))
    ));
    assert_eq!(AES128Key::<GMAC>::KEY_TYPE, KeyType::MACKey);
}

#[test]
fn a_key_below_its_own_strength_is_refused_at_construction() {
    let mut weak = material::<32>(0x88, KeyType::MACKey);
    weak.set_security_strength(SecurityStrength::_128bit).unwrap();
    assert!(matches!(
        AES256Key::<GMAC>::from_key_material(&weak),
        Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::SecurityStrength(_)))
    ));
    assert!(matches!(
        AES_GMAC_256::<Encrypting>::new_nonce(&weak, &NONCE),
        Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::SecurityStrength(_)))
    ));
}

#[test]
fn generate_draws_a_mac_key() {
    let mut rng = FixedSeedRNG::<32>::new([0x24u8; 32]);
    let key = AES256Key::<GMAC>::generate(&mut rng).unwrap();
    let tag = key.create_generator_nonce(&NONCE).mac(MSG);
    assert!(key.create_verifier(&NONCE).verify(MSG, &tag));
}

/// The sizes the docs quote: a GMAC key is a GCM key, and a worker is a `Gcm`.
#[test]
fn sizes() {
    use core::mem::size_of;
    assert_eq!(size_of::<AES128Key<GMAC>>(), size_of::<GcmKeyState<AES128Internal>>());
    assert_eq!(
        [size_of::<AES128Key<GMAC>>(), size_of::<AES192Key<GMAC>>(), size_of::<AES256Key<GMAC>>()],
        [192, 224, 256]
    );
    assert_eq!(size_of::<AES128Key<GMAC>>(), size_of::<AES128Key<GCM>>());
    assert_eq!(size_of::<AES_GMAC_128<Encrypting>>(), size_of::<AES_GCM_128<Encrypting>>());
    assert_eq!(
        size_of::<AES_GMAC_192<Decrypting>>(),
        size_of::<Gmac<AES192Internal, Decrypting, 24, 16>>()
    );
}
