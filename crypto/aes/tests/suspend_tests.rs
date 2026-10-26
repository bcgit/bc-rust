//! Suspend-and-resume round trips through the AES aliases.
//!
//! The impls live on the generic modes in `bouncycastle-cipher`, where they are tested over a
//! toy permutation; what is checked here is that each alias, at each key length, made from its
//! key, reaches them and resumes from the key's state. The engine itself has no state and nothing
//! to suspend: a resumed mode rebuilds it from the re-supplied key. The test does part of an
//! operation, suspends a clone, resumes it, and finishes both the same way.

use bouncycastle_aes::hazmat::{AES_ECB_128, AES_ECB_192, AES_ECB_256};
use bouncycastle_aes::{
    AES_CBC_128, AES_CBC_192, AES_CBC_256, AES_CCM_128, AES_CCM_192, AES_CCM_256, AES_CFB_128,
    AES_CFB_192, AES_CFB_256, AES_CFB8_128, AES_CFB8_192, AES_CFB8_256, AES_CTR_128, AES_CTR_192,
    AES_CTR_256, AES_GCM_128, AES_GCM_192, AES_GCM_256, AES128Key, AES192Key, AES256Key,
};
use bouncycastle_cipher::Encrypting;
use bouncycastle_cipher::modes::hazmat::ecb::ECB;
use bouncycastle_cipher::modes::{CBC, CCM_Packet, CFB, CFB8, CTR, GCM};
use bouncycastle_cipher::padding::PKCS7;
use bouncycastle_core::hazmat::ModeKey;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{
    AeadEncryptionKey, FromKeyMaterial, SymmetricEncryptionKey,
};
use bouncycastle_core::traits::{
    AEADCipherEncryptor, StreamCipherEncryptor, SuspendableKeyed, SymmetricCipherEncryptor,
};
use bouncycastle_core_test_framework::suspendable_state::TestFrameworkSuspendableKeyedState;
use bouncycastle_rng::HashDRBG_SHA512;

fn material<const K: usize>() -> KeyMaterial<K> {
    KeyMaterial::<K>::from_bytes_as_type(&[0x42; K], KeyType::SymmetricCipherKey).unwrap()
}

/// The key under a mode, at key length `K`; its workers borrow it, and resume takes its state.
fn key_for<const K: usize, Key: FromKeyMaterial<K>>() -> Key {
    Key::from_key_material(&material::<K>()).expect("a valid key")
}

fn rng() -> HashDRBG_SHA512 {
    HashDRBG_SHA512::new_from_os()
}

fn round_trip<'k, const N: usize, C>(
    cipher: C,
    key: &'k C::Key,
    finish: impl Fn(C) -> Vec<u8>,
) -> Vec<u8>
where
    C: SuspendableKeyed<'k, N> + Clone,
{
    TestFrameworkSuspendableKeyedState::new().test(&cipher, key);
    let resumed = C::from_suspended(cipher.clone().suspend(), key).unwrap();
    let original_output = finish(cipher);
    assert_eq!(original_output, finish(resumed), "the resumed cipher must continue identically");
    original_output
}

/// Runs every alias family at one key length. The families are built and finished differently,
/// and each needs its own `SUSPENDED_STATE_LEN` as a const argument, which a generic function
/// cannot take from a type parameter; so the per-size repetition is a macro.
macro_rules! every_alias_family_is_suspendable {
    ($k:literal, $key:ident, $cbc:ident, $ecb:ident, $cfb:ident, $cfb8:ident, $ctr:ident, $gcm:ident, $ccm:ident) => {{
        type CbcEnc<'k> = $cbc<'k, Encrypting, PKCS7>;
        let key = key_for::<$k, $key<CBC<PKCS7>>>();
        let (mut cbc, _) = key.create_encryptor(&mut rng()).unwrap();
        cbc.do_encrypt_out(&[0x11u8; 20], &mut [0u8; 16]).unwrap();
        round_trip::<{ CbcEnc::SUSPENDED_STATE_LEN }, _>(cbc, key.state(), |mut e| {
            let mut out = [0u8; 16];
            e.do_encrypt_out(&[0x22u8; 12], &mut out).unwrap();
            let (last, n) = e.do_encrypt_final().unwrap();
            [out.as_slice(), &last[..n]].concat()
        });

        type EcbEnc<'k> = $ecb<'k, Encrypting, PKCS7>;
        let key = key_for::<$k, $key<ECB<PKCS7>>>();
        let (mut ecb, _) = key.create_encryptor(&mut rng()).unwrap();
        ecb.do_encrypt_out(&[0x11u8; 20], &mut [0u8; 16]).unwrap();
        round_trip::<{ EcbEnc::SUSPENDED_STATE_LEN }, _>(ecb, key.state(), |e| {
            let (last, n) = e.do_encrypt_final().unwrap();
            last[..n].to_vec()
        });

        let key = key_for::<$k, $key<CFB>>();
        let (mut cfb, _) = key.create_encryptor(&mut rng()).unwrap();
        cfb.do_encrypt_inplace(&mut [0x11u8; 7]).unwrap();
        round_trip::<{ $cfb::<Encrypting>::SUSPENDED_STATE_LEN }, _>(cfb, key.state(), |mut e| {
            let mut data = [0x22u8; 25];
            e.do_encrypt_inplace(&mut data).unwrap();
            data.to_vec()
        });

        let key = key_for::<$k, $key<CFB8>>();
        let (mut cfb8, _) = key.create_encryptor(&mut rng()).unwrap();
        cfb8.do_encrypt_inplace(&mut [0x11u8; 7]).unwrap();
        round_trip::<{ $cfb8::<Encrypting>::SUSPENDED_STATE_LEN }, _>(
            cfb8,
            key.state(),
            |mut e| {
                let mut data = [0x22u8; 9];
                e.do_encrypt_inplace(&mut data).unwrap();
                data.to_vec()
            },
        );

        let key = key_for::<$k, $key<CTR>>();
        let (mut ctr, _) = key.create_encryptor(&mut rng()).unwrap();
        ctr.do_encrypt_inplace(&mut [0x11u8; 7]).unwrap();
        round_trip::<{ $ctr::<Encrypting>::SUSPENDED_STATE_LEN }, _>(ctr, key.state(), |mut e| {
            let mut data = [0x22u8; 25];
            e.do_encrypt_inplace(&mut data).unwrap();
            data.to_vec()
        });

        let key = key_for::<$k, $key<GCM>>();
        let (mut gcm, _) = key.create_encryptor(&mut rng()).unwrap();
        gcm.do_update_aad(b"header").unwrap();
        gcm.do_encrypt_out(&[0x11u8; 7], &mut [0u8; 7]).unwrap();
        round_trip::<{ $gcm::<Encrypting>::SUSPENDED_STATE_LEN }, _>(gcm, key.state(), |mut e| {
            let mut out = [0u8; 25];
            e.do_encrypt_out(&[0x22u8; 25], &mut out).unwrap();
            let (tag, n) = e.do_encrypt_final().unwrap();
            [out.as_slice(), &tag[..n]].concat()
        });

        type CcmEnc<'k> = $ccm<'k, Encrypting, 12, 16, 64, 32>;
        let key = key_for::<$k, $key<CCM_Packet<12, 16, 64, 32>>>();
        let mut ccm = key.create_encryptor_nonce(&[0x24u8; 12]);
        ccm.do_update_aad(b"header").unwrap();
        let mut head = [0u8; 7];
        ccm.do_encrypt_out(&[0x11u8; 7], &mut head).unwrap();
        round_trip::<{ CcmEnc::SUSPENDED_STATE_LEN }, _>(ccm, key.state(), |mut e| {
            let mut out = [0u8; 25];
            e.do_encrypt_out(&[0x22u8; 25], &mut out).unwrap();
            let (tag, n) = e.do_encrypt_final().unwrap();
            [out.as_slice(), &tag[..n]].concat()
        });
    }};
}

#[test]
fn every_aes128_alias_family_is_suspendable() {
    every_alias_family_is_suspendable!(
        16, AES128Key, AES_CBC_128, AES_ECB_128, AES_CFB_128, AES_CFB8_128, AES_CTR_128,
        AES_GCM_128, AES_CCM_128
    );
}

#[test]
fn every_aes192_alias_family_is_suspendable() {
    every_alias_family_is_suspendable!(
        24, AES192Key, AES_CBC_192, AES_ECB_192, AES_CFB_192, AES_CFB8_192, AES_CTR_192,
        AES_GCM_192, AES_CCM_192
    );
}

#[test]
fn every_aes256_alias_family_is_suspendable() {
    every_alias_family_is_suspendable!(
        32, AES256Key, AES_CBC_256, AES_ECB_256, AES_CFB_256, AES_CFB8_256, AES_CTR_256,
        AES_GCM_256, AES_CCM_256
    );
}
