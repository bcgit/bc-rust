//! Suspend-and-resume round trips through the AES aliases.
//!
//! The impls live on the generic modes in `bouncycastle-cipher`, where they are tested over a
//! toy permutation; what is checked here is that each alias, at each key length, reaches them with
//! the right key type. The engine itself has no state and nothing to suspend: a resumed mode
//! rebuilds it from the re-supplied key. The test does part of an operation, suspends a clone,
//! resumes it, and finishes both the same way.

use bouncycastle_aes::hazmat::{
    AES_ECB_128, AES_ECB_128_Key, AES_ECB_192, AES_ECB_192_Key, AES_ECB_256, AES_ECB_256_Key,
};
use bouncycastle_aes::{
    AES_CBC_128, AES_CBC_128_Key, AES_CBC_192, AES_CBC_192_Key, AES_CBC_256, AES_CBC_256_Key,
    AES_CCM_128_Key, AES_CCM_128_Packet, AES_CCM_192_Key, AES_CCM_192_Packet, AES_CCM_256_Key,
    AES_CCM_256_Packet, AES_CFB_128, AES_CFB_128_Key, AES_CFB_192, AES_CFB_192_Key, AES_CFB_256,
    AES_CFB_256_Key, AES_CFB8_128, AES_CFB8_128_Key, AES_CFB8_192, AES_CFB8_192_Key, AES_CFB8_256,
    AES_CFB8_256_Key, AES_CTR_128, AES_CTR_128_Key, AES_CTR_192, AES_CTR_192_Key, AES_CTR_256,
    AES_CTR_256_Key, AES_GCM_128, AES_GCM_128_Key, AES_GCM_192, AES_GCM_192_Key, AES_GCM_256,
    AES_GCM_256_Key,
};
use bouncycastle_cipher::Encrypting;
use bouncycastle_cipher::padding::PKCS7;
use bouncycastle_core::traits::{
    AEADCipherEncryptor, StreamCipherEncryptor, SuspendableKeyed, SymmetricCipherEncryptor,
    SymmetricCipherKey,
};
use bouncycastle_core_test_framework::suspendable_state::TestFrameworkSuspendableKeyedState;

/// The same `K` bytes wrapped as whichever alias's key type is asked for.
fn key<Key: SymmetricCipherKey<K>, const K: usize>() -> Key {
    Key::from_bytes(&[0x42; K]).unwrap()
}

fn round_trip<const N: usize, const K: usize, C>(
    cipher: C,
    finish: impl Fn(C) -> Vec<u8>,
) -> Vec<u8>
where
    C: SuspendableKeyed<N> + Clone,
    C::Key: SymmetricCipherKey<K>,
{
    let key = key::<C::Key, K>();
    TestFrameworkSuspendableKeyedState::new().test(&cipher, &key);
    let resumed = C::from_suspended(cipher.clone().suspend(), &key).unwrap();
    let original_output = finish(cipher);
    assert_eq!(original_output, finish(resumed), "the resumed cipher must continue identically");
    original_output
}

/// Runs every alias family at one key length, each `alias / key type` pair keyed with that
/// family's own key type. The families are built and finished differently, and each needs its own
/// `SUSPENDED_STATE_LEN` as a const argument, which a generic function cannot take from a type
/// parameter; so the per-size repetition is a macro.
macro_rules! every_alias_family_is_suspendable {
    (
        $k:literal,
        $cbc:ident / $cbc_key:ident,
        $ecb:ident / $ecb_key:ident,
        $cfb:ident / $cfb_key:ident,
        $cfb8:ident / $cfb8_key:ident,
        $ctr:ident / $ctr_key:ident,
        $gcm:ident / $gcm_key:ident,
        $ccm:ident / $ccm_key:ident $(,)?
    ) => {{
        type CbcEnc = $cbc<Encrypting, PKCS7>;
        let (mut cbc, _) = CbcEnc::do_encrypt_init(&key::<$cbc_key, $k>()).unwrap();
        cbc.do_encrypt_out(&[0x11u8; 20], &mut [0u8; 16]).unwrap();
        round_trip::<{ CbcEnc::SUSPENDED_STATE_LEN }, $k, _>(cbc, |mut e| {
            let mut out = [0u8; 16];
            e.do_encrypt_out(&[0x22u8; 12], &mut out).unwrap();
            let (last, n) = e.do_encrypt_final().unwrap();
            [out.as_slice(), &last[..n]].concat()
        });

        type EcbEnc = $ecb<Encrypting, PKCS7>;
        let (mut ecb, _) = EcbEnc::do_encrypt_init(&key::<$ecb_key, $k>()).unwrap();
        ecb.do_encrypt_out(&[0x11u8; 20], &mut [0u8; 16]).unwrap();
        round_trip::<{ EcbEnc::SUSPENDED_STATE_LEN }, $k, _>(ecb, |e| {
            let (last, n) = e.do_encrypt_final().unwrap();
            last[..n].to_vec()
        });

        let (mut cfb, _) = $cfb::<Encrypting>::do_encrypt_init(&key::<$cfb_key, $k>()).unwrap();
        cfb.do_encrypt_inplace(&mut [0x11u8; 7]).unwrap();
        round_trip::<{ $cfb::<Encrypting>::SUSPENDED_STATE_LEN }, $k, _>(cfb, |mut e| {
            let mut data = [0x22u8; 25];
            e.do_encrypt_inplace(&mut data).unwrap();
            data.to_vec()
        });

        let (mut cfb8, _) = $cfb8::<Encrypting>::do_encrypt_init(&key::<$cfb8_key, $k>()).unwrap();
        cfb8.do_encrypt_inplace(&mut [0x11u8; 7]).unwrap();
        round_trip::<{ $cfb8::<Encrypting>::SUSPENDED_STATE_LEN }, $k, _>(cfb8, |mut e| {
            let mut data = [0x22u8; 9];
            e.do_encrypt_inplace(&mut data).unwrap();
            data.to_vec()
        });

        let (mut ctr, _) = $ctr::<Encrypting>::do_encrypt_init(&key::<$ctr_key, $k>()).unwrap();
        ctr.do_encrypt_inplace(&mut [0x11u8; 7]).unwrap();
        round_trip::<{ $ctr::<Encrypting>::SUSPENDED_STATE_LEN }, $k, _>(ctr, |mut e| {
            let mut data = [0x22u8; 25];
            e.do_encrypt_inplace(&mut data).unwrap();
            data.to_vec()
        });

        let (mut gcm, _) = $gcm::<Encrypting>::do_encrypt_init(&key::<$gcm_key, $k>()).unwrap();
        gcm.do_update_aad(b"header").unwrap();
        gcm.do_encrypt_out(&[0x11u8; 7], &mut [0u8; 7]).unwrap();
        round_trip::<{ $gcm::<Encrypting>::SUSPENDED_STATE_LEN }, $k, _>(gcm, |mut e| {
            let mut out = [0u8; 25];
            e.do_encrypt_out(&[0x22u8; 25], &mut out).unwrap();
            let (tag, n) = e.do_encrypt_final().unwrap();
            [out.as_slice(), &tag[..n]].concat()
        });

        type CcmEnc = $ccm<Encrypting, 12, 16>;
        let mut ccm = CcmEnc::new(&key::<$ccm_key, $k>(), &[0x24u8; 12], b"header", 32).unwrap();
        ccm.do_encrypt_inplace(&mut [0x11u8; 7]).unwrap();
        round_trip::<{ CcmEnc::SUSPENDED_STATE_LEN }, $k, _>(ccm, |mut e| {
            let mut data = [0x22u8; 25];
            e.do_encrypt_inplace(&mut data).unwrap();
            [data.as_slice(), &e.do_encrypt_final().unwrap()].concat()
        });
    }};
}

#[test]
fn every_aes128_alias_family_is_suspendable() {
    every_alias_family_is_suspendable!(
        16,
        AES_CBC_128 / AES_CBC_128_Key,
        AES_ECB_128 / AES_ECB_128_Key,
        AES_CFB_128 / AES_CFB_128_Key,
        AES_CFB8_128 / AES_CFB8_128_Key,
        AES_CTR_128 / AES_CTR_128_Key,
        AES_GCM_128 / AES_GCM_128_Key,
        AES_CCM_128_Packet / AES_CCM_128_Key,
    );
}

#[test]
fn every_aes192_alias_family_is_suspendable() {
    every_alias_family_is_suspendable!(
        24,
        AES_CBC_192 / AES_CBC_192_Key,
        AES_ECB_192 / AES_ECB_192_Key,
        AES_CFB_192 / AES_CFB_192_Key,
        AES_CFB8_192 / AES_CFB8_192_Key,
        AES_CTR_192 / AES_CTR_192_Key,
        AES_GCM_192 / AES_GCM_192_Key,
        AES_CCM_192_Packet / AES_CCM_192_Key,
    );
}

#[test]
fn every_aes256_alias_family_is_suspendable() {
    every_alias_family_is_suspendable!(
        32,
        AES_CBC_256 / AES_CBC_256_Key,
        AES_ECB_256 / AES_ECB_256_Key,
        AES_CFB_256 / AES_CFB_256_Key,
        AES_CFB8_256 / AES_CFB8_256_Key,
        AES_CTR_256 / AES_CTR_256_Key,
        AES_GCM_256 / AES_GCM_256_Key,
        AES_CCM_256_Packet / AES_CCM_256_Key,
    );
}
