//! Suspend-and-resume round trips through the AES aliases.
//!
//! The impls live on the generic modes in `bouncycastle-cipher`, where they are tested over a
//! toy permutation; what is checked here is that each alias, made from its key, reaches them and
//! resumes from the key's material. The engine itself has no state and nothing to suspend: a
//! resumed mode rebuilds it from the re-supplied material. The test does part of an operation,
//! suspends a clone, resumes it, and finishes both the same way.

use bouncycastle_aes::hazmat::{AES_ECB_128, AES128Internal};
use bouncycastle_aes::{
    AES_CBC_128, AES_CCM_128, AES_CFB_128, AES_CFB8_128, AES_CTR_128, AES_GCM_128, AES128Key,
};
use bouncycastle_cipher::Encrypting;
use bouncycastle_cipher::modes::hazmat::ECB;
use bouncycastle_cipher::modes::{CBC, CCMFrame, CFB, CFB8, CTR, GCM};
use bouncycastle_cipher::padding::PKCS7;
use bouncycastle_core::hazmat::Mode;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{
    AeadEncryptionKey, FromKeyMaterial, SymmetricEncryptionKey,
};
use bouncycastle_core::traits::{
    AEADCipherEncryptor, StreamCipherEncryptor, SuspendableKeyed, SymmetricCipherEncryptor,
};
use bouncycastle_core_test_framework::suspendable_state::TestFrameworkSuspendableKeyedState;
use bouncycastle_rng::HashDRBG_SHA512;

fn material() -> KeyMaterial<16> {
    KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap()
}

/// The key under the mode `M`; resume still takes the material, through `material()`.
fn key_for<M: Mode<AES128Internal>>() -> AES128Key<M> {
    AES128Key::from_key_material(&material()).expect("a valid key")
}

fn rng() -> HashDRBG_SHA512 {
    HashDRBG_SHA512::new_from_os()
}

fn round_trip<const N: usize, C>(cipher: C, finish: impl Fn(C) -> Vec<u8>) -> Vec<u8>
where
    C: SuspendableKeyed<N, Key = KeyMaterial<16>> + Clone,
{
    let material = material();
    TestFrameworkSuspendableKeyedState::new().test(&cipher, &material);
    let resumed = C::from_suspended(cipher.clone().suspend(), &material).unwrap();
    let original_output = finish(cipher);
    assert_eq!(original_output, finish(resumed), "the resumed cipher must continue identically");
    original_output
}

#[test]
fn every_alias_family_is_suspendable() {
    type CbcEnc = AES_CBC_128<Encrypting, PKCS7>;
    let (mut cbc, _) = key_for::<CBC<PKCS7>>().create_encryptor(&mut rng()).unwrap();
    cbc.do_encrypt_out(&[0x11u8; 20], &mut [0u8; 16]).unwrap();
    round_trip::<{ CbcEnc::SUSPENDED_STATE_LEN }, _>(cbc, |mut e| {
        let mut out = [0u8; 16];
        e.do_encrypt_out(&[0x22u8; 12], &mut out).unwrap();
        let (last, n) = e.do_encrypt_final().unwrap();
        [out.as_slice(), &last[..n]].concat()
    });

    type EcbEnc = AES_ECB_128<Encrypting, PKCS7>;
    let (mut ecb, _) = key_for::<ECB<PKCS7>>().create_encryptor(&mut rng()).unwrap();
    ecb.do_encrypt_out(&[0x11u8; 20], &mut [0u8; 16]).unwrap();
    round_trip::<{ EcbEnc::SUSPENDED_STATE_LEN }, _>(ecb, |e| {
        let (last, n) = e.do_encrypt_final().unwrap();
        last[..n].to_vec()
    });

    let (mut cfb, _) = key_for::<CFB>().create_encryptor(&mut rng()).unwrap();
    cfb.do_encrypt_inplace(&mut [0x11u8; 7]).unwrap();
    round_trip::<{ AES_CFB_128::<Encrypting>::SUSPENDED_STATE_LEN }, _>(cfb, |mut e| {
        let mut data = [0x22u8; 25];
        e.do_encrypt_inplace(&mut data).unwrap();
        data.to_vec()
    });

    let (mut cfb8, _) = key_for::<CFB8>().create_encryptor(&mut rng()).unwrap();
    cfb8.do_encrypt_inplace(&mut [0x11u8; 7]).unwrap();
    round_trip::<{ AES_CFB8_128::<Encrypting>::SUSPENDED_STATE_LEN }, _>(cfb8, |mut e| {
        let mut data = [0x22u8; 9];
        e.do_encrypt_inplace(&mut data).unwrap();
        data.to_vec()
    });

    let (mut ctr, _) = key_for::<CTR>().create_encryptor(&mut rng()).unwrap();
    ctr.do_encrypt_inplace(&mut [0x11u8; 7]).unwrap();
    round_trip::<{ AES_CTR_128::<Encrypting>::SUSPENDED_STATE_LEN }, _>(ctr, |mut e| {
        let mut data = [0x22u8; 25];
        e.do_encrypt_inplace(&mut data).unwrap();
        data.to_vec()
    });

    let (mut gcm, _) = key_for::<GCM>().create_encryptor(&mut rng()).unwrap();
    gcm.do_update_aad(b"header").unwrap();
    gcm.do_encrypt_out(&[0x11u8; 7], &mut [0u8; 7]).unwrap();
    round_trip::<{ AES_GCM_128::<Encrypting>::SUSPENDED_STATE_LEN }, _>(gcm, |mut e| {
        let mut out = [0u8; 25];
        e.do_encrypt_out(&[0x22u8; 25], &mut out).unwrap();
        let (tag, n) = e.do_encrypt_final().unwrap();
        [out.as_slice(), &tag[..n]].concat()
    });

    type CcmEnc = AES_CCM_128<Encrypting, 12, 16, 64, 32>;
    let mut ccm = key_for::<CCMFrame<12, 16, 64, 32>>().create_encryptor_nonce(&[0x24u8; 12]);
    ccm.do_update_aad(b"header").unwrap();
    let mut head = [0u8; 7];
    ccm.do_encrypt_out(&[0x11u8; 7], &mut head).unwrap();
    round_trip::<{ CcmEnc::SUSPENDED_STATE_LEN }, _>(ccm, |mut e| {
        let mut out = [0u8; 25];
        e.do_encrypt_out(&[0x22u8; 25], &mut out).unwrap();
        let (tag, n) = e.do_encrypt_final().unwrap();
        [out.as_slice(), &tag[..n]].concat()
    });
}
