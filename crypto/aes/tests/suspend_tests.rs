//! Suspend-and-resume round trips through the AES aliases.
//!
//! The impls live on the generic modes in `bouncycastle-cipher`, where they are tested over a
//! toy permutation; what is checked here is that each alias reaches them with the right key
//! type. The engine itself has no state and nothing to suspend: a resumed mode rebuilds it from
//! the re-supplied key. The test does part of an operation, suspends a clone, resumes it, and
//! finishes both the same way.

use bouncycastle_aes::hazmat::AES_ECB_128;
use bouncycastle_aes::{
    AES_CBC_128, AES_CCM_128, AES_CFB_128, AES_CFB8_128, AES_CTR_128, AES_GCM_128,
};
use bouncycastle_cipher::Encrypting;
use bouncycastle_cipher::padding::PKCS7;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{
    AEADCipherEncryptor, StreamCipherEncryptor, SuspendableKeyed, SymmetricCipherEncryptor,
};
use bouncycastle_core_test_framework::suspendable_state::TestFrameworkSuspendableKeyedState;

fn key() -> KeyMaterial<16> {
    KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap()
}

fn round_trip<const N: usize, C>(cipher: C, finish: impl Fn(C) -> Vec<u8>) -> Vec<u8>
where
    C: SuspendableKeyed<N, Key = KeyMaterial<16>> + Clone,
{
    let key = key();
    TestFrameworkSuspendableKeyedState::new().test(&cipher, &key);
    let resumed = C::from_suspended(cipher.clone().suspend(), &key).unwrap();
    let original_output = finish(cipher);
    assert_eq!(original_output, finish(resumed), "the resumed cipher must continue identically");
    original_output
}

#[test]
fn every_alias_family_is_suspendable() {
    type CbcEnc = AES_CBC_128<Encrypting, PKCS7>;
    let (mut cbc, _) = CbcEnc::do_encrypt_init(&key()).unwrap();
    cbc.do_encrypt_out(&[0x11u8; 20], &mut [0u8; 16]).unwrap();
    round_trip::<{ CbcEnc::SUSPENDED_STATE_LEN }, _>(cbc, |mut e| {
        let mut out = [0u8; 16];
        e.do_encrypt_out(&[0x22u8; 12], &mut out).unwrap();
        let (last, n) = e.do_final().unwrap();
        [out.as_slice(), &last[..n]].concat()
    });

    type EcbEnc = AES_ECB_128<Encrypting, PKCS7>;
    let (mut ecb, _) = EcbEnc::do_encrypt_init(&key()).unwrap();
    ecb.do_encrypt_out(&[0x11u8; 20], &mut [0u8; 16]).unwrap();
    round_trip::<{ EcbEnc::SUSPENDED_STATE_LEN }, _>(ecb, |e| {
        let (last, n) = e.do_final().unwrap();
        last[..n].to_vec()
    });

    let (mut cfb, _) = AES_CFB_128::<Encrypting>::do_encrypt_init(&key()).unwrap();
    cfb.do_encrypt(&mut [0x11u8; 7]).unwrap();
    round_trip::<{ AES_CFB_128::<Encrypting>::SUSPENDED_STATE_LEN }, _>(cfb, |mut e| {
        let mut data = [0x22u8; 25];
        e.do_encrypt(&mut data).unwrap();
        data.to_vec()
    });

    let (mut cfb8, _) = AES_CFB8_128::<Encrypting>::do_encrypt_init(&key()).unwrap();
    cfb8.do_encrypt(&mut [0x11u8; 7]).unwrap();
    round_trip::<{ AES_CFB8_128::<Encrypting>::SUSPENDED_STATE_LEN }, _>(cfb8, |mut e| {
        let mut data = [0x22u8; 9];
        e.do_encrypt(&mut data).unwrap();
        data.to_vec()
    });

    let (mut ctr, _) = AES_CTR_128::<Encrypting>::do_encrypt_init(&key()).unwrap();
    ctr.do_encrypt(&mut [0x11u8; 7]).unwrap();
    round_trip::<{ AES_CTR_128::<Encrypting>::SUSPENDED_STATE_LEN }, _>(ctr, |mut e| {
        let mut data = [0x22u8; 25];
        e.do_encrypt(&mut data).unwrap();
        data.to_vec()
    });

    let (mut gcm, _) = AES_GCM_128::<Encrypting>::do_encrypt_init(&key()).unwrap();
    gcm.do_update_aad(b"header").unwrap();
    gcm.do_encrypt_out(&[0x11u8; 7], &mut [0u8; 7]).unwrap();
    round_trip::<{ AES_GCM_128::<Encrypting>::SUSPENDED_STATE_LEN }, _>(gcm, |mut e| {
        let mut out = [0u8; 25];
        e.do_encrypt_out(&[0x22u8; 25], &mut out).unwrap();
        let (tag, n) = e.do_final().unwrap();
        [out.as_slice(), &tag[..n]].concat()
    });

    type CcmEnc = AES_CCM_128<Encrypting, 12, 16>;
    let mut ccm = CcmEnc::new(&key(), &[0x24u8; 12], b"header", 32).unwrap();
    ccm.do_encrypt(&mut [0x11u8; 7]).unwrap();
    round_trip::<{ CcmEnc::SUSPENDED_STATE_LEN }, _>(ccm, |mut e| {
        let mut data = [0x22u8; 25];
        e.do_encrypt(&mut data).unwrap();
        [data.as_slice(), &e.do_encrypt_final().unwrap()].concat()
    });
}
