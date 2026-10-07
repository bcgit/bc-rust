//! Suspend-and-resume round trips for every mode and adapter, over the test framework's toy
//! permutation.
//!
//! Each test does part of an operation, suspends a clone of the cipher, resumes it with the
//! re-supplied key, and then finishes both the original and the resumed cipher the same way. The
//! two must agree byte for byte, which is the whole contract: a resumed cipher is the suspended
//! one, continued. The shared framework suite runs once per type for the version-header rules.
//! The AES aliases get the same impls through these generic types, so this is where they are
//! pinned; `bouncycastle-aes` only checks that each alias reaches them.

use bouncycastle_cipher::modes::hazmat::Ecb;
use bouncycastle_cipher::modes::{Cbc, Ccm, Cfb, Cfb8, Ctr, Gcm};
use bouncycastle_cipher::padding::{PKCS7, PaddedBlockCipherDecryptor, PaddedBlockCipherEncryptor};
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, BlockCipherDecryptor, BlockCipherEncryptor,
    StreamCipherDecryptor, StreamCipherEncryptor, SuspendableKeyed, SymmetricCipherDecryptor,
    SymmetricCipherEncryptor, SymmetricCipherKey,
};
use bouncycastle_core_test_framework::suspendable_state::TestFrameworkSuspendableKeyedState;
use bouncycastle_core_test_framework::{ToyBlockCipher, ToyCipherKey};

type ToyEcb<Dir> = Ecb<ToyBlockCipher, Dir, ToyCipherKey, 16, 16>;
type ToyCbc<Dir> = Cbc<ToyBlockCipher, Dir, ToyCipherKey, 16, 16>;
type ToyCfb<Dir> = Cfb<ToyBlockCipher, Dir, ToyCipherKey, 16, 16>;
type ToyCfb8<Dir> = Cfb8<ToyBlockCipher, Dir, ToyCipherKey, 16, 16>;
type ToyCtr<Dir> = Ctr<ToyBlockCipher, Dir, ToyCipherKey, 16, 16, 12>;
type ToyGcm<Dir> = Gcm<ToyBlockCipher, Dir, ToyCipherKey, 16, 16>;
type ToyCcm<Dir> = Ccm<ToyBlockCipher, Dir, ToyCipherKey, 16, 16, 12, 16>;
type ToyPaddedEnc = PaddedBlockCipherEncryptor<ToyCbc<Encrypting>, PKCS7, ToyCipherKey, 16, 16, 16>;
type ToyPaddedDec = PaddedBlockCipherDecryptor<ToyCbc<Decrypting>, PKCS7, ToyCipherKey, 16, 16, 16>;

fn key() -> ToyCipherKey {
    ToyCipherKey::from_bytes(&[0x42; 16]).unwrap()
}

fn message(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(7).wrapping_add(3)).collect()
}

/// Runs the framework suite on `cipher`, then suspends a clone, resumes it, and finishes both
/// with `finish`. Whatever `finish` returns must be identical for the two.
fn round_trip<const N: usize, C>(cipher: C, finish: impl Fn(C) -> Vec<u8>) -> Vec<u8>
where
    C: SuspendableKeyed<N, Key = ToyCipherKey> + Clone,
{
    let key = key();
    TestFrameworkSuspendableKeyedState::new().test(&cipher, &key);
    let resumed = C::from_suspended(cipher.clone().suspend(), &key).unwrap();
    let original_output = finish(cipher);
    assert_eq!(original_output, finish(resumed), "the resumed cipher must continue identically");
    original_output
}

#[test]
fn cbc_both_directions() {
    let (mut enc, iv) = ToyCbc::<Encrypting>::do_encrypt_init(&key()).unwrap();
    let mut first = [0x11u8; 16];
    enc.do_encrypt_inplace(&mut first).unwrap();
    let rest = round_trip::<{ ToyCbc::<Encrypting>::SUSPENDED_STATE_LEN }, _>(enc, |mut e| {
        let mut data = [0x22u8; 48];
        e.do_encrypt_inplace(&mut data).unwrap();
        data.to_vec()
    });

    let mut dec = ToyCbc::<Decrypting>::do_decrypt_init(&key(), &iv).unwrap();
    dec.do_decrypt_inplace(&mut first).unwrap();
    assert_eq!(first, [0x11u8; 16]);
    let plain = round_trip::<{ ToyCbc::<Decrypting>::SUSPENDED_STATE_LEN }, _>(dec, |mut d| {
        let mut data: [u8; 48] = rest.as_slice().try_into().unwrap();
        d.do_decrypt_inplace(&mut data).unwrap();
        data.to_vec()
    });
    assert_eq!(plain, vec![0x22u8; 48]);
}

#[test]
fn ecb_both_directions() {
    let (mut enc, _) = ToyEcb::<Encrypting>::do_encrypt_init(&key()).unwrap();
    enc.do_encrypt_inplace(&mut [0x11u8; 16]).unwrap();
    round_trip::<{ ToyEcb::<Encrypting>::SUSPENDED_STATE_LEN }, _>(enc, |mut e| {
        let mut data = [0x22u8; 32];
        e.do_encrypt_inplace(&mut data).unwrap();
        data.to_vec()
    });
    let dec = ToyEcb::<Decrypting>::do_decrypt_init(&key(), &[]).unwrap();
    round_trip::<{ ToyEcb::<Decrypting>::SUSPENDED_STATE_LEN }, _>(dec, |mut d| {
        let mut data = [0x33u8; 32];
        d.do_decrypt_inplace(&mut data).unwrap();
        data.to_vec()
    });
}

#[test]
fn cfb_mid_segment_both_directions() {
    let msg = message(40);
    let (mut enc, iv) = ToyCfb::<Encrypting>::do_encrypt_init(&key()).unwrap();
    let mut head = msg[..7].to_vec();
    enc.do_encrypt_inplace(&mut head).unwrap();
    let tail = round_trip::<{ ToyCfb::<Encrypting>::SUSPENDED_STATE_LEN }, _>(enc, |mut e| {
        let mut data = msg[7..].to_vec();
        e.do_encrypt_inplace(&mut data).unwrap();
        data
    });

    let mut dec = ToyCfb::<Decrypting>::do_decrypt_init(&key(), &iv).unwrap();
    dec.do_decrypt_inplace(&mut head).unwrap();
    assert_eq!(head, msg[..7]);
    let plain = round_trip::<{ ToyCfb::<Decrypting>::SUSPENDED_STATE_LEN }, _>(dec, |mut d| {
        let mut data = tail.clone();
        d.do_decrypt_inplace(&mut data).unwrap();
        data
    });
    assert_eq!(plain, msg[7..]);
}

#[test]
fn cfb8_both_directions() {
    let msg = message(20);
    let (mut enc, iv) = ToyCfb8::<Encrypting>::do_encrypt_init(&key()).unwrap();
    let mut head = msg[..5].to_vec();
    enc.do_encrypt_inplace(&mut head).unwrap();
    let tail = round_trip::<{ ToyCfb8::<Encrypting>::SUSPENDED_STATE_LEN }, _>(enc, |mut e| {
        let mut data = msg[5..].to_vec();
        e.do_encrypt_inplace(&mut data).unwrap();
        data
    });
    let mut dec = ToyCfb8::<Decrypting>::do_decrypt_init(&key(), &iv).unwrap();
    dec.do_decrypt_inplace(&mut head).unwrap();
    let plain = round_trip::<{ ToyCfb8::<Decrypting>::SUSPENDED_STATE_LEN }, _>(dec, |mut d| {
        let mut data = tail.clone();
        d.do_decrypt_inplace(&mut data).unwrap();
        data
    });
    assert_eq!(plain, msg[5..]);
}

#[test]
fn ctr_mid_block_both_directions() {
    let msg = message(50);
    let (mut enc, nonce) = ToyCtr::<Encrypting>::do_encrypt_init(&key()).unwrap();
    let mut head = msg[..7].to_vec();
    enc.do_encrypt_inplace(&mut head).unwrap();
    let tail = round_trip::<{ ToyCtr::<Encrypting>::SUSPENDED_STATE_LEN }, _>(enc, |mut e| {
        let mut data = msg[7..].to_vec();
        e.do_encrypt_inplace(&mut data).unwrap();
        data
    });
    let mut dec = ToyCtr::<Decrypting>::do_decrypt_init(&key(), &nonce).unwrap();
    dec.do_decrypt_inplace(&mut head).unwrap();
    let plain = round_trip::<{ ToyCtr::<Decrypting>::SUSPENDED_STATE_LEN }, _>(dec, |mut d| {
        let mut data = tail.clone();
        d.do_decrypt_inplace(&mut data).unwrap();
        data
    });
    assert_eq!(plain, msg[7..]);
}

#[test]
fn gcm_both_directions_with_aad() {
    let msg = message(45);
    let aad = b"authenticated header";

    let (mut enc, nonce) = ToyGcm::<Encrypting>::do_encrypt_init(&key()).unwrap();
    enc.do_update_aad(aad).unwrap();
    let mut head = [0u8; 5];
    enc.do_encrypt_out(&msg[..5], &mut head).unwrap();
    // Ciphertext of the rest, then the tag.
    let tail = round_trip::<{ ToyGcm::<Encrypting>::SUSPENDED_STATE_LEN }, _>(enc, |mut e| {
        let mut out = vec![0u8; 40];
        e.do_encrypt_out(&msg[5..], &mut out).unwrap();
        let (tag, tag_len) = e.do_encrypt_final().unwrap();
        out.extend_from_slice(&tag[..tag_len]);
        out
    });
    let mut ciphertext = head.to_vec();
    ciphertext.extend_from_slice(&tail);

    // The decryptor holds the last 16 bytes back, so after 10 bytes nothing has been released,
    // but data has started and the AAD phase is closed: a state worth suspending.
    let mut dec = ToyGcm::<Decrypting>::do_decrypt_init(&key(), &nonce).unwrap();
    dec.do_update_aad(aad).unwrap();
    let mut nothing = [0u8; 0];
    assert_eq!(dec.do_decrypt_out(&ciphertext[..10], &mut nothing).unwrap(), 0);
    let plain = round_trip::<{ ToyGcm::<Decrypting>::SUSPENDED_STATE_LEN }, _>(dec, |mut d| {
        let mut out = vec![0u8; ciphertext.len()];
        let n = d.do_decrypt_out(&ciphertext[10..], &mut out).unwrap();
        let (_, last) = d.do_decrypt_final().expect("the tag must verify after a resume");
        out.truncate(n + last);
        out
    });
    assert_eq!(plain, msg);
}

#[test]
fn ccm_both_directions() {
    let msg = message(37);
    let nonce = [0x24u8; 12];
    let aad = b"header";

    let mut enc = ToyCcm::<Encrypting>::new(&key(), &nonce, aad, msg.len()).unwrap();
    let mut head = msg[..9].to_vec();
    enc.do_encrypt(&mut head).unwrap();
    let tail = round_trip::<{ ToyCcm::<Encrypting>::SUSPENDED_STATE_LEN }, _>(enc, |mut e| {
        let mut data = msg[9..].to_vec();
        e.do_encrypt(&mut data).unwrap();
        data.extend_from_slice(&e.do_encrypt_final().unwrap());
        data
    });
    let (ct_tail, tag) = tail.split_at(msg.len() - 9);
    let tag: [u8; 16] = tag.try_into().unwrap();

    let mut dec = ToyCcm::<Decrypting>::new(&key(), &nonce, aad, msg.len()).unwrap();
    dec.do_decrypt_update(&mut head).unwrap();
    let plain = round_trip::<{ ToyCcm::<Decrypting>::SUSPENDED_STATE_LEN }, _>(dec, |mut d| {
        let mut data = ct_tail.to_vec();
        d.do_decrypt_update(&mut data).unwrap();
        d.do_decrypt_final(&tag).expect("the tag must verify after a resume");
        data
    });
    assert_eq!(plain, msg[9..]);
}

#[test]
fn padded_cbc_both_directions() {
    let msg = message(45);
    let (mut enc, iv) = ToyPaddedEnc::do_encrypt_init(&key()).unwrap();
    let mut head = [0u8; 16];
    // 20 bytes in: one block out, four buffered.
    assert_eq!(enc.do_encrypt_out(&msg[..20], &mut head).unwrap(), 16);
    let tail = round_trip::<{ ToyPaddedEnc::SUSPENDED_STATE_LEN }, _>(enc, |mut e| {
        let mut out = vec![0u8; 32];
        let n = e.do_encrypt_out(&msg[20..], &mut out).unwrap();
        out.truncate(n);
        let (last, last_len) = e.do_encrypt_final().unwrap();
        out.extend_from_slice(&last[..last_len]);
        out
    });
    let mut ciphertext = head.to_vec();
    ciphertext.extend_from_slice(&tail);
    assert_eq!(ciphertext.len(), 48);

    // 20 bytes in: one block released, one held back, four buffered.
    let mut dec = ToyPaddedDec::do_decrypt_init(&key(), &iv).unwrap();
    let mut first = [0u8; 16];
    assert_eq!(dec.do_decrypt_out(&ciphertext[..36], &mut first).unwrap(), 16);
    let plain = round_trip::<{ ToyPaddedDec::SUSPENDED_STATE_LEN }, _>(dec, |mut d| {
        let mut out = vec![0u8; 32];
        let n = d.do_decrypt_out(&ciphertext[36..], &mut out).unwrap();
        out.truncate(n);
        let (last, data_len) = d.do_decrypt_final().unwrap();
        out.extend_from_slice(&last[..data_len]);
        out
    });
    let mut recovered = first.to_vec();
    recovered.extend_from_slice(&plain);
    assert_eq!(recovered, msg);
}
