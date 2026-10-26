//! Suspend-and-resume round trips for every mode and adapter, over the toy
//! permutation in `common/toy_block_cipher.rs`.
//!
//! Each test does part of an operation, suspends a clone of the cipher, resumes it with the
//! re-supplied key, and then finishes both the original and the resumed cipher the same way. The
//! two must agree byte for byte, which is the whole contract: a resumed cipher is the suspended
//! one, continued. The shared framework suite runs once per type for the version-header rules.
//! The AES aliases get the same impls through these generic types, so this is where they are
//! pinned; `bouncycastle-aes` only checks that each alias reaches them.

use bouncycastle_cipher::modes::hazmat::ecb::{ECB, Ecb};
use bouncycastle_cipher::modes::{
    Blocks, CBC, CCM_Packet, CFB, CFB8, CTR, Cbc, CcmPacketDecryptor, CcmPacketEncryptor, Cfb,
    Cfb8, Ctr, GCM, Gcm,
};
use bouncycastle_cipher::padding::{PKCS7, PaddedBlockCipherDecryptor, PaddedBlockCipherEncryptor};
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::errors::SuspendableError;
use bouncycastle_core::hazmat::{EcbDecryptionKey, EcbEncryptionKey, Mode};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{
    AeadDecryptionKey, AeadEncryptionKey, BlockDecryptionKey, BlockEncryptionKey, FromKeyMaterial,
    SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, BlockCipherDecryptor, BlockCipherEncryptor,
    StreamCipherDecryptor, StreamCipherEncryptor, SuspendableKeyed, SymmetricCipherDecryptor,
    SymmetricCipherEncryptor,
};
use bouncycastle_core_test_framework::suspendable_state::TestFrameworkSuspendableKeyedState;

#[path = "common/toy_block_cipher.rs"]
mod toy_block_cipher;
#[path = "common/toy_key.rs"]
#[allow(dead_code)]
mod toy_key;
use toy_block_cipher::ToyBlockCipher;
use toy_key::{ToyKey, os_rng};

type ToyEcb<'k, Dir> = Ecb<'k, ToyBlockCipher, Dir, 16>;
type ToyCbc<'k, Dir> = Cbc<'k, ToyBlockCipher, Dir, 16>;
type ToyCfb<'k, Dir> = Cfb<'k, ToyBlockCipher, Dir, 16>;
type ToyCfb8<'k, Dir> = Cfb8<'k, ToyBlockCipher, Dir, 16>;
type ToyCtr<'k, Dir> = Ctr<'k, ToyBlockCipher, Dir, 16, 12>;
type ToyGcm<'k, Dir> = Gcm<'k, ToyBlockCipher, Dir, 16>;
// A 64-byte AAD capacity and 37-byte frames, the message `ccm_both_directions` uses.
type ToyCcmPacket = CCM_Packet<12, 16, 64, 37>;
type ToyCcmEnc<'k> = CcmPacketEncryptor<'k, ToyBlockCipher, 16, 12, 16, 64, 37>;
type ToyCcmDec<'k> = CcmPacketDecryptor<'k, ToyBlockCipher, 16, 12, 16, 64, 37>;
type ToyPaddedEnc<'k> = PaddedBlockCipherEncryptor<ToyCbc<'k, Encrypting>, PKCS7, 16, 16>;
type ToyPaddedDec<'k> = PaddedBlockCipherDecryptor<ToyCbc<'k, Decrypting>, PKCS7, 16, 16>;

fn key() -> KeyMaterial<16> {
    KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap()
}

/// The toy key under the mode `M`; its workers borrow it, and resume takes its state.
fn key_for<M: Mode<ToyBlockCipher>>() -> ToyKey<ToyBlockCipher, M> {
    ToyKey::from_key_material(&key()).expect("the toy key")
}

fn message(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(7).wrapping_add(3)).collect()
}

/// Runs the framework suite on `cipher`, then suspends a clone, resumes it over `key`, the mode's
/// key state the cipher borrows, and finishes both with `finish`. Whatever `finish` returns must
/// be identical for the two.
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

#[test]
fn cbc_both_directions() {
    let key = key_for::<CBC<Blocks>>();
    let (mut enc, iv) = key.create_encryptor(&mut os_rng()).unwrap();
    let mut first = [0x11u8; 16];
    enc.do_encrypt_blocks_inplace(first.as_chunks_mut().0).unwrap();
    let rest = round_trip::<{ ToyCbc::<Encrypting>::SUSPENDED_STATE_LEN }, _>(
        enc,
        key.state(),
        |mut e| {
            let mut data = [0x22u8; 48];
            e.do_encrypt_blocks_inplace(data.as_chunks_mut().0).unwrap();
            data.to_vec()
        },
    );

    let key = key_for::<CBC<Blocks>>();
    let mut dec = key.create_decryptor(&iv);
    dec.do_decrypt_blocks_inplace(first.as_chunks_mut().0).unwrap();
    assert_eq!(first, [0x11u8; 16]);
    let plain = round_trip::<{ ToyCbc::<Decrypting>::SUSPENDED_STATE_LEN }, _>(
        dec,
        key.state(),
        |mut d| {
            let mut data: [u8; 48] = rest.as_slice().try_into().unwrap();
            d.do_decrypt_blocks_inplace(data.as_chunks_mut().0).unwrap();
            data.to_vec()
        },
    );
    assert_eq!(plain, vec![0x22u8; 48]);
}

#[test]
fn ecb_both_directions() {
    let key = key_for::<ECB<Blocks>>();
    let mut enc = key.create_encryptor();
    enc.do_encrypt_blocks_inplace(&mut [[0x11u8; 16]]).unwrap();
    round_trip::<{ ToyEcb::<Encrypting>::SUSPENDED_STATE_LEN }, _>(enc, key.state(), |mut e| {
        let mut data = [0x22u8; 32];
        e.do_encrypt_blocks_inplace(data.as_chunks_mut().0).unwrap();
        data.to_vec()
    });
    let key = key_for::<ECB<Blocks>>();
    let dec = key.create_decryptor();
    round_trip::<{ ToyEcb::<Decrypting>::SUSPENDED_STATE_LEN }, _>(dec, key.state(), |mut d| {
        let mut data = [0x33u8; 32];
        d.do_decrypt_blocks_inplace(data.as_chunks_mut().0).unwrap();
        data.to_vec()
    });
}

#[test]
fn cfb_mid_segment_both_directions() {
    let msg = message(40);
    let key = key_for::<CFB>();
    let (mut enc, iv) = key.create_encryptor(&mut os_rng()).unwrap();
    let mut head = msg[..7].to_vec();
    enc.do_encrypt_inplace(&mut head).unwrap();
    let tail = round_trip::<{ ToyCfb::<Encrypting>::SUSPENDED_STATE_LEN }, _>(
        enc,
        key.state(),
        |mut e| {
            let mut data = msg[7..].to_vec();
            e.do_encrypt_inplace(&mut data).unwrap();
            data
        },
    );

    let key = key_for::<CFB>();
    let mut dec = key.create_decryptor(&iv);
    dec.do_decrypt_inplace(&mut head).unwrap();
    assert_eq!(head, msg[..7]);
    let plain = round_trip::<{ ToyCfb::<Decrypting>::SUSPENDED_STATE_LEN }, _>(
        dec,
        key.state(),
        |mut d| {
            let mut data = tail.clone();
            d.do_decrypt_inplace(&mut data).unwrap();
            data
        },
    );
    assert_eq!(plain, msg[7..]);
}

#[test]
fn cfb8_both_directions() {
    let msg = message(20);
    let key = key_for::<CFB8>();
    let (mut enc, iv) = key.create_encryptor(&mut os_rng()).unwrap();
    let mut head = msg[..5].to_vec();
    enc.do_encrypt_inplace(&mut head).unwrap();
    let tail = round_trip::<{ ToyCfb8::<Encrypting>::SUSPENDED_STATE_LEN }, _>(
        enc,
        key.state(),
        |mut e| {
            let mut data = msg[5..].to_vec();
            e.do_encrypt_inplace(&mut data).unwrap();
            data
        },
    );
    let key = key_for::<CFB8>();
    let mut dec = key.create_decryptor(&iv);
    dec.do_decrypt_inplace(&mut head).unwrap();
    let plain = round_trip::<{ ToyCfb8::<Decrypting>::SUSPENDED_STATE_LEN }, _>(
        dec,
        key.state(),
        |mut d| {
            let mut data = tail.clone();
            d.do_decrypt_inplace(&mut data).unwrap();
            data
        },
    );
    assert_eq!(plain, msg[5..]);
}

#[test]
fn ctr_mid_block_both_directions() {
    let msg = message(50);
    let key = key_for::<CTR<12>>();
    let (mut enc, nonce) = key.create_encryptor(&mut os_rng()).unwrap();
    let mut head = msg[..7].to_vec();
    enc.do_encrypt_inplace(&mut head).unwrap();
    let tail = round_trip::<{ ToyCtr::<Encrypting>::SUSPENDED_STATE_LEN }, _>(
        enc,
        key.state(),
        |mut e| {
            let mut data = msg[7..].to_vec();
            e.do_encrypt_inplace(&mut data).unwrap();
            data
        },
    );
    let key = key_for::<CTR<12>>();
    let mut dec = key.create_decryptor(&nonce);
    dec.do_decrypt_inplace(&mut head).unwrap();
    let plain = round_trip::<{ ToyCtr::<Decrypting>::SUSPENDED_STATE_LEN }, _>(
        dec,
        key.state(),
        |mut d| {
            let mut data = tail.clone();
            d.do_decrypt_inplace(&mut data).unwrap();
            data
        },
    );
    assert_eq!(plain, msg[7..]);
}

#[test]
fn gcm_both_directions_with_aad() {
    let msg = message(45);
    let aad = b"authenticated header";

    let key = key_for::<GCM<16>>();
    let (mut enc, nonce) = key.create_encryptor(&mut os_rng()).unwrap();
    enc.do_update_aad(aad).unwrap();
    let mut head = [0u8; 5];
    enc.do_encrypt_out(&msg[..5], &mut head).unwrap();
    // Ciphertext of the rest, then the tag.
    let tail = round_trip::<{ ToyGcm::<Encrypting>::SUSPENDED_STATE_LEN }, _>(
        enc,
        key.state(),
        |mut e| {
            let mut out = vec![0u8; 40];
            e.do_encrypt_out(&msg[5..], &mut out).unwrap();
            let (tag, tag_len) = e.do_encrypt_final().unwrap();
            out.extend_from_slice(&tag[..tag_len]);
            out
        },
    );
    let mut ciphertext = head.to_vec();
    ciphertext.extend_from_slice(&tail);

    // The decryptor holds the last 16 bytes back, so after 10 bytes nothing has been released,
    // but data has started and the AAD phase is closed: a state worth suspending.
    let key = key_for::<GCM<16>>();
    let mut dec = key.create_decryptor(&nonce);
    dec.do_update_aad(aad).unwrap();
    let mut nothing = [0u8; 0];
    assert_eq!(dec.do_decrypt_out(&ciphertext[..10], &mut nothing).unwrap(), 0);
    let plain = round_trip::<{ ToyGcm::<Decrypting>::SUSPENDED_STATE_LEN }, _>(
        dec,
        key.state(),
        |mut d| {
            let mut out = vec![0u8; ciphertext.len()];
            let n = d.do_decrypt_out(&ciphertext[10..], &mut out).unwrap();
            let (_, last) = d.do_decrypt_final().expect("the tag must verify after a resume");
            out.truncate(n + last);
            out
        },
    );
    assert_eq!(plain, msg);
}

/// An encryptor with the AAD phase closed and 31 bytes encrypted, one whole block and 15 more, so
/// GHASH holds 15 pending bytes: the most a legitimate state carries.
fn gcm_with_fifteen_pending(key: &ToyKey<ToyBlockCipher, GCM<16>>) -> ToyGcm<'_, Encrypting> {
    let (mut enc, _) = key.create_encryptor(&mut os_rng()).unwrap();
    enc.do_update_aad(b"authenticated header").unwrap();
    let mut out = [0u8; 31];
    enc.do_encrypt_out(&message(31), &mut out).unwrap();
    enc
}

#[test]
fn gcm_resumes_with_fifteen_pending_bytes() {
    let msg = message(20);
    let key = key_for::<GCM<16>>();
    round_trip::<{ ToyGcm::<Encrypting>::SUSPENDED_STATE_LEN }, _>(
        gcm_with_fifteen_pending(&key),
        key.state(),
        |mut e| {
            let mut out = vec![0u8; msg.len()];
            e.do_encrypt_out(&msg, &mut out).unwrap();
            let (tag, tag_len) = e.do_encrypt_final().unwrap();
            out.extend_from_slice(&tag[..tag_len]);
            out
        },
    );
}

#[test]
fn gcm_rejects_a_suspended_state_with_a_whole_block_pending() {
    const N: usize = ToyGcm::<Encrypting>::SUSPENDED_STATE_LEN;
    // `ToyGcm`'s tag length, its last type parameter.
    const TAG_LEN: usize = 16;
    // The GHASH state is followed by `aad_len`, `data_len`, `phase`, `tail` and `tail_len`, and
    // `pending_len` is its last 8 bytes.
    const PENDING_LEN_AT: usize = N - (8 + 8 + 1 + TAG_LEN + 8) - 8;

    let key = key_for::<GCM<16>>();
    let mut state: [u8; N] = gcm_with_fifteen_pending(&key).suspend();
    // The suspended `u64`s are little-endian (`CursorMut::u64`): read and written here with
    // `u64::from_le_bytes` and `to_le_bytes`.
    let field = &mut state[PENDING_LEN_AT..PENDING_LEN_AT + 8];
    assert_eq!(
        u64::from_le_bytes(field.try_into().unwrap()),
        15,
        "pending_len is not where the documented layout puts it"
    );
    field.copy_from_slice(&16u64.to_le_bytes());
    assert!(matches!(
        ToyGcm::<Encrypting>::from_suspended(state, key.state()),
        Err(SuspendableError::InvalidData)
    ));
}

#[test]
fn ccm_both_directions() {
    let msg = message(37);
    let nonce = [0x24u8; 12];
    let aad = b"header";

    // Suspended with half the AAD held back and no payload yet, and again mid-payload; both
    // must continue to the one answer.
    let key = key_for::<ToyCcmPacket>();
    let mut enc = key.create_encryptor_nonce(&nonce);
    enc.do_update_aad(&aad[..3]).unwrap();
    let sealed = round_trip::<{ ToyCcmEnc::SUSPENDED_STATE_LEN }, _>(enc, key.state(), |mut e| {
        e.do_update_aad(&aad[3..]).unwrap();
        let mut out = vec![0u8; 37];
        e.do_encrypt_out(&msg, &mut out).unwrap();
        let (_, _, tag) = e.do_encrypt_final_detached().unwrap();
        out.extend_from_slice(&tag);
        out
    });
    let key = key_for::<ToyCcmPacket>();
    let mut enc = key.create_encryptor_nonce(&nonce);
    enc.do_update_aad(aad).unwrap();
    let mut head = vec![0u8; 9];
    enc.do_encrypt_out(&msg[..9], &mut head).unwrap();
    let tail = round_trip::<{ ToyCcmEnc::SUSPENDED_STATE_LEN }, _>(enc, key.state(), |mut e| {
        let mut out = vec![0u8; 28];
        e.do_encrypt_out(&msg[9..], &mut out).unwrap();
        let (_, _, tag) = e.do_encrypt_final_detached().unwrap();
        out.extend_from_slice(&tag);
        out
    });
    assert_eq!([&head[..], &tail[..]].concat(), sealed, "both suspend points give the one answer");
    let (ct, tag) = sealed.split_at(37);
    let tag: [u8; 16] = tag.try_into().unwrap();

    let key = key_for::<ToyCcmPacket>();
    let mut dec = key.create_decryptor(&nonce);
    dec.do_update_aad(aad).unwrap();
    let mut opened_head = vec![0u8; 9];
    dec.do_decrypt_out(&ct[..9], &mut opened_head).unwrap();
    let plain = round_trip::<{ ToyCcmDec::SUSPENDED_STATE_LEN }, _>(dec, key.state(), |mut d| {
        let mut out = vec![0u8; 28];
        d.do_decrypt_out(&ct[9..], &mut out).unwrap();
        d.do_decrypt_final_detached(&tag).expect("the tag must verify after a resume");
        out
    });
    assert_eq!([&opened_head[..], &plain[..]].concat(), msg);

    // ...and with part of an inline tag already held back at the suspend point.
    let key = key_for::<ToyCcmPacket>();
    let mut dec = key.create_decryptor(&nonce);
    dec.do_update_aad(aad).unwrap();
    let mut opened = vec![0u8; 37];
    dec.do_decrypt_out(&sealed[..40], &mut opened).unwrap();
    round_trip::<{ ToyCcmDec::SUSPENDED_STATE_LEN }, _>(dec, key.state(), |mut d| {
        d.do_decrypt_out(&sealed[40..], &mut []).unwrap();
        d.do_decrypt_final().expect("the held-back tag must survive a resume");
        Vec::new()
    });
    assert_eq!(opened, msg);
}

#[test]
fn padded_cbc_both_directions() {
    let msg = message(45);
    let key = key_for::<CBC<PKCS7>>();
    let (mut enc, iv) = key.create_encryptor(&mut os_rng()).unwrap();
    let mut head = [0u8; 16];
    // 20 bytes in: one block out, four buffered.
    assert_eq!(enc.do_encrypt_out(&msg[..20], &mut head).unwrap(), 16);
    let tail = round_trip::<{ ToyPaddedEnc::SUSPENDED_STATE_LEN }, _>(enc, key.state(), |mut e| {
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
    let key = key_for::<CBC<PKCS7>>();
    let mut dec = key.create_decryptor(&iv);
    let mut first = [0u8; 16];
    assert_eq!(dec.do_decrypt_out(&ciphertext[..36], &mut first).unwrap(), 16);
    let plain =
        round_trip::<{ ToyPaddedDec::SUSPENDED_STATE_LEN }, _>(dec, key.state(), |mut d| {
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
