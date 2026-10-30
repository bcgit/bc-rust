use bouncycastle_chacha20::ChaCha20;
use bouncycastle_chacha20_poly1305_aead::{
    ChaCha20_Poly1305, ChaCha20Poly1305Key, MAX_MESSAGE_LEN,
    SUSPENDED_CHACHA20_POLY1305_DECRYPTOR_STATE_LEN as DEC_STATE_LEN,
    SUSPENDED_CHACHA20_POLY1305_ENCRYPTOR_STATE_LEN as ENC_STATE_LEN,
};
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::errors::{KeyMaterialError, SuspendableError, SymmetricCipherError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey, FromKeyMaterial};
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, Algorithm, SuspendableKeyed,
    SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};
use bouncycastle_core_test_framework::aead::{
    TestFrameworkAEADCipher, TestFrameworkAEADTaggedLayout,
};
use bouncycastle_core_test_framework::from_key_material::TestFrameworkFromKeyMaterial;
use bouncycastle_core_test_framework::suspendable_state::TestFrameworkSuspendableKeyedState;
use bouncycastle_rng::HashDRBG_SHA512;

type Enc<'k> = ChaCha20_Poly1305<'k, Encrypting>;
type Dec<'k> = ChaCha20_Poly1305<'k, Decrypting>;

fn material() -> KeyMaterial<32> {
    KeyMaterial::<32>::from_bytes_as_type(&[7; 32], KeyType::SymmetricCipherKey).unwrap()
}

fn key() -> ChaCha20Poly1305Key {
    ChaCha20Poly1305Key::from_key_material(&material()).unwrap()
}

#[test]
fn core_aead_and_symmetric_contracts() {
    let key = key();
    TestFrameworkAEADCipher::new()
        .test_key::<32, 12, 16, 16, _>(&key, &mut HashDRBG_SHA512::new_from_os());
    TestFrameworkAEADTaggedLayout::new().test_key::<32, 12, 16, 16, _>(&key);
}

/// The key's construction suite: the type and strength policy of `from_key_material`.
#[test]
fn the_key_enforces_the_material_policy() {
    TestFrameworkFromKeyMaterial::new()
        .test::<32, ChaCha20Poly1305Key>(Enc::ALG_NAME, SecurityStrength::_256bit);
}

/// Both directions of each cipher report one name, and the AEAD's is not the keystream's.
#[test]
fn the_two_algorithms_have_distinct_names() {
    assert_eq!(Enc::ALG_NAME, "ChaCha20-Poly1305");
    assert_eq!(Dec::ALG_NAME, Enc::ALG_NAME);
    assert_eq!(ChaCha20::<'static, Encrypting>::ALG_NAME, "ChaCha20");
    assert_eq!(ChaCha20::<'static, Decrypting>::ALG_NAME, "ChaCha20");
}

/// RFC 8439 Sec 2.8: "P_MAX (maximum size of the plaintext) is 274,877,906,880 bytes".
#[test]
fn max_message_len_is_the_rfc_p_max() {
    assert_eq!(MAX_MESSAGE_LEN, 274_877_906_880);
}

#[test]
fn failed_update_can_be_retried_without_ending_aad() {
    let key = key();
    let nonce = [9; 12];
    let msg = [0x42; 65];
    let mut enc = key.create_encryptor_nonce(&nonce);
    let mut short = [0xa5; 64];
    assert_eq!(
        enc.do_encrypt_out(&msg, &mut short),
        Err(SymmetricCipherError::OutputBufferTooSmall(65))
    );
    assert_eq!(short, [0; 64], "a refused call zeroizes its output buffer");
    enc.do_update_aad(b"aad").unwrap();
    let mut ct = [0u8; 65];
    enc.do_encrypt_out(&msg, &mut ct).unwrap();
    let (tag, _) = enc.do_encrypt_final().unwrap();
    let mut dec = key.create_decryptor(&nonce);
    let mut short = [0xa5; 48];
    assert_eq!(
        dec.do_decrypt_out(&ct, &mut short),
        Err(SymmetricCipherError::OutputBufferTooSmall(49))
    );
    assert_eq!(short, [0; 48], "a refused call zeroizes its output buffer");
    dec.do_update_aad(b"aad").unwrap();
    let mut pt = [0u8; 65];
    let n = dec.do_decrypt_out(&ct, &mut pt).unwrap();
    let (last, m) = dec.do_decrypt_final_detached(&tag).unwrap();
    pt[n..n + m].copy_from_slice(&last[..m]);
    assert_eq!(pt, msg);
}

#[test]
fn key_capacity_does_not_replace_key_length() {
    for len in 0..32 {
        let mut short = material();
        short.set_key_len(len).unwrap();
        assert!(matches!(
            ChaCha20Poly1305Key::from_key_material(&short),
            Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::InvalidLength))
        ));
    }
}

/// The figures in the crate docs' Memory Usage table.
#[cfg(target_pointer_width = "64")]
#[test]
fn sizes_match_the_documented_memory_table() {
    use core::mem::size_of;
    assert_eq!(size_of::<ChaCha20Poly1305Key>(), 32);
    assert_eq!(size_of::<Enc<'static>>(), 344);
    assert_eq!(size_of::<Dec<'static>>(), 344);
    assert_eq!(ENC_STATE_LEN, 176);
    assert_eq!(DEC_STATE_LEN, 193);
}

/// The framework's suspend suite works on a clone of the value it is given, and a worker cannot be
/// cloned, since two copies would encrypt under one nonce. These stand in for one: a suspended
/// state that every resume puts through the worker's own `from_suspended`.
#[derive(Clone)]
struct SuspendedEnc([u8; ENC_STATE_LEN]);

impl<'k> SuspendableKeyed<'k, ENC_STATE_LEN> for SuspendedEnc {
    type Key = ChaCha20Poly1305Key;
    fn suspend(self) -> [u8; ENC_STATE_LEN] {
        self.0
    }
    fn from_suspended(
        state: [u8; ENC_STATE_LEN],
        key: &'k Self::Key,
    ) -> Result<Self, SuspendableError> {
        Enc::from_suspended(state, key).map(|enc| Self(enc.suspend()))
    }
}

#[derive(Clone)]
struct SuspendedDec([u8; DEC_STATE_LEN]);

impl<'k> SuspendableKeyed<'k, DEC_STATE_LEN> for SuspendedDec {
    type Key = ChaCha20Poly1305Key;
    fn suspend(self) -> [u8; DEC_STATE_LEN] {
        self.0
    }
    fn from_suspended(
        state: [u8; DEC_STATE_LEN],
        key: &'k Self::Key,
    ) -> Result<Self, SuspendableError> {
        Dec::from_suspended(state, key).map(|dec| Self(dec.suspend()))
    }
}

/// A worker part-way through its data, in each direction.
fn mid_stream_states(key: &ChaCha20Poly1305Key) -> ([u8; ENC_STATE_LEN], [u8; DEC_STATE_LEN]) {
    let mut enc = key.create_encryptor_nonce(&[5; 12]);
    enc.do_update_aad(b"header").unwrap();
    enc.do_encrypt_out(&[1; 70], &mut [0; 70]).unwrap();
    let mut dec = key.create_decryptor(&[5; 12]);
    dec.do_update_aad(b"header").unwrap();
    dec.do_decrypt_out(&[1; 70], &mut [0; 54]).unwrap();
    (enc.suspend(), dec.suspend())
}

#[test]
fn the_suspended_states_pass_the_framework_suite() {
    let key = key();
    let (enc, dec) = mid_stream_states(&key);
    TestFrameworkSuspendableKeyedState::new().test(&SuspendedEnc(enc), &key);
    TestFrameworkSuspendableKeyedState::new().test(&SuspendedDec(dec), &key);
}

/// Each direction suspended part-way through the AAD and again part-way through the data, at block
/// boundaries and inside blocks, and resumed under the re-supplied key, gives the uninterrupted
/// output.
#[test]
fn suspend_and_resume_mid_stream_matches_an_uninterrupted_run() {
    let key = key();
    let nonce = [5; 12];
    let aad: Vec<u8> = (0..37u8).collect();
    let msg: Vec<u8> = (0..150u8).map(|b| b.wrapping_mul(3)).collect();
    let mut sealed = vec![0u8; msg.len() + 16];
    key.encrypt_with_aad_nonce_out(&nonce, &aad, &msg, &mut sealed).unwrap();

    for aad_split in [0, 1, 16, 20, 37] {
        for split in [0, 1, 63, 64, 65, 70, 150] {
            let mut enc = key.create_encryptor_nonce(&nonce);
            enc.do_update_aad(&aad[..aad_split]).unwrap();
            let mut enc = Enc::from_suspended(enc.suspend(), &key).unwrap();
            enc.do_update_aad(&aad[aad_split..]).unwrap();
            let mut out = vec![0u8; sealed.len()];
            enc.do_encrypt_out(&msg[..split], &mut out[..split]).unwrap();
            let mut enc = Enc::from_suspended(enc.suspend(), &key).unwrap();
            enc.do_encrypt_out(&msg[split..], &mut out[split..msg.len()]).unwrap();
            out[msg.len()..].copy_from_slice(&enc.do_encrypt_final().unwrap().0);
            assert_eq!(out, sealed, "encrypting, AAD split {aad_split}, data split {split}");
        }
        for split in [0, 1, 15, 16, 63, 90, 150, 166] {
            let mut dec = key.create_decryptor(&nonce);
            dec.do_update_aad(&aad[..aad_split]).unwrap();
            let mut dec = Dec::from_suspended(dec.suspend(), &key).unwrap();
            dec.do_update_aad(&aad[aad_split..]).unwrap();
            let mut out = vec![0u8; sealed.len()];
            let mut n = dec.do_decrypt_out(&sealed[..split], &mut out).unwrap();
            let mut dec = Dec::from_suspended(dec.suspend(), &key).unwrap();
            n += dec.do_decrypt_out(&sealed[split..], &mut out[n..]).unwrap();
            assert_eq!(dec.do_decrypt_final().unwrap().1, 0, "the held bytes were the tag");
            assert_eq!(
                &out[..n],
                &msg[..],
                "decrypting, AAD split {aad_split}, data split {split}"
            );
        }
    }
}

/// Resume refuses what the worker never writes: the other direction's state (each cut or padded to
/// the other's length), a zeroed or unknown call-state byte, data counted before the AAD phase
/// ended or past the message limit, a block counter out of step with the data, a Poly1305 state
/// out of its bounds, and a held-back count above the tag length.
#[test]
fn resume_refuses_states_the_worker_never_writes() {
    // Offsets after the 3-byte version: ChaCha20's nonce and block counter lead its 92 bytes, then
    // Poly1305's limbs, buffer and buffered length take 64, then the two counts and the call state.
    const COUNTER: usize = 3 + 12;
    const POLY1305: usize = 3 + 92;
    const BUFFERED: usize = POLY1305 + 40 + 16;
    const DATA_LEN: usize = ENC_STATE_LEN - 9;
    const CALL_STATE: usize = ENC_STATE_LEN - 1;
    let key = key();
    let (enc, dec) = mid_stream_states(&key);
    let enc_refused = |s: [u8; ENC_STATE_LEN]| {
        matches!(Enc::from_suspended(s, &key), Err(SuspendableError::InvalidData))
    };
    let dec_refused = |s: [u8; DEC_STATE_LEN]| {
        matches!(Dec::from_suspended(s, &key), Err(SuspendableError::InvalidData))
    };
    let with = |offset: usize, value: u64| {
        let mut s = enc;
        s[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        s
    };
    let with_byte = |offset: usize, value: u8| {
        let mut s = enc;
        s[offset] = value;
        s
    };
    assert!(Enc::from_suspended(enc, &key).is_ok());
    assert!(Dec::from_suspended(dec, &key).is_ok());

    let mut enc_as_dec = [0u8; DEC_STATE_LEN];
    enc_as_dec[..ENC_STATE_LEN].copy_from_slice(&enc);
    assert!(dec_refused(enc_as_dec), "an encrypting state, padded to the decrypting length");
    assert!(enc_refused(dec[..ENC_STATE_LEN].try_into().unwrap()), "a decrypting state, cut short");

    assert!(enc_refused(with_byte(CALL_STATE, 0)), "a zeroed call state");
    assert!(enc_refused(with_byte(CALL_STATE, enc[CALL_STATE] ^ 0x40)), "an unknown marker");
    assert!(enc_refused(with_byte(CALL_STATE, enc[CALL_STATE] & !1)), "data before the AAD ended");
    assert!(enc_refused(with(DATA_LEN, MAX_MESSAGE_LEN + 1)), "data past the message limit");

    let counter = u64::from_le_bytes(enc[COUNTER..COUNTER + 8].try_into().unwrap());
    assert_eq!(counter, 3, "block 0 is the one-time key, then 70 bytes take blocks 1 and 2");
    assert!(enc_refused(with(COUNTER, counter + 1)), "a counter ahead of the data");
    assert!(enc_refused(with(COUNTER, counter - 1)), "a counter behind it, repeating keystream");
    assert!(enc_refused(with(COUNTER, 0)), "block 0, the one-time key");

    assert!(enc_refused(with(POLY1305, 1 << 26)), "a Poly1305 limb past 26 bits");
    assert!(enc_refused(with(BUFFERED, 16)), "a whole Poly1305 block buffered");

    let mut held = dec;
    held[DEC_STATE_LEN - 1] = 17;
    assert!(dec_refused(held), "more held back than the tag");
}
