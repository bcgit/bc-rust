//! What a resumed CCM state refuses: the bounds the pair and its `Ccm` state check when they
//! are rebuilt from a suspended array, each tampered with on its own.
//!
//! The round trips in `suspend_tests.rs` show that a faithful state resumes. These show that an
//! unfaithful one does not, which is the other half of the contract and the half that pins each
//! check individually: with the flags octet, the counter field, the counter index, the CBC-MAC
//! position, the owed payload, the AAD length and the phase flag all validated, a test that
//! corrupts several at once would still pass if any one check were dropped.
//!
//! The offsets are those of the layout the `SuspendableComponent` impls write, in order: the
//! library version, the `Ccm` state (the keystream's counter template and counter index, the
//! stream cipher's pending block and its `used` count, then the chaining block, `mac_pos`,
//! `aad_owed` and `owed`), the held-back AAD, its length and the phase flag; the decryptor adds
//! the held-back tag and its length. Every integer is a little-endian `u64`. Spec references are
//! to NIST SP 800-38C (May 2004, errata update 07-20-2007).

use bouncycastle_cipher::modes::{CCM, CCM_Packet, CcmPacketDecryptor, CcmPacketEncryptor};
use bouncycastle_core::errors::SuspendableError;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey, FromKeyMaterial};
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, SuspendableKeyed, SymmetricCipherDecryptor,
    SymmetricCipherEncryptor,
};
use bouncycastle_utils::suspendable_state::LIB_VERSION_LEN;

#[path = "common/toy_block_cipher.rs"]
mod toy_block_cipher;
#[path = "common/toy_key.rs"]
mod toy_key;
use toy_block_cipher::ToyBlockCipher;
use toy_key::ToyKey;

/// A 12-byte nonce, so `q = 3`: the counter field is the template's last three octets and the
/// payload limit is `2^24 - 1`.
const NONCE_LEN: usize = 12;
const BLOCK_LEN: usize = 16;
const AAD_LEN: usize = 16;
const DATA_LEN: usize = 32;
type ToyEnc<'k> =
    CcmPacketEncryptor<'k, ToyBlockCipher, BLOCK_LEN, NONCE_LEN, 16, AAD_LEN, DATA_LEN>;
type ToyDec<'k> =
    CcmPacketDecryptor<'k, ToyBlockCipher, BLOCK_LEN, NONCE_LEN, 16, AAD_LEN, DATA_LEN>;
const N: usize = ToyEnc::SUSPENDED_STATE_LEN;
const ND: usize = ToyDec::SUSPENDED_STATE_LEN;

/// A.1's `2^8q - 1`, which bounds the counter field: there is one counter block per payload
/// block, so `MAX_COUNTER` is the same number for every `q < 8`.
const LIMIT: u64 = CCM::<NONCE_LEN, 16>::MAX_PAYLOAD_LEN;

// Field offsets within the suspended array.
const TEMPLATE: usize = LIB_VERSION_LEN;
const NEXT_CTR: usize = TEMPLATE + BLOCK_LEN;
const PACKET_END: usize = N - AAD_LEN - 8 - 1;
const MAC_POS: usize = PACKET_END - 24;
const AAD_OWED: usize = PACKET_END - 16;
const OWED: usize = PACKET_END - 8;
const AAD_LEN_AT: usize = PACKET_END + AAD_LEN;
const FORMATTED: usize = AAD_LEN_AT + 8;
const TAG_LEN_AT: usize = ND - 8;

fn key() -> KeyMaterial<16> {
    KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap()
}

/// The key the pair is made from; its workers borrow it, and resume takes its state.
fn frame_key() -> ToyKey<ToyBlockCipher, CCM_Packet<NONCE_LEN, 16, AAD_LEN, DATA_LEN>> {
    ToyKey::from_key_material(&key()).unwrap()
}

/// An encryptor holding its AAD back, before any payload: the header is not yet formatted, so
/// the CBC-MAC has absorbed nothing.
fn unformatted() -> [u8; N] {
    let key = frame_key();
    let mut enc = key.create_encryptor_nonce(&[0x24u8; NONCE_LEN]);
    enc.do_update_aad(b"aad").unwrap();
    enc.suspend()
}

/// An encryptor one block into its payload: the header is formatted, `next_ctr = 2`, the CBC-MAC
/// block boundary has just been crossed, and 16 of the 32 bytes are still owed.
fn mid_payload() -> [u8; N] {
    let key = frame_key();
    let mut enc = key.create_encryptor_nonce(&[0x24u8; NONCE_LEN]);
    enc.do_update_aad(b"aad").unwrap();
    let mut out = [0u8; 16];
    enc.do_encrypt_out(&[0x5Au8; 16], &mut out).unwrap();
    enc.suspend()
}

fn with_u64<const L: usize>(mut state: [u8; L], at: usize, value: u64) -> [u8; L] {
    state[at..at + 8].copy_from_slice(&value.to_le_bytes());
    state
}

fn resumes(state: [u8; N]) -> Result<(), SuspendableError> {
    let key = frame_key();
    ToyEnc::from_suspended(state, key.state()).map(|_| ())
}

/// `mac_pos` is how much of the current CBC-MAC block has been XORed in, and a full block is
/// enciphered at once, so `BLOCK_LEN - 1` is the largest value a real state can hold.
#[test]
fn mac_pos_is_held_below_the_block_length() {
    let state = mid_payload();
    assert!(resumes(with_u64(state, MAC_POS, (BLOCK_LEN - 1) as u64)).is_ok());
    assert_eq!(
        resumes(with_u64(state, MAC_POS, BLOCK_LEN as u64)),
        Err(SuspendableError::InvalidData)
    );
}

/// `owed` is what `B0` committed to minus what has been supplied, so it can never exceed the
/// frame; the frame itself is a legal value, since nothing has to have been supplied yet. The
/// packet's own bound, A.1's `2^8q - 1`, sits behind that.
#[test]
fn owed_is_held_to_the_frame() {
    let state = mid_payload();
    assert!(resumes(with_u64(state, OWED, DATA_LEN as u64)).is_ok());
    assert_eq!(
        resumes(with_u64(state, OWED, DATA_LEN as u64 + 1)),
        Err(SuspendableError::InvalidData)
    );
    assert_eq!(resumes(with_u64(state, OWED, LIMIT + 1)), Err(SuspendableError::InvalidData));
}

/// The counter index runs from 1 (`S0` is the tag mask, step 7 starts the payload keystream at
/// `S1`) to one past the last counter value, which is where it stands once every block has been
/// used; 0 and anything beyond are not states the mode can have been in.
#[test]
fn the_counter_index_is_held_to_its_range() {
    let state = mid_payload();
    assert!(resumes(with_u64(state, NEXT_CTR, 1)).is_ok());
    assert!(resumes(with_u64(state, NEXT_CTR, LIMIT + 1)).is_ok(), "every counter used");
    assert_eq!(resumes(with_u64(state, NEXT_CTR, 0)), Err(SuspendableError::InvalidData));
    assert_eq!(resumes(with_u64(state, NEXT_CTR, LIMIT + 2)), Err(SuspendableError::InvalidData));
}

/// A.3 Table 4 fixes the template's flags octet at `[q-1]_3` with every other bit zero, and the
/// counter field is zero in the template because the index is written over it per block. Each
/// is checked on its own: the flags octet with the right `q` but a stray bit, a wrong `q`, and a
/// non-zero byte in each position of the counter field.
#[test]
fn the_counter_template_is_checked_byte_by_byte() {
    let state = mid_payload();
    assert!(resumes(state).is_ok());
    assert_eq!(state[TEMPLATE], 2, "q - 1 for a 12-byte nonce");

    let mut stray_bit = state;
    stray_bit[TEMPLATE] |= 0x40;
    assert_eq!(resumes(stray_bit), Err(SuspendableError::InvalidData));
    let mut wrong_q = state;
    wrong_q[TEMPLATE] = 1;
    assert_eq!(resumes(wrong_q), Err(SuspendableError::InvalidData));

    for i in BLOCK_LEN - 3..BLOCK_LEN {
        let mut counter_field = state;
        counter_field[TEMPLATE + i] = 1;
        assert_eq!(
            resumes(counter_field),
            Err(SuspendableError::InvalidData),
            "counter field octet {i}"
        );
    }
    // The nonce octets before the counter field are the caller's: any value resumes.
    let mut nonce_byte = state;
    nonce_byte[TEMPLATE + 1] ^= 0xFF;
    assert!(resumes(nonce_byte).is_ok());
}

/// Until the header is formatted nothing has gone into the CBC-MAC and no AAD is owed to it, so
/// a state that says "not formatted" with either count non-zero is one the pair never produces.
/// The flag itself is a bool, and only 0 and 1 encode one.
#[test]
fn an_unformatted_state_has_absorbed_nothing() {
    let state = unformatted();
    assert!(resumes(state).is_ok());
    assert_eq!(state[FORMATTED], 0);
    assert_eq!(resumes(with_u64(state, MAC_POS, 1)), Err(SuspendableError::InvalidData));
    assert_eq!(resumes(with_u64(state, AAD_OWED, 1)), Err(SuspendableError::InvalidData));
    let mut not_a_bool = state;
    not_a_bool[FORMATTED] = 2;
    assert_eq!(resumes(not_a_bool), Err(SuspendableError::InvalidData));
    // The formatted state carries those counts legitimately.
    assert_eq!(mid_payload()[FORMATTED], 1);
}

/// The held-back AAD can be no longer than the buffer that holds it.
#[test]
fn the_aad_length_is_held_to_its_capacity() {
    let state = unformatted();
    assert!(resumes(with_u64(state, AAD_LEN_AT, AAD_LEN as u64)).is_ok());
    assert_eq!(
        resumes(with_u64(state, AAD_LEN_AT, AAD_LEN as u64 + 1)),
        Err(SuspendableError::InvalidData)
    );
}

/// The same checks run for the decrypting direction, which shares the adapter, plus the bound
/// on the tag bytes it holds back.
#[test]
fn the_decrypting_direction_checks_the_same_bounds() {
    let key = frame_key();
    let mut dec = key.create_decryptor(&[0x24u8; NONCE_LEN]);
    dec.do_update_aad(b"aad").unwrap();
    let mut out = [0u8; 16];
    dec.do_decrypt_out(&[0x5Au8; 16], &mut out).unwrap();
    let state = dec.suspend();
    let key = frame_key();
    let resumes = |state: [u8; ND]| ToyDec::from_suspended(state, key.state()).map(|_| ());

    assert!(resumes(state).is_ok());
    assert!(resumes(with_u64(state, OWED, DATA_LEN as u64 + 1)).is_err());
    assert!(resumes(with_u64(state, NEXT_CTR, 0)).is_err());
    assert!(resumes(with_u64(state, TAG_LEN_AT, 16)).is_ok());
    assert!(resumes(with_u64(state, TAG_LEN_AT, 17)).is_err());
}
