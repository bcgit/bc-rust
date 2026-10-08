//! What a resumed CCM state refuses: the bounds `Ccm` and its keystream check when they are
//! rebuilt from a suspended array, each tampered with on its own.
//!
//! The round trips in `suspend_tests.rs` show that a faithful state resumes. These show that an
//! unfaithful one does not, which is the other half of the contract and the half that pins each
//! check individually: with the flags octet, the counter field, the counter index, the CBC-MAC
//! position and the owed payload all validated in one `if`, a test that corrupts several at
//! once would still pass if any one check were dropped.
//!
//! The offsets are those of the layout the `SuspendableComponent` impls write, in order: the
//! library version, the keystream (counter template, counter index), the stream cipher's pending
//! block and its `used` count, then the chaining block, `mac_pos`, `aad_owed` and `owed`, every
//! integer a little-endian `u64`. Spec references are to NIST SP 800-38C (May 2004, errata
//! update 07-20-2007).

use bouncycastle_cipher::modes::Ccm;
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::errors::SuspendableError;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::SuspendableKeyed;
use bouncycastle_utils::suspendable_state::LIB_VERSION_LEN;

#[path = "common/toy_block_cipher.rs"]
mod toy_block_cipher;
use toy_block_cipher::ToyBlockCipher;

/// A 12-byte nonce, so `q = 3`: the counter field is the template's last three octets and the
/// payload limit is `2^24 - 1`.
const NONCE_LEN: usize = 12;
const BLOCK_LEN: usize = 16;
type ToyCcm<Dir> = Ccm<ToyBlockCipher, Dir, 16, BLOCK_LEN, NONCE_LEN, 16>;
const N: usize = ToyCcm::<Encrypting>::SUSPENDED_STATE_LEN;

/// A.1's `2^8q - 1`, which bounds both the owed payload and, since there is one counter block per
/// payload block, the counter field; `MAX_COUNTER` is the same number for every `q < 8`.
const LIMIT: u64 = ToyCcm::<Encrypting>::MAX_PAYLOAD_LEN;

// Field offsets within the suspended array.
const TEMPLATE: usize = LIB_VERSION_LEN;
const NEXT_CTR: usize = TEMPLATE + BLOCK_LEN;
const MAC_POS: usize = N - 24;
const OWED: usize = N - 8;

fn key() -> KeyMaterial<16> {
    KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap()
}

/// A freshly constructed encryptor's state: `next_ctr = 1`, `mac_pos = 0` after `B0`, `owed` as
/// declared.
fn fresh(payload_len: usize) -> [u8; N] {
    ToyCcm::<Encrypting>::new(&key(), &[0x24u8; NONCE_LEN], b"aad", payload_len).unwrap().suspend()
}

fn with_u64(mut state: [u8; N], at: usize, value: u64) -> [u8; N] {
    state[at..at + 8].copy_from_slice(&value.to_le_bytes());
    state
}

fn resumes(state: [u8; N]) -> Result<(), SuspendableError> {
    ToyCcm::<Encrypting>::from_suspended(state, &key()).map(|_| ())
}

/// `mac_pos` is how much of the current CBC-MAC block has been XORed in, and a full block is
/// enciphered at once, so `BLOCK_LEN - 1` is the largest value a real state can hold.
#[test]
fn mac_pos_is_held_below_the_block_length() {
    let state = fresh(32);
    assert!(resumes(with_u64(state, MAC_POS, (BLOCK_LEN - 1) as u64)).is_ok());
    assert_eq!(
        resumes(with_u64(state, MAC_POS, BLOCK_LEN as u64)),
        Err(SuspendableError::InvalidData)
    );
}

/// `owed` is what `B0` committed to minus what has been supplied, so it can never exceed A.1's
/// `2^8q - 1`; the limit itself is a legal value, since nothing has to have been supplied yet.
#[test]
fn owed_is_held_to_the_payload_limit() {
    let state = fresh(32);
    assert!(resumes(with_u64(state, OWED, LIMIT)).is_ok());
    assert_eq!(resumes(with_u64(state, OWED, LIMIT + 1)), Err(SuspendableError::InvalidData));
}

/// The counter index runs from 1 (`S0` is the tag mask, step 7 starts the payload keystream at
/// `S1`) to one past the last counter value, which is where it stands once every block has been
/// used; 0 and anything beyond are not states a `Ccm` can have been in.
#[test]
fn the_counter_index_is_held_to_its_range() {
    let state = fresh(32);
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
    let state = fresh(32);
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

/// The same checks run for the decrypting direction, which shares the impl.
#[test]
fn the_decrypting_direction_checks_the_same_bounds() {
    let state =
        ToyCcm::<Decrypting>::new(&key(), &[0x24u8; NONCE_LEN], b"aad", 32).unwrap().suspend();
    assert!(ToyCcm::<Decrypting>::from_suspended(state, &key()).is_ok());
    assert!(
        ToyCcm::<Decrypting>::from_suspended(with_u64(state, OWED, LIMIT + 1), &key()).is_err()
    );
    assert!(ToyCcm::<Decrypting>::from_suspended(with_u64(state, NEXT_CTR, 0), &key()).is_err());
}
