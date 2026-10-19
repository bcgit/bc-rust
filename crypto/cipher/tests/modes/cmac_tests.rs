//! Structural tests for CMAC, driven by a toy permutation: the two routes onto it agree, the
//! held-back final block comes out the same wherever the call boundaries fall, the tag rules, key
//! validation and suspend/resume. The known-answer tests (NIST CSRC, ACVP, Wycheproof) are in the
//! `aes` crate, `crypto/aes/tests/cmac_*.rs`.

mod common;
#[path = "../common/toy_key.rs"]
mod toy_key;

use bouncycastle_cipher::modes::{CMAC_MIN_TAG_LEN, Cmac, CmacKeyState, ModeNames};
use bouncycastle_core::errors::{MACError, SuspendableError};
use bouncycastle_core::hazmat::ElectronicCodeBook;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{FromKeyMaterial, MacGenerationKey, MacVerificationKey};
use bouncycastle_core::traits::{MAC, SuspendableKeyed};
use bouncycastle_core_test_framework::from_key_material::TestFrameworkFromKeyMaterial;
use bouncycastle_core_test_framework::mac::TestFrameworkMAC;
use common::{TOY_LEN, Toy, toy_key};
use toy_key::{ToyCMAC, ToyKey};

type ToyCmac = Cmac<Toy, TOY_LEN, TOY_LEN>;
type ToyCmacKey = ToyKey<Toy, ToyCMAC>;

fn cmac_key() -> ToyCmacKey {
    ToyCmacKey::from_key_material(&mac_key()).expect("the toy MAC key")
}

const STATE_LEN: usize = ToyCmac::SUSPENDED_STATE_LEN;

fn mac_key() -> KeyMaterial<TOY_LEN> {
    KeyMaterial::<TOY_LEN>::from_bytes_as_type(toy_key().ref_to_bytes(), KeyType::MACKey).unwrap()
}

fn key_state() -> CmacKeyState<Toy, TOY_LEN> {
    CmacKeyState::new::<TOY_LEN>(Toy::new(&toy_key()).unwrap())
}

fn message(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(29).wrapping_add(3)).collect()
}

/// The key object and the bare key state give the same tag, and the key passes the shared MAC
/// key suite against it.
#[test]
fn the_key_and_the_key_state_agree() {
    let state = key_state();
    let key = cmac_key();
    for len in [0, 1, 15, 16, 17, 32, 33, 100] {
        let msg = message(len);
        let from_key = key.mac(&msg);
        let from_state = ToyCmac::from_key_state(&state).mac(&msg);
        assert_eq!(from_state, from_key, "len {len}");
        assert!(ToyCmac::from_key_state(&state).verify(&msg, &from_key));
        assert!(key.verify(&msg, &from_state));
        TestFrameworkMAC::new().test_mac_key(&key, &msg, &from_state);
    }
}

/// Every two-way split, plus byte-at-a-time, matches the one-shot: the pending block must come
/// out the same wherever the call boundaries fall, including a boundary exactly on a block edge.
#[test]
fn streaming_split_points() {
    let state = key_state();
    for mlen in [16, 20, 32, 33, 64] {
        let msg = message(mlen);
        let expected = ToyCmac::from_key_state(&state).mac(&msg);
        for split in 0..=mlen {
            let mut cmac = ToyCmac::from_key_state(&state);
            cmac.do_update(&msg[..split]);
            cmac.do_update(&msg[split..]);
            assert_eq!(cmac.do_final(), expected, "mlen {mlen}, split at {split}");
        }
        let mut cmac = ToyCmac::from_key_state(&state);
        for b in &msg {
            cmac.do_update(core::slice::from_ref(b));
        }
        assert_eq!(cmac.do_final(), expected, "mlen {mlen}, byte at a time");
    }
}

/// A complete final block takes `K1`, a padded one `K2` (Sec 6.2 step 4), so a message and the
/// same message with the `10^j` padding spelled out must differ.
#[test]
fn a_complete_final_block_and_its_padded_twin_differ() {
    let state = key_state();
    let short = message(20);
    let mut padded = short.clone();
    padded.push(0x80);
    padded.resize(32, 0);
    assert_ne!(
        ToyCmac::from_key_state(&state).mac(&short),
        ToyCmac::from_key_state(&state).mac(&padded)
    );
    assert_ne!(ToyCmac::from_key_state(&state).mac(&[]), ToyCmac::from_key_state(&state).mac(&[0]));
}

/// The key's construction suite: a `MACKey` of the permutation's length and strength, bound to
/// the CMAC name or to nothing; a block cipher key is not a CMAC key (SP 800-38B Sec 5.2, key
/// separation).
#[test]
fn the_key_enforces_the_material_policy() {
    TestFrameworkFromKeyMaterial::new()
        .test::<TOY_LEN, ToyCmacKey>(Toy::CMAC_ALG_NAME, SecurityStrength::_128bit);
}

#[test]
fn truncation() {
    let state = key_state();
    let msg = message(20);
    let full = ToyCmac::from_key_state(&state).mac(&msg);
    assert_eq!(full.len(), TOY_LEN);
    assert_eq!(ToyCmac::from_key_state(&state).output_len(), TOY_LEN);

    let mut out = [0xAAu8; CMAC_MIN_TAG_LEN];
    assert_eq!(ToyCmac::from_key_state(&state).mac_out(&msg, &mut out).unwrap(), 8);
    assert_eq!(out[..], full[..8]);
    let mut long = [0xAAu8; 24];
    assert_eq!(ToyCmac::from_key_state(&state).mac_out(&msg, &mut long).unwrap(), 16);
    assert_eq!(long[..16], full[..]);
    assert_eq!(long[16..], [0u8; 8]);

    // Below 64 bits the call fails, and the buffer is left zeroized.
    let mut out = [0xAAu8; CMAC_MIN_TAG_LEN - 1];
    assert!(matches!(
        ToyCmac::from_key_state(&state).mac_out(&msg, &mut out),
        Err(MACError::InvalidLength(_))
    ));
    assert_eq!(out, [0u8; CMAC_MIN_TAG_LEN - 1]);

    // `verify` wants the full tag.
    assert!(ToyCmac::from_key_state(&state).verify(&msg, &full));
    assert!(!ToyCmac::from_key_state(&state).verify(&msg, &full[..15]));
    let mut long = full.clone();
    long.push(0);
    assert!(!ToyCmac::from_key_state(&state).verify(&msg, &long));
    let mut wrong = full.clone();
    wrong[15] ^= 1;
    assert!(!ToyCmac::from_key_state(&state).verify(&msg, &wrong));
}

#[test]
fn suspend_resume() {
    let key = mac_key();
    for mlen in [0, 16, 20, 64] {
        let msg = message(mlen);
        let expected = cmac_key().mac(&msg);
        for split in 0..=mlen {
            let mut cmac = cmac_key().create_generator();
            cmac.do_update(&msg[..split]);
            let state: [u8; STATE_LEN] = cmac.suspend();
            let mut resumed = ToyCmac::from_suspended(state, &key).unwrap();
            resumed.do_update(&msg[split..]);
            assert_eq!(resumed.do_final(), expected, "mlen {mlen}, suspended at {split}");
        }
    }
}

#[test]
fn suspend_resume_rejects() {
    let key = mac_key();
    let mut cmac = cmac_key().create_generator();
    cmac.do_update(b"some data");
    let state: [u8; STATE_LEN] = cmac.suspend();
    assert_eq!(STATE_LEN, 3 + 2 * TOY_LEN + 1);

    let mut bad_len = state;
    bad_len[STATE_LEN - 1] = TOY_LEN as u8 + 1;
    assert_eq!(ToyCmac::from_suspended(bad_len, &key).err(), Some(SuspendableError::InvalidData));
    let mut full_len = state;
    full_len[STATE_LEN - 1] = TOY_LEN as u8;
    assert!(ToyCmac::from_suspended(full_len, &key).is_ok());

    let mut no_ver = state;
    no_ver[..3].fill(0);
    assert_eq!(
        ToyCmac::from_suspended(no_ver, &key).err(),
        Some(SuspendableError::IncompatibleVersion)
    );

    let wrong_len = KeyMaterial::<32>::from_bytes_as_type(&[7u8; 32], KeyType::MACKey).unwrap();
    assert_eq!(
        ToyCmac::from_suspended(state, &wrong_len).err(),
        Some(SuspendableError::InvalidData)
    );
    assert_eq!(
        ToyCmac::from_suspended(state, &toy_key()).err(),
        Some(SuspendableError::InvalidData),
        "a cipher key is the wrong type"
    );
}
