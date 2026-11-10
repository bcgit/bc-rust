//! Structural tests for CMAC, driven by a toy permutation: the two routes onto it agree, the
//! held-back final block comes out the same wherever the call boundaries fall, verification and
//! key validation. The known-answer tests (NIST CSRC, ACVP, Wycheproof) are in the
//! `aes` crate, `crypto/aes/tests/cmac_*.rs`.

mod common;

use bouncycastle_cipher::BlockCipherKey;
use bouncycastle_cipher::modes::{CMAC, Cmac, ModeNames};
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::errors::MACError;
use bouncycastle_core::hazmat::{KeyExpansion, MacMode, Mode};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{FromKeyMaterial, MacGenerationKey, MacVerificationKey};
use bouncycastle_core::traits::{MACGenerator, MACVerifier};
use bouncycastle_core_test_framework::from_key_material::TestFrameworkFromKeyMaterial;
use bouncycastle_core_test_framework::mac::TestFrameworkMAC;
use common::{TOY_LEN, Toy, toy_key};

type ToyCmac<'k, Dir> = Cmac<'k, Toy, Dir, TOY_LEN>;
type ToyCmacKey = BlockCipherKey<Toy, CMAC>;

fn cmac_key() -> ToyCmacKey {
    ToyCmacKey::from_key_material(&mac_key()).expect("the toy MAC key")
}

fn mac_key() -> KeyMaterial<TOY_LEN> {
    KeyMaterial::<TOY_LEN>::from_bytes_as_type(toy_key().ref_to_bytes(), KeyType::MACKey).unwrap()
}

/// The mode's own route onto the workers, through the hazmat mode traits the key forwards to.
fn key_state() -> <CMAC as Mode<Toy>>::KeyState {
    <CMAC as Mode<Toy>>::key_state(Toy::new(&toy_key()).unwrap())
}

fn mode_generator(state: &<CMAC as Mode<Toy>>::KeyState) -> ToyCmac<'_, Encrypting> {
    <CMAC as MacMode<Toy, TOY_LEN>>::generate_init(state)
}

fn mode_verifier(state: &<CMAC as Mode<Toy>>::KeyState) -> ToyCmac<'_, Decrypting> {
    <CMAC as MacMode<Toy, TOY_LEN>>::verify_init(state)
}

fn message(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(29).wrapping_add(3)).collect()
}

/// The key object and the mode's own route give the same tag, and the key passes the shared MAC
/// key suite against it.
#[test]
fn the_key_and_the_key_state_agree() {
    let state = key_state();
    let key = cmac_key();
    for len in [0, 1, 15, 16, 17, 32, 33, 100] {
        let msg = message(len);
        let from_key = key.mac(&msg);
        let mut generator = mode_generator(&state);
        generator.do_update(&msg);
        let from_state = generator.do_final();
        assert_eq!(from_state, from_key, "len {len}");
        let mut verifier = mode_verifier(&state);
        verifier.do_update(&msg);
        assert_eq!(verifier.do_verify_final(&from_key), Ok(()));
        assert_eq!(key.verify(&msg, &from_state), Ok(()));
        TestFrameworkMAC::new().test_mac_key(&key, &msg, &from_state);
    }
}

/// Every two-way split, plus byte-at-a-time, matches the one-shot: the pending block must come
/// out the same wherever the call boundaries fall, including a boundary exactly on a block edge.
#[test]
fn streaming_split_points() {
    let key = cmac_key();
    for mlen in [16, 20, 32, 33, 64] {
        let msg = message(mlen);
        let expected = key.mac(&msg);
        for split in 0..=mlen {
            let mut cmac = key.create_generator();
            cmac.do_update(&msg[..split]);
            cmac.do_update(&msg[split..]);
            assert_eq!(cmac.do_final(), expected, "mlen {mlen}, split at {split}");
        }
        let mut cmac = key.create_generator();
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
    let key = cmac_key();
    let short = message(20);
    let mut padded = short.clone();
    padded.push(0x80);
    padded.resize(32, 0);
    assert_ne!(key.mac(&short), key.mac(&padded));
    assert_ne!(key.mac(&[]), key.mac(&[0]));
}

/// The key's construction suite: a `MACKey` of the permutation's length and strength, bound to
/// the CMAC name or to nothing; a block cipher key is not a CMAC key (SP 800-38B Sec 5.2, key
/// separation).
#[test]
fn the_key_enforces_the_material_policy() {
    TestFrameworkFromKeyMaterial::new()
        .test::<TOY_LEN, ToyCmacKey>(Toy::CMAC_ALG_NAME, SecurityStrength::_128bit);
}

/// The tag is the full block, and verification wants exactly it.
#[test]
fn verification() {
    let key = cmac_key();
    let msg = message(20);
    let full = key.mac(&msg);
    assert_eq!(full.len(), TOY_LEN);

    assert_eq!(key.verify(&msg, &full), Ok(()));
    let mut wrong = full;
    wrong[15] ^= 1;
    assert_eq!(key.verify(&msg, &wrong), Err(MACError::VerificationFailed));
    assert_eq!(key.verify(&msg[..19], &full), Err(MACError::VerificationFailed));
}
