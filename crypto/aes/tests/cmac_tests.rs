//! `AES*Key<CMAC>` against the NIST CSRC AES-CMAC examples through the MAC trait test framework,
//! plus the streaming split points, the key's construction policy and suspend/resume over the
//! real cipher. The structural tests are in `bouncycastle-cipher` over a toy; the large vector
//! sets are in `cmac_bc-test-data.rs` and `cmac_wycheproof.rs`.

use bouncycastle_aes::hazmat::{AES128Internal, AES256Internal};
use bouncycastle_aes::{AES_CMAC_128, AES_CMAC_256, AES128Key, AES192Key, AES256Key};
use bouncycastle_cipher::modes::{CMAC, CMAC_MIN_TAG_LEN, ModeNames};
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{FromKeyMaterial, MacGenerationKey, MacVerificationKey};
use bouncycastle_core::traits::{Algorithm, MAC, SuspendableKeyed};
use bouncycastle_core_test_framework::from_key_material::TestFrameworkFromKeyMaterial;
use bouncycastle_core_test_framework::mac::TestFrameworkMAC;
use bouncycastle_hex as hex;

const STATE_LEN: usize = AES_CMAC_128::SUSPENDED_STATE_LEN;

/// `KeyType::MACKey` material from hex, including the all-zero key some vector sets use.
fn mac_key<const N: usize>(key_hex: &str) -> KeyMaterial<N> {
    let bytes = hex::decode(key_hex).unwrap();
    let mut key = KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::MACKey).unwrap();
    if key.key_type() != KeyType::MACKey {
        do_hazardous_operations(&mut key, |k| {
            k.set_key_type(KeyType::MACKey)?;
            k.set_security_strength(SecurityStrength::from_bytes(N))
        })
        .unwrap();
    }
    key
}

// NIST CSRC "CMAC Mode for Authentication" examples (AES_CMAC.pdf, linked from SP 800-38B
// Appendix D): the same four messages under each key length. Examples 1-4 exercise, in order, the
// empty message (K2, n = 1), one complete block (K1), a partial final block (K2) and four complete
// blocks (K1).
const MSG: &str = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51\
                   30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
const MLENS: [usize; 4] = [0, 16, 20, 64];
const KEY_128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const KEY_192: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
const KEY_256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
const TAGS_128: [&str; 4] = [
    "bb1d6929e95937287fa37d129b756746",
    "070a16b46b4d4144f79bdd9dd04a287c",
    "7d85449ea6ea19c823a7bf78837dfade",
    "51f0bebf7e3b9d92fc49741779363cfe",
];
const TAGS_192: [&str; 4] = [
    "d17ddf46adaacde531cac483de7a9367",
    "9e99a7bf31e710900662f65e617c5184",
    "3d75c194ed96070444a9fa7ec740ecf8",
    "a1d5df0eed790f794d77589659f39a11",
];
const TAGS_256: [&str; 4] = [
    "028962f61b7bf89efc6b551f4667d983",
    "28a7023f452e8f82bd4bf28d8c37c35c",
    "156727dc0878944a023c1fe03bad6d93",
    "e1992190549f6ed5696a2c056c315410",
];

#[test]
fn csrc_examples() {
    let msg = hex::decode(MSG).unwrap();
    let tf = TestFrameworkMAC::new();
    let key_128 = AES128Key::<CMAC>::from_key_material(&mac_key::<16>(KEY_128)).unwrap();
    for (mlen, tag) in MLENS.iter().zip(TAGS_128) {
        tf.test_mac_key(&key_128, &msg[..*mlen], &hex::decode(tag).unwrap());
    }
    let key_192 = AES192Key::<CMAC>::from_key_material(&mac_key::<24>(KEY_192)).unwrap();
    for (mlen, tag) in MLENS.iter().zip(TAGS_192) {
        tf.test_mac_key(&key_192, &msg[..*mlen], &hex::decode(tag).unwrap());
    }
    let key_256 = AES256Key::<CMAC>::from_key_material(&mac_key::<32>(KEY_256)).unwrap();
    for (mlen, tag) in MLENS.iter().zip(TAGS_256) {
        tf.test_mac_key(&key_256, &msg[..*mlen], &hex::decode(tag).unwrap());
    }
}

/// Every two-way split of the 64-byte message, plus byte-at-a-time, matches the one-shot: the
/// held-back final block must come out the same wherever the call boundaries fall.
#[test]
fn streaming_split_points() {
    let key = AES128Key::<CMAC>::from_key_material(&mac_key::<16>(KEY_128)).unwrap();
    let msg = hex::decode(MSG).unwrap();
    for mlen in [20, 32, 33, 64] {
        let expected = key.mac(&msg[..mlen]);
        for split in 0..=mlen {
            let mut cmac = key.create_generator();
            cmac.do_update(&msg[..split]);
            cmac.do_update(&msg[split..mlen]);
            assert_eq!(cmac.do_final(), expected, "mlen {mlen}, split at {split}");
        }
        let mut cmac = key.create_generator();
        for b in &msg[..mlen] {
            cmac.do_update(core::slice::from_ref(b));
        }
        assert_eq!(cmac.do_final(), expected, "mlen {mlen}, byte at a time");
    }
    assert_eq!(
        key.mac(&msg),
        hex::decode(TAGS_128[3]).unwrap(),
        "the 64-byte one-shot is the CSRC example"
    );
}

/// The key's construction suite at both ends of the key-length range: a `MACKey` of the right
/// length and strength, bound to the CMAC name or to nothing; a block cipher key is not a CMAC
/// key (SP 800-38B Sec 5.2, key separation). Wrong lengths are a compile-time matter on this path.
#[test]
fn the_key_enforces_the_material_policy() {
    TestFrameworkFromKeyMaterial::new()
        .test::<16, AES128Key<CMAC>>(AES128Internal::CMAC_ALG_NAME, SecurityStrength::_128bit);
    TestFrameworkFromKeyMaterial::new()
        .test::<32, AES256Key<CMAC>>(AES256Internal::CMAC_ALG_NAME, SecurityStrength::_256bit);
}

#[test]
fn truncation_to_the_minimum_tag() {
    let key = AES128Key::<CMAC>::from_key_material(&mac_key::<16>(KEY_128)).unwrap();
    let msg = hex::decode(MSG).unwrap();
    let full = hex::decode(TAGS_128[2]).unwrap();
    let mut out = [0xAAu8; CMAC_MIN_TAG_LEN];
    assert_eq!(key.mac_out(&msg[..20], &mut out).unwrap(), 8);
    assert_eq!(out[..], full[..8]);
    assert!(!key.verify(&msg[..20], &full[..8]));
}

#[test]
fn algorithm_params() {
    assert_eq!(AES_CMAC_128::ALG_NAME, "AES_CMAC_128");
    assert_eq!(AES_CMAC_256::MAX_SECURITY_STRENGTH, SecurityStrength::_256bit);
    let cmac =
        AES192Key::<CMAC>::from_key_material(&mac_key::<24>(KEY_192)).unwrap().create_generator();
    assert_eq!(cmac.output_len(), 16);
    assert_eq!(cmac.max_security_strength(), SecurityStrength::_192bit);
    assert_eq!(STATE_LEN, 36);
}

/// Suspending after every prefix of the message and resuming under the same key gives the
/// one-shot tag.
#[test]
fn suspend_resume() {
    let material = mac_key::<16>(KEY_128);
    let key = AES128Key::<CMAC>::from_key_material(&material).unwrap();
    let msg = hex::decode(MSG).unwrap();
    for (mlen, tag) in MLENS.iter().zip(TAGS_128) {
        let expected = hex::decode(tag).unwrap();
        for split in 0..=*mlen {
            let mut cmac = key.create_generator();
            cmac.do_update(&msg[..split]);
            let state: [u8; STATE_LEN] = cmac.suspend();
            let mut resumed = AES_CMAC_128::from_suspended(state, &material).unwrap();
            resumed.do_update(&msg[split..*mlen]);
            assert_eq!(resumed.do_final(), expected, "mlen {mlen}, suspended at {split}");
        }
    }
}
