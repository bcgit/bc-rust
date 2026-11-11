//! CMAC over TDEA through the generic `bouncycastle_cipher::BlockCipherKey`, the one key with a
//! MAC role over this crate's permutations (`TDESKey` has none): three-key generates and
//! verifies, two-key verifies only (SP 800-131A Rev 2 Table 9), its generator being a compile
//! error pinned by the doctest on `TDES2Internal`. Known answers from NIST's CMAC example file for
//! TDES (csrc.nist.gov, "TDES_CMAC.pdf"), both the three-key set and the two-key set
//! (`Key3 = Key1`), all four samples each.

use bouncycastle_cipher::BlockCipherKey;
use bouncycastle_cipher::modes::CMAC;
use bouncycastle_core::errors::MACError;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{FromKeyMaterial, MacGenerationKey, MacVerificationKey};
use bouncycastle_core::traits::MACVerifier;
use bouncycastle_hex as hex;
use bouncycastle_tdes::BLOCK_LEN;
use bouncycastle_tdes::hazmat::{TDES2Internal, TDESInternal};

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

/// The NIST sample plaintexts: empty, 16, 20 and 32 bytes.
const MSGS: [&str; 4] = [
    "",
    "6bc1bee22e409f96e93d7e117393172a",
    "6bc1bee22e409f96e93d7e117393172aae2d8a57",
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
];

/// Three-key bundle `0123456789abcdef 23456789abcdef01 456789abcdef0123` and its four tags.
const KEY3: &str = "0123456789abcdef23456789abcdef01456789abcdef0123";
const TAGS3: [&str; 4] =
    ["7db0d37df936c550", "30239cf1f52e6609", "6c9f3ee4923f6be2", "99429bd0bf7904e5"];

/// Two-key bundle `0123456789abcdef 23456789abcdef01` (`Key3 = Key1`) and its four tags.
const KEY2: &str = "0123456789abcdef23456789abcdef01";
const TAGS2: [&str; 4] =
    ["79ce52a7f786a960", "cc18a0b79af2413b", "c06d377ecd101969", "9cd33580f9b64dfb"];

#[test]
fn three_key_cmac_generates_and_verifies_the_nist_samples() {
    let material = KeyMaterial::<24>::from_bytes_as_type(&h(KEY3), KeyType::MACKey).unwrap();
    let key =
        BlockCipherKey::<TDESInternal, CMAC<BLOCK_LEN>>::from_key_material(&material).unwrap();
    for (msg, tag) in MSGS.iter().zip(TAGS3) {
        let msg = h(msg);
        let tag: [u8; BLOCK_LEN] = h(tag).try_into().unwrap();
        assert_eq!(key.mac(&msg), tag);
        assert_eq!(key.verify(&msg, &tag), Ok(()));
    }
}

#[test]
fn two_key_cmac_verifies_the_nist_samples_and_refuses_a_changed_tag() {
    let material = KeyMaterial::<16>::from_bytes_as_type(&h(KEY2), KeyType::MACKey).unwrap();
    let key =
        BlockCipherKey::<TDES2Internal, CMAC<BLOCK_LEN>>::from_key_material(&material).unwrap();
    for (msg, tag) in MSGS.iter().zip(TAGS2) {
        let msg = h(msg);
        let tag: [u8; BLOCK_LEN] = h(tag).try_into().unwrap();
        assert_eq!(key.verify(&msg, &tag), Ok(()));
        let mut bad = tag;
        bad[0] ^= 0x01;
        assert_eq!(key.verify(&msg, &bad), Err(MACError::VerificationFailed));
        let mut verifier = key.create_verifier();
        for chunk in msg.chunks(3) {
            verifier.do_update(chunk);
        }
        assert_eq!(verifier.do_verify_final(&tag), Ok(()));
    }
}
