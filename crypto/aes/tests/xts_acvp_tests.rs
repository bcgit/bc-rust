//! XTS-AES-128 and XTS-AES-256 against NIST's ACVP sample vector sets `ACVP-AES-XTS-1.0` and
//! `ACVP-AES-XTS-2.0`: `prompt.json` and `expectedResults.json` in
//! `bc-test-data/crypto/acvp/ACVP-AES-XTS-{1.0,2.0}/`, as published in NIST's ACVP-Server
//! repository (`gen-val/json-files`, commit `975de31e`). Requires bc-test-data at
//! `../bc-test-data`; absent, the tests warn and pass.
//!
//! Every case that is one data unit of a whole number of bytes is run, in both directions
//! whichever one it was generated for. The rest are counted and skipped: an ACVP data unit can be
//! any number of bits, where this API takes whole bytes, and the 2.0 set's cases whose
//! `dataUnitLen` differs from their `payloadLen` are not a data unit of the key's one length. The
//! counts are asserted, so a case cannot drop out of the run unnoticed.
//!
//! A case of tweak mode "number" gives the data unit's sequence number, and the tweak is its
//! 128-bit little-endian encoding (IEEE 1619-2007 Sec 5.1); one of mode "hex" gives the tweak.

use bouncycastle_aes::hazmat::{AES128Internal, AES256Internal};
use bouncycastle_cipher::modes::XTSKey;
use bouncycastle_core::hazmat::BlockPermutation;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::FromKeyMaterial;
use bouncycastle_core_test_framework::test_data_loaders::{Value, bc_test_data_json, hex_field};
use std::collections::HashMap;

/// A number, which the files give as a number or as a string.
fn number(v: &Value) -> u64 {
    v.as_u64().unwrap_or_else(|| v.as_str().expect("a number").parse().expect("a number"))
}

/// Checks one case through `XTSKey<P, N>` under its `KEY_LEN`-byte key, in both directions.
fn check<P, const KEY_LEN: usize, const N: usize>(
    key: &[u8],
    tweak: &[u8; 16],
    pt: &[u8],
    ct: &[u8],
    tc_id: u64,
) where
    P: BlockPermutation<16>,
    XTSKey<P, N>: FromKeyMaterial<KEY_LEN>,
{
    let material =
        KeyMaterial::<KEY_LEN>::from_bytes_as_type(key, KeyType::SymmetricCipherKey).unwrap();
    let key = XTSKey::<P, N>::from_key_material(&material)
        .unwrap_or_else(|e| panic!("tcId {tc_id}: the key is refused: {e:?}"));
    let pt: [u8; N] = pt.try_into().expect("an N-byte plaintext");
    let ct: [u8; N] = ct.try_into().expect("an N-byte ciphertext");

    let mut data_unit = pt;
    assert_eq!(key.encrypt_inplace(tweak, &mut data_unit), N, "tcId {tc_id}");
    assert_eq!(data_unit, ct, "tcId {tc_id}: encryption");

    let mut data_unit = ct;
    assert_eq!(key.decrypt_inplace(tweak, &mut data_unit), N, "tcId {tc_id}");
    assert_eq!(data_unit, pt, "tcId {tc_id}: decryption");
}

fn check_128<const N: usize>(key: &[u8], tweak: &[u8; 16], pt: &[u8], ct: &[u8], tc_id: u64) {
    check::<AES128Internal, 32, N>(key, tweak, pt, ct, tc_id);
}

fn check_256<const N: usize>(key: &[u8], tweak: &[u8; 16], pt: &[u8], ct: &[u8], tc_id: u64) {
    check::<AES256Internal, 64, N>(key, tweak, pt, ct, tc_id);
}

/// Calls `$check::<N>` for the data-unit length `$len`. The length is a const parameter of the
/// key type, so every whole-byte length in the two files has an arm.
macro_rules! dispatch {
    ($len:expr, $check:ident, $args:tt, $tc_id:expr, [$($n:literal)*]) => {
        match $len {
            $($n => $check::<$n> $args,)*
            other => panic!("tcId {}: no arm for a {other}-byte data unit; add one", $tc_id),
        }
    };
}

/// Runs every whole-byte, single-data-unit case of one revision's vector set, and returns how
/// many ran under each key size and how many were skipped.
fn run(revision: &str) -> Option<(usize, usize, usize)> {
    let dir = format!("crypto/acvp/ACVP-AES-XTS-{revision}");
    let prompt = bc_test_data_json(&dir, "prompt.json")?;
    let expected = bc_test_data_json(&dir, "expectedResults.json")?;
    let results: HashMap<u64, &Value> = expected["testGroups"]
        .as_array()
        .expect("testGroups")
        .iter()
        .flat_map(|g| g["tests"].as_array().expect("tests"))
        .map(|t| (number(&t["tcId"]), t))
        .collect();

    let (mut ran_128, mut ran_256, mut skipped) = (0usize, 0usize, 0usize);
    for group in prompt["testGroups"].as_array().expect("testGroups") {
        let key_len = number(&group["keyLen"]);
        let encrypt = match group["direction"].as_str().expect("direction") {
            "encrypt" => true,
            "decrypt" => false,
            other => panic!("unexpected direction {other}"),
        };
        for case in group["tests"].as_array().expect("tests") {
            let tc_id = number(&case["tcId"]);
            // Revision 1.0 gives the length once per group, 2.0 per case and beside the
            // data-unit length.
            let payload_bits = number(case.get("payloadLen").unwrap_or(&group["payloadLen"]));
            let data_unit_bits = case.get("dataUnitLen").map_or(payload_bits, number);
            if !payload_bits.is_multiple_of(8) || data_unit_bits != payload_bits {
                skipped += 1;
                continue;
            }
            let len = (payload_bits / 8) as usize;

            let tweak: [u8; 16] = match group["tweakMode"].as_str().expect("tweakMode") {
                "hex" => hex_field(case, "tweakValue", tc_id).try_into().expect("a 16-byte tweak"),
                "number" => u128::from(number(&case["sequenceNumber"])).to_le_bytes(),
                other => panic!("tcId {tc_id}: unexpected tweakMode {other}"),
            };
            let key = hex_field(case, "key", tc_id);
            let result = results[&tc_id];
            let (pt, ct) = if encrypt {
                (hex_field(case, "pt", tc_id), hex_field(result, "ct", tc_id))
            } else {
                (hex_field(result, "pt", tc_id), hex_field(case, "ct", tc_id))
            };
            assert_eq!(pt.len(), len, "tcId {tc_id}: the plaintext is payloadLen bits");

            #[rustfmt::skip]
            macro_rules! by_len {
                ($check:ident) => {
                    dispatch!(len, $check, (&key, &tweak, &pt, &ct, tc_id), tc_id, [
                        16 21 23 27 29 31 46 48 56 57 59 62 64 75 77 78 84 86 92 93 94 100 119 126
                        262 308 320 559 669 912 919 1184 1447 1451 1568 1616 1950 2051 2528 2538
                        2669 2792 3001 3152 3216 3536 3632 3744 3788 4000 4151 4539 4610 5166 5344
                        5375 5909 6317 6321 6494 6528 6672 6732 6780 7089 7312 7856 7968 8024 8192
                    ])
                };
            }
            match key_len {
                128 => {
                    by_len!(check_128);
                    ran_128 += 1;
                }
                256 => {
                    by_len!(check_256);
                    ran_256 += 1;
                }
                other => panic!("tcId {tc_id}: unexpected keyLen {other}"),
            }
        }
    }
    println!(
        "ACVP-AES-XTS-{revision}: {ran_128} XTS-AES-128 and {ran_256} XTS-AES-256 cases, \
         {skipped} skipped (not whole bytes, or not one data unit)"
    );
    Some((ran_128, ran_256, skipped))
}

#[test]
fn acvp_aes_xts_1_0() {
    let Some(counts) = run("1.0") else {
        return;
    };
    assert_eq!(counts, (130, 130, 140));
}

#[test]
fn acvp_aes_xts_2_0() {
    let Some(counts) = run("2.0") else {
        return;
    };
    assert_eq!(counts, (42, 30, 728));
}
