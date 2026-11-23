//! XTS-AES-128 and XTS-AES-256 against NIST's ACVP sample vector sets `ACVP-AES-XTS-1.0` and
//! `ACVP-AES-XTS-2.0`: `prompt.json` and `expectedResults.json` in
//! `bc-test-data/crypto/acvp/ACVP-AES-XTS-{1.0,2.0}/`, as published in NIST's ACVP-Server
//! repository (`gen-val/json-files`, commit `975de31e`). Requires bc-test-data at
//! `../bc-test-data`; absent, the tests warn and pass.
//!
//! Every case that is one data unit of a whole number of bytes is run, in both directions
//! whichever one it was generated for. The rest are counted and skipped: an ACVP data unit can be
//! any number of bits, where this API takes whole bytes, and the payload of a 2.0 case whose
//! `dataUnitLen` differs from its `payloadLen` is not one data unit of the stated length. The
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

/// Checks one case through `XTSKey<P>` under its `KEY_LEN`-byte key, in both directions.
fn check<P, const KEY_LEN: usize>(key: &[u8], tweak: &[u8; 16], pt: &[u8], ct: &[u8], tc_id: u64)
where
    P: BlockPermutation<16>,
    XTSKey<P>: FromKeyMaterial<KEY_LEN>,
{
    let material =
        KeyMaterial::<KEY_LEN>::from_bytes_as_type(key, KeyType::SymmetricCipherKey).unwrap();
    let key = XTSKey::<P>::from_key_material(&material)
        .unwrap_or_else(|e| panic!("tcId {tc_id}: the key is refused: {e:?}"));
    assert_eq!(ct.len(), pt.len(), "tcId {tc_id}: the ciphertext is as long as the plaintext");

    let mut data_unit = pt.to_vec();
    assert_eq!(key.encrypt_inplace(tweak, &mut data_unit), Ok(pt.len()), "tcId {tc_id}");
    assert_eq!(data_unit, ct, "tcId {tc_id}: encryption");

    let mut data_unit = ct.to_vec();
    assert_eq!(key.decrypt_inplace(tweak, &mut data_unit), Ok(ct.len()), "tcId {tc_id}");
    assert_eq!(data_unit, pt, "tcId {tc_id}: decryption");
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

            match key_len {
                128 => {
                    check::<AES128Internal, 32>(&key, &tweak, &pt, &ct, tc_id);
                    ran_128 += 1;
                }
                256 => {
                    check::<AES256Internal, 64>(&key, &tweak, &pt, &ct, tc_id);
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
