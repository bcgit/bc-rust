//! NIST ACVP "KDA OneStep SP800-56Cr2" vectors (the ACVP-Server sample vector set, `prompt.json`
//! and `expectedResults.json` in `bc-test-data/crypto/acvp/KDA-OneStep-Sp800-56Cr2/`): every
//! group whose auxiliary function is a hash, SP 800-56C Rev. 2 Option 1. The HMAC and KMAC
//! groups (Options 2 and 3) are not read. FixedInfo is built as the ACVP KDA specification's
//! capabilities section says, by the group's pattern `t||uPartyInfo||vPartyInfo||l`, with a party
//! info `partyId { || ephemeralData }` and `l` the output length in bits in 32 big-endian bits.
//! AFT cases check the derived keying material; VAL cases check that it matches the supplied
//! value exactly when the expected results say the case passes. A missing `bc-test-data`
//! checkout fails the test rather than skipping it.

use bouncycastle_concatkdf::{
    ConcatKDF_SHA3_224, ConcatKDF_SHA3_256, ConcatKDF_SHA3_384, ConcatKDF_SHA3_512,
    ConcatKDF_SHA224, ConcatKDF_SHA256, ConcatKDF_SHA384, ConcatKDF_SHA512, ConcatKDF_SHA512_224,
    ConcatKDF_SHA512_256,
};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

const TEST_DATA_PATH_RELATIVE: &str = "../../../bc-test-data/crypto/acvp/KDA-OneStep-Sp800-56Cr2";
const TEST_DATA_PATH: &str = "../bc-test-data/crypto/acvp/KDA-OneStep-Sp800-56Cr2";

fn get_test_data(filename: &str) -> Value {
    let dir = [TEST_DATA_PATH_RELATIVE, TEST_DATA_PATH]
        .into_iter()
        .find(|d| Path::new(d).exists())
        .unwrap_or_else(|| {
            panic!(
                "bc-test-data not found (looked in {TEST_DATA_PATH_RELATIVE:?} and \
                 {TEST_DATA_PATH:?}); the concatenation KDF ACVP suite requires it rather than \
                 skipping"
            )
        });
    let text = fs::read_to_string(format!("{dir}/{filename}"))
        .unwrap_or_else(|e| panic!("failed to read ACVP vector file {dir}/{filename}: {e}"));
    serde_json::from_str(&text).unwrap()
}

fn hex(v: &Value) -> Vec<u8> {
    bouncycastle_hex::decode(v.as_str().unwrap()).unwrap()
}

/// A tcId, which the files give as a number or as a string.
fn tc_id(v: &Value) -> u64 {
    v.as_u64().unwrap_or_else(|| v.as_str().unwrap().parse().unwrap())
}

/// `partyId { || ephemeralData }`.
fn party_info(v: &Value) -> Vec<u8> {
    let mut out = hex(&v["partyId"]);
    if let Some(e) = v.get("ephemeralData") {
        out.extend(hex(e));
    }
    out
}

fn derive(aux: &str, z: &KeyMaterial<8192>, fixed_info: &[u8], len: usize) -> Vec<u8> {
    let mut out = KeyMaterial::<256>::new();
    let written = match aux {
        "SHA2-224" => ConcatKDF_SHA224::derive_out(z, fixed_info, len, &mut out),
        "SHA2-256" => ConcatKDF_SHA256::derive_out(z, fixed_info, len, &mut out),
        "SHA2-384" => ConcatKDF_SHA384::derive_out(z, fixed_info, len, &mut out),
        "SHA2-512" => ConcatKDF_SHA512::derive_out(z, fixed_info, len, &mut out),
        "SHA2-512/224" => ConcatKDF_SHA512_224::derive_out(z, fixed_info, len, &mut out),
        "SHA2-512/256" => ConcatKDF_SHA512_256::derive_out(z, fixed_info, len, &mut out),
        "SHA3-224" => ConcatKDF_SHA3_224::derive_out(z, fixed_info, len, &mut out),
        "SHA3-256" => ConcatKDF_SHA3_256::derive_out(z, fixed_info, len, &mut out),
        "SHA3-384" => ConcatKDF_SHA3_384::derive_out(z, fixed_info, len, &mut out),
        "SHA3-512" => ConcatKDF_SHA3_512::derive_out(z, fixed_info, len, &mut out),
        other => panic!("unexpected auxiliary function {other}"),
    }
    .unwrap();
    assert_eq!(written, len);
    out.ref_to_bytes().to_vec()
}

#[test]
fn acvp_kda_onestep_sp800_56cr2_hash() {
    let prompt = get_test_data("prompt.json");
    let expected = get_test_data("expectedResults.json");
    let results: HashMap<u64, &Value> = expected["testGroups"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|g| g["tests"].as_array().unwrap())
        .map(|t| (tc_id(&t["tcId"]), t))
        .collect();

    let mut checked = HashMap::<String, usize>::new();
    for group in prompt["testGroups"].as_array().unwrap() {
        let config = &group["kdfConfiguration"];
        let aux = config["auxFunction"].as_str().unwrap();
        if aux.starts_with("HMAC-") || aux.starts_with("KMAC-") {
            continue;
        }
        assert_eq!(config["fixedInfoPattern"], "t||uPartyInfo||vPartyInfo||l");
        assert_eq!(config["fixedInfoEncoding"], "concatenation");
        let l_bits = config["l"].as_u64().unwrap() as u32;
        assert_eq!(l_bits % 8, 0, "the library derives whole bytes");
        let len = (l_bits / 8) as usize;
        let test_type = group["testType"].as_str().unwrap();

        for test in group["tests"].as_array().unwrap() {
            let id = tc_id(&test["tcId"]);
            let p = &test["kdfParameter"];
            let z = KeyMaterial::<8192>::from_bytes_as_type(&hex(&p["z"]), KeyType::SharedSecret)
                .unwrap();
            let mut fixed_info = hex(&p["t"]);
            fixed_info.extend(party_info(&test["fixedInfoPartyU"]));
            fixed_info.extend(party_info(&test["fixedInfoPartyV"]));
            fixed_info.extend(l_bits.to_be_bytes());

            let dkm = derive(aux, &z, &fixed_info, len);
            let result = results[&id];
            match test_type {
                "AFT" => assert_eq!(dkm, hex(&result["dkm"]), "{aux} tcId {id}"),
                "VAL" => assert_eq!(
                    dkm == hex(&test["dkm"]),
                    result["testPassed"].as_bool().unwrap(),
                    "{aux} tcId {id}"
                ),
                other => panic!("unexpected test type {other}"),
            }
            *checked.entry(format!("{aux} {test_type}")).or_default() += 1;
        }
    }
    // Ten groups of five per hash in the sample set, half AFT and half VAL.
    for aux in ["SHA2-224", "SHA2-512", "SHA3-512"] {
        for t in ["AFT", "VAL"] {
            assert_eq!(checked.get(&format!("{aux} {t}")), Some(&25), "{aux} {t}");
        }
    }
    assert_eq!(checked.values().sum::<usize>(), 150);
}
