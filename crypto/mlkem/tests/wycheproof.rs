//! Test against the project wycheproof repo available at:
//!     https://github.com/C2SP/wycheproof
//! Requires that the wycheproof repository is cloned and available for testing at "../wycheproof"
//! relative to the root of this git project.
//!
//! This test file exercises the following test sets:
//!
//!  * mlkem_512_encaps_test.json
//!  * mlkem_512_keygen_seed_test.json
//!  * mlkem_512_semi_expanded_decaps_test.json
//!  * mlkem_512_test.json
//!  * mlkem_768_encaps_test.json
//!  * mlkem_768_keygen_seed_test.json
//!  * mlkem_768_semi_expanded_decaps_test.json
//!  * mlkem_768_test.json
//!  * mlkem_1024_encaps_test.json
//!  * mlkem_1024_keygen_seed_test.json
//!  * mlkem_1024_semi_expanded_decaps_test.json
//!  * mlkem_1024_test.json

#![allow(dead_code)]

use bouncycastle_core::key_material::{KeyMaterial512, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{KEMDecapsulator, KEMPrivateKey, KEMPublicKey, SecurityStrength};
use bouncycastle_hex as hex;
use bouncycastle_mlkem::{
    MLKEM512, MLKEM512PrivateKey, MLKEM512PublicKey, MLKEM768, MLKEM768PrivateKey,
    MLKEM768PublicKey, MLKEM1024, MLKEM1024PrivateKey, MLKEM1024PublicKey, MLKEMTrait,
};

#[cfg(test)]
mod wycheproof {
    use crate::{
        MLKEMEncapsTestCase, MLKEMKeygenSeedTestCase, MLKEMSemiExpandedDecapsTestCase,
        MLKEMTestCase, ParameterSet,
    };
    use std::fs;
    use std::path::Path;
    use std::sync::Once;

    const TEST_DATA_PATH_RELATIVE: &str = "../../../wycheproof/testvectors_v1";
    const TEST_DATA_PATH: &str = "../wycheproof/testvectors_v1";

    static TEST_DATA_CHECK: Once = Once::new();

    fn get_test_data(filename: &str) -> Result<String, ()> {
        let found: u8;
        if Path::new(TEST_DATA_PATH_RELATIVE).exists() {
            found = 1;
        } else if Path::new(TEST_DATA_PATH).exists() {
            found = 2;
        } else {
            found = 3;
        };

        // just print once
        TEST_DATA_CHECK.call_once(|| match found {
            1 => println!("wycheproof found at: {:?}", TEST_DATA_PATH_RELATIVE),
            2 => println!("wycheproof found at: {:?}", TEST_DATA_PATH),
            _ => println!("WARNING: wycheproof directory not found; tests will be skipped"),
        });

        if !found == 3 {
            return Err(());
        }

        let contents = if Path::new(TEST_DATA_PATH_RELATIVE).exists() {
            fs::read_to_string(TEST_DATA_PATH_RELATIVE.to_string() + "/" + filename).unwrap()
        } else if Path::new(TEST_DATA_PATH).exists() {
            fs::read_to_string(TEST_DATA_PATH.to_string() + "/" + filename).unwrap()
        } else {
            return Err(());
        };

        Ok(contents)
    }

    #[test]
    fn mlkem_512_encaps_test() {
        let contents = match get_test_data("mlkem_512_encaps_test.json") {
            Ok(contents) => contents,
            Err(()) => return,
        };

        let test_cases = MLKEMEncapsTestCase::parse(contents, ParameterSet::Mlkem512);

        let num_test_cases = test_cases.len();
        for test_case in test_cases {
            test_case.run_mlkem512();
        }

        println!("mlkem_512_encaps_test: all {} test cases passed.", num_test_cases);
    }

    #[test]
    fn mlkem_512_keygen_seed_test() {
        let contents = match get_test_data("mlkem_512_keygen_seed_test.json") {
            Ok(contents) => contents,
            Err(()) => return,
        };

        let test_cases = MLKEMKeygenSeedTestCase::parse(contents, ParameterSet::Mlkem512);

        let num_test_cases = test_cases.len();
        for test_case in test_cases {
            test_case.run_mlkem512();
        }

        println!("mlkem_512_keygen_seed_test: all {} test cases passed.", num_test_cases);
    }

    #[test]
    fn mlkem_512_semi_expanded_decaps_test() {
        let contents = match get_test_data("mlkem_512_semi_expanded_decaps_test.json") {
            Ok(contents) => contents,
            Err(()) => return,
        };

        let test_cases = MLKEMSemiExpandedDecapsTestCase::parse(contents, ParameterSet::Mlkem512);

        let num_test_cases = test_cases.len();
        for test_case in test_cases {
            test_case.run_mlkem512();
        }

        println!("mlkem_512_semi_expanded_decaps_test: all {} test cases passed.", num_test_cases);
    }

    #[test]
    fn mlkem_512_test() {
        let contents = match get_test_data("mlkem_512_test.json") {
            Ok(contents) => contents,
            Err(()) => return,
        };

        let test_cases = MLKEMTestCase::parse(contents, ParameterSet::Mlkem512);

        let num_test_cases = test_cases.len();
        for test_case in test_cases {
            test_case.run_mlkem512();
        }

        println!("mlkem_512_test: all {} test cases passed.", num_test_cases);
    }

    #[test]
    fn mlkem_768_encaps_test() {
        let contents = match get_test_data("mlkem_768_encaps_test.json") {
            Ok(contents) => contents,
            Err(()) => return,
        };

        let test_cases = MLKEMEncapsTestCase::parse(contents, ParameterSet::Mlkem768);

        let num_test_cases = test_cases.len();
        for test_case in test_cases {
            test_case.run_mlkem768();
        }

        println!("mlkem_768_encaps_test: all {} test cases passed.", num_test_cases);
    }

    #[test]
    fn mlkem_768_keygen_seed_test() {
        let contents = match get_test_data("mlkem_768_keygen_seed_test.json") {
            Ok(contents) => contents,
            Err(()) => return,
        };

        let test_cases = MLKEMKeygenSeedTestCase::parse(contents, ParameterSet::Mlkem768);

        let num_test_cases = test_cases.len();
        for test_case in test_cases {
            test_case.run_mlkem768();
        }

        println!("mlkem_768_keygen_seed_test: all {} test cases passed.", num_test_cases);
    }

    #[test]
    fn mlkem_768_semi_expanded_decaps_test() {
        let contents = match get_test_data("mlkem_768_semi_expanded_decaps_test.json") {
            Ok(contents) => contents,
            Err(()) => return,
        };

        let test_cases = MLKEMSemiExpandedDecapsTestCase::parse(contents, ParameterSet::Mlkem768);

        let num_test_cases = test_cases.len();
        for test_case in test_cases {
            test_case.run_mlkem768();
        }

        println!("mlkem_768_semi_expanded_decaps_test: all {} test cases passed.", num_test_cases);
    }

    #[test]
    fn mlkem_768_test() {
        let contents = match get_test_data("mlkem_768_test.json") {
            Ok(contents) => contents,
            Err(()) => return,
        };

        let test_cases = MLKEMTestCase::parse(contents, ParameterSet::Mlkem768);

        let num_test_cases = test_cases.len();
        for test_case in test_cases {
            test_case.run_mlkem768();
        }

        println!("mlkem_768_test: all {} test cases passed.", num_test_cases);
    }

    #[test]
    fn mlkem_1024_encaps_test() {
        let contents = match get_test_data("mlkem_1024_encaps_test.json") {
            Ok(contents) => contents,
            Err(()) => return,
        };

        let test_cases = MLKEMEncapsTestCase::parse(contents, ParameterSet::Mlkem1024);

        let num_test_cases = test_cases.len();
        for test_case in test_cases {
            test_case.run_mlkem1024();
        }

        println!("mlkem_1024_encaps_test: all {} test cases passed.", num_test_cases);
    }

    #[test]
    fn mlkem_1024_keygen_seed_test() {
        let contents = match get_test_data("mlkem_1024_keygen_seed_test.json") {
            Ok(contents) => contents,
            Err(()) => return,
        };

        let test_cases = MLKEMKeygenSeedTestCase::parse(contents, ParameterSet::Mlkem1024);

        let num_test_cases = test_cases.len();
        for test_case in test_cases {
            test_case.run_mlkem1024();
        }

        println!("mlkem_1024_keygen_seed_test: all {} test cases passed.", num_test_cases);
    }

    #[test]
    fn mlkem_1024_semi_expanded_decaps_test() {
        let contents = match get_test_data("mlkem_1024_semi_expanded_decaps_test.json") {
            Ok(contents) => contents,
            Err(()) => return,
        };

        let test_cases = MLKEMSemiExpandedDecapsTestCase::parse(contents, ParameterSet::Mlkem1024);

        let num_test_cases = test_cases.len();
        for test_case in test_cases {
            test_case.run_mlkem1024();
        }

        println!("mlkem_1024_semi_expanded_decaps_test: all {} test cases passed.", num_test_cases);
    }

    #[test]
    fn mlkem_1024_test() {
        let contents = match get_test_data("mlkem_1024_test.json") {
            Ok(contents) => contents,
            Err(()) => return,
        };

        let test_cases = MLKEMTestCase::parse(contents, ParameterSet::Mlkem1024);

        let num_test_cases = test_cases.len();
        for test_case in test_cases {
            test_case.run_mlkem1024();
        }

        println!("mlkem_1024_test: all {} test cases passed.", num_test_cases);
    }
}

/* Structs for holding test data */

#[derive(Clone, Debug, PartialEq)]
enum ParameterSet {
    Mlkem512,
    Mlkem768,
    Mlkem1024,
}

#[derive(Clone)]
struct MLKEMEncapsTestCase {
    parameter_set: ParameterSet,
    tc_id: u32,
    comment: String,
    m: String,
    ek: String,
    c: String,
    k: String,
    result: String,
}

impl MLKEMEncapsTestCase {
    fn new(parameter_set: ParameterSet) -> Self {
        Self {
            parameter_set,
            tc_id: 0,
            comment: String::new(),
            m: String::new(),
            ek: String::new(),
            c: String::new(),
            k: String::new(),
            result: String::new(),
        }
    }

    fn parse(data: String, parameter_set: ParameterSet) -> Vec<Self> {
        let json: serde_json::Value =
            serde_json::from_str(&data).expect("test data is not valid JSON");

        let mut test_cases = Vec::<Self>::new();

        let groups = json["testGroups"].as_array().expect("testGroups is not an array");
        for group in groups {
            let tests = group["tests"].as_array().expect("tests is not an array");
            for test in tests {
                test_cases.push(Self {
                    parameter_set: parameter_set.clone(),
                    tc_id: test["tcId"].as_u64().expect("tcId missing") as u32,
                    comment: test["comment"].as_str().unwrap_or("").to_string(),
                    m: test["m"].as_str().unwrap_or("").to_string(),
                    ek: test["ek"].as_str().unwrap_or("").to_string(),
                    c: test["c"].as_str().unwrap_or("").to_string(),
                    k: test["K"].as_str().unwrap_or("").to_string(),
                    result: test["result"].as_str().unwrap_or("").to_string(),
                });
            }
        }

        test_cases
    }

    fn run_mlkem512(&self) {
        assert_eq!(self.parameter_set, ParameterSet::Mlkem512);

        /* Load the key */

        let ek = match MLKEM512PublicKey::from_bytes(&hex::decode(&self.ek).unwrap()) {
            Err(e) => {
                if self.result == "invalid" {
                    /* good */
                    return;
                } else {
                    panic!("{:?}", e);
                }
            }
            Ok(pk) => pk,
        };

        /* Perform the deterministic encaps and compare results */

        let (k, ct) =
            MLKEM512::encaps_internal(&ek, None, hex::decode(&self.m).unwrap().try_into().unwrap());

        if self.result == "valid" {
            assert_eq!(k, hex::decode(&self.k).unwrap().as_slice());
            assert_eq!(ct, hex::decode(&self.c).unwrap().as_slice());
        } else {
            // is there anything to test here?
        }
    }

    fn run_mlkem768(&self) {
        assert_eq!(self.parameter_set, ParameterSet::Mlkem768);

        /* Load the key */

        let ek = match MLKEM768PublicKey::from_bytes(&hex::decode(&self.ek).unwrap()) {
            Err(e) => {
                if self.result == "invalid" {
                    /* good */
                    return;
                } else {
                    panic!("{:?}", e);
                }
            }
            Ok(pk) => pk,
        };

        /* Perform the deterministic encaps and compare results */

        let (k, ct) =
            MLKEM768::encaps_internal(&ek, None, hex::decode(&self.m).unwrap().try_into().unwrap());

        if self.result == "valid" {
            assert_eq!(k, hex::decode(&self.k).unwrap().as_slice());
            assert_eq!(ct, hex::decode(&self.c).unwrap().as_slice());
        } else {
            // is there anything to test here?
        }
    }

    fn run_mlkem1024(&self) {
        assert_eq!(self.parameter_set, ParameterSet::Mlkem1024);

        /* Load the key */

        let ek = match MLKEM1024PublicKey::from_bytes(&hex::decode(&self.ek).unwrap()) {
            Err(e) => {
                if self.result == "invalid" {
                    /* good */
                    return;
                } else {
                    panic!("{:?}", e);
                }
            }
            Ok(pk) => pk,
        };

        /* Perform the deterministic encaps and compare results */

        let (k, ct) = MLKEM1024::encaps_internal(
            &ek,
            None,
            hex::decode(&self.m).unwrap().try_into().unwrap(),
        );

        if self.result == "valid" {
            assert_eq!(k, hex::decode(&self.k).unwrap().as_slice());
            assert_eq!(ct, hex::decode(&self.c).unwrap().as_slice());
        } else {
            // is there anything to test here?
        }
    }
}

#[derive(Clone)]
struct MLKEMKeygenSeedTestCase {
    parameter_set: ParameterSet,
    tc_id: u32,
    comment: String,
    seed: String,
    ek: String,
    dk: String,
    result: String,
}

impl MLKEMKeygenSeedTestCase {
    fn new(parameter_set: ParameterSet) -> Self {
        Self {
            parameter_set,
            tc_id: 0,
            comment: String::new(),
            seed: String::new(),
            ek: String::new(),
            dk: String::new(),
            result: String::new(),
        }
    }

    fn parse(data: String, parameter_set: ParameterSet) -> Vec<Self> {
        let json: serde_json::Value =
            serde_json::from_str(&data).expect("test data is not valid JSON");

        let mut test_cases = Vec::<Self>::new();

        let groups = json["testGroups"].as_array().expect("testGroups is not an array");
        for group in groups {
            let tests = group["tests"].as_array().expect("tests is not an array");
            for test in tests {
                test_cases.push(Self {
                    parameter_set: parameter_set.clone(),
                    tc_id: test["tcId"].as_u64().expect("tcId missing") as u32,
                    comment: test["comment"].as_str().unwrap_or("").to_string(),
                    seed: test["seed"].as_str().unwrap_or("").to_string(),
                    ek: test["ek"].as_str().unwrap_or("").to_string(),
                    dk: test["dk"].as_str().unwrap_or("").to_string(),
                    result: test["result"].as_str().unwrap_or("").to_string(),
                });
            }
        }

        test_cases
    }

    fn run_mlkem512(&self) {
        assert_eq!(self.parameter_set, ParameterSet::Mlkem512);

        // currently, the wycheproof tests contain only valid tests, so just run them; no errors to check

        let seed =
            KeyMaterial512::from_bytes_as_type(&hex::decode(&self.seed).unwrap(), KeyType::Seed)
                .unwrap();

        let (ek, dk) = MLKEM512::keygen_from_seed(&seed).unwrap();

        assert_eq!(ek, MLKEM512PublicKey::from_bytes(&hex::decode(&self.ek).unwrap()).unwrap());
        assert_eq!(&ek.encode(), hex::decode(&self.ek).unwrap().as_slice());

        assert_eq!(dk, MLKEM512PrivateKey::from_bytes(&hex::decode(&self.dk).unwrap()).unwrap());
        assert_eq!(&dk.encode(), hex::decode(&self.dk).unwrap().as_slice());
    }

    fn run_mlkem768(&self) {
        assert_eq!(self.parameter_set, ParameterSet::Mlkem768);

        // currently, the wycheproof tests contain only valid tests, so just run them; no errors to check

        let seed =
            KeyMaterial512::from_bytes_as_type(&hex::decode(&self.seed).unwrap(), KeyType::Seed)
                .unwrap();

        let (ek, dk) = MLKEM768::keygen_from_seed(&seed).unwrap();

        assert_eq!(ek, MLKEM768PublicKey::from_bytes(&hex::decode(&self.ek).unwrap()).unwrap());
        assert_eq!(&ek.encode(), hex::decode(&self.ek).unwrap().as_slice());

        assert_eq!(dk, MLKEM768PrivateKey::from_bytes(&hex::decode(&self.dk).unwrap()).unwrap());
        assert_eq!(&dk.encode(), hex::decode(&self.dk).unwrap().as_slice());
    }

    fn run_mlkem1024(&self) {
        assert_eq!(self.parameter_set, ParameterSet::Mlkem1024);

        // currently, the wycheproof tests contain only valid tests, so just run them; no errors to check

        let seed =
            KeyMaterial512::from_bytes_as_type(&hex::decode(&self.seed).unwrap(), KeyType::Seed)
                .unwrap();

        let (ek, dk) = MLKEM1024::keygen_from_seed(&seed).unwrap();

        assert_eq!(ek, MLKEM1024PublicKey::from_bytes(&hex::decode(&self.ek).unwrap()).unwrap());
        assert_eq!(&ek.encode(), hex::decode(&self.ek).unwrap().as_slice());

        assert_eq!(dk, MLKEM1024PrivateKey::from_bytes(&hex::decode(&self.dk).unwrap()).unwrap());
        assert_eq!(&dk.encode(), hex::decode(&self.dk).unwrap().as_slice());
    }
}

#[derive(Clone)]
struct MLKEMSemiExpandedDecapsTestCase {
    parameter_set: ParameterSet,
    tc_id: u32,
    comment: String,
    dk: String,
    c: String,
    result: String,
}

impl MLKEMSemiExpandedDecapsTestCase {
    fn new(parameter_set: ParameterSet) -> Self {
        Self {
            parameter_set,
            tc_id: 0,
            comment: String::new(),
            dk: String::new(),
            c: String::new(),
            result: String::new(),
        }
    }

    fn parse(data: String, parameter_set: ParameterSet) -> Vec<Self> {
        let json: serde_json::Value =
            serde_json::from_str(&data).expect("test data is not valid JSON");

        let mut test_cases = Vec::<Self>::new();

        let groups = json["testGroups"].as_array().expect("testGroups is not an array");
        for group in groups {
            let tests = group["tests"].as_array().expect("tests is not an array");
            for test in tests {
                test_cases.push(Self {
                    parameter_set: parameter_set.clone(),
                    tc_id: test["tcId"].as_u64().expect("tcId missing") as u32,
                    comment: test["comment"].as_str().unwrap_or("").to_string(),
                    dk: test["dk"].as_str().unwrap_or("").to_string(),
                    c: test["c"].as_str().unwrap_or("").to_string(),
                    result: test["result"].as_str().unwrap_or("").to_string(),
                });
            }
        }

        test_cases
    }

    fn run_mlkem512(&self) {
        assert_eq!(self.parameter_set, ParameterSet::Mlkem512);

        /* Load the private key */
        let _dk = match MLKEM512PrivateKey::from_bytes(&hex::decode(&self.dk).unwrap()) {
            Ok(dk) => dk,
            Err(e) => {
                if self.result == "invalid" {
                    /* good */
                    return;
                } else {
                    panic!("Failed to load private key: {:?}", e);
                }
            }
        };

        // these tests provide c, but not the output key k,
        // so there's really no reason to perform the decaps since there's really nothing to check it against
    }

    fn run_mlkem768(&self) {
        assert_eq!(self.parameter_set, ParameterSet::Mlkem768);

        /* Load the private key */
        let _dk = match MLKEM768PrivateKey::from_bytes(&hex::decode(&self.dk).unwrap()) {
            Ok(dk) => dk,
            Err(e) => {
                if self.result == "invalid" {
                    /* good */
                    return;
                } else {
                    panic!("Failed to load private key: {:?}", e);
                }
            }
        };

        // these tests provide c, but not the output key k,
        // so there's really no reason to perform the decaps since there's really nothing to check it against
    }

    fn run_mlkem1024(&self) {
        assert_eq!(self.parameter_set, ParameterSet::Mlkem1024);

        /* Load the private key */
        let _dk = match MLKEM1024PrivateKey::from_bytes(&hex::decode(&self.dk).unwrap()) {
            Ok(dk) => dk,
            Err(e) => {
                if self.result == "invalid" {
                    /* good */
                    return;
                } else {
                    panic!("Failed to load private key: {:?}", e);
                }
            }
        };

        // these tests provide c, but not the output key k,
        // so there's really no reason to perform the decaps since there's really nothing to check it against
    }
}

#[derive(Clone)]
struct MLKEMTestCase {
    parameter_set: ParameterSet,
    tc_id: u32,
    comment: String,
    seed: String,
    ek: String,
    c: String,
    k: String,
    result: String,
}

impl MLKEMTestCase {
    fn new(parameter_set: ParameterSet) -> Self {
        Self {
            parameter_set,
            tc_id: 0,
            comment: String::new(),
            seed: String::new(),
            ek: String::new(),
            c: String::new(),
            k: String::new(),
            result: String::new(),
        }
    }

    fn parse(data: String, parameter_set: ParameterSet) -> Vec<Self> {
        let json: serde_json::Value =
            serde_json::from_str(&data).expect("test data is not valid JSON");

        let mut test_cases = Vec::<Self>::new();

        let groups = json["testGroups"].as_array().expect("testGroups is not an array");
        for group in groups {
            let tests = group["tests"].as_array().expect("tests is not an array");
            for test in tests {
                test_cases.push(Self {
                    parameter_set: parameter_set.clone(),
                    tc_id: test["tcId"].as_u64().expect("tcId missing") as u32,
                    comment: test["comment"].as_str().unwrap_or("").to_string(),
                    seed: test["seed"].as_str().unwrap_or("").to_string(),
                    ek: test["ek"].as_str().unwrap_or("").to_string(),
                    c: test["c"].as_str().unwrap_or("").to_string(),
                    k: test["K"].as_str().unwrap_or("").to_string(),
                    result: test["result"].as_str().unwrap_or("").to_string(),
                });
            }
        }

        test_cases
    }

    fn run_mlkem512(&self) {
        assert_eq!(self.parameter_set, ParameterSet::Mlkem512);

        /* Load the private key */
        let mut seed = match KeyMaterial512::from_bytes_as_type(
            &hex::decode(&self.seed).unwrap(),
            KeyType::Seed,
        ) {
            Ok(seed) => seed,
            Err(e) => {
                if self.result == "invalid" {
                    /* good */
                    return;
                } else {
                    panic!("Failed to load seed: {:?}", e);
                }
            }
        };
        // allow an all-zero seed for testing
        seed.allow_hazardous_operations();
        seed.set_key_type(KeyType::Seed).unwrap();
        match seed.set_security_strength(SecurityStrength::_256bit) {
            Ok(_) => (),
            Err(e) => {
                if self.result == "invalid" {
                    /* good */
                    return;
                } else {
                    panic!("{:?}", e)
                }
            }
        }

        let (ek, dk) = match MLKEM512::keygen_from_seed(&seed) {
            Ok((ek, dk)) => (ek, dk),
            Err(e) => {
                if self.result == "invalid" {
                    return;
                } else {
                    panic!("Failed to generate key pair: {:?}", e);
                }
            }
        };

        // check that the derived ek matches the provided one
        assert_eq!(&ek.encode(), &hex::decode(&self.ek).unwrap().as_slice());

        // these tests don't provide m, so can't test deterministic encaps

        // test decaps
        let k = match MLKEM512::decaps(&dk, &hex::decode(&self.c).unwrap().as_slice()) {
            Ok(k) => k,
            Err(e) => {
                if self.result == "invalid" {
                    return;
                } else {
                    panic!("Failed to decapsulate: {:?}", e);
                }
            }
        };

        assert_eq!(k.ref_to_bytes(), hex::decode(&self.k).unwrap().as_slice());
    }

    fn run_mlkem768(&self) {
        assert_eq!(self.parameter_set, ParameterSet::Mlkem768);

        /* Load the private key */
        let mut seed = match KeyMaterial512::from_bytes_as_type(
            &hex::decode(&self.seed).unwrap(),
            KeyType::Seed,
        ) {
            Ok(seed) => seed,
            Err(e) => {
                if self.result == "invalid" {
                    /* good */
                    return;
                } else {
                    panic!("Failed to load seed: {:?}", e);
                }
            }
        };
        // allow an all-zero seed for testing
        seed.allow_hazardous_operations();
        seed.set_key_type(KeyType::Seed).unwrap();
        match seed.set_security_strength(SecurityStrength::_256bit) {
            Ok(_) => (),
            Err(e) => {
                if self.result == "invalid" {
                    /* good */
                    return;
                } else {
                    panic!("{:?}", e)
                }
            }
        }

        let (ek, dk) = match MLKEM768::keygen_from_seed(&seed) {
            Ok((ek, dk)) => (ek, dk),
            Err(e) => {
                if self.result == "invalid" {
                    return;
                } else {
                    panic!("Failed to generate key pair: {:?}", e);
                }
            }
        };

        // check that the derived ek matches the provided one
        assert_eq!(&ek.encode(), &hex::decode(&self.ek).unwrap().as_slice());

        // these tests don't provide m, so can't test deterministic encaps

        // test decaps
        let k = match MLKEM768::decaps(&dk, &hex::decode(&self.c).unwrap().as_slice()) {
            Ok(k) => k,
            Err(e) => {
                if self.result == "invalid" {
                    return;
                } else {
                    panic!("Failed to decapsulate: {:?}", e);
                }
            }
        };

        assert_eq!(k.ref_to_bytes(), hex::decode(&self.k).unwrap().as_slice());
    }

    fn run_mlkem1024(&self) {
        assert_eq!(self.parameter_set, ParameterSet::Mlkem1024);

        /* Load the private key */
        let mut seed = match KeyMaterial512::from_bytes_as_type(
            &hex::decode(&self.seed).unwrap(),
            KeyType::Seed,
        ) {
            Ok(seed) => seed,
            Err(e) => {
                if self.result == "invalid" {
                    /* good */
                    return;
                } else {
                    panic!("Failed to load seed: {:?}", e);
                }
            }
        };
        // allow an all-zero seed for testing
        seed.allow_hazardous_operations();
        seed.set_key_type(KeyType::Seed).unwrap();
        match seed.set_security_strength(SecurityStrength::_256bit) {
            Ok(_) => (),
            Err(e) => {
                if self.result == "invalid" {
                    /* good */
                    return;
                } else {
                    panic!("{:?}", e)
                }
            }
        }

        let (ek, dk) = match MLKEM1024::keygen_from_seed(&seed) {
            Ok((ek, dk)) => (ek, dk),
            Err(e) => {
                if self.result == "invalid" {
                    return;
                } else {
                    panic!("Failed to generate key pair: {:?}", e);
                }
            }
        };

        // check that the derived ek matches the provided one
        assert_eq!(&ek.encode(), &hex::decode(&self.ek).unwrap().as_slice());

        // these tests don't provide m, so can't test deterministic encaps

        // test decaps
        let k = match MLKEM1024::decaps(&dk, &hex::decode(&self.c).unwrap().as_slice()) {
            Ok(k) => k,
            Err(e) => {
                if self.result == "invalid" {
                    return;
                } else {
                    panic!("Failed to decapsulate: {:?}", e);
                }
            }
        };

        assert_eq!(k.ref_to_bytes(), hex::decode(&self.k).unwrap().as_slice());
    }
}
