//! Test against the project wycheproof repo available at:
//!     https://github.com/C2SP/wycheproof
//! Requires that the wycheproof repository is cloned and available for testing at "../wycheproof"
//! relative to the root of this git project.
//!
//! This test file exercises the following test sets:
//!
//!  * mldsa_44_sign_noseed_test
//!  * mldsa_44_sign_seed_test
//!  * mldsa_44_verify_test
//!  * mldsa_65_sign_noseed_test
//!  * mldsa_65_sign_seed_test
//!  * mldsa_65_verify_test
//!  * mldsa_87_sign_noseed_test
//!  * mldsa_87_sign_seed_test
//!  * mldsa_87_verify_test

#![allow(dead_code)]

use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::key_material::{
    KeyMaterial256, KeyMaterialTrait, KeyType, do_hazardous_operations,
};
use bouncycastle_core::traits::{
    SecurityStrength, SignaturePrivateKey, SignaturePublicKey, SignatureVerifier,
};
use bouncycastle_hex as hex;
use bouncycastle_mldsa::{
    MLDSA44, MLDSA44PrivateKey, MLDSA44PublicKey, MLDSA65, MLDSA65PrivateKey, MLDSA65PublicKey,
    MLDSA87, MLDSA87PrivateKey, MLDSA87PublicKey, MLDSAPublicKeyTrait, MLDSATrait, MuBuilder,
};

#[cfg(test)]
mod wycheproof {
    use crate::{
        MLDSASignNoSeedTestCase, MLDSASignSeedTestCase, MLDSAVerifyTestCase, ParameterSet,
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
    fn mldsa_44_sign_noseed_test() {
        let contents = match get_test_data("mldsa_44_sign_noseed_test.json") {
            Ok(contents) => contents,
            Err(_) => return,
        };
        let test_cases = MLDSASignNoSeedTestCase::parse(contents, ParameterSet::Mldsa44);

        let num_test_cases = test_cases.len();
        for test_case in test_cases {
            test_case.run_mldsa44();
        }

        println!("mldsa_44_sign_noseed_test: all {} test cases passed.", num_test_cases);
    }

    #[test]
    fn mldsa_44_sign_seed_test() {
        let contents = match get_test_data("mldsa_44_sign_seed_test.json") {
            Ok(contents) => contents,
            Err(_) => return,
        };
        let test_cases = MLDSASignSeedTestCase::parse(contents, ParameterSet::Mldsa44);

        let num_test_cases = test_cases.len();
        for test_case in test_cases {
            test_case.run_mldsa44();
        }

        println!("mldsa_44_sign_seed_test: all {} test cases passed.", num_test_cases);
    }

    #[test]
    fn mldsa_44_verify_test() {
        let contents = match get_test_data("mldsa_44_verify_test.json") {
            Ok(contents) => contents,
            Err(_) => return,
        };
        let test_cases = MLDSAVerifyTestCase::parse(contents, ParameterSet::Mldsa44);

        let num_test_cases = test_cases.len();
        for test_case in test_cases {
            test_case.run_mldsa44();
        }

        println!("mldsa_44_verify_test: all {} test cases passed.", num_test_cases);
    }

    #[test]
    fn mldsa_65_sign_noseed_test() {
        let contents = match get_test_data("mldsa_65_sign_noseed_test.json") {
            Ok(contents) => contents,
            Err(_) => return,
        };
        let test_cases = MLDSASignNoSeedTestCase::parse(contents, ParameterSet::Mldsa65);

        let num_test_cases = test_cases.len();
        for test_case in test_cases {
            test_case.run_mldsa65();
        }

        println!("mldsa_65_sign_noseed_test: all {} test cases passed.", num_test_cases);
    }

    #[test]
    fn mldsa_65_sign_seed_test() {
        let contents = match get_test_data("mldsa_65_sign_seed_test.json") {
            Ok(contents) => contents,
            Err(_) => return,
        };
        let test_cases = MLDSASignSeedTestCase::parse(contents, ParameterSet::Mldsa65);

        let num_test_cases = test_cases.len();
        for test_case in test_cases {
            test_case.run_mldsa65();
        }

        println!("mldsa_65_sign_seed_test: all {} test cases passed.", num_test_cases);
    }

    #[test]
    fn mldsa_65_verify_test() {
        let contents = match get_test_data("mldsa_65_verify_test.json") {
            Ok(contents) => contents,
            Err(_) => return,
        };
        let test_cases = MLDSAVerifyTestCase::parse(contents, ParameterSet::Mldsa65);

        let num_test_cases = test_cases.len();
        for test_case in test_cases {
            test_case.run_mldsa65();
        }

        println!("mldsa_65_verify_test: all {} test cases passed.", num_test_cases);
    }

    #[test]
    fn mldsa_87_sign_noseed_test() {
        let contents = match get_test_data("mldsa_87_sign_noseed_test.json") {
            Ok(contents) => contents,
            Err(_) => return,
        };

        let test_cases = MLDSASignNoSeedTestCase::parse(contents, ParameterSet::Mldsa87);

        let num_test_cases = test_cases.len();
        for test_case in test_cases {
            test_case.run_mldsa87();
        }

        println!("mldsa_87_sign_noseed_test: all {} test cases passed.", num_test_cases);
    }

    #[test]
    fn mldsa_87_sign_seed_test() {
        let contents = match get_test_data("mldsa_87_sign_seed_test.json") {
            Ok(contents) => contents,
            Err(_) => return,
        };
        let test_cases = MLDSASignSeedTestCase::parse(contents, ParameterSet::Mldsa87);

        let num_test_cases = test_cases.len();
        for test_case in test_cases {
            test_case.run_mldsa87();
        }

        println!("mldsa_87_sign_seed_test: all {} test cases passed.", num_test_cases);
    }

    #[test]
    fn mldsa_87_verify_test() {
        let contents = match get_test_data("mldsa_87_verify_test.json") {
            Ok(contents) => contents,
            Err(_) => return,
        };
        let test_cases = MLDSAVerifyTestCase::parse(contents, ParameterSet::Mldsa87);

        let num_test_cases = test_cases.len();
        for test_case in test_cases {
            test_case.run_mldsa87();
        }

        println!("mldsa_87_verify_test: all {} test cases passed.", num_test_cases);
    }
}

/* Structs for holding test data */

#[derive(Clone, Debug, PartialEq)]
enum ParameterSet {
    Mldsa44,
    Mldsa65,
    Mldsa87,
}

#[derive(Clone)]
struct MLDSASignNoSeedTestCase {
    parameter_set: ParameterSet,
    // testGroup-level fields, copied onto every test case in the group
    private_key: String,
    public_key: String,
    // test-level `rnd`: present only on hedged/randomized cases; absent = deterministic (all-zero).
    rnd: Option<String>,
    // test-level fields
    tc_id: u32,
    comment: String,
    msg: Option<String>,
    mu: String,
    ctx: Option<String>,
    sig: String,
    result: String,
}

impl MLDSASignNoSeedTestCase {
    fn new(parameter_set: ParameterSet) -> Self {
        Self {
            parameter_set,
            private_key: String::new(),
            public_key: String::new(),
            rnd: None,
            tc_id: 0,
            comment: String::new(),
            msg: None,
            mu: String::new(),
            ctx: None,
            sig: String::new(),
            result: String::new(),
        }
    }

    fn parse(data: String, parameter_set: ParameterSet) -> Vec<Self> {
        let json: serde_json::Value =
            serde_json::from_str(&data).expect("test data is not valid JSON");

        let mut test_cases = Vec::<Self>::new();

        let groups = json["testGroups"].as_array().expect("testGroups is not an array");
        for group in groups {
            // The private/public key are defined once per group and shared by
            // every test in that group.
            let private_key = group["privateKey"].as_str().unwrap_or("").to_string();
            let public_key = group["publicKey"].as_str().unwrap_or("").to_string();

            let tests = group["tests"].as_array().expect("tests is not an array");
            for test in tests {
                test_cases.push(Self {
                    parameter_set: parameter_set.clone(),
                    private_key: private_key.clone(),
                    public_key: public_key.clone(),
                    rnd: test["rnd"].as_str().map(|s| s.to_string()),
                    tc_id: test["tcId"].as_u64().expect("tcId missing") as u32,
                    comment: test["comment"].as_str().unwrap_or("").to_string(),
                    msg: match test["msg"].as_str() {
                        Some(msg) => Some(msg.to_string()),
                        None => None,
                    },
                    mu: test["mu"].as_str().unwrap_or("").to_string(),
                    ctx: test["ctx"].as_str().map(|s| s.to_string()),
                    sig: test["sig"].as_str().unwrap_or("").to_string(),
                    result: test["result"].as_str().unwrap_or("").to_string(),
                });
            }
        }

        test_cases
    }

    fn run_mldsa44(&self) {
        assert_eq!(self.parameter_set, ParameterSet::Mldsa44);

        /* Load the keys */

        let sk = match MLDSA44PrivateKey::from_bytes(&hex::decode(&self.private_key).unwrap()) {
            Ok(sk) => sk,
            Err(SignatureError::DecodingError(_)) => {
                if self.result == "invalid" {
                    /* good */
                    return;
                } else {
                    panic!("Failed to decode private key: {}", self.comment);
                }
            }
            _ => {
                panic!("something else went wrong");
            }
        };

        let pk = MLDSA44PublicKey::from_bytes(&hex::decode(&self.public_key).unwrap()).unwrap();

        /* Compute the signature */

        let ctx_vec = self.ctx.as_ref().map(|ctx| hex::decode(ctx).unwrap());

        // build mu
        let mu: [u8; 64] = if self.msg.is_none() {
            // we can't compute it, so just take the one provided
            hex::decode(&self.mu).unwrap().as_slice().try_into().unwrap()
        } else {
            match MuBuilder::compute_mu(
                &pk.compute_tr(),
                &hex::decode(self.msg.clone().unwrap()).unwrap(),
                ctx_vec.as_ref().and_then(|ctx| Some(ctx.as_slice())),
            ) {
                Ok(mu) => mu,
                Err(SignatureError::LengthError(_)) => {
                    if self.result == "invalid" {
                        /* good -- test passed */
                        return;
                    } else {
                        panic!("failed to compute mu")
                    }
                }
                _ => panic!("failed to compute mu"),
            }
        };
        assert_eq!(mu, hex::decode(&self.mu).unwrap().as_slice());

        // generate the signature using an all-zero signing nonce
        // Use the vector's `rnd` when present (hedged/randomized cases); deterministic vectors omit
        // it and are signed with the all-zero nonce.
        let rnd: [u8; 32] = self
            .rnd
            .as_ref()
            .map(|r| hex::decode(r).unwrap().try_into().unwrap())
            .unwrap_or([0u8; 32]);
        let sig = MLDSA44::sign_mu_deterministic(&sk, None, &mu, rnd).unwrap();
        assert_eq!(sig, hex::decode(&self.sig).unwrap().as_slice());

        let res = MLDSA44::verify_mu(
            &pk,
            Some(&pk.A_hat()),
            &mu,
            &hex::decode(&self.sig).unwrap().try_into().unwrap(),
        );

        if self.result == "valid" {
            res.unwrap()
        } else {
            assert!(res.is_err());
        };
    }

    fn run_mldsa65(&self) {
        assert_eq!(self.parameter_set, ParameterSet::Mldsa65);

        /* Load the keys */

        let sk = match MLDSA65PrivateKey::from_bytes(&hex::decode(&self.private_key).unwrap()) {
            Ok(sk) => sk,
            Err(SignatureError::DecodingError(_)) => {
                if self.result == "invalid" {
                    /* good */
                    return;
                } else {
                    panic!("Failed to decode private key: {}", self.comment);
                }
            }
            _ => {
                panic!("something else went wrong");
            }
        };

        let pk = MLDSA65PublicKey::from_bytes(&hex::decode(&self.public_key).unwrap()).unwrap();

        /* Compute the signature */

        let ctx_vec = self.ctx.as_ref().map(|ctx| hex::decode(ctx).unwrap());

        // build mu
        let mu: [u8; 64] = if self.msg.is_none() {
            // we can't compute it, so just take the one provided
            hex::decode(&self.mu).unwrap().as_slice().try_into().unwrap()
        } else {
            match MuBuilder::compute_mu(
                &pk.compute_tr(),
                &hex::decode(self.msg.clone().unwrap()).unwrap(),
                ctx_vec.as_ref().and_then(|ctx| Some(ctx.as_slice())),
            ) {
                Ok(mu) => mu,
                Err(SignatureError::LengthError(_)) => {
                    if self.result == "invalid" {
                        /* good -- test passed */
                        return;
                    } else {
                        panic!("failed to compute mu")
                    }
                }
                _ => panic!("failed to compute mu"),
            }
        };
        assert_eq!(mu, hex::decode(&self.mu).unwrap().as_slice());

        // generate the signature using an all-zero signing nonce
        // Use the vector's `rnd` when present (hedged/randomized cases); deterministic vectors omit
        // it and are signed with the all-zero nonce.
        let rnd: [u8; 32] = self
            .rnd
            .as_ref()
            .map(|r| hex::decode(r).unwrap().try_into().unwrap())
            .unwrap_or([0u8; 32]);
        let sig = MLDSA65::sign_mu_deterministic(&sk, None, &mu, rnd).unwrap();
        assert_eq!(sig, hex::decode(&self.sig).unwrap().as_slice());

        let res = MLDSA65::verify_mu(
            &pk,
            Some(&pk.A_hat()),
            &mu,
            &hex::decode(&self.sig).unwrap().try_into().unwrap(),
        );

        if self.result == "valid" {
            res.unwrap()
        } else {
            assert!(res.is_err());
        };
    }

    fn run_mldsa87(&self) {
        assert_eq!(self.parameter_set, ParameterSet::Mldsa87);

        /* Load the keys */

        let sk = match MLDSA87PrivateKey::from_bytes(&hex::decode(&self.private_key).unwrap()) {
            Ok(sk) => sk,
            Err(SignatureError::DecodingError(_)) => {
                if self.result == "invalid" {
                    /* good */
                    return;
                } else {
                    panic!("Failed to decode private key: {}", self.comment);
                }
            }
            _ => {
                panic!("something else went wrong");
            }
        };

        let pk = MLDSA87PublicKey::from_bytes(&hex::decode(&self.public_key).unwrap()).unwrap();

        /* Compute the signature */

        let ctx_vec = self.ctx.as_ref().map(|ctx| hex::decode(ctx).unwrap());

        // build mu
        let mu: [u8; 64] = if self.msg.is_none() {
            // we can't compute it, so just take the one provided
            hex::decode(&self.mu).unwrap().as_slice().try_into().unwrap()
        } else {
            match MuBuilder::compute_mu(
                &pk.compute_tr(),
                &hex::decode(self.msg.clone().unwrap()).unwrap(),
                ctx_vec.as_ref().and_then(|ctx| Some(ctx.as_slice())),
            ) {
                Ok(mu) => mu,
                Err(SignatureError::LengthError(_)) => {
                    if self.result == "invalid" {
                        /* good -- test passed */
                        return;
                    } else {
                        panic!("failed to compute mu")
                    }
                }
                _ => panic!("failed to compute mu"),
            }
        };
        assert_eq!(mu, hex::decode(&self.mu).unwrap().as_slice());

        // generate the signature using an all-zero signing nonce
        // Use the vector's `rnd` when present (hedged/randomized cases); deterministic vectors omit
        // it and are signed with the all-zero nonce.
        let rnd: [u8; 32] = self
            .rnd
            .as_ref()
            .map(|r| hex::decode(r).unwrap().try_into().unwrap())
            .unwrap_or([0u8; 32]);
        let sig = MLDSA87::sign_mu_deterministic(&sk, None, &mu, rnd).unwrap();
        assert_eq!(sig, hex::decode(&self.sig).unwrap().as_slice());

        let res = MLDSA87::verify_mu(
            &pk,
            Some(&pk.A_hat()),
            &mu,
            &hex::decode(&self.sig).unwrap().try_into().unwrap(),
        );

        if self.result == "valid" {
            res.unwrap();
        } else {
            assert!(res.is_err());
        };
    }
}

#[derive(Clone)]
struct MLDSASignSeedTestCase {
    parameter_set: ParameterSet,
    // testGroup-level fields, copied onto every test case in the group
    private_seed: String,
    public_key: String,
    // test-level `rnd`: present only on hedged/randomized cases; absent = deterministic (all-zero).
    rnd: Option<String>,
    // test-level fields
    tc_id: u32,
    comment: String,
    msg: Option<String>,
    mu: String,
    ctx: Option<String>,
    sig: String,
    result: String,
}

impl MLDSASignSeedTestCase {
    fn new(parameter_set: ParameterSet) -> Self {
        Self {
            parameter_set,
            private_seed: String::new(),
            public_key: String::new(),
            rnd: None,
            tc_id: 0,
            comment: String::new(),
            msg: None,
            mu: String::new(),
            ctx: None,
            sig: String::new(),
            result: String::new(),
        }
    }

    fn parse(data: String, parameter_set: ParameterSet) -> Vec<Self> {
        let json: serde_json::Value =
            serde_json::from_str(&data).expect("test data is not valid JSON");

        let mut test_cases = Vec::<Self>::new();

        let groups = json["testGroups"].as_array().expect("testGroups is not an array");
        for group in groups {
            // The private/public key are defined once per group and shared by
            // every test in that group.
            let private_seed = group["privateSeed"].as_str().unwrap_or("").to_string();
            let public_key = group["publicKey"].as_str().unwrap_or("").to_string();

            let tests = group["tests"].as_array().expect("tests is not an array");
            for test in tests {
                test_cases.push(Self {
                    parameter_set: parameter_set.clone(),
                    private_seed: private_seed.clone(),
                    public_key: public_key.clone(),
                    rnd: test["rnd"].as_str().map(|s| s.to_string()),
                    tc_id: test["tcId"].as_u64().expect("tcId missing") as u32,
                    comment: test["comment"].as_str().unwrap_or("").to_string(),
                    msg: match test["msg"].as_str() {
                        Some(msg) => Some(msg.to_string()),
                        None => None,
                    },
                    mu: test["mu"].as_str().unwrap_or("").to_string(),
                    ctx: test["ctx"].as_str().map(|s| s.to_string()),
                    sig: test["sig"].as_str().unwrap_or("").to_string(),
                    result: test["result"].as_str().unwrap_or("").to_string(),
                });
            }
        }

        test_cases
    }

    fn run_mldsa44(&self) {
        assert_eq!(self.parameter_set, ParameterSet::Mldsa44);

        /* Load the keys */

        let mut seed = match KeyMaterial256::from_bytes_as_type(
            &hex::decode(&self.private_seed).unwrap(),
            KeyType::Seed,
        ) {
            Ok(seed) => seed,
            Err(e) => {
                if self.result == "invalid" {
                    /* good */
                    return;
                } else {
                    panic!("{:?}", e)
                }
            }
        };
        // allow an all-zero seed for testing
        do_hazardous_operations(&mut seed, |seed| seed.set_key_type(KeyType::Seed)).unwrap();
        match do_hazardous_operations(&mut seed, |seed| {
            seed.set_security_strength(SecurityStrength::_256bit)
        }) {
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

        let (pk, sk) = match MLDSA44::keygen_from_seed(&seed) {
            Ok((pk, sk)) => (pk, sk),
            Err(e) => {
                panic!("{:?}", e)
            }
        };

        let loaded_pk =
            MLDSA44PublicKey::from_bytes(&hex::decode(&self.public_key).unwrap()).unwrap();
        assert_eq!(loaded_pk, pk);

        /* Compute the signature */

        let ctx_vec = self.ctx.as_ref().map(|ctx| hex::decode(ctx).unwrap());

        // build mu
        let mu: [u8; 64] = if self.msg.is_none() {
            // we can't compute it, so just take the one provided
            hex::decode(&self.mu).unwrap().as_slice().try_into().unwrap()
        } else {
            match MuBuilder::compute_mu(
                &pk.compute_tr(),
                &hex::decode(self.msg.clone().unwrap()).unwrap(),
                ctx_vec.as_ref().and_then(|ctx| Some(ctx.as_slice())),
            ) {
                Ok(mu) => mu,
                Err(SignatureError::LengthError(_)) => {
                    if self.result == "invalid" {
                        /* good -- test passed */
                        return;
                    } else {
                        panic!("failed to compute mu")
                    }
                }
                _ => panic!("failed to compute mu"),
            }
        };
        assert_eq!(mu, hex::decode(&self.mu).unwrap().as_slice());

        // generate the signature using an all-zero signing nonce
        // Use the vector's `rnd` when present (hedged/randomized cases); deterministic vectors omit
        // it and are signed with the all-zero nonce.
        let rnd: [u8; 32] = self
            .rnd
            .as_ref()
            .map(|r| hex::decode(r).unwrap().try_into().unwrap())
            .unwrap_or([0u8; 32]);
        let sig = MLDSA44::sign_mu_deterministic(&sk, None, &mu, rnd).unwrap();
        assert_eq!(sig, hex::decode(&self.sig).unwrap().as_slice());

        let res = MLDSA44::verify_mu(
            &pk,
            Some(&pk.A_hat()),
            &mu,
            &hex::decode(&self.sig).unwrap().try_into().unwrap(),
        );

        if self.result == "valid" {
            res.unwrap();
        } else {
            assert!(res.is_err());
        };
    }

    fn run_mldsa65(&self) {
        assert_eq!(self.parameter_set, ParameterSet::Mldsa65);

        /* Load the keys */

        let mut seed = match KeyMaterial256::from_bytes_as_type(
            &hex::decode(&self.private_seed).unwrap(),
            KeyType::Seed,
        ) {
            Ok(seed) => seed,
            Err(e) => {
                if self.result == "invalid" {
                    /* good */
                    return;
                } else {
                    panic!("{:?}", e)
                }
            }
        };
        // allow an all-zero seed for testing
        do_hazardous_operations(&mut seed, |seed| seed.set_key_type(KeyType::Seed)).unwrap();
        match do_hazardous_operations(&mut seed, |seed| {
            seed.set_security_strength(SecurityStrength::_256bit)
        }) {
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

        let (pk, sk) = match MLDSA65::keygen_from_seed(&seed) {
            Ok((pk, sk)) => (pk, sk),
            Err(e) => {
                panic!("{:?}", e)
            }
        };

        let loaded_pk =
            MLDSA65PublicKey::from_bytes(&hex::decode(&self.public_key).unwrap()).unwrap();
        assert_eq!(loaded_pk, pk);

        /* Compute the signature */

        let ctx_vec = self.ctx.as_ref().map(|ctx| hex::decode(ctx).unwrap());

        // build mu
        let mu: [u8; 64] = if self.msg.is_none() {
            // we can't compute it, so just take the one provided
            hex::decode(&self.mu).unwrap().as_slice().try_into().unwrap()
        } else {
            match MuBuilder::compute_mu(
                &pk.compute_tr(),
                &hex::decode(self.msg.clone().unwrap()).unwrap(),
                ctx_vec.as_ref().and_then(|ctx| Some(ctx.as_slice())),
            ) {
                Ok(mu) => mu,
                Err(SignatureError::LengthError(_)) => {
                    if self.result == "invalid" {
                        /* good -- test passed */
                        return;
                    } else {
                        panic!("failed to compute mu")
                    }
                }
                _ => panic!("failed to compute mu"),
            }
        };
        assert_eq!(mu, hex::decode(&self.mu).unwrap().as_slice());

        // generate the signature using an all-zero signing nonce
        // Use the vector's `rnd` when present (hedged/randomized cases); deterministic vectors omit
        // it and are signed with the all-zero nonce.
        let rnd: [u8; 32] = self
            .rnd
            .as_ref()
            .map(|r| hex::decode(r).unwrap().try_into().unwrap())
            .unwrap_or([0u8; 32]);
        let sig = MLDSA65::sign_mu_deterministic(&sk, None, &mu, rnd).unwrap();
        assert_eq!(sig, hex::decode(&self.sig).unwrap().as_slice());

        let res = MLDSA65::verify_mu(
            &pk,
            Some(&pk.A_hat()),
            &mu,
            &hex::decode(&self.sig).unwrap().try_into().unwrap(),
        );

        if self.result == "valid" {
            res.unwrap();
        } else {
            assert!(res.is_err());
        };
    }

    fn run_mldsa87(&self) {
        assert_eq!(self.parameter_set, ParameterSet::Mldsa87);

        /* Load the keys */

        let mut seed = match KeyMaterial256::from_bytes_as_type(
            &hex::decode(&self.private_seed).unwrap(),
            KeyType::Seed,
        ) {
            Ok(seed) => seed,
            Err(e) => {
                if self.result == "invalid" {
                    /* good */
                    return;
                } else {
                    panic!("{:?}", e)
                }
            }
        };
        // allow an all-zero seed for testing
        do_hazardous_operations(&mut seed, |seed| seed.set_key_type(KeyType::Seed)).unwrap();
        match do_hazardous_operations(&mut seed, |seed| {
            seed.set_security_strength(SecurityStrength::_256bit)
        }) {
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

        let (pk, sk) = match MLDSA87::keygen_from_seed(&seed) {
            Ok((pk, sk)) => (pk, sk),
            Err(e) => {
                panic!("{:?}", e)
            }
        };

        let loaded_pk =
            MLDSA87PublicKey::from_bytes(&hex::decode(&self.public_key).unwrap()).unwrap();
        assert_eq!(loaded_pk, pk);

        /* Compute the signature */

        let ctx_vec = self.ctx.as_ref().map(|ctx| hex::decode(ctx).unwrap());

        // build mu
        let mu: [u8; 64] = if self.msg.is_none() {
            // we can't compute it, so just take the one provided
            hex::decode(&self.mu).unwrap().as_slice().try_into().unwrap()
        } else {
            match MuBuilder::compute_mu(
                &pk.compute_tr(),
                &hex::decode(self.msg.clone().unwrap()).unwrap(),
                ctx_vec.as_ref().and_then(|ctx| Some(ctx.as_slice())),
            ) {
                Ok(mu) => mu,
                Err(SignatureError::LengthError(_)) => {
                    if self.result == "invalid" {
                        /* good -- test passed */
                        return;
                    } else {
                        panic!("failed to compute mu")
                    }
                }
                _ => panic!("failed to compute mu"),
            }
        };
        assert_eq!(mu, hex::decode(&self.mu).unwrap().as_slice());

        // generate the signature using an all-zero signing nonce
        // Use the vector's `rnd` when present (hedged/randomized cases); deterministic vectors omit
        // it and are signed with the all-zero nonce.
        let rnd: [u8; 32] = self
            .rnd
            .as_ref()
            .map(|r| hex::decode(r).unwrap().try_into().unwrap())
            .unwrap_or([0u8; 32]);
        let sig = MLDSA87::sign_mu_deterministic(&sk, None, &mu, rnd).unwrap();
        assert_eq!(sig, hex::decode(&self.sig).unwrap().as_slice());

        let res = MLDSA87::verify_mu(
            &pk,
            Some(&pk.A_hat()),
            &mu,
            &hex::decode(&self.sig).unwrap().try_into().unwrap(),
        );

        if self.result == "valid" {
            res.unwrap();
        } else {
            assert!(res.is_err());
        };
    }
}

#[derive(Clone)]
struct MLDSAVerifyTestCase {
    parameter_set: ParameterSet,
    // testGroup-level fields, copied onto every test case in the group
    public_key: String,
    // test-level fields
    tc_id: u32,
    comment: String,
    msg: String,
    ctx: Option<String>,
    sig: String,
    result: String,
}

impl MLDSAVerifyTestCase {
    fn new(parameter_set: ParameterSet) -> Self {
        Self {
            parameter_set,
            public_key: String::new(),
            tc_id: 0,
            comment: String::new(),
            msg: String::new(),
            ctx: None,
            sig: String::new(),
            result: String::new(),
        }
    }

    fn parse(data: String, parameter_set: ParameterSet) -> Vec<Self> {
        let json: serde_json::Value =
            serde_json::from_str(&data).expect("test data is not valid JSON");

        let mut test_cases = Vec::<Self>::new();

        let groups = json["testGroups"].as_array().expect("testGroups is not an array");
        for group in groups {
            // The private/public key are defined once per group and shared by
            // every test in that group.
            let public_key = group["publicKey"].as_str().unwrap_or("").to_string();

            let tests = group["tests"].as_array().expect("tests is not an array");
            for test in tests {
                test_cases.push(Self {
                    parameter_set: parameter_set.clone(),
                    public_key: public_key.clone(),
                    tc_id: test["tcId"].as_u64().expect("tcId missing") as u32,
                    comment: test["comment"].as_str().unwrap_or("").to_string(),
                    msg: test["msg"].as_str().unwrap_or("").to_string(),
                    ctx: test["ctx"].as_str().map(|s| s.to_string()),
                    sig: test["sig"].as_str().unwrap_or("").to_string(),
                    result: test["result"].as_str().unwrap_or("").to_string(),
                });
            }
        }

        test_cases
    }

    fn run_mldsa44(&self) {
        assert_eq!(self.parameter_set, ParameterSet::Mldsa44);

        /* Load the key */

        let pk = match MLDSA44PublicKey::from_bytes(&hex::decode(&self.public_key).unwrap()) {
            Ok(pk) => pk,
            Err(e) => {
                if self.result == "invalid" {
                    /* good */
                    return;
                } else {
                    panic!("{:?}", e)
                }
            }
        };

        /* Verify the signature */

        let ctx_vec = self.ctx.as_ref().map(|ctx| hex::decode(ctx).unwrap());

        match MLDSA44::verify(
            &pk,
            &hex::decode(&self.msg).unwrap(),
            ctx_vec.as_ref().and_then(|ctx| Some(ctx.as_slice())),
            &hex::decode(&self.sig).unwrap(),
        ) {
            Ok(()) => {
                if self.result != "valid" {
                    panic!("signature passed when it should have failed:");
                }
            }
            Err(e) => {
                if self.result != "invalid" {
                    panic!("signature failed when it should have passed: {:?}", e);
                }
            }
        }
    }

    fn run_mldsa65(&self) {
        assert_eq!(self.parameter_set, ParameterSet::Mldsa65);

        /* Load the key */

        let pk = match MLDSA65PublicKey::from_bytes(&hex::decode(&self.public_key).unwrap()) {
            Ok(pk) => pk,
            Err(e) => {
                if self.result == "invalid" {
                    /* good */
                    return;
                } else {
                    panic!("{:?}", e)
                }
            }
        };

        /* Verify the signature */

        let ctx_vec = self.ctx.as_ref().map(|ctx| hex::decode(ctx).unwrap());

        match MLDSA65::verify(
            &pk,
            &hex::decode(&self.msg).unwrap(),
            ctx_vec.as_ref().and_then(|ctx| Some(ctx.as_slice())),
            &hex::decode(&self.sig).unwrap(),
        ) {
            Ok(()) => {
                if self.result != "valid" {
                    panic!("signature passed when it should have failed:");
                }
            }
            Err(e) => {
                if self.result != "invalid" {
                    panic!("signature failed when it should have passed: {:?}", e);
                }
            }
        }
    }

    fn run_mldsa87(&self) {
        assert_eq!(self.parameter_set, ParameterSet::Mldsa87);

        /* Load the key */

        let pk = match MLDSA87PublicKey::from_bytes(&hex::decode(&self.public_key).unwrap()) {
            Ok(pk) => pk,
            Err(e) => {
                if self.result == "invalid" {
                    /* good */
                    return;
                } else {
                    panic!("{:?}", e)
                }
            }
        };

        /* Verify the signature */

        let ctx_vec = self.ctx.as_ref().map(|ctx| hex::decode(ctx).unwrap());

        match MLDSA87::verify(
            &pk,
            &hex::decode(&self.msg).unwrap(),
            ctx_vec.as_ref().and_then(|ctx| Some(ctx.as_slice())),
            &hex::decode(&self.sig).unwrap(),
        ) {
            Ok(()) => {
                if self.result != "valid" {
                    panic!("signature passed when it should have failed");
                }
            }
            Err(e) => {
                if self.result != "invalid" {
                    panic!("signature failed when it should have passed: {:?}", e);
                }
            }
        }
    }
}
