//! Known-answer tests for ML-KEM-512/768/1024 against `ML-KEM-keyGen.txt`.
//!
//! Vectors are read from the bc-test-data repo (https://github.com/bcgit/bc-test-data), which must be
//! cloned alongside this repo at "../bc-test-data", under `pqc/crypto/mlkem/`. If it is not
//! present the tests print a warning and pass vacuously.
//!
//! `ML-KEM-encapDecap.txt` is not run: its decapsulation cases give the expanded private key `dk`,
//! and this crate's private keys hold only the 64-byte seed, which the file does not carry.
//! Decapsulation is covered instead by Wycheproof's seed-keyed `mlkem_*_test.json` files (including
//! the implicit-rejection cases), by the framework's bit-flip test, and by `cross_check_tests.rs`
//! against `bouncycastle-mlkem`, which does run the encapDecap file.

use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::{KeyMaterial512, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::KEMPublicKey;
use bouncycastle_core_test_framework::test_data_loaders::bc_test_data;
use bouncycastle_hex as hex;
use bouncycastle_mlkem_lowmemory::mlkem::{
    MLKEM512_FULL_SK_LEN, MLKEM768_FULL_SK_LEN, MLKEM1024_FULL_SK_LEN,
};
use bouncycastle_mlkem_lowmemory::{
    MLKEM512, MLKEM512_PK_LEN, MLKEM768, MLKEM768_PK_LEN, MLKEM1024, MLKEM1024_PK_LEN,
    MLKEMPrivateKeyTrait, MLKEMTrait,
};

const TEST_DATA_DIR: &str = "pqc/crypto/mlkem";

#[test]
#[allow(non_snake_case)]
fn ML_KEM_keyGen() {
    let Some(contents) = bc_test_data(TEST_DATA_DIR, "ML-KEM-keyGen.txt") else { return };

    let test_cases = KeyGenTestCase::parse(contents);

    for test_case in test_cases {
        test_case.run();
    }
}

#[derive(Clone)]
struct KeyGenTestCase {
    vs_id: u32,
    algorithm: String,
    mode: String,
    revision: String,
    is_sample: bool,
    tg_id: u32,
    test_type: String,
    parameter_set: String,
    tc_id: u32,
    z: String,
    d: String,
    ek: String,
    dk: String,
}

impl KeyGenTestCase {
    fn new() -> Self {
        Self {
            vs_id: 0,
            algorithm: String::new(),
            mode: String::new(),
            revision: String::new(),
            is_sample: false,
            tg_id: 0,
            test_type: String::new(),
            parameter_set: String::new(),
            tc_id: 0,
            z: String::new(),
            d: String::new(),
            ek: String::new(),
            dk: String::new(),
        }
    }

    fn is_full(&self) -> bool {
        !self.algorithm.is_empty()
    }

    fn parse(data: String) -> Vec<KeyGenTestCase> {
        let mut test_cases = Vec::<KeyGenTestCase>::new();
        let mut test_case = KeyGenTestCase::new();
        for line in data.lines() {
            let (tag, value) = match line.split_once(" = ") {
                Some(pair) => pair,
                None => {
                    if test_case.is_full() {
                        test_cases.push(test_case.clone());
                    }
                    continue;
                }
            };

            match tag {
                "vsId" => test_case.vs_id = value.parse().unwrap(),
                "algorithm" => test_case.algorithm = value.to_string(),
                "mode" => test_case.mode = value.to_string(),
                "revision" => test_case.revision = value.to_string(),
                "isSample" => test_case.is_sample = value.parse().unwrap(),
                "tgId" => test_case.tg_id = value.parse().unwrap(),
                "testType" => test_case.test_type = value.to_string(),
                "parameterSet" => test_case.parameter_set = value.to_string(),
                "tcId" => test_case.tc_id = value.parse().unwrap(),
                "z" => test_case.z = value.to_string(),
                "d" => test_case.d = value.to_string(),
                "ek" => test_case.ek = value.to_string(),
                "dk" => test_case.dk = value.to_string(),
                val => panic!("Invalid tag: {}", val),
            }
        }

        test_cases
    }

    fn run(&self) {
        assert_eq!(self.mode, "keyGen");

        let mut seed_bytes = [0u8; 64];
        seed_bytes[..32].copy_from_slice(&hex::decode(&self.d).unwrap());
        seed_bytes[32..].copy_from_slice(&hex::decode(&self.z).unwrap());

        let mut seed = KeyMaterial512::from_bytes_as_type(&seed_bytes, KeyType::Seed).unwrap();

        // for the purposes of the test cases, accept an all-zero seed
        do_hazardous_operations(&mut seed, |seed| {
            seed.set_key_type(KeyType::Seed)?;
            seed.set_security_strength(SecurityStrength::_256bit)
        })
        .unwrap();

        match self.parameter_set.as_str() {
            "ML-KEM-512" => {
                let (pk, sk) = MLKEM512::keygen_from_seed(&seed).unwrap();
                let pk_sized: [u8; MLKEM512_PK_LEN] =
                    hex::decode(&self.ek).unwrap().try_into().unwrap();
                assert_eq!(pk.encode(), pk_sized);
                let sk_sized: [u8; MLKEM512_FULL_SK_LEN] =
                    hex::decode(&self.dk).unwrap().try_into().unwrap();
                assert_eq!(sk.encode_full_sk(), sk_sized);
            }
            "ML-KEM-768" => {
                let (pk, sk) = MLKEM768::keygen_from_seed(&seed).unwrap();
                let pk_sized: [u8; MLKEM768_PK_LEN] =
                    hex::decode(&self.ek).unwrap().try_into().unwrap();
                assert_eq!(pk.encode(), pk_sized);
                let sk_sized: [u8; MLKEM768_FULL_SK_LEN] =
                    hex::decode(&self.dk).unwrap().try_into().unwrap();
                assert_eq!(sk.encode_full_sk(), sk_sized);
            }
            "ML-KEM-1024" => {
                let (pk, sk) = MLKEM1024::keygen_from_seed(&seed).unwrap();
                let pk_sized: [u8; MLKEM1024_PK_LEN] =
                    hex::decode(&self.ek).unwrap().try_into().unwrap();
                assert_eq!(pk.encode(), pk_sized);
                let sk_sized: [u8; MLKEM1024_FULL_SK_LEN] =
                    hex::decode(&self.dk).unwrap().try_into().unwrap();
                assert_eq!(sk.encode_full_sk(), sk_sized);
            }
            val => panic!("Invalid parameter set: {}", val),
        }
    }
}
