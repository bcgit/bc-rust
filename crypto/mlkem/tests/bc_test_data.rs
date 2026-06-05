// Test against the bc-test-data repo
// Requires that the bc-test-data repository is cloned and available for testing at "../bc-test-data"
// relative to the root of this git project.

#[cfg(test)]
mod bc_test_data {
    use bouncycastle_core::key_material::{KeyMaterial512, KeyMaterialTrait, KeyType};
    use bouncycastle_core::traits::{KEM, KEMPrivateKey, KEMPublicKey, SecurityStrength};
    use bouncycastle_hex as hex;
    use bouncycastle_mlkem::{
        MLKEM512, MLKEM512_PK_LEN, MLKEM512_SK_LEN, MLKEM512PrivateKey, MLKEM512PublicKey,
        MLKEM768, MLKEM768_PK_LEN, MLKEM768_SK_LEN, MLKEM768PrivateKey, MLKEM768PublicKey,
        MLKEM1024, MLKEM1024_PK_LEN, MLKEM1024_SK_LEN, MLKEM1024PrivateKey, MLKEM1024PublicKey,
        MLKEMTrait,
    };
    use std::fs;
    use std::path::Path;
    use std::sync::Once;

    const TEST_DATA_PATH_RELATIVE: &str = "../../../bc-test-data/pqc/crypto/mlkem";
    const TEST_DATA_PATH: &str = "../bc-test-data/pqc/crypto/mlkem";

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
    #[allow(non_snake_case)]
    fn ML_KEM_keyGen() {
        let contents = match get_test_data("ML-KEM-keyGen.txt") {
            Ok(contents) => contents,
            Err(()) => return,
        };

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
            seed_bytes[..32].copy_from_slice(&*hex::decode(&self.d).unwrap());
            seed_bytes[32..].copy_from_slice(&*hex::decode(&self.z).unwrap());

            let mut seed = KeyMaterial512::from_bytes_as_type(&seed_bytes, KeyType::Seed).unwrap();

            // for the purposes of the test cases, accept an all-zero seed
            seed.allow_hazardous_operations();
            seed.set_key_type(KeyType::Seed).unwrap();
            seed.set_security_strength(SecurityStrength::_256bit).unwrap();
            seed.drop_hazardous_operations();

            match self.parameter_set.as_str() {
                "ML-KEM-512" => {
                    let (pk, sk) = MLKEM512::keygen_from_seed(&seed).unwrap();
                    let pk_sized: [u8; MLKEM512_PK_LEN] =
                        hex::decode(&self.ek).unwrap().try_into().unwrap();
                    assert_eq!(pk.encode(), pk_sized);
                    let sk_sized: [u8; MLKEM512_SK_LEN] =
                        hex::decode(&self.dk).unwrap().try_into().unwrap();
                    assert_eq!(sk.encode(), sk_sized);
                }
                "ML-KEM-768" => {
                    let (pk, sk) = MLKEM768::keygen_from_seed(&seed).unwrap();
                    let pk_sized: [u8; MLKEM768_PK_LEN] =
                        hex::decode(&self.ek).unwrap().try_into().unwrap();
                    assert_eq!(pk.encode(), pk_sized);
                    let sk_sized: [u8; MLKEM768_SK_LEN] =
                        hex::decode(&self.dk).unwrap().try_into().unwrap();
                    assert_eq!(sk.encode(), sk_sized);
                }
                "ML-KEM-1024" => {
                    let (pk, sk) = MLKEM1024::keygen_from_seed(&seed).unwrap();
                    let pk_sized: [u8; MLKEM1024_PK_LEN] =
                        hex::decode(&self.ek).unwrap().try_into().unwrap();
                    assert_eq!(pk.encode(), pk_sized);
                    let sk_sized: [u8; MLKEM1024_SK_LEN] =
                        hex::decode(&self.dk).unwrap().try_into().unwrap();
                    assert_eq!(sk.encode(), sk_sized);
                }
                val => panic!("Invalid parameter set: {}", val),
            }
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn ML_KEM_encapDecap() {
        let contents = match get_test_data("ML-KEM-encapDecap.txt") {
            Ok(contents) => contents,
            Err(()) => return,
        };

        let test_cases = EncapDecapTestCase::parse(contents);

        let num_tests = test_cases.len();
        for test_case in test_cases {
            test_case.run();
        }

        println!("SUCCESS! ML-DSA-sigGen test cases passed: {}!", num_tests);
    }

    #[derive(Clone)]
    struct EncapDecapTestCase {
        vs_id: u32,
        algorithm: String,
        mode: String,
        revision: String,
        is_sample: bool,
        tg_id: u32,
        test_type: String,
        parameter_set: String,
        function: String,
        tc_id: u32,
        ek: String,
        dk: String,
        m: String,
        c: String,
        k: String,
    }

    impl EncapDecapTestCase {
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
                function: String::new(),
                tc_id: 0,
                ek: String::new(),
                dk: String::new(),
                m: String::new(),
                c: String::new(),
                k: String::new(),
            }
        }

        fn is_full(&self) -> bool {
            !self.algorithm.is_empty()
        }

        fn parse(data: String) -> Vec<EncapDecapTestCase> {
            let mut test_cases = Vec::<EncapDecapTestCase>::new();
            let mut test_case = EncapDecapTestCase::new();
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
                    "function" => test_case.function = value.to_string(),
                    "tcId" => test_case.tc_id = value.parse().unwrap(),
                    "ek" => test_case.ek = value.to_string(),
                    "dk" => test_case.dk = value.to_string(),
                    "m" => test_case.m = value.to_string(),
                    "c" => test_case.c = value.to_string(),
                    "k" => test_case.k = value.to_string(),
                    val => panic!("Invalid tag: {}", val),
                }
            }

            test_cases
        }

        fn run(&self) {
            assert_eq!(self.mode, "encapDecap");

            match self.parameter_set.as_str() {
                "ML-KEM-512" => {
                    match self.function.as_str() {
                        "encapsulation" => {
                            let pk = MLKEM512PublicKey::from_bytes(&hex::decode(&self.ek).unwrap())
                                .unwrap();
                            let m: [u8; 32] = hex::decode(&self.m).unwrap().try_into().unwrap();
                            let (ss, ct) = MLKEM512::encaps_internal(&pk, None, m);

                            let expected_ss = hex::decode(&self.k).unwrap();
                            let expected_ct = hex::decode(&self.c).unwrap();

                            assert_eq!(ss, expected_ss.as_slice());
                            assert_eq!(ct, expected_ct.as_slice());
                        }
                        "decapsulation" => {
                            let sk =
                                MLKEM512PrivateKey::from_bytes(&hex::decode(&self.dk).unwrap())
                                    .unwrap();
                            let ct = hex::decode(&self.c).unwrap();
                            let ss = MLKEM512::decaps(&sk, ct.as_slice()).unwrap();

                            let expected_ss = hex::decode(&self.k).unwrap();
                            assert_eq!(ss.ref_to_bytes(), expected_ss.as_slice());
                        }
                        _ => panic!("Invalid function: {}", self.function),
                    };
                }
                "ML-KEM-768" => {
                    match self.function.as_str() {
                        "encapsulation" => {
                            let pk = MLKEM768PublicKey::from_bytes(&hex::decode(&self.ek).unwrap())
                                .unwrap();
                            let m: [u8; 32] = hex::decode(&self.m).unwrap().try_into().unwrap();
                            let (ss, ct) = MLKEM768::encaps_internal(&pk, None, m);

                            let expected_ss = hex::decode(&self.k).unwrap();
                            let expected_ct = hex::decode(&self.c).unwrap();

                            assert_eq!(ss, expected_ss.as_slice());
                            assert_eq!(ct, expected_ct.as_slice());
                        }
                        "decapsulation" => {
                            let sk =
                                MLKEM768PrivateKey::from_bytes(&hex::decode(&self.dk).unwrap())
                                    .unwrap();
                            let ct = hex::decode(&self.c).unwrap();
                            let ss = MLKEM768::decaps(&sk, ct.as_slice()).unwrap();

                            let expected_ss = hex::decode(&self.k).unwrap();
                            assert_eq!(ss.ref_to_bytes(), expected_ss.as_slice());
                        }
                        _ => panic!("Invalid function: {}", self.function),
                    };
                }
                "ML-KEM-1024" => {
                    match self.function.as_str() {
                        "encapsulation" => {
                            let pk =
                                MLKEM1024PublicKey::from_bytes(&hex::decode(&self.ek).unwrap())
                                    .unwrap();
                            let m: [u8; 32] = hex::decode(&self.m).unwrap().try_into().unwrap();
                            let (ss, ct) = MLKEM1024::encaps_internal(&pk, None, m);

                            let expected_ss = hex::decode(&self.k).unwrap();
                            let expected_ct = hex::decode(&self.c).unwrap();

                            assert_eq!(ss, expected_ss.as_slice());
                            assert_eq!(ct, expected_ct.as_slice());
                        }
                        "decapsulation" => {
                            let sk =
                                MLKEM1024PrivateKey::from_bytes(&hex::decode(&self.dk).unwrap())
                                    .unwrap();
                            let ct = hex::decode(&self.c).unwrap();
                            let ss = MLKEM1024::decaps(&sk, ct.as_slice()).unwrap();

                            let expected_ss = hex::decode(&self.k).unwrap();
                            assert_eq!(ss.ref_to_bytes(), expected_ss.as_slice());
                        }
                        _ => panic!("Invalid function: {}", self.function),
                    };
                }
                val => panic!("Invalid parameter set: {}", val),
            }
        }
    }
}
