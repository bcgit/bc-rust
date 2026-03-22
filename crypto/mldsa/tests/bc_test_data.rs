// Test against the bc-test-data repo
// Requires that the bc-test-data repository is cloned and available for testing at "../bc-test-data"
// relative to the root of this git project.

use bouncycastle_core_interface::errors::SignatureError;
use bouncycastle_core_interface::traits::XOF;
use bouncycastle_sha3::SHAKE256;

#[cfg(test)]
mod bc_test_data {
    #![allow(dead_code)]

    use std::{fs};
    use bouncycastle_core_interface::errors::SignatureError;
    use bouncycastle_hex as hex;
    use bouncycastle_core_interface::key_material::{KeyMaterial, KeyMaterial256, KeyType};
    use bouncycastle_core_interface::traits::{Hash, SecurityStrength, Signature, SignaturePrivateKey, SignaturePublicKey};
    use bouncycastle_mldsa::{HashMLDSA44_with_SHA512, HashMLDSA65_with_SHA512, HashMLDSA87_with_SHA512, MLDSA44PrivateKey, MLDSA44PublicKey, MLDSA65PrivateKey, MLDSA65PublicKey, MLDSA87PrivateKey, MLDSA87PublicKey, MLDSAPrivateKeyTrait, MLDSATrait, MLDSA44, MLDSA65, MLDSA87};
    use bouncycastle_sha2::SHA512;
    use crate::BustedMuBuilder;

    const TEST_DATA_PATH: &str = "../../../bc-test-data/pqc/crypto/mldsa";

    // #[test]
    #[allow(non_snake_case)]
    fn ML_DSA_keyGen() {
        let contents = fs::read_to_string(TEST_DATA_PATH.to_string() + "/ML-DSA-keyGen.txt").unwrap();
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
        seed: String,
        pk: String,
        sk: String,
    }

    impl KeyGenTestCase {
        fn new() -> Self {
            Self{ vs_id: 0, algorithm: String::new(), mode: String::new(), revision: String::new(), is_sample: false, tg_id: 0, test_type: String::new(), parameter_set: String::new(), tc_id: 0, seed: String::new(), pk: String::new(), sk: String::new()}
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
                        if test_case.is_full() { test_cases.push(test_case.clone()); }
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
                    "seed" => test_case.seed = value.to_string(),
                    "pk" => test_case.pk = value.to_string(),
                    "sk" => test_case.sk = value.to_string(),
                    val => panic!("Invalid tag: {}", val),
                }
            }

            test_cases
        }

        fn run(&self) {
            assert_eq!(self.mode, "keyGen");

            let mut seed = KeyMaterial256::from_bytes_as_type(
                &hex::decode(&self.seed).unwrap(),
                KeyType::Seed,
            ).unwrap();
            // for the purposes of the test cases, accept an all-zero seed
            seed.allow_hazardous_operations();
            seed.set_key_type(KeyType::Seed).unwrap();
            seed.set_security_strength(SecurityStrength::_256bit).unwrap();
            seed.drop_hazardous_operations();

            match self.parameter_set.as_str() {
                "ML-DSA-44" => {
                    let (pk, sk) = MLDSA44::keygen_from_seed(&seed).unwrap();
                    assert_eq!(pk.encode(), hex::decode(&self.pk).unwrap());
                    assert_eq!(sk.encode(), hex::decode(&self.sk).unwrap());
                },
                "ML-DSA-65" => {
                    let (pk, sk) = MLDSA65::keygen_from_seed(&seed).unwrap();
                    assert_eq!(pk.encode(), hex::decode(&self.pk).unwrap());
                    assert_eq!(sk.encode(), hex::decode(&self.sk).unwrap());
                },
                "ML-DSA-87" => {
                    let (pk, sk) = MLDSA87::keygen_from_seed(&seed).unwrap();
                    assert_eq!(pk.encode(), hex::decode(&self.pk).unwrap());
                    assert_eq!(sk.encode(), hex::decode(&self.sk).unwrap());
                },
                val => panic!("Invalid parameter set: {}", val),

            }
        }
    }

    // #[test]
    #[allow(non_snake_case)]
    fn ML_DSA_sigGen() {
        let contents = fs::read_to_string(TEST_DATA_PATH.to_string() + "/ML-DSA-sigGen.txt").unwrap();
        let test_cases = SigGenTestCase::parse(contents);

        let num_tests = test_cases.len();
        for test_case in test_cases {
            test_case.run();
        }

        println!("SUCCESS! ML-DSA-sigGen test cases passed: {}!", num_tests);
    }

    #[derive(Clone)]
    struct SigGenTestCase {
        vs_id: u32,
        algorithm: String,
        mode: String,
        revision: String,
        is_sample: bool,
        tg_id: u32,
        test_type: String,
        parameter_set: String,
        deterministic: bool,
        tc_id: u32,
        sk: String,
        message: String,
        rnd: String,
        signature: String,
    }

    impl SigGenTestCase {
        fn new() -> Self {
            Self{ vs_id: 0, algorithm: String::new(), mode: String::new(), revision: String::new(), is_sample: false, tg_id: 0, test_type: String::new(), parameter_set: String::new(), deterministic: false, tc_id: 0, sk: String::new(), message: String::new(), rnd: String::new(), signature: String::new()}
        }

        fn is_full(&self) -> bool {
            !self.algorithm.is_empty()
        }

        fn parse(data: String) -> Vec<SigGenTestCase> {
            let mut test_cases = Vec::<SigGenTestCase>::new();
            let mut test_case = SigGenTestCase::new();
            for line in data.lines() {
                let (tag, value) = match line.split_once(" = ") {
                    Some(pair) => pair,
                    None => {
                        if test_case.is_full(){ test_cases.push(test_case.clone()); }
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
                    "deterministic" => test_case.deterministic = value.parse().unwrap(),
                    "tcId" => test_case.tc_id = value.parse().unwrap(),
                    "sk" => test_case.sk = value.to_string(),
                    "message" => test_case.message = value.to_string(),
                    "rnd" => test_case.rnd = value.to_string(),
                    "signature" => test_case.signature = value.to_string(),
                    val => panic!("Invalid tag: {}", val),
                }
            }

            test_cases
        }

        fn run(&self) {
            assert_eq!(self.mode, "sigGen");

            let rnd = if self.deterministic{ [0u8; 32] } else { hex::decode(&self.rnd).unwrap().as_slice().try_into().unwrap() };

            match self.parameter_set.as_str() {
                "ML-DSA-44" => {
                    let sk = MLDSA44PrivateKey::from_bytes(&hex::decode(&self.sk).unwrap()).unwrap();

                    // note: we're exposing a sign_mu_deterministic(), but not sign_deterministic()
                    // so need to manually compute mu
                    // let mu = MLDSA44::compute_mu_from_tr(
                    //     &hex::decode(&self.message).unwrap(),
                    //     None,
                    //     sk.tr(),
                    // ).unwrap();
                    let mut mb = BustedMuBuilder::do_init(&sk.tr()).unwrap();
                    mb.do_update(&hex::decode(&self.message).unwrap());
                    let mu = mb.do_final();

                    let sig = MLDSA44::sign_mu_deterministic(&sk, &mu, rnd).unwrap();
                    assert_eq!(&sig, &*hex::decode(&self.signature).unwrap(), "ML-DSA-sigGen params: {}, vsId: {}, tgId: {}, tcId: {}", self.parameter_set, self.vs_id, self.tg_id, self.tc_id);
                },
                "ML-DSA-65" => {
                    let sk = MLDSA65PrivateKey::from_bytes(&hex::decode(&self.sk).unwrap()).unwrap();

                    // note: we're exposing a sign_mu_deterministic(), but not sign_deterministic()
                    // so need to manually compute mu
                    // let mu = MLDSA65::compute_mu_from_tr(
                    //     &hex::decode(&self.message).unwrap(),
                    //     None,
                    //     sk.tr(),
                    // ).unwrap();
                    let mut mb = BustedMuBuilder::do_init(&sk.tr()).unwrap();
                    mb.do_update(&hex::decode(&self.message).unwrap());
                    let mu = mb.do_final();

                    let sig = MLDSA65::sign_mu_deterministic(&sk, &mu, rnd).unwrap();
                    assert_eq!(&sig, &*hex::decode(&self.signature).unwrap());
                },
                "ML-DSA-87" => {
                    let sk = MLDSA87PrivateKey::from_bytes(&hex::decode(&self.sk).unwrap()).unwrap();

                    // note: we're exposing a sign_mu_deterministic(), but not sign_deterministic()
                    // so need to manually compute mu
                    // let mu = MLDSA87::compute_mu_from_tr(
                    //     &hex::decode(&self.message).unwrap(),
                    //     None,
                    //     sk.tr(),
                    // ).unwrap();
                    let mut mb = BustedMuBuilder::do_init(&sk.tr()).unwrap();
                    mb.do_update(&hex::decode(&self.message).unwrap());
                    let mu = mb.do_final();

                    let sig = MLDSA87::sign_mu_deterministic(&sk, &mu, rnd).unwrap();
                    assert_eq!(&sig, &*hex::decode(&self.signature).unwrap());
                },
                val => panic!("Invalid parameter set: {}", val),

            }
        }
    }

    // This is also against the non-compliant mu that doesn't have a ctx, which I don't have an easy way to test
    // #[test]
    #[allow(non_snake_case)]
    fn ML_DSA_sigVer() {
        let contents = fs::read_to_string(TEST_DATA_PATH.to_string() + "/ML-DSA-sigVer.txt").unwrap();
        let test_cases = SigVerTestCase::parse(contents);

        for test_case in test_cases {
            test_case.run();
        }
    }

    #[derive(Clone)]
    struct SigVerTestCase {
        vs_id: u32,
        algorithm: String,
        mode: String,
        revision: String,
        is_sample: bool,
        tg_id: u32,
        test_type: String,
        parameter_set: String,
        pk: String,
        tc_id: u32,
        message: String,
        signature: String,
        test_passed: bool,
    }

    impl SigVerTestCase {
        fn new() -> Self {
            Self{ vs_id: 0, algorithm: String::new(), mode: String::new(), revision: String::new(), is_sample: false, tg_id: 0, test_type: String::new(), parameter_set: String::new(), tc_id: 0, pk: String::new(), message: String::new(), signature: String::new(), test_passed: false}
        }

        fn is_full(&self) -> bool {
            !self.algorithm.is_empty()
        }

        fn parse(data: String) -> Vec<SigVerTestCase> {
            let mut test_cases = Vec::<SigVerTestCase>::new();
            let mut test_case = SigVerTestCase::new();
            for line in data.lines() {
                let (tag, value) = match line.split_once(" = ") {
                    Some(pair) => pair,
                    None => {
                        if test_case.is_full() { test_cases.push(test_case.clone()); }
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
                    "pk" => test_case.pk = value.to_string(),
                    "tcId" => test_case.tc_id = value.parse().unwrap(),
                    "message" => test_case.message = value.to_string(),
                    "signature" => test_case.signature = value.to_string(),
                    "testPassed" => test_case.test_passed = value.parse().unwrap(),
                    val => panic!("Invalid tag: {}", val),
                }
            }

            test_cases
        }

        fn run(&self) {
            assert_eq!(self.mode, "sigVer");

            match self.parameter_set.as_str() {
                "ML-DSA-44" => {
                    let pk = MLDSA44PublicKey::from_bytes(&hex::decode(&self.pk).unwrap()).unwrap();

                    match MLDSA44::verify(&pk, &hex::decode(&self.message).unwrap(), None, &hex::decode(&self.signature).unwrap()) {
                        Ok(()) => if !self.test_passed { panic!("Verification succeeded when it shouldn't have!") },
                        Err(SignatureError::SignatureVerificationFailed) => { if self.test_passed { panic!("Verification failed when it shouldn't have! vsId: {}, tgId: {}, tcId: {}", self.vs_id, self.tg_id, self.tc_id) } },
                        _ => panic!("An unexpected error occurred")
                    }
                },
                "ML-DSA-65" => {
                    let pk = MLDSA65PublicKey::from_bytes(&hex::decode(&self.pk).unwrap()).unwrap();

                    match MLDSA65::verify(&pk, &hex::decode(&self.message).unwrap(), None, &hex::decode(&self.signature).unwrap()) {
                        Ok(()) => if self.test_passed { /* good */ } else { panic!("Verification succeeded when it shouldn't have!") },
                        Err(SignatureError::SignatureVerificationFailed) => { if !self.test_passed {} else { panic!("Verification failed when it should have!") } },
                        _ => panic!("An unexpected error occurred")
                    }
                },
                "ML-DSA-87" => {
                    let pk = MLDSA87PublicKey::from_bytes(&hex::decode(&self.pk).unwrap()).unwrap();

                    match MLDSA87::verify(&pk, &hex::decode(&self.message).unwrap(), None, &hex::decode(&self.signature).unwrap()) {
                        Ok(()) => if self.test_passed { /* good */ } else { panic!("Verification succeeded when it shouldn't have!") },
                        Err(SignatureError::SignatureVerificationFailed) => { if !self.test_passed {} else { panic!("Verification failed when it should have!") } },
                        _ => panic!("An unexpected error occurred")
                    }
                },
                val => panic!("Invalid parameter set: {}", val),

            }
        }
    }

    // not working, not totally sure why
    // #[test]
    #[allow(non_snake_case)]
    fn ML_DSA_rsp() {
        // MLDsa44
        let contents = fs::read_to_string(TEST_DATA_PATH.to_string() + "/mldsa44.rsp").unwrap();
        let test_cases = MldsaRspTestCase::<false>::parse(contents);
        for test_case in test_cases {
            test_case.run("MLDsa44");
        }

        // MLDsa65
        let contents = fs::read_to_string(TEST_DATA_PATH.to_string() + "/mldsa65.rsp").unwrap();
        let test_cases = MldsaRspTestCase::<false>::parse(contents);
        for test_case in test_cases {
            test_case.run("MLDsa65");
        }


        // MLDsa87
        let contents = fs::read_to_string(TEST_DATA_PATH.to_string() + "/mldsa87.rsp").unwrap();
        let test_cases = MldsaRspTestCase::<false>::parse(contents);
        for test_case in test_cases {
            test_case.run("MLDsa87");
        }


        // MLDsa44
        let contents = fs::read_to_string(TEST_DATA_PATH.to_string() + "/mldsa44sha512.rsp").unwrap();
        let test_cases = MldsaRspTestCase::<true>::parse(contents);
        for test_case in test_cases {
            test_case.run("MLDsa44");
        }

        // MLDsa65
        let contents = fs::read_to_string(TEST_DATA_PATH.to_string() + "/mldsa65sha512.rsp").unwrap();
        let test_cases = MldsaRspTestCase::<true>::parse(contents);
        for test_case in test_cases {
            test_case.run("MlDsa65");
        }


        // MLDsa87
        let contents = fs::read_to_string(TEST_DATA_PATH.to_string() + "/mldsa87sha512.rsp").unwrap();
        let test_cases = MldsaRspTestCase::<true>::parse(contents);
        for test_case in test_cases {
            test_case.run("MlDsa87");
        }
    }

    #[derive(Clone)]
    struct MldsaRspTestCase<const IS_HASH_MLDSA: bool> {
        count: u32,
        seed: String,
        mlen: u32,
        msg: String,
        pk: String,
        sk: String,
        smlen: u32,
        sm: String,
        message_hash: String,
        message_prime: String,
        context: String,
    }

    impl<const IS_HASH_MLDSA: bool> MldsaRspTestCase<IS_HASH_MLDSA> {
        fn new() -> Self {
            Self{ count: 0, seed: String::new(), mlen: 0, msg: String::new(), pk: String::new(), sk: String::new(), smlen: 0, sm: String::new(), message_hash: String::new(), message_prime: String::new(), context: String::new()}
        }

        fn is_full(&self) -> bool {
            !self.seed.is_empty()
        }

        fn parse(data: String) -> Vec<MldsaRspTestCase<IS_HASH_MLDSA>> {
            let mut test_cases = Vec::<>::new();
            let mut test_case = MldsaRspTestCase::new();
            for line in data.lines() {
                let (tag, value) = match line.split_once(" = ") {
                    Some(pair) => pair,
                    None => {
                        if test_case.is_full() { test_cases.push(test_case.clone()); }
                        continue;
                    }
                };

                match tag {
                    "count" => test_case.count = value.parse().unwrap(),
                    "seed" => test_case.seed = value.to_string(),
                    "mlen" => test_case.mlen = value.parse().unwrap(),
                    "msg" => test_case.msg = value.to_string(),
                    "pk" => test_case.pk = value.to_string(),
                    "sk" => test_case.sk = value.to_string(),
                    "smlen" => test_case.smlen = value.parse().unwrap(),
                    "sm" => test_case.sm = value.to_string(),
                    "message_hash" => test_case.message_hash = value.to_string(),
                    "message_prime" => test_case.message_prime = value.to_string(),
                    "context" => {
                        test_case.context = value.to_string();
                        if test_case.context == "zero_length" || test_case.context == "none" {
                            test_case.context = String::new();
                        }
                    },
                    val => panic!("Invalid tag: {}", val),
                }
            }

            test_cases
        }

        fn run(&self, parameter_set: &str) {
            match parameter_set {
                "MLDsa44" => {
                    let mut seed = KeyMaterial256::from_bytes_as_type(
                        &hex::decode(&self.seed).unwrap(),
                        KeyType::Seed,
                    ).unwrap();
                    // for the purposes of the test cases, accept an all-zero seed
                    seed.allow_hazardous_operations();
                    seed.set_key_type(KeyType::Seed).unwrap();
                    seed.set_security_strength(SecurityStrength::_256bit).unwrap();
                    seed.drop_hazardous_operations();


                    let (pk, sk) = MLDSA44::keygen_from_seed(&seed).unwrap();
                    assert_eq!(pk.encode(), hex::decode(&self.pk).unwrap());
                    assert_eq!(sk.encode(), hex::decode(&self.sk).unwrap());

                    if IS_HASH_MLDSA {
                        // we're only testing SHA512
                        let ph: [u8; 64] = SHA512::new().hash(&hex::decode(&self.msg).unwrap()).as_slice().try_into().unwrap();
                        assert_eq!(ph, &*hex::decode(&self.message_hash).unwrap());

                        let sig = HashMLDSA44_with_SHA512::sign_ph_deterministic(&sk, Some(&*hex::decode(&self.context).unwrap()), &ph, [0u8; 32]).unwrap();
                        assert_eq!(sig, &*hex::decode(&self.sm).unwrap());

                        HashMLDSA44_with_SHA512::verify(&pk,
                                                        &*hex::decode(&self.msg).unwrap(),
                                                        Some(&*hex::decode(&self.context).unwrap()),
                                                        &sig).expect(&format!("paramSet: {}, is_hash: {}, count: {}", parameter_set, IS_HASH_MLDSA, self.count));
                    } else {
                        // note: we're exposing a sign_mu_deterministic(), but not sign_deterministic()
                        // so need to manually compute mu
                        let mu = MLDSA65::compute_mu_from_tr(
                            &hex::decode(&self.msg).unwrap(),
                            Some(&hex::decode(&self.context).unwrap()),
                            sk.tr(),
                        ).unwrap();

                        let sig = MLDSA44::sign_mu_deterministic(&sk, &mu, [0u8; 32]).unwrap();
                        assert_eq!(sig, &*hex::decode(&self.sm).unwrap(), "paramSet: {}, count: {}", parameter_set, self.count);

                        MLDSA44::verify(&pk, &hex::decode(&self.msg).unwrap(), Some(&hex::decode(&self.context).unwrap()), &sig).unwrap();
                    }
                },
                "MlDsa65" | "MLDsa65" => {
                    let mut seed = KeyMaterial256::from_bytes_as_type(
                        &hex::decode(&self.seed).unwrap(),
                        KeyType::Seed,
                    ).unwrap();
                    // for the purposes of the test cases, accept an all-zero seed
                    seed.allow_hazardous_operations();
                    seed.set_key_type(KeyType::Seed).unwrap();
                    seed.set_security_strength(SecurityStrength::_256bit).unwrap();
                    seed.drop_hazardous_operations();

                    let (pk, sk) = MLDSA65::keygen_from_seed(&seed).unwrap();
                    assert_eq!(pk.encode(), hex::decode(&self.pk).unwrap());
                    assert_eq!(sk.encode(), hex::decode(&self.sk).unwrap());

                    if IS_HASH_MLDSA {
                        // we're only testing SHA512
                        let ph: [u8; 64] = SHA512::new().hash(&hex::decode(&self.msg).unwrap()).as_slice().try_into().unwrap();
                        assert_eq!(ph, &*hex::decode(&self.message_hash).unwrap());

                        let sig = HashMLDSA65_with_SHA512::sign_ph_deterministic(&sk, Some(&*hex::decode(&self.context).unwrap()), &ph, [0u8; 32]).unwrap();
                        assert_eq!(sig, &*hex::decode(&self.sm).unwrap());

                        HashMLDSA65_with_SHA512::verify(&pk,
                                                        &*hex::decode(&self.message_hash).unwrap(),
                                                        Some(&*hex::decode(&self.context).unwrap()),
                                                        &sig).expect(&format!("paramSet: {}, isHash: {}, count: {}", parameter_set, IS_HASH_MLDSA, self.count));
                    } else {
                        // note: we're exposing a sign_mu_deterministic(), but not sign_deterministic()
                        // so need to manually compute mu
                        let mu = MLDSA65::compute_mu_from_tr(
                            &hex::decode(&self.msg).unwrap(),
                            Some(&hex::decode(&self.context).unwrap()),
                            sk.tr(),
                        ).unwrap();

                        let sig = MLDSA65::sign_mu_deterministic(&sk, &mu, [0u8; 32]).unwrap();
                        assert_eq!(sig, &*hex::decode(&self.sm).unwrap());

                        MLDSA65::verify(&pk, &hex::decode(&self.msg).unwrap(), Some(&hex::decode(&self.context).unwrap()), &sig).unwrap();
                    }
                },
                "MLDsa87" => {
                    let mut seed = KeyMaterial256::from_bytes_as_type(
                        &hex::decode(&self.seed).unwrap(),
                        KeyType::Seed,
                    ).unwrap();
                    // for the purposes of the test cases, accept an all-zero seed
                    seed.allow_hazardous_operations();
                    seed.set_key_type(KeyType::Seed).unwrap();
                    seed.set_security_strength(SecurityStrength::_256bit).unwrap();
                    seed.drop_hazardous_operations();

                    let (pk, sk) = MLDSA87::keygen_from_seed(&seed).unwrap();
                    assert_eq!(pk.encode(), hex::decode(&self.pk).unwrap());
                    assert_eq!(sk.encode(), hex::decode(&self.sk).unwrap());


                    if IS_HASH_MLDSA {
                        // we're only testing SHA512
                        let ph: [u8; 64] = SHA512::new().hash(&hex::decode(&self.msg).unwrap()).as_slice().try_into().unwrap();
                        assert_eq!(ph, &*hex::decode(&self.message_hash).unwrap());

                        let sig = HashMLDSA87_with_SHA512::sign_ph_deterministic(&sk, Some(&*hex::decode(&self.context).unwrap()), &ph, [0u8; 32]).unwrap();
                        assert_eq!(sig, &*hex::decode(&self.sm).unwrap());

                        HashMLDSA87_with_SHA512::verify(&pk,
                                                        &*hex::decode(&self.message_hash).unwrap(),
                                                        Some(&*hex::decode(&self.context).unwrap()),
                                                        &sig).unwrap();
                    } else {
                        // note: we're exposing a sign_mu_deterministic(), but not sign_deterministic()
                        // so need to manually compute mu
                        let mu = MLDSA65::compute_mu_from_tr(
                            &hex::decode(&self.msg).unwrap(),
                            Some(&hex::decode(&self.context).unwrap()),
                            sk.tr(),
                        ).unwrap();

                        let sig = MLDSA87::sign_mu_deterministic(&sk, &mu, [0u8; 32]).unwrap();
                        assert_eq!(sig, &*hex::decode(&self.sm).unwrap());

                        MLDSA87::verify(&pk, &hex::decode(&self.msg).unwrap(), Some(&hex::decode(&self.context).unwrap()), &sig).unwrap();
                    }
                },
                val => panic!("Invalid parameter set: {}", val),
            }
        }
    }
}



/// This builds a "busted" mu where the ctx is absent (not 0-length, but actually not there)
/// just for the sake of compatibility with the bc-test-data tests
pub struct BustedMuBuilder {
    h: SHAKE256,
}

impl BustedMuBuilder {
    /// Algorithm 7
    /// 6: 𝜇 ← H(BytesToBits(𝑡𝑟)||𝑀′, 64)
    pub fn compute_mu(msg: &[u8], tr: &[u8; 64]) -> Result<[u8; 64], SignatureError> {
        let mut mu_builder = Self::do_init(&tr)?;
        mu_builder.do_update(msg);
        let mu = mu_builder.do_final();

        Ok(mu)
    }

    /// This function requires the public key hash `tr`, which can be computed from the public key using [MLDSAPublicKey::compute_tr].
    pub fn do_init(tr: &[u8; 64], /*ctx: Option<&[u8]>*/) -> Result<Self, SignatureError> {
        // let ctx = match ctx {
        //     Some(ctx) => ctx,
        //     None => &[]
        // };

        // Algorithm 2
        // 1: if |𝑐𝑡𝑥| > 255 then
        // if ctx.len() > 255 {
        //     return Err(SignatureError::LengthError("ctx value is longer than 255 bytes"));
        // }

        // Algorithm 7
        // 6: 𝜇 ← H(BytesToBits(𝑡𝑟)||𝑀', 64)
        let mut mb = Self { h: SHAKE256::new() };
        mb.h.absorb(tr);

        // Algorithm 2
        // 10: 𝑀′ ← BytesToBits(IntegerToBytes(0, 1) ∥ IntegerToBytes(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥) ∥ 𝑀
        // all done together
        // mb.h.absorb(&[0u8]);   // these are the busted lines -- bc-java just doesn't do these in the test code
        // mb.h.absorb(&[ctx.len() as u8]);
        // mb.h.absorb(ctx);

        // now ready to absorb M
        Ok(mb)
    }

    /// Stream a chunk of the message.
    pub fn do_update(&mut self, msg_chunk: &[u8]) {
        self.h.absorb(msg_chunk);
    }

    /// Finalize and return the mu value.
    pub fn do_final(mut self) -> [u8; 64] {
        // Completion of
        // Algorithm 7
        // 6: 𝜇 ← H(BytesToBits(𝑡𝑟)||𝑀 ′, 64)
        let mut mu = [0u8; 64];
        self.h.squeeze_out(&mut mu);

        mu
    }
}