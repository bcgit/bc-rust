//! `KeyPairGenerator` for every `mldsa` parameter set, through the core test framework.

use bouncycastle_core_test_framework::key_pair::TestFrameworkKeyPairGenerator;
use bouncycastle_pqc::mldsa::{MLDSA44PrivateKey, MLDSA65PrivateKey, MLDSA87PrivateKey};
use bouncycastle_rng::DefaultRNG;

#[test]
fn mldsa_keys_generate() {
    let framework = TestFrameworkKeyPairGenerator::new();
    let mut rng = DefaultRNG::default();
    framework.test::<MLDSA44PrivateKey>(&mut rng);
    framework.test::<MLDSA65PrivateKey>(&mut rng);
    framework.test::<MLDSA87PrivateKey>(&mut rng);
}
