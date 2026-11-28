//! `KeyPairGenerator` for every `mlkem` parameter set, through the core test framework.

use bouncycastle_core_test_framework::key_pair::TestFrameworkKeyPairGenerator;
use bouncycastle_pqc::mlkem::{MLKEM512PrivateKey, MLKEM768PrivateKey, MLKEM1024PrivateKey};
use bouncycastle_rng::DefaultRNG;

#[test]
fn mlkem_keys_generate() {
    let framework = TestFrameworkKeyPairGenerator::new();
    let mut rng = DefaultRNG::default();
    framework.test::<MLKEM512PrivateKey>(&mut rng);
    framework.test::<MLKEM768PrivateKey>(&mut rng);
    framework.test::<MLKEM1024PrivateKey>(&mut rng);
}
