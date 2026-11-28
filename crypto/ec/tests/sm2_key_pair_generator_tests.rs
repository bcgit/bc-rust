//! `KeyPairGenerator` for SM2 signing and encryption keys, through the core test framework.

use bouncycastle_core_test_framework::key_pair::TestFrameworkKeyPairGenerator;
use bouncycastle_ec::sm2::encryption::SM2EncryptionPrivateKey;
use bouncycastle_ec::sm2::keys::SM2PrivateKey;
use bouncycastle_rng::DefaultRNG;

#[test]
fn sm2_keys_generate() {
    let framework = TestFrameworkKeyPairGenerator::new();
    let mut rng = DefaultRNG::default();
    framework.test::<SM2PrivateKey>(&mut rng);
    framework.test::<SM2EncryptionPrivateKey>(&mut rng);
}
