//! `KeyPairGenerator` for RSA signature and key-establishment keys, through the core test
//! framework, at RSA-2048: generation is the size's FIPS 186-5 generator at every size.

use bouncycastle_core_test_framework::key_pair::TestFrameworkKeyPairGenerator;
use bouncycastle_modexp::rsa::keys::RsaPrivateKey;
use bouncycastle_modexp::rsa::rsa_2048::{
    RSA2048KEMPrivateKey, RSASSA_PKCS1_v1_5_SHA256, RSASSA_PSS_SHA256,
};
use bouncycastle_rng::DefaultRNG;

#[test]
fn rsa_keys_generate() {
    let framework = TestFrameworkKeyPairGenerator::new();
    let mut rng = DefaultRNG::default();
    framework.test::<RsaPrivateKey<RSASSA_PKCS1_v1_5_SHA256>>(&mut rng);
    framework.test::<RsaPrivateKey<RSASSA_PSS_SHA256>>(&mut rng);
    framework.test::<RSA2048KEMPrivateKey>(&mut rng);
}
