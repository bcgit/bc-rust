//! `KeyPairGenerator` for ECDSA keys on every curve, through the core test framework.

use bouncycastle_core_test_framework::key_pair::TestFrameworkKeyPairGenerator;
use bouncycastle_digest::sha2::{SHA256, SHA384, SHA512};
use bouncycastle_ec::ecdsa::keys::ECDSAPrivateKey;
use bouncycastle_ec::{Bp256r1, Bp384r1, Bp512r1, P256, P384, P521, Secp256K1};
use bouncycastle_rng::DefaultRNG;

#[test]
fn ecdsa_keys_generate() {
    let framework = TestFrameworkKeyPairGenerator::new();
    let mut rng = DefaultRNG::default();
    framework.test::<ECDSAPrivateKey<P256, SHA256>>(&mut rng);
    framework.test::<ECDSAPrivateKey<P384, SHA384>>(&mut rng);
    framework.test::<ECDSAPrivateKey<P521, SHA512>>(&mut rng);
    framework.test::<ECDSAPrivateKey<Secp256K1, SHA256>>(&mut rng);
    framework.test::<ECDSAPrivateKey<Bp256r1, SHA256>>(&mut rng);
    framework.test::<ECDSAPrivateKey<Bp384r1, SHA384>>(&mut rng);
    framework.test::<ECDSAPrivateKey<Bp512r1, SHA512>>(&mut rng);
}
