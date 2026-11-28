//! `KeyPairGenerator` for ECC CDH keys on every curve, through the core test framework.

use bouncycastle_core_test_framework::key_pair::TestFrameworkKeyPairGenerator;
use bouncycastle_ec::eccdh::keys::ECCDHPrivateKey;
use bouncycastle_ec::{Bp256r1, Bp384r1, Bp512r1, P256, P384, P521, Secp256K1};
use bouncycastle_rng::DefaultRNG;

#[test]
fn eccdh_keys_generate() {
    let framework = TestFrameworkKeyPairGenerator::new();
    let mut rng = DefaultRNG::default();
    framework.test::<ECCDHPrivateKey<P256>>(&mut rng);
    framework.test::<ECCDHPrivateKey<P384>>(&mut rng);
    framework.test::<ECCDHPrivateKey<P521>>(&mut rng);
    framework.test::<ECCDHPrivateKey<Secp256K1>>(&mut rng);
    framework.test::<ECCDHPrivateKey<Bp256r1>>(&mut rng);
    framework.test::<ECCDHPrivateKey<Bp384r1>>(&mut rng);
    framework.test::<ECCDHPrivateKey<Bp512r1>>(&mut rng);
}
