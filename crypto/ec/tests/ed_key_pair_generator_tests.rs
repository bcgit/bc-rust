//! `KeyPairGenerator` for Ed25519, Ed448, X25519 and X448 keys, through the core test framework.

use bouncycastle_core_test_framework::key_pair::TestFrameworkKeyPairGenerator;
use bouncycastle_ec::ed::ed448::Ed448PrivateKey;
use bouncycastle_ec::ed::ed25519::Ed25519PrivateKey;
use bouncycastle_ec::ed::x448::X448PrivateKey;
use bouncycastle_ec::ed::x25519::X25519PrivateKey;
use bouncycastle_rng::DefaultRNG;

#[test]
fn ed_keys_generate() {
    let framework = TestFrameworkKeyPairGenerator::new();
    let mut rng = DefaultRNG::default();
    framework.test::<Ed25519PrivateKey>(&mut rng);
    framework.test::<Ed448PrivateKey>(&mut rng);
    framework.test::<X25519PrivateKey>(&mut rng);
    framework.test::<X448PrivateKey>(&mut rng);
}
