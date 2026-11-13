//! ECC CDH secp256k1: the shared behavioural suite in `eccdh_common`, instantiated for the curve.

mod eccdh_common;

use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_ec::Secp256K1;

#[test]
fn framework_and_metadata() {
    eccdh_common::framework_and_metadata::<Secp256K1, 65, 32, 32>(
        "ECC-CDH-secp256k1",
        SecurityStrength::_128bit,
    );
}

#[test]
fn key_loading() {
    eccdh_common::key_loading::<Secp256K1, 65, 32>();
}

#[test]
fn rng_rules() {
    eccdh_common::rng_rules::<Secp256K1, 65>(SecurityStrength::_128bit, SecurityStrength::_112bit);
}

/// The pairings' derived key is one output of the matched hash long here; the parameters name any.
#[test]
fn kdf_variants() {
    eccdh_common::kdf_variants::<Secp256K1, 65, 32, 32>(SecurityStrength::_128bit);
}
