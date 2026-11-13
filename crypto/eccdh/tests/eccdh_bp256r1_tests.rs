//! ECC CDH brainpoolP256r1: the shared behavioural suite in `eccdh_common`, instantiated for the curve.

mod eccdh_common;

use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_ec::Bp256r1;

#[test]
fn framework_and_metadata() {
    eccdh_common::framework_and_metadata::<Bp256r1, 65, 32, 32>(
        "ECC-CDH-brainpoolP256r1",
        SecurityStrength::_128bit,
    );
}

#[test]
fn key_loading() {
    eccdh_common::key_loading::<Bp256r1, 65, 32>();
}

#[test]
fn rng_rules() {
    eccdh_common::rng_rules::<Bp256r1, 65>(SecurityStrength::_128bit, SecurityStrength::_112bit);
}

/// The pairings' derived key is one output of the matched hash long here; the parameters name any.
#[test]
fn kdf_variants() {
    eccdh_common::kdf_variants::<Bp256r1, 65, 32, 32>(SecurityStrength::_128bit);
}
