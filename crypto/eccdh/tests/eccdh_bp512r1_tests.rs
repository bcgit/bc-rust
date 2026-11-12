//! ECC CDH brainpoolP512r1: the shared behavioural suite in `eccdh_common`, instantiated for the curve.

mod eccdh_common;

use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_ec::Bp512r1;

#[test]
fn framework_and_metadata() {
    eccdh_common::framework_and_metadata::<Bp512r1, 129, 64, 64>(
        "ECC-CDH-brainpoolP512r1",
        SecurityStrength::_256bit,
    );
}

#[test]
fn key_loading() {
    eccdh_common::key_loading::<Bp512r1, 129, 64>();
}

#[test]
fn rng_rules() {
    eccdh_common::rng_rules::<Bp512r1, 129>(SecurityStrength::_256bit, SecurityStrength::_192bit);
}

/// The pairings' derived key is one output of the matched hash long here; the parameters name any.
#[test]
fn kdf_variants() {
    eccdh_common::kdf_variants::<Bp512r1, 129, 64, 64>(SecurityStrength::_256bit);
}
