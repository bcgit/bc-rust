//! ECC CDH P-521: the shared behavioural suite in `eccdh_common`, instantiated for the curve.

mod eccdh_common;

use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_ec::P521;

#[test]
fn framework_and_metadata() {
    eccdh_common::framework_and_metadata::<P521, 133, 66, 66>(
        "ECC-CDH-P521",
        SecurityStrength::_256bit,
    );
}

#[test]
fn key_loading() {
    eccdh_common::key_loading::<P521, 133, 66>();
}

#[test]
fn rng_rules() {
    eccdh_common::rng_rules::<P521, 133>(SecurityStrength::_256bit, SecurityStrength::_192bit);
}

/// The pairings' derived key is one output of the matched hash long here; the parameters name any.
#[test]
fn kdf_variants() {
    eccdh_common::kdf_variants::<P521, 133, 66, 64>(SecurityStrength::_256bit);
}
