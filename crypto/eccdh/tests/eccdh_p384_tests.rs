//! ECC CDH P-384: the shared behavioural suite in `eccdh_common`, instantiated for the curve.

mod eccdh_common;

use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_ec::P384;

#[test]
fn framework_and_metadata() {
    eccdh_common::framework_and_metadata::<P384, 97, 48, 48>(
        "ECC-CDH-P384",
        SecurityStrength::_192bit,
    );
}

#[test]
fn key_loading() {
    eccdh_common::key_loading::<P384, 97, 48>();
}

#[test]
fn rng_rules() {
    eccdh_common::rng_rules::<P384, 97>(SecurityStrength::_192bit, SecurityStrength::_128bit);
}

/// The pairings' derived key is one output of the matched hash long here; the parameters name any.
#[test]
fn kdf_variants() {
    eccdh_common::kdf_variants::<P384, 97, 48, 48>(SecurityStrength::_192bit);
}
