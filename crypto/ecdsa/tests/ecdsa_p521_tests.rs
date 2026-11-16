//! ECDSA over P-521 with SHA512: the shared behavioural suite in `ecdsa_common`, instantiated for
//! the curve's conventional pairing.

mod ecdsa_common;

use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_ec::P521;
use bouncycastle_sha2::SHA512;

#[test]
fn framework_and_metadata() {
    ecdsa_common::framework_and_metadata::<P521, SHA512, 133, 66, 132>(
        "ECDSA-P521-SHA512",
        "ECDetDSA-P521-SHA512",
        SecurityStrength::_256bit,
    );
}

#[test]
fn two_signers_one_verifier() {
    ecdsa_common::two_signers_one_verifier::<P521, SHA512, 132>();
}

#[test]
fn key_loading() {
    ecdsa_common::key_loading::<P521, SHA512, 133, 66>();
}

#[test]
fn rng_rules() {
    ecdsa_common::rng_rules::<P521, SHA512, 133>(
        SecurityStrength::_256bit,
        SecurityStrength::_192bit,
    );
}

#[test]
fn signature_length_and_range() {
    ecdsa_common::signature_length_and_range::<P521, SHA512, 66, 132>();
}
