//! ECDSA over P-256 with SHA256: the shared behavioural suite in `ecdsa_common`, instantiated for
//! the curve's conventional pairing.

mod ecdsa_common;

use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_ec::P256;
use bouncycastle_sha2::SHA256;

#[test]
fn framework_and_metadata() {
    ecdsa_common::framework_and_metadata::<P256, SHA256, 65, 32, 64>(
        "ECDSA-P256-SHA256",
        "ECDetDSA-P256-SHA256",
        SecurityStrength::_128bit,
    );
}

#[test]
fn two_signers_one_verifier() {
    ecdsa_common::two_signers_one_verifier::<P256, SHA256, 64>();
}

#[test]
fn key_loading() {
    ecdsa_common::key_loading::<P256, SHA256, 65, 32>();
}

#[test]
fn rng_rules() {
    ecdsa_common::rng_rules::<P256, SHA256, 65>(
        SecurityStrength::_128bit,
        SecurityStrength::_112bit,
    );
}

#[test]
fn signature_length_and_range() {
    ecdsa_common::signature_length_and_range::<P256, SHA256, 32, 64>();
}
