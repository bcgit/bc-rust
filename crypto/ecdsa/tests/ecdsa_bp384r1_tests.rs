//! ECDSA over brainpoolP384r1 with SHA384: the shared behavioural suite in `ecdsa_common`, instantiated for
//! the curve's conventional pairing.

mod ecdsa_common;

use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_ec::Bp384r1;
use bouncycastle_sha2::SHA384;

#[test]
fn framework_and_metadata() {
    ecdsa_common::framework_and_metadata::<Bp384r1, SHA384, 97, 48, 96>(
        "ECDSA-brainpoolP384r1-SHA384",
        "ECDetDSA-brainpoolP384r1-SHA384",
        SecurityStrength::_192bit,
    );
}

#[test]
fn two_signers_one_verifier() {
    ecdsa_common::two_signers_one_verifier::<Bp384r1, SHA384, 96>();
}

#[test]
fn key_loading() {
    ecdsa_common::key_loading::<Bp384r1, SHA384, 97, 48>();
}

#[test]
fn rng_rules() {
    ecdsa_common::rng_rules::<Bp384r1, SHA384, 97>(
        SecurityStrength::_192bit,
        SecurityStrength::_128bit,
    );
}

#[test]
fn signature_length_and_range() {
    ecdsa_common::signature_length_and_range::<Bp384r1, SHA384, 48, 96>();
}
