//! ECDSA over brainpoolP512r1 with SHA512: the shared behavioural suite in `ecdsa_common`, instantiated for
//! the curve's conventional pairing.

mod ecdsa_common;

use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_ec::Bp512r1;
use bouncycastle_sha2::SHA512;

#[test]
fn framework_and_metadata() {
    ecdsa_common::framework_and_metadata::<Bp512r1, SHA512, 129, 64, 128>(
        "ECDSA-brainpoolP512r1-SHA512",
        "ECDetDSA-brainpoolP512r1-SHA512",
        SecurityStrength::_256bit,
    );
}

#[test]
fn two_signers_one_verifier() {
    ecdsa_common::two_signers_one_verifier::<Bp512r1, SHA512, 128>();
}

#[test]
fn key_loading() {
    ecdsa_common::key_loading::<Bp512r1, SHA512, 129, 64>();
}

#[test]
fn rng_rules() {
    ecdsa_common::rng_rules::<Bp512r1, SHA512, 129>(
        SecurityStrength::_256bit,
        SecurityStrength::_192bit,
    );
}

#[test]
fn signature_length_and_range() {
    ecdsa_common::signature_length_and_range::<Bp512r1, SHA512, 64, 128>();
}
