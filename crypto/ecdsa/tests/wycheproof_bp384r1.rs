//! Wycheproof ECDSA vectors for brainpoolP384r1, every hash the v1 files pair it with that this crate
//! implements (the SHAKE files need an XOF, which `ECDSA<C, H>` does not take); see
//! `wycheproof_common` for the files, the verdict rules and the DER handling.

mod wycheproof_common;

use bouncycastle_ec::Bp384r1;
use bouncycastle_sha2::SHA384;
use bouncycastle_sha3::SHA3_384;
use wycheproof_common::{Encoding, run};

#[test]
fn sha384_p1363() {
    run::<Bp384r1, SHA384, 97, 96>(
        "ecdsa_brainpoolP384r1_sha384_p1363_test.json",
        "brainpoolP384r1",
        "SHA-384",
        Encoding::P1363,
    );
}

#[test]
fn sha384_der() {
    run::<Bp384r1, SHA384, 97, 96>(
        "ecdsa_brainpoolP384r1_sha384_test.json",
        "brainpoolP384r1",
        "SHA-384",
        Encoding::Der,
    );
}

#[test]
fn sha3_384_der() {
    run::<Bp384r1, SHA3_384, 97, 96>(
        "ecdsa_brainpoolP384r1_sha3_384_test.json",
        "brainpoolP384r1",
        "SHA3-384",
        Encoding::Der,
    );
}
