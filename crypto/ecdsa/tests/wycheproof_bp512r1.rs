//! Wycheproof ECDSA vectors for brainpoolP512r1, every hash the v1 files pair it with that this crate
//! implements (the SHAKE files need an XOF, which `ECDSA<C, H>` does not take); see
//! `wycheproof_common` for the files, the verdict rules and the DER handling.

mod wycheproof_common;

use bouncycastle_ec::Bp512r1;
use bouncycastle_sha2::SHA512;
use bouncycastle_sha3::SHA3_512;
use wycheproof_common::{Encoding, run};

#[test]
fn sha512_p1363() {
    run::<Bp512r1, SHA512, 129, 128>(
        "ecdsa_brainpoolP512r1_sha512_p1363_test.json",
        "brainpoolP512r1",
        "SHA-512",
        Encoding::P1363,
    );
}

#[test]
fn sha512_der() {
    run::<Bp512r1, SHA512, 129, 128>(
        "ecdsa_brainpoolP512r1_sha512_test.json",
        "brainpoolP512r1",
        "SHA-512",
        Encoding::Der,
    );
}

#[test]
fn sha3_512_der() {
    run::<Bp512r1, SHA3_512, 129, 128>(
        "ecdsa_brainpoolP512r1_sha3_512_test.json",
        "brainpoolP512r1",
        "SHA3-512",
        Encoding::Der,
    );
}
