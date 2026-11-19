//! Wycheproof ECDSA vectors for brainpoolP256r1, every hash the v1 files pair it with that this crate
//! implements (the SHAKE files need an XOF, which `ECDSA<C, H>` does not take); see
//! `wycheproof_common` for the files, the verdict rules and the DER handling.

mod wycheproof_common;

use bouncycastle_ec::Bp256r1;
use bouncycastle_sha2::SHA256;
use bouncycastle_sha3::SHA3_256;
use wycheproof_common::{Encoding, run};

#[test]
fn sha256_p1363() {
    run::<Bp256r1, SHA256, 65, 64>(
        "ecdsa_brainpoolP256r1_sha256_p1363_test.json",
        "brainpoolP256r1",
        "SHA-256",
        Encoding::P1363,
    );
}

#[test]
fn sha256_der() {
    run::<Bp256r1, SHA256, 65, 64>(
        "ecdsa_brainpoolP256r1_sha256_test.json",
        "brainpoolP256r1",
        "SHA-256",
        Encoding::Der,
    );
}

#[test]
fn sha3_256_der() {
    run::<Bp256r1, SHA3_256, 65, 64>(
        "ecdsa_brainpoolP256r1_sha3_256_test.json",
        "brainpoolP256r1",
        "SHA3-256",
        Encoding::Der,
    );
}
