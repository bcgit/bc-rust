//! Wycheproof ECDSA vectors for secp384r1, every hash the v1 files pair it with that this crate
//! implements (the SHAKE files need an XOF, which `ECDSA<C, H>` does not take); see
//! `wycheproof_common` for the files, the verdict rules and the DER handling.

mod wycheproof_common;

use bouncycastle_ec::P384;
use bouncycastle_sha2::{SHA256, SHA384, SHA512};
use bouncycastle_sha3::{SHA3_384, SHA3_512};
use wycheproof_common::{Encoding, run};

#[test]
fn sha256_der() {
    run::<P384, SHA256, 97, 96>(
        "ecdsa_secp384r1_sha256_test.json",
        "secp384r1",
        "SHA-256",
        Encoding::Der,
    );
}

#[test]
fn sha384_p1363() {
    run::<P384, SHA384, 97, 96>(
        "ecdsa_secp384r1_sha384_p1363_test.json",
        "secp384r1",
        "SHA-384",
        Encoding::P1363,
    );
}

#[test]
fn sha384_der() {
    run::<P384, SHA384, 97, 96>(
        "ecdsa_secp384r1_sha384_test.json",
        "secp384r1",
        "SHA-384",
        Encoding::Der,
    );
}

#[test]
fn sha512_p1363() {
    run::<P384, SHA512, 97, 96>(
        "ecdsa_secp384r1_sha512_p1363_test.json",
        "secp384r1",
        "SHA-512",
        Encoding::P1363,
    );
}

#[test]
fn sha512_der() {
    run::<P384, SHA512, 97, 96>(
        "ecdsa_secp384r1_sha512_test.json",
        "secp384r1",
        "SHA-512",
        Encoding::Der,
    );
}

#[test]
fn sha3_384_der() {
    run::<P384, SHA3_384, 97, 96>(
        "ecdsa_secp384r1_sha3_384_test.json",
        "secp384r1",
        "SHA3-384",
        Encoding::Der,
    );
}

#[test]
fn sha3_512_der() {
    run::<P384, SHA3_512, 97, 96>(
        "ecdsa_secp384r1_sha3_512_test.json",
        "secp384r1",
        "SHA3-512",
        Encoding::Der,
    );
}
