//! NIST CAVP legacy vectors for P-256 under every SHA-2 the files pair it with, from
//! `bc-test-data/crypto/cavp/`: `ECDSA_SigVer.rsp` (verification, positive and negative),
//! `ECDSA_SigGen.txt` (signing with the per-message secret `k` given, so signing output itself
//! is checked), `ECDSA_PKV.rsp` (public-key validation) and `ECDSA_KeyPair.rsp` (key-pair
//! consistency). `ECDSA_SigGen.rsp`, the response-file form without `d` or `k`, is not read: as
//! verify-only data it duplicates `SigVer`'s `Result = P` cases; the `SHA-1` sections and the
//! `K-*`/`B-*` binary-field curves are not read either. See `cavp_common` for the parser, the
//! runners, and why a missing `bc-test-data` checkout fails these tests rather than skipping.

mod cavp_common;

use bouncycastle_ec::P256;
use bouncycastle_sha2::{SHA224, SHA256, SHA384, SHA512};

const PK_LEN: usize = 65;
const SK_LEN: usize = 32;
const SIG_LEN: usize = 64;

#[test]
fn pkv() {
    cavp_common::pkv::<P256, PK_LEN>("P-256");
}

#[test]
fn keypair() {
    cavp_common::keypair::<P256, SHA256, PK_LEN, SK_LEN, SIG_LEN>("P-256");
}

#[test]
fn sigver_sha224() {
    cavp_common::sigver::<P256, SHA224, PK_LEN, SIG_LEN>("P-256,SHA-224");
}

#[test]
fn siggen_sha224() {
    cavp_common::siggen::<P256, SHA224, PK_LEN, SK_LEN, SIG_LEN>("P-256,SHA-224");
}

#[test]
fn sigver_sha256() {
    cavp_common::sigver::<P256, SHA256, PK_LEN, SIG_LEN>("P-256,SHA-256");
}

#[test]
fn siggen_sha256() {
    cavp_common::siggen::<P256, SHA256, PK_LEN, SK_LEN, SIG_LEN>("P-256,SHA-256");
}

#[test]
fn sigver_sha384() {
    cavp_common::sigver::<P256, SHA384, PK_LEN, SIG_LEN>("P-256,SHA-384");
}

#[test]
fn siggen_sha384() {
    cavp_common::siggen::<P256, SHA384, PK_LEN, SK_LEN, SIG_LEN>("P-256,SHA-384");
}

#[test]
fn sigver_sha512() {
    cavp_common::sigver::<P256, SHA512, PK_LEN, SIG_LEN>("P-256,SHA-512");
}

#[test]
fn siggen_sha512() {
    cavp_common::siggen::<P256, SHA512, PK_LEN, SK_LEN, SIG_LEN>("P-256,SHA-512");
}
