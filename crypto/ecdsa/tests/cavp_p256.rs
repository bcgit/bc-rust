//! NIST CAVP legacy vectors for P-256/SHA-256, from `bc-test-data/crypto/cavp/`: `ECDSA_SigVer.rsp`
//! (signature verification, positive and negative), `ECDSA_PKV.rsp` (public key validation),
//! `ECDSA_KeyPair.rsp` (private/public key-pair consistency), and `ECDSA_SigGen.txt` (signature
//! generation with the per-message secret `k` given, so signing output itself is checked -- see
//! `cavp_siggen`). `ECDSA_SigGen.rsp`, the response-file form of the same vectors without `d` or
//! `k`, is not read: as verify-only data it duplicates `SigVer`'s `Result = P` cases.
//!
//! See `cavp_common`'s docs for the parser, and for why a missing `bc-test-data` checkout fails
//! these tests rather than skipping them. `K-*`/`B-*` (binary-field) curve sections in these
//! files are not read: this crate implements prime-field curves only.
//!
//! `ECDSA_KeyPair.rsp` gives `(d, Qx, Qy)` triples with no direct "derive the public key from a
//! private key" entry point in this crate's public API to check `[d]G == Q` against. Rather than
//! reach into `bouncycastle_ec` directly (which would test that crate's multiplier, not anything
//! `bouncycastle-ecdsa` itself does), each triple is checked through the public API instead: sign a
//! fixed message with the private key built from `d`, then verify that signature against the
//! public key built from `(Qx, Qy)`. Verification's own math (`R' = [u]G + [v]Q`) only succeeds if
//! `Q` really is `[d]G`, so this is a full, if indirect, consistency check.

mod cavp_common;

use bouncycastle_core::traits::{
    SignaturePrivateKey, SignaturePublicKey, SignatureVerifier, Signer,
};
use bouncycastle_ecdsa::ecdsa_p256::{ECDSAP256, SIG_LEN};
use bouncycastle_ecdsa::keys::{ECDSAP256PrivateKey, ECDSAP256PublicKey};
use cavp_common::{
    FixedBytesRng, Record, decrement_be, get_test_data, hex_bytes, hex_field, parse_records,
    result_is_pass,
};

const FIELD_WIDTH: usize = 32;
const SECTION: &str = "P-256,SHA-256";
const KEY_SECTION: &str = "P-256";

/// SEC 1 §2.3.3 case 3 (`04 || X || Y`), built dynamically rather than into a fixed-size array:
/// `ECDSA_PKV.rsp`'s "out of range" vectors deliberately supply a coordinate wider than
/// [`FIELD_WIDTH`] (see `hex_field`'s docs), and this must reproduce that oversized encoding
/// rather than truncate it, so the decoder's own length check is what rejects it.
fn uncompressed_pk(qx: &[u8], qy: &[u8]) -> Vec<u8> {
    let mut out = vec![0x04u8];
    out.extend_from_slice(qx);
    out.extend_from_slice(qy);
    out
}

fn signature_bytes(r: &[u8], s: &[u8]) -> [u8; SIG_LEN] {
    let mut out = [0u8; SIG_LEN];
    out[..FIELD_WIDTH].copy_from_slice(r);
    out[FIELD_WIDTH..].copy_from_slice(s);
    out
}

#[test]
fn cavp_sigver() {
    let content = get_test_data("ECDSA_SigVer.rsp");
    let records: Vec<Record> = parse_records(&content)
        .into_iter()
        .filter(|r| r.section == SECTION && r.fields.contains_key("Result"))
        .collect();
    assert!(!records.is_empty(), "no P-256,SHA-256 SigVer records found");

    for record in &records {
        let msg = hex_bytes(&record.fields, "Msg");
        let qx = hex_field(&record.fields, "Qx", FIELD_WIDTH);
        let qy = hex_field(&record.fields, "Qy", FIELD_WIDTH);
        let r = hex_field(&record.fields, "R", FIELD_WIDTH);
        let s = hex_field(&record.fields, "S", FIELD_WIDTH);
        let expect_pass = result_is_pass(&record.fields);

        // A malformed/out-of-range public key is itself grounds for the CAVP vector to be a
        // failure case; from_bytes rejecting it satisfies that without ever reaching verify.
        let pk = match ECDSAP256PublicKey::from_bytes(&uncompressed_pk(&qx, &qy)) {
            Ok(pk) => pk,
            Err(_) => {
                assert!(!expect_pass, "public key was rejected but this vector expects Result = P");
                continue;
            }
        };
        let sig = signature_bytes(&r, &s);
        let result = ECDSAP256::verify(&pk, &msg, None, &sig);
        assert_eq!(result.is_ok(), expect_pass, "mismatch for record {:?}", record.fields);
    }
}

#[test]
fn cavp_pkv() {
    let content = get_test_data("ECDSA_PKV.rsp");
    let records: Vec<Record> = parse_records(&content)
        .into_iter()
        .filter(|r| r.section == KEY_SECTION && r.fields.contains_key("Result"))
        .collect();
    assert!(!records.is_empty(), "no P-256 PKV records found");

    for record in &records {
        let qx = hex_field(&record.fields, "Qx", FIELD_WIDTH);
        let qy = hex_field(&record.fields, "Qy", FIELD_WIDTH);
        let expect_pass = result_is_pass(&record.fields);

        let result = ECDSAP256PublicKey::from_bytes(&uncompressed_pk(&qx, &qy));
        assert_eq!(result.is_ok(), expect_pass, "mismatch for record {:?}", record.fields);
    }
}

#[test]
fn cavp_keypair_consistency() {
    let content = get_test_data("ECDSA_KeyPair.rsp");
    let records: Vec<Record> = parse_records(&content)
        .into_iter()
        .filter(|r| r.section == KEY_SECTION && r.fields.contains_key("d"))
        .collect();
    assert!(!records.is_empty(), "no P-256 KeyPair records found");

    let msg = b"CAVP KeyPair (d, Q) consistency check";
    for record in &records {
        let d = hex_field(&record.fields, "d", FIELD_WIDTH);
        let qx = hex_field(&record.fields, "Qx", FIELD_WIDTH);
        let qy = hex_field(&record.fields, "Qy", FIELD_WIDTH);

        let sk = ECDSAP256PrivateKey::from_bytes(&d).expect("CAVP d must be a valid private key");
        let pk = ECDSAP256PublicKey::from_bytes(&uncompressed_pk(&qx, &qy))
            .expect("CAVP Q must be a valid public key");

        let sig = ECDSAP256::sign(&sk, msg, None).expect("signing with a valid key must succeed");
        ECDSAP256::verify(&pk, msg, None, &sig)
            .expect("Q must be [d]G for this (d, Q) pair to verify");
    }
}

/// `ECDSA_SigGen.txt` -- NIST's `SigGen.txt` from `186-4ecdsatestvectors.zip`, the form of the
/// SigGen vectors that carries `d` and the per-message secret `k`, which the response-file form
/// `ECDSA_SigGen.rsp` omits. `k` is injected through [`FixedBytesRng`] and `sign_randomized`
/// (see that type's docs for why an RNG returning `k - 1` yields exactly `k`), so this pins
/// signing output against NIST's values through the public API. RFC 6979's own vectors pin the
/// deterministic path; this is the only NIST check on the randomised one.
#[test]
fn cavp_siggen() {
    let content = get_test_data("ECDSA_SigGen.txt");
    let records: Vec<Record> = parse_records(&content)
        .into_iter()
        .filter(|r| r.section == SECTION && r.fields.contains_key("k"))
        .collect();
    assert!(!records.is_empty(), "no P-256 SigGen records with k found");

    for record in &records {
        let msg = hex_bytes(&record.fields, "Msg");
        let d = hex_field(&record.fields, "d", FIELD_WIDTH);
        let qx = hex_field(&record.fields, "Qx", FIELD_WIDTH);
        let qy = hex_field(&record.fields, "Qy", FIELD_WIDTH);
        let mut k_minus_1 = hex_field(&record.fields, "k", FIELD_WIDTH);
        decrement_be(&mut k_minus_1);
        let r = hex_field(&record.fields, "R", FIELD_WIDTH);
        let s = hex_field(&record.fields, "S", FIELD_WIDTH);

        let sk = ECDSAP256PrivateKey::from_bytes(&d).expect("CAVP d must be a valid private key");
        let pk = ECDSAP256PublicKey::from_bytes(&uncompressed_pk(&qx, &qy))
            .expect("CAVP Q must be a valid public key");

        let mut rng = FixedBytesRng::new(k_minus_1);
        let sig = ECDSAP256::sign_randomized(&sk, &msg, &mut rng)
            .expect("signing with a valid key and k must succeed");
        assert_eq!(sig, signature_bytes(&r, &s), "mismatch for record {:?}", record.fields);
        ECDSAP256::verify(&pk, &msg, None, &sig).expect("NIST's own signature must verify");
    }
}
