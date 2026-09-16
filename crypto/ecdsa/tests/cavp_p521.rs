//! NIST CAVP legacy vectors for P-521/SHA-512, from `bc-test-data/crypto/cavp/`. Identical in shape
//! to `cavp_p256.rs` -- see that file's docs for the full reasoning (why `ECDSA_SigGen.rsp` isn't
//! read separately, and how `ECDSA_KeyPair.rsp`'s `(d, Q)` pairs are checked through the public API
//! rather than by reaching into `bouncycastle_ec` directly) -- with P-521's types and field width
//! substituted. `FIELD_WIDTH = 66` is `ceil(521 / 8)`: `hex_field`'s odd-hex-digit padding matters
//! most here, since P-521's top byte only ever has 1 significant bit.

mod cavp_common;

use bouncycastle_core::traits::{
    SignaturePrivateKey, SignaturePublicKey, SignatureVerifier, Signer,
};
use bouncycastle_ecdsa::ecdsa_p521::{ECDSAP521, SIG_LEN};
use bouncycastle_ecdsa::keys_p521::{ECDSAP521PrivateKey, ECDSAP521PublicKey};
use cavp_common::{Record, get_test_data, hex_bytes, hex_field, parse_records, result_is_pass};

const FIELD_WIDTH: usize = 66;
const SECTION: &str = "P-521,SHA-512";
const KEY_SECTION: &str = "P-521";

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
    let Some(content) = get_test_data("ECDSA_SigVer.rsp") else { return };
    let records: Vec<Record> = parse_records(&content)
        .into_iter()
        .filter(|r| r.section == SECTION && r.fields.contains_key("Result"))
        .collect();
    assert!(!records.is_empty(), "no P-521,SHA-512 SigVer records found");

    for record in &records {
        let msg = hex_bytes(&record.fields, "Msg");
        let qx = hex_field(&record.fields, "Qx", FIELD_WIDTH);
        let qy = hex_field(&record.fields, "Qy", FIELD_WIDTH);
        let r = hex_field(&record.fields, "R", FIELD_WIDTH);
        let s = hex_field(&record.fields, "S", FIELD_WIDTH);
        let expect_pass = result_is_pass(&record.fields);

        let pk = match ECDSAP521PublicKey::from_bytes(&uncompressed_pk(&qx, &qy)) {
            Ok(pk) => pk,
            Err(_) => {
                assert!(!expect_pass, "public key was rejected but this vector expects Result = P");
                continue;
            }
        };
        let sig = signature_bytes(&r, &s);
        let result = ECDSAP521::verify(&pk, &msg, None, &sig);
        assert_eq!(result.is_ok(), expect_pass, "mismatch for record {:?}", record.fields);
    }
}

#[test]
fn cavp_pkv() {
    let Some(content) = get_test_data("ECDSA_PKV.rsp") else { return };
    let records: Vec<Record> = parse_records(&content)
        .into_iter()
        .filter(|r| r.section == KEY_SECTION && r.fields.contains_key("Result"))
        .collect();
    assert!(!records.is_empty(), "no P-521 PKV records found");

    for record in &records {
        let qx = hex_field(&record.fields, "Qx", FIELD_WIDTH);
        let qy = hex_field(&record.fields, "Qy", FIELD_WIDTH);
        let expect_pass = result_is_pass(&record.fields);

        let result = ECDSAP521PublicKey::from_bytes(&uncompressed_pk(&qx, &qy));
        assert_eq!(result.is_ok(), expect_pass, "mismatch for record {:?}", record.fields);
    }
}

#[test]
fn cavp_keypair_consistency() {
    let Some(content) = get_test_data("ECDSA_KeyPair.rsp") else { return };
    let records: Vec<Record> = parse_records(&content)
        .into_iter()
        .filter(|r| r.section == KEY_SECTION && r.fields.contains_key("d"))
        .collect();
    assert!(!records.is_empty(), "no P-521 KeyPair records found");

    let msg = b"CAVP KeyPair (d, Q) consistency check";
    for record in &records {
        let d = hex_field(&record.fields, "d", FIELD_WIDTH);
        let qx = hex_field(&record.fields, "Qx", FIELD_WIDTH);
        let qy = hex_field(&record.fields, "Qy", FIELD_WIDTH);

        let sk = ECDSAP521PrivateKey::from_bytes(&d).expect("CAVP d must be a valid private key");
        let pk = ECDSAP521PublicKey::from_bytes(&uncompressed_pk(&qx, &qy))
            .expect("CAVP Q must be a valid public key");

        let sig = ECDSAP521::sign(&sk, msg, None).expect("signing with a valid key must succeed");
        ECDSAP521::verify(&pk, msg, None, &sig)
            .expect("Q must be [d]G for this (d, Q) pair to verify");
    }
}
