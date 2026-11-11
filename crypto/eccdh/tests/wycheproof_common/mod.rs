//! Runner for the Wycheproof ECDH test sets (`../wycheproof/testvectors_v1/ecdh_*.json`, the
//! path convention of `bouncycastle-ecdsa`'s suites), generic over a curve's key types. A missing
//! clone fails the test rather than skipping: these are the adversarial checks on the decoder
//! (off-curve, wrong-curve and malformed points) and the multiplier's edge cases.
//!
//! Two encodings are read. `ecpoint` files carry the peer key as a raw SEC 1 point. `asn` files
//! carry it as an X.509 `SubjectPublicKeyInfo`, which this crate does not parse; the runner takes
//! the point out of it with a strict DER walk (`SEQUENCE { AlgorithmIdentifier, BIT STRING }`,
//! minimal lengths, no trailing bytes), requires the `AlgorithmIdentifier` to be byte-identical
//! to the curve's own from the file's first `Normal` vector, and treats anything else as a key
//! rejected at decode. Verdicts: `valid` must decode and agree to `shared`; `invalid` must fail
//! at decode or at `agree`; `acceptable` may do either, but an agreement must equal `shared`,
//! and a compressed point (flag `CompressedPoint`, the one acceptable case the decoder accepts)
//! must agree. The number that agreed is pinned per file, so a decoder that starts rejecting
//! what it accepted, or the DER walk masking a vector, is noticed.

#![allow(dead_code)]

use bouncycastle_core::agreement_key::AgreementKey;
use bouncycastle_core::key_material::KeyMaterialTrait;
use bouncycastle_core::traits::{KeyAgreementPrivateKey, KeyAgreementPublicKey};
use bouncycastle_hex::decode as hex_decode;
use serde_json::Value;
use std::fs;
use std::path::Path;

const TEST_DATA_PATH_RELATIVE: &str = "../../../wycheproof/testvectors_v1";
const TEST_DATA_PATH: &str = "../wycheproof/testvectors_v1";

fn get_test_data(filename: &str) -> String {
    for dir in [TEST_DATA_PATH_RELATIVE, TEST_DATA_PATH] {
        let path = format!("{dir}/{filename}");
        if Path::new(&path).exists() {
            return fs::read_to_string(path).unwrap();
        }
    }
    panic!(
        "wycheproof not found (looked for {filename} in {TEST_DATA_PATH_RELATIVE:?} and \
         {TEST_DATA_PATH:?}); these suites require it rather than skipping"
    );
}

/// One DER TLV at the front of `bytes`: `(tag, content, rest)`, with the length minimal as DER
/// requires (short form below 128, else the shortest long form), or `None`.
fn tlv(bytes: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *bytes.first()?;
    let first = *bytes.get(1)?;
    let (len, header) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || bytes.len() < 2 + n || bytes[2] == 0 {
            return None;
        }
        let len = bytes[2..2 + n].iter().fold(0usize, |acc, b| (acc << 8) | *b as usize);
        if len < 0x80 {
            return None;
        }
        (len, 2 + n)
    };
    let content = bytes.get(header..header + len)?;
    Some((tag, content, &bytes[header + len..]))
}

/// The SEC 1 point inside a `SubjectPublicKeyInfo`, with its `AlgorithmIdentifier` TLV bytes.
fn spki_point(spki: &[u8]) -> Option<(&[u8], &[u8])> {
    let (0x30, seq, []) = tlv(spki)? else { return None };
    let (0x30, _alg, rest) = tlv(seq)? else { return None };
    let alg_tlv = &seq[..seq.len() - rest.len()];
    let (0x03, bits, []) = tlv(rest)? else { return None };
    let (&0, point) = bits.split_first()? else { return None };
    Some((point, alg_tlv))
}

/// A Wycheproof private key, a hex integer of any width, as the curve's fixed-width big-endian
/// encoding; `None` if it is wider than `SK_LEN` bytes once leading zeros are stripped.
fn private_key_bytes<const SK_LEN: usize>(hex: &str) -> Option<[u8; SK_LEN]> {
    let hex = if hex.len() % 2 == 1 { format!("0{hex}") } else { hex.to_string() };
    let bytes = hex_decode(&hex).unwrap();
    let stripped: &[u8] = {
        let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
        &bytes[first..]
    };
    if stripped.len() > SK_LEN {
        return None;
    }
    let mut out = [0u8; SK_LEN];
    out[SK_LEN - stripped.len()..].copy_from_slice(stripped);
    Some(out)
}

/// Runs one file. `expected` is the file's `numberOfTests`, pinned so a changed clone is noticed,
/// and `expected_agreed` how many vectors must reach the library and agree: the valid ones and
/// the compressed point.
pub fn run<PK, SK, const PK_LEN: usize, const SK_LEN: usize, const SS_LEN: usize>(
    filename: &str,
    curve: &str,
    expected: usize,
    expected_agreed: usize,
) where
    PK: KeyAgreementPublicKey<PK_LEN>,
    SK: KeyAgreementPrivateKey<SK_LEN> + AgreementKey<(), SS_LEN, PublicKey = PK>,
{
    let doc: Value = serde_json::from_str(&get_test_data(filename)).unwrap();
    assert_eq!(doc["numberOfTests"].as_u64().unwrap() as usize, expected, "{filename}");
    let groups = doc["testGroups"].as_array().unwrap();

    // The curve's AlgorithmIdentifier, from the first Normal vector of an `asn` file.
    let mut expected_alg: Option<Vec<u8>> = None;
    for group in groups {
        if group["encoding"] != "asn" {
            continue;
        }
        for test in group["tests"].as_array().unwrap() {
            if test["result"] == "valid" && test["flags"] == serde_json::json!(["Normal"]) {
                let spki = hex_decode(test["public"].as_str().unwrap()).unwrap();
                expected_alg = Some(spki_point(&spki).expect("a Normal SPKI parses").1.to_vec());
                break;
            }
        }
        if expected_alg.is_some() {
            break;
        }
    }

    let (mut valid, mut invalid, mut acceptable, mut agreed) = (0usize, 0usize, 0usize, 0usize);
    for group in groups {
        assert_eq!(group["curve"], curve, "{filename}");
        let encoding = group["encoding"].as_str().unwrap();
        for test in group["tests"].as_array().unwrap() {
            let tc_id = test["tcId"].as_u64().unwrap();
            let flags = &test["flags"];
            let result = test["result"].as_str().unwrap();
            match result {
                "valid" => valid += 1,
                "invalid" => invalid += 1,
                "acceptable" => acceptable += 1,
                other => panic!("tcId {tc_id}: unknown result {other}"),
            }

            let public = hex_decode(test["public"].as_str().unwrap()).unwrap();
            let point: Option<&[u8]> = match encoding {
                "ecpoint" => Some(&public),
                "asn" => spki_point(&public)
                    .filter(|(_, alg)| Some(alg.to_vec()) == expected_alg)
                    .map(|(point, _)| point),
                other => panic!("{filename}: unknown encoding {other}"),
            };
            let shared = hex_decode(test["shared"].as_str().unwrap()).unwrap();

            let z = point.and_then(|point| PK::from_bytes(point).ok()).and_then(|pk| {
                let sk = SK::from_bytes(&private_key_bytes::<SK_LEN>(
                    test["private"].as_str().unwrap(),
                )?)
                .ok()?;
                sk.agree(&pk, ()).ok()
            });

            match (result, z) {
                ("valid", None) => panic!(
                    "tcId {tc_id}: a valid vector was rejected; flags {flags}, comment {:?}",
                    test["comment"]
                ),
                ("invalid", Some(_)) => panic!(
                    "tcId {tc_id}: an invalid vector agreed; flags {flags}, comment {:?}",
                    test["comment"]
                ),
                (_, Some(z)) => {
                    agreed += 1;
                    assert_eq!(
                        z.ref_to_bytes(),
                        shared.as_slice(),
                        "tcId {tc_id}: Z differs; flags {flags}, comment {:?}",
                        test["comment"]
                    );
                }
                ("acceptable", None) if has_flag(flags, "CompressedPoint") => panic!(
                    "tcId {tc_id}: a compressed point was rejected; flags {flags}, comment {:?}",
                    test["comment"]
                ),
                (_, None) => {}
            }
        }
    }
    println!(
        "{filename}: {expected} vectors ({valid} valid, {acceptable} acceptable, {invalid} invalid), {agreed} agreed"
    );
    assert_eq!(valid + invalid + acceptable, expected);
    assert_eq!(agreed, expected_agreed, "{filename}: vectors that reached the library and agreed");
}

fn has_flag(flags: &Value, flag: &str) -> bool {
    flags.as_array().is_some_and(|flags| flags.iter().any(|f| f == flag))
}
