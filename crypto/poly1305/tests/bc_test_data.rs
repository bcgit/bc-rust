//! RFC known-answer vectors are loaded from bc-test-data, with no embedded fixture data.
//! The shared MAC framework assumes truncatable tags and variable-length keys; Poly1305
//! instead enforces a 32-byte key and full 16-byte tag, covered in poly1305_tests.rs.
use bouncycastle_core::{
    key_material::{KeyMaterial, KeyType},
    traits::MAC,
};
use bouncycastle_poly1305::Poly1305;
use serde_json::Value;
use std::{fs, path::PathBuf};

#[test]
fn rfc8439_poly1305_including_reduction_edge_cases() {
    let override_root = std::env::var_os("BC_TEST_DATA");
    let root = override_root
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../bc-test-data"));
    let path = root.join("crypto/rfc8439/poly1305.json");
    if !path.exists() && override_root.is_none() {
        eprintln!("WARNING: {} not found; RFC 8439 Poly1305 vectors skipped", path.display());
        return;
    }
    let document: Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("RFC vector file")).unwrap();
    let cases = document["tests"].as_array().unwrap();
    assert_eq!(cases.len(), 12);
    for case in cases {
        let decode = |field: &str| bouncycastle_hex::decode(case[field].as_str().unwrap()).unwrap();
        let key = KeyMaterial::<32>::from_bytes_as_type(&decode("key"), KeyType::MACKey).unwrap();
        let msg = decode("msg");
        let tag = decode("tag");
        let id = case["id"].as_str().unwrap();
        assert_eq!(Poly1305::new_allow_weak_key(&key).unwrap().mac(&msg), tag, "RFC {id}");
        let mut out = [0xa5; 24];
        assert_eq!(
            Poly1305::new_allow_weak_key(&key).unwrap().mac_out(&msg, &mut out).unwrap(),
            16
        );
        assert_eq!(&out[..16], tag);
        assert_eq!(&out[16..], &[0; 8]);
        assert!(Poly1305::new_allow_weak_key(&key).unwrap().verify(&msg, &tag));
        // Every split of each published message exercises full and partial buffered blocks.
        for split in 0..=msg.len() {
            let mut mac = Poly1305::new_allow_weak_key(&key).unwrap();
            mac.do_update(&msg[..split]);
            mac.do_update(&[]);
            mac.do_update(&msg[split..]);
            assert_eq!(mac.do_final(), tag, "RFC {id}, split {split}");
        }
    }
    println!("RFC 8439 Poly1305: {} vectors passed", cases.len());
}
