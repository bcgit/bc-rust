//! RFC known-answer vectors are loaded from bc-test-data, with no embedded fixture data.
use bouncycastle_core::{
    key_material::{KeyMaterial, KeyType},
    traits::MAC,
};
use bouncycastle_core_test_framework::external_vectors::{ExternalVectors, external_vector_file};
use bouncycastle_core_test_framework::mac::TestFrameworkMAC;
use bouncycastle_poly1305::Poly1305;
use serde_json::Value;
use std::fs;

#[test]
fn rfc8439_poly1305_including_reduction_edge_cases() {
    let Some(path) =
        external_vector_file(ExternalVectors::BcTestData, "crypto/rfc8439/poly1305.json")
    else {
        return;
    };
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
        TestFrameworkMAC::new().test_mac_fixed_output::<Poly1305>(&key, &msg, &tag);
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
