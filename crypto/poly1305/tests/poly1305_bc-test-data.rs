//! RFC known-answer vectors are loaded from bc-test-data, with no embedded fixture data.
use bouncycastle_core::traits::{MACGenerator, MACVerifier};
use bouncycastle_core_test_framework::mac::TestFrameworkMAC;
use bouncycastle_core_test_framework::test_data_loaders::bc_test_data_json;
use bouncycastle_poly1305::hazmat::key_from_bytes;

#[test]
fn rfc8439_poly1305_including_reduction_edge_cases() {
    let Some(document) = bc_test_data_json("crypto/rfc8439", "poly1305.json") else { return };
    let cases = document["tests"].as_array().unwrap();
    assert_eq!(cases.len(), 12);
    for case in cases {
        let decode = |field: &str| bouncycastle_hex::decode(case[field].as_str().unwrap()).unwrap();
        let key: [u8; 32] = decode("key").try_into().unwrap();
        let msg = decode("msg");
        let tag: [u8; 16] = decode("tag").try_into().unwrap();
        let id = case["id"].as_str().unwrap();
        // A published key, so a test may make as many keys from it as it likes.
        let generator = || key_from_bytes(&key).into_generator();
        let verifier = || key_from_bytes(&key).into_verifier();
        // Under `r = 0` (A.3.1, A.3.2) the tag is `s` whatever the message, which the generic
        // suite's check that another message gets another tag cannot allow for.
        if key[..16] != [0; 16] {
            TestFrameworkMAC::new().test_one_time_mac(generator, verifier, &msg, &tag);
        }
        let mut mac = generator();
        mac.do_update(&msg);
        assert_eq!(mac.do_final(), tag, "RFC {id}");
        let mut mac = verifier();
        mac.do_update(&msg);
        assert_eq!(mac.do_verify_final(&tag), Ok(()), "RFC {id}");
        // Every split of each published message exercises full and partial buffered blocks.
        for split in 0..=msg.len() {
            let mut mac = generator();
            mac.do_update(&msg[..split]);
            mac.do_update(&[]);
            mac.do_update(&msg[split..]);
            assert_eq!(mac.do_final(), tag, "RFC {id}, split {split}");
        }
    }
    println!("RFC 8439 Poly1305: {} vectors passed", cases.len());
}
