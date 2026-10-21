//! RFC known-answer vectors are loaded from bc-test-data, with no embedded fixture data.
use bouncycastle_core::traits::MAC;
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
        let tag = decode("tag");
        let id = case["id"].as_str().unwrap();
        // A published key, so a test may make as many keys from it as it likes.
        let generator = || key_from_bytes(&key).into_generator();
        // Under `r = 0` (A.3.1, A.3.2) the tag is `s` whatever the message, which the generic
        // suite's check that another message gets another tag cannot allow for.
        if key[..16] != [0; 16] {
            TestFrameworkMAC::new().test_one_time_mac(generator, &msg, &tag);
        }
        assert_eq!(generator().mac(&msg), tag, "RFC {id}");
        let mut out = [0xa5; 24];
        assert_eq!(generator().mac_out(&msg, &mut out).unwrap(), 16);
        assert_eq!(&out[..16], tag);
        assert_eq!(&out[16..], &[0; 8]);
        assert!(key_from_bytes(&key).into_verifier().verify(&msg, &tag));
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
