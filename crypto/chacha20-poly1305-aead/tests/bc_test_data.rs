//! RFC fixtures live at bc-test-data/crypto/rfc8439. BC_TEST_DATA overrides its root.
mod common;

#[test]
fn rfc8439_aead_encryption_and_decryption() {
    let Some(doc) =
        common::load("BC_TEST_DATA", "bc-test-data", "crypto/rfc8439/chacha20-poly1305-aead.json")
    else {
        return;
    };
    let cases = doc["tests"].as_array().unwrap();
    assert_eq!(cases.len(), 2);
    for case in cases {
        let key = common::key(&common::decode(case, "key"));
        let nonce: [u8; 12] = common::decode(case, "nonce").try_into().unwrap();
        let tag: [u8; 16] = common::decode(case, "tag").try_into().unwrap();
        common::check_valid(
            &key,
            &nonce,
            &common::decode(case, "aad"),
            &common::decode(case, "msg"),
            &common::decode(case, "ct"),
            &tag,
            &[1, 3, 15, 16, 17, 63, 64, 65, 1024],
        );
    }
    println!("RFC 8439 ChaCha20-Poly1305: {} vectors passed", cases.len());
}
