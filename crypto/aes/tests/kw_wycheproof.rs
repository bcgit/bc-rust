//! Project Wycheproof's `aes_wrap_test.json` (KW) and `aes_kwp_test.json` (KWP) through
//! `AES*Key<KW>` and `AES*Key<KWP>`, via the shared runner. Requires the Wycheproof repository at
//! `../wycheproof`; absent, the tests warn and pass.

use bouncycastle_aes::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_cipher::modes::{KW, KWP};
use bouncycastle_cipher_test_framework::wycheproof;

#[test]
fn wycheproof_aes_kw() {
    let Some(count) = wycheproof::key_wrap::<AES128Internal, KW, 16>("aes_wrap_test.json") else {
        return;
    };
    let count = count
        + wycheproof::key_wrap::<AES192Internal, KW, 24>("aes_wrap_test.json")
            .expect("the file was found above");
    let count = count
        + wycheproof::key_wrap::<AES256Internal, KW, 32>("aes_wrap_test.json")
            .expect("the file was found above");
    println!("Wycheproof AES-KW: {count} cases");
    assert!(count > 0, "expected the key-wrap cases to run");
}

#[test]
fn wycheproof_aes_kwp() {
    let Some(count) = wycheproof::key_wrap::<AES128Internal, KWP, 16>("aes_kwp_test.json") else {
        return;
    };
    let count = count
        + wycheproof::key_wrap::<AES192Internal, KWP, 24>("aes_kwp_test.json")
            .expect("the file was found above");
    let count = count
        + wycheproof::key_wrap::<AES256Internal, KWP, 32>("aes_kwp_test.json")
            .expect("the file was found above");
    println!("Wycheproof AES-KWP: {count} cases");
    assert!(count > 0, "expected the key-wrap-with-padding cases to run");
}
