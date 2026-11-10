//! Project Wycheproof's `aria_wrap_test.json` (KW) and `aria_kwp_test.json` (KWP) through
//! `ARIA*Key<KW>` and `ARIA*Key<KWP>`, via the shared runner. Requires the Wycheproof repository at
//! `../wycheproof`; absent, the tests warn and pass.

use bouncycastle_aria::hazmat::{ARIA128Internal, ARIA192Internal, ARIA256Internal};
use bouncycastle_cipher::modes::{KW, KWP};
use bouncycastle_cipher_test_framework::wycheproof;

#[test]
fn wycheproof_aria_kw() {
    let Some(count) = wycheproof::key_wrap::<ARIA128Internal, KW, 16>("aria_wrap_test.json") else {
        return;
    };
    let count = count
        + wycheproof::key_wrap::<ARIA192Internal, KW, 24>("aria_wrap_test.json")
            .expect("the file was found above");
    let count = count
        + wycheproof::key_wrap::<ARIA256Internal, KW, 32>("aria_wrap_test.json")
            .expect("the file was found above");
    println!("Wycheproof ARIA-KW: {count} cases");
    assert_eq!(count, 159, "expected all 159 Wycheproof ARIA key-wrap cases to run");
}

#[test]
fn wycheproof_aria_kwp() {
    let Some(count) = wycheproof::key_wrap::<ARIA128Internal, KWP, 16>("aria_kwp_test.json") else {
        return;
    };
    let count = count
        + wycheproof::key_wrap::<ARIA192Internal, KWP, 24>("aria_kwp_test.json")
            .expect("the file was found above");
    let count = count
        + wycheproof::key_wrap::<ARIA256Internal, KWP, 32>("aria_kwp_test.json")
            .expect("the file was found above");
    println!("Wycheproof ARIA-KWP: {count} cases");
    assert_eq!(count, 252, "expected all 252 Wycheproof ARIA key-wrap-with-padding cases to run");
}
