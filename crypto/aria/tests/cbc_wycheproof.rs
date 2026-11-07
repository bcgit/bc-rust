//! Project Wycheproof's `aria_cbc_pkcs5_test.json` through `ARIA*Key<CBC<PKCS7>>`, via the shared
//! runner: the valid cases in both directions under the vector's IV, and every invalid case failing
//! with the error its flags predict. Requires the Wycheproof repository at `../wycheproof`; absent,
//! the test warns and passes.

use bouncycastle_aria::hazmat::{ARIA128Internal, ARIA192Internal, ARIA256Internal};
use bouncycastle_cipher_test_framework::wycheproof;

#[test]
fn wycheproof_aria_cbc_pkcs7_known_answer_tests() {
    let Some(counts) =
        wycheproof::cbc_pkcs7::<ARIA128Internal, 16>("aria_cbc_pkcs5_test.json", "ARIA-CBC-PKCS5")
    else {
        return;
    };
    let counts = counts
        + wycheproof::cbc_pkcs7::<ARIA192Internal, 24>(
            "aria_cbc_pkcs5_test.json",
            "ARIA-CBC-PKCS5",
        )
        .expect("the file was found above");
    let counts = counts
        + wycheproof::cbc_pkcs7::<ARIA256Internal, 32>(
            "aria_cbc_pkcs5_test.json",
            "ARIA-CBC-PKCS5",
        )
        .expect("the file was found above");
    // Guards against a silently-vacuous run.
    assert!(counts.valid > 0, "expected valid cases");
    assert!(counts.bad_padding > 0, "expected bad-padding cases, which are the point of this set");
    assert!(counts.no_final_block > 0, "expected the empty-ciphertext cases");
}
