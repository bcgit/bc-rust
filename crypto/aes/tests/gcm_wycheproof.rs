//! Project Wycheproof's `aes_gcm_test.json` through `AES*Key<GCM>`, via the shared runner: the
//! 96-bit-IV cases in both directions, the other IV lengths counted as outside `Gcm`'s shape, and
//! the valid empty-message cases run again as GMAC known answers through `AES*Key<GMAC>`.
//! Requires the Wycheproof repository at `../wycheproof`; absent, the tests warn and pass.

use bouncycastle_aes::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_cipher_test_framework::wycheproof;

#[test]
fn wycheproof_aes_gcm_known_answer_tests() {
    let Some(counts) = wycheproof::gcm::<AES128Internal, 16>("aes_gcm_test.json", "AES-GCM") else {
        return;
    };
    let counts = counts
        + wycheproof::gcm::<AES192Internal, 24>("aes_gcm_test.json", "AES-GCM")
            .expect("the file was found above");
    let counts = counts
        + wycheproof::gcm::<AES256Internal, 32>("aes_gcm_test.json", "AES-GCM")
            .expect("the file was found above");
    assert!(counts.run() > 0, "expected the 96-bit-IV groups to be dispatchable");
    assert!(counts.valid > 0, "expected at least some valid cases to be run");
    assert!(counts.invalid > 0, "expected at least some invalid (tag-failure) cases to be run");
    assert!(counts.unsupported > 0, "expected the other-IV-length cases to be outside Gcm's shape");
}

#[test]
fn wycheproof_empty_message_cases_are_gmac_known_answers() {
    let Some(run) =
        wycheproof::gmac_from_empty_gcm_cases::<AES128Internal, 16>("aes_gcm_test.json")
    else {
        return;
    };
    let run = run
        + wycheproof::gmac_from_empty_gcm_cases::<AES192Internal, 24>("aes_gcm_test.json")
            .expect("the file was found above");
    let run = run
        + wycheproof::gmac_from_empty_gcm_cases::<AES256Internal, 32>("aes_gcm_test.json")
            .expect("the file was found above");
    assert!(run >= 3, "expected at least one empty-message case per key length, ran {run}");
}
