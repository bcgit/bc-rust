//! Project Wycheproof's `sm4_gcm_test.json` through `SM4*Key<GCM>`, via the shared runner: the
//! 96-bit-IV cases in both directions, the other IV lengths counted as outside `Gcm`'s shape, and
//! the valid empty-message cases run again as GMAC known answers through `SM4*Key<GMAC>`.
//! Requires the Wycheproof repository at `../wycheproof`; absent, the tests warn and pass.

use bouncycastle_cipher_test_framework::wycheproof;
use bouncycastle_sm4::hazmat::SM4Internal;

#[test]
fn wycheproof_sm4_gcm_known_answer_tests() {
    let Some(counts) = wycheproof::gcm::<SM4Internal, 16>("sm4_gcm_test.json", "SM4-GCM") else {
        return;
    };
    assert!(counts.run() > 0, "expected the 96-bit-IV groups to be dispatchable");
    assert!(counts.valid > 0, "expected at least some valid cases to be run");
    assert!(counts.invalid > 0, "expected at least some invalid (tag-failure) cases to be run");
    assert!(counts.unsupported > 0, "expected the other-IV-length cases to be outside Gcm's shape");
}

#[test]
fn wycheproof_empty_message_cases_are_gmac_known_answers() {
    let Some(run) = wycheproof::gmac_from_empty_gcm_cases::<SM4Internal, 16>("sm4_gcm_test.json")
    else {
        return;
    };
    assert!(run >= 1, "expected at least one empty-message case per key length, ran {run}");
}
