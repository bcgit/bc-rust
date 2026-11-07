//! Project Wycheproof's `aria_ccm_test.json` through `ARIA*Key<CCM<N, T>>`, via the shared
//! runner. The set is adversarial: most of its nonce and tag sizes are outside SP 800-38C A.1's
//! sets and so have no key type to run under, and are counted rather than dropped. Requires the
//! Wycheproof repository at `../wycheproof`; absent, the test warns and passes.

use bouncycastle_aria::hazmat::{ARIA128Internal, ARIA192Internal, ARIA256Internal};
use bouncycastle_cipher_test_framework::wycheproof;

#[test]
fn wycheproof_aria_ccm_known_answer_tests() {
    let Some(counts) = wycheproof::ccm::<ARIA128Internal, 16>("aria_ccm_test.json") else { return };
    let counts = counts
        + wycheproof::ccm::<ARIA192Internal, 24>("aria_ccm_test.json")
            .expect("the file was found above");
    let counts = counts
        + wycheproof::ccm::<ARIA256Internal, 32>("aria_ccm_test.json")
            .expect("the file was found above");
    assert!(counts.run() > 0, "expected at least some cases to be within A.1's dispatchable sets");
    assert!(counts.valid > 0, "expected at least some valid cases to be run");
    assert!(counts.invalid > 0, "expected at least some invalid (tag-failure) cases to be run");
    assert!(
        counts.unsupported > 0,
        "expected most of this adversarial set to be outside A.1's sets"
    );
}
