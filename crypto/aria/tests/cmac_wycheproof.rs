//! Project Wycheproof's `aria_cmac_test.json` through `ARIA*Key<CMAC>`, via the shared runner:
//! every tag through the worker the key hands out and through the key's own one-shots. Requires
//! the Wycheproof repository at `../wycheproof`; absent, the test warns and passes.

use bouncycastle_aria::hazmat::{ARIA128Internal, ARIA192Internal, ARIA256Internal};
use bouncycastle_cipher_test_framework::wycheproof;

#[test]
fn wycheproof_aria_cmac() {
    let Some(counts) = wycheproof::cmac::<ARIA128Internal, 16>("aria_cmac_test.json") else {
        return;
    };
    let counts = counts
        + wycheproof::cmac::<ARIA192Internal, 24>("aria_cmac_test.json")
            .expect("the file was found above");
    let counts = counts
        + wycheproof::cmac::<ARIA256Internal, 32>("aria_cmac_test.json")
            .expect("the file was found above");
    // "InvalidKeySize": no `ARIA*Key<CMAC>` takes those, since the key length is in the type.
    let bad_key = wycheproof::cases_with_other_key_lengths("aria_cmac_test.json", &[16, 24, 32])
        .expect("the file was found above");
    assert_eq!(counts.run() + bad_key, 311, "expected all 311 Wycheproof ARIA-CMAC cases to run");
}
