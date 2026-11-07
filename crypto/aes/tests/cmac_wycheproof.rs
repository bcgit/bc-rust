//! Project Wycheproof's `aes_cmac_test.json` through `AES*Key<CMAC>`, via the shared runner:
//! every tag through the worker the key hands out and through the key's own one-shots. Requires
//! the Wycheproof repository at `../wycheproof`; absent, the test warns and passes.

use bouncycastle_aes::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_cipher_test_framework::wycheproof;

#[test]
fn wycheproof_aes_cmac() {
    let Some(counts) = wycheproof::cmac::<AES128Internal, 16>("aes_cmac_test.json") else { return };
    let counts = counts
        + wycheproof::cmac::<AES192Internal, 24>("aes_cmac_test.json")
            .expect("the file was found above");
    let counts = counts
        + wycheproof::cmac::<AES256Internal, 32>("aes_cmac_test.json")
            .expect("the file was found above");
    // "InvalidKeySize": no `AES*Key<CMAC>` takes those, since the key length is in the type.
    let bad_key = wycheproof::cases_with_other_key_lengths("aes_cmac_test.json", &[16, 24, 32])
        .expect("the file was found above");
    assert_eq!(counts.run() + bad_key, 311, "expected all 311 Wycheproof AES-CMAC cases to run");
}
