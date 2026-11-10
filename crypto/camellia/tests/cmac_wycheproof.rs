//! Project Wycheproof's `camellia_cmac_test.json` through `Camellia*Key<CMAC>`, via the shared runner:
//! every tag through the worker the key hands out and through the key's own one-shots. Requires
//! the Wycheproof repository at `../wycheproof`; absent, the test warns and passes.

use bouncycastle_camellia::hazmat::{
    Camellia128Internal, Camellia192Internal, Camellia256Internal,
};
use bouncycastle_cipher_test_framework::wycheproof;

#[test]
fn wycheproof_camellia_cmac() {
    let Some(counts) = wycheproof::cmac::<Camellia128Internal, 16>("camellia_cmac_test.json")
    else {
        return;
    };
    let counts = counts
        + wycheproof::cmac::<Camellia192Internal, 24>("camellia_cmac_test.json")
            .expect("the file was found above");
    let counts = counts
        + wycheproof::cmac::<Camellia256Internal, 32>("camellia_cmac_test.json")
            .expect("the file was found above");
    // "InvalidKeySize": no `Camellia*Key<CMAC>` takes those, since the key length is in the type.
    let bad_key =
        wycheproof::cases_with_other_key_lengths("camellia_cmac_test.json", &[16, 24, 32])
            .expect("the file was found above");
    assert_eq!(
        counts.run() + bad_key,
        311,
        "expected all 311 Wycheproof Camellia-CMAC cases to run"
    );
}
