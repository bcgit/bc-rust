//! Project Wycheproof's `camellia_wrap_test.json` (KW) through
//! `Camellia*Key<KW>`, via the shared runner. Requires the Wycheproof repository at
//! `../wycheproof`; absent, the tests warn and pass.

use bouncycastle_camellia::hazmat::{
    Camellia128Internal, Camellia192Internal, Camellia256Internal,
};
use bouncycastle_cipher::modes::KW;
use bouncycastle_cipher_test_framework::wycheproof;

#[test]
fn wycheproof_camellia_kw() {
    let Some(count) =
        wycheproof::key_wrap::<Camellia128Internal, KW, 16>("camellia_wrap_test.json")
    else {
        return;
    };
    let count = count
        + wycheproof::key_wrap::<Camellia192Internal, KW, 24>("camellia_wrap_test.json")
            .expect("the file was found above");
    let count = count
        + wycheproof::key_wrap::<Camellia256Internal, KW, 32>("camellia_wrap_test.json")
            .expect("the file was found above");
    println!("Wycheproof Camellia-KW: {count} cases");
    assert_eq!(count, 159, "expected all 159 Wycheproof Camellia key-wrap cases to run");
}
