//! Wycheproof ECDH vectors for P-384: see `wycheproof_common` for the files, the SPKI
//! handling and the verdict rules.

mod wycheproof_common;

use bouncycastle_eccdh::eccdh_p384::SS_LEN;
use bouncycastle_eccdh::keys_p384::{ECCDHP384PrivateKey, ECCDHP384PublicKey, PK_LEN, SK_LEN};

#[test]
fn ecdh_secp384r1_test() {
    wycheproof_common::run::<ECCDHP384PublicKey, ECCDHP384PrivateKey, PK_LEN, SK_LEN, SS_LEN>(
        "ecdh_secp384r1_test.json",
        "secp384r1",
        1047,
        772,
    );
}

#[test]
fn ecdh_secp384r1_ecpoint_test() {
    wycheproof_common::run::<ECCDHP384PublicKey, ECCDHP384PrivateKey, PK_LEN, SK_LEN, SS_LEN>(
        "ecdh_secp384r1_ecpoint_test.json",
        "secp384r1",
        790,
        772,
    );
}
