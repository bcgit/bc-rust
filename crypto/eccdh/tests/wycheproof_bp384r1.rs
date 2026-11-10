//! Wycheproof ECDH vectors for brainpoolP384r1: see `wycheproof_common` for the files, the SPKI
//! handling and the verdict rules.

mod wycheproof_common;

use bouncycastle_eccdh::eccdh_bp384r1::SS_LEN;
use bouncycastle_eccdh::keys_bp384r1::{
    ECCDHBp384r1PrivateKey, ECCDHBp384r1PublicKey, PK_LEN, SK_LEN,
};

#[test]
fn ecdh_brainpoolp384r1_test() {
    wycheproof_common::run::<ECCDHBp384r1PublicKey, ECCDHBp384r1PrivateKey, PK_LEN, SK_LEN, SS_LEN>(
        "ecdh_brainpoolP384r1_test.json",
        "brainpoolP384r1",
        936,
        642,
    );
}
