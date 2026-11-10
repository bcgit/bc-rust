//! Wycheproof ECDH vectors for brainpoolP512r1: see `wycheproof_common` for the files, the SPKI
//! handling and the verdict rules.

mod wycheproof_common;

use bouncycastle_eccdh::eccdh_bp512r1::SS_LEN;
use bouncycastle_eccdh::keys_bp512r1::{
    ECCDHBp512r1PrivateKey, ECCDHBp512r1PublicKey, PK_LEN, SK_LEN,
};

#[test]
fn ecdh_brainpoolp512r1_test() {
    wycheproof_common::run::<ECCDHBp512r1PublicKey, ECCDHBp512r1PrivateKey, PK_LEN, SK_LEN, SS_LEN>(
        "ecdh_brainpoolP512r1_test.json",
        "brainpoolP512r1",
        794,
        512,
    );
}
