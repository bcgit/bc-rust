//! Wycheproof ECDH vectors for brainpoolP256r1: see `wycheproof_common` for the files, the SPKI
//! handling and the verdict rules.

mod wycheproof_common;

use bouncycastle_eccdh::eccdh_bp256r1::SS_LEN;
use bouncycastle_eccdh::keys_bp256r1::{
    ECCDHBp256r1PrivateKey, ECCDHBp256r1PublicKey, PK_LEN, SK_LEN,
};

#[test]
fn ecdh_brainpoolp256r1_test() {
    wycheproof_common::run::<ECCDHBp256r1PublicKey, ECCDHBp256r1PrivateKey, PK_LEN, SK_LEN, SS_LEN>(
        "ecdh_brainpoolP256r1_test.json",
        "brainpoolP256r1",
        804,
        518,
    );
}
