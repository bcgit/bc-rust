//! Wycheproof ECDH vectors for secp256k1: see `wycheproof_common` for the files, the SPKI
//! handling and the verdict rules.

mod wycheproof_common;

use bouncycastle_eccdh::eccdh_p256k1::SS_LEN;
use bouncycastle_eccdh::keys_p256k1::{
    ECCDHSecp256K1PrivateKey, ECCDHSecp256K1PublicKey, PK_LEN, SK_LEN,
};

#[test]
fn ecdh_secp256k1_test() {
    wycheproof_common::run::<
        ECCDHSecp256K1PublicKey,
        ECCDHSecp256K1PrivateKey,
        PK_LEN,
        SK_LEN,
        SS_LEN,
    >("ecdh_secp256k1_test.json", "secp256k1", 752, 474);
}
