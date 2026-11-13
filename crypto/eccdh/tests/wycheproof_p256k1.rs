//! Wycheproof ECDH vectors for secp256k1: see `wycheproof_common` for the files, the SPKI
//! handling and the verdict rules.

mod wycheproof_common;

use bouncycastle_ec::Secp256K1;
use bouncycastle_ec::curve::Curve;
use bouncycastle_eccdh::keys::{ECCDHPrivateKey, ECCDHPublicKey};

#[test]
fn ecdh_secp256k1_test() {
    wycheproof_common::run::<
        ECCDHPublicKey<Secp256K1>,
        ECCDHPrivateKey<Secp256K1>,
        { Secp256K1::PK_UNCOMPRESSED_LEN },
        { Secp256K1::SCALAR_LEN },
        { Secp256K1::FE_LEN },
    >("ecdh_secp256k1_test.json", "secp256k1", 752, 474);
}
