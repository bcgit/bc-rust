//! Wycheproof ECDH vectors for P-256: see `wycheproof_common` for the files, the SPKI
//! handling and the verdict rules.

mod wycheproof_common;

use bouncycastle_ec::P256;
use bouncycastle_ec::curve::Curve;
use bouncycastle_eccdh::keys::{ECCDHPrivateKey, ECCDHPublicKey};

#[test]
fn ecdh_secp256r1_test() {
    wycheproof_common::run::<
        ECCDHPublicKey<P256>,
        ECCDHPrivateKey<P256>,
        { P256::PK_UNCOMPRESSED_LEN },
        { P256::SCALAR_LEN },
        { P256::FE_LEN },
    >("ecdh_secp256r1_test.json", "secp256r1", 612, 331);
}

#[test]
fn ecdh_secp256r1_ecpoint_test() {
    wycheproof_common::run::<
        ECCDHPublicKey<P256>,
        ECCDHPrivateKey<P256>,
        { P256::PK_UNCOMPRESSED_LEN },
        { P256::SCALAR_LEN },
        { P256::FE_LEN },
    >("ecdh_secp256r1_ecpoint_test.json", "secp256r1", 355, 331);
}
