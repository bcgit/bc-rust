//! Wycheproof ECDH vectors for P-521: see `wycheproof_common` for the files, the SPKI
//! handling and the verdict rules.

mod wycheproof_common;

use bouncycastle_ec::P521;
use bouncycastle_ec::curve::Curve;
use bouncycastle_eccdh::keys::{ECCDHPrivateKey, ECCDHPublicKey};

#[test]
fn ecdh_secp521r1_test() {
    wycheproof_common::run::<
        ECCDHPublicKey<P521>,
        ECCDHPrivateKey<P521>,
        { P521::PK_UNCOMPRESSED_LEN },
        { P521::SCALAR_LEN },
        { P521::FE_LEN },
    >("ecdh_secp521r1_test.json", "secp521r1", 916, 633);
}

#[test]
fn ecdh_secp521r1_ecpoint_test() {
    wycheproof_common::run::<
        ECCDHPublicKey<P521>,
        ECCDHPrivateKey<P521>,
        { P521::PK_UNCOMPRESSED_LEN },
        { P521::SCALAR_LEN },
        { P521::FE_LEN },
    >("ecdh_secp521r1_ecpoint_test.json", "secp521r1", 661, 633);
}
