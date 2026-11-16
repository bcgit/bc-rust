//! Wycheproof ECDH vectors for P-384: see `wycheproof_common` for the files, the SPKI
//! handling and the verdict rules.

mod wycheproof_common;

use bouncycastle_ec::P384;
use bouncycastle_ec::curve::Curve;
use bouncycastle_eccdh::keys::{ECCDHPrivateKey, ECCDHPublicKey};

#[test]
fn ecdh_secp384r1_test() {
    wycheproof_common::run::<
        ECCDHPublicKey<P384>,
        ECCDHPrivateKey<P384>,
        { P384::PK_UNCOMPRESSED_LEN },
        { P384::SCALAR_LEN },
        { P384::FE_LEN },
    >("ecdh_secp384r1_test.json", "secp384r1", 1047, 772);
}

#[test]
fn ecdh_secp384r1_ecpoint_test() {
    wycheproof_common::run::<
        ECCDHPublicKey<P384>,
        ECCDHPrivateKey<P384>,
        { P384::PK_UNCOMPRESSED_LEN },
        { P384::SCALAR_LEN },
        { P384::FE_LEN },
    >("ecdh_secp384r1_ecpoint_test.json", "secp384r1", 790, 772);
}
