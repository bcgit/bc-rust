//! Wycheproof ECDH vectors for brainpoolP512r1: see `wycheproof_common` for the files, the SPKI
//! handling and the verdict rules.

mod wycheproof_common;

use bouncycastle_ec::Bp512r1;
use bouncycastle_ec::curve::Curve;
use bouncycastle_eccdh::keys::{ECCDHPrivateKey, ECCDHPublicKey};

#[test]
fn ecdh_brainpoolp512r1_test() {
    wycheproof_common::run::<
        ECCDHPublicKey<Bp512r1>,
        ECCDHPrivateKey<Bp512r1>,
        { Bp512r1::PK_UNCOMPRESSED_LEN },
        { Bp512r1::SCALAR_LEN },
        { Bp512r1::FE_LEN },
    >("ecdh_brainpoolP512r1_test.json", "brainpoolP512r1", 794, 512);
}
