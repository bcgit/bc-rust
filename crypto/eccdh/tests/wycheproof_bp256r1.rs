//! Wycheproof ECDH vectors for brainpoolP256r1: see `wycheproof_common` for the files, the SPKI
//! handling and the verdict rules.

mod wycheproof_common;

use bouncycastle_ec::Bp256r1;
use bouncycastle_ec::curve::Curve;
use bouncycastle_eccdh::keys::{ECCDHPrivateKey, ECCDHPublicKey};

#[test]
fn ecdh_brainpoolp256r1_test() {
    wycheproof_common::run::<
        ECCDHPublicKey<Bp256r1>,
        ECCDHPrivateKey<Bp256r1>,
        { Bp256r1::PK_UNCOMPRESSED_LEN },
        { Bp256r1::SCALAR_LEN },
        { Bp256r1::FE_LEN },
    >("ecdh_brainpoolP256r1_test.json", "brainpoolP256r1", 804, 518);
}
