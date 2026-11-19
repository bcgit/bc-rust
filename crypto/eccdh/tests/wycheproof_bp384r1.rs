//! Wycheproof ECDH vectors for brainpoolP384r1: see `wycheproof_common` for the files, the SPKI
//! handling and the verdict rules.

mod wycheproof_common;

use bouncycastle_ec::Bp384r1;
use bouncycastle_ec::curve::Curve;
use bouncycastle_eccdh::keys::{ECCDHPrivateKey, ECCDHPublicKey};

#[test]
fn ecdh_brainpoolp384r1_test() {
    wycheproof_common::run::<
        ECCDHPublicKey<Bp384r1>,
        ECCDHPrivateKey<Bp384r1>,
        { Bp384r1::PK_UNCOMPRESSED_LEN },
        { Bp384r1::SCALAR_LEN },
        { Bp384r1::FE_LEN },
    >("ecdh_brainpoolP384r1_test.json", "brainpoolP384r1", 936, 642);
}
