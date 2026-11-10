//! Wycheproof ECDH vectors for P-256: see `wycheproof_common` for the files, the SPKI
//! handling and the verdict rules.

mod wycheproof_common;

use bouncycastle_eccdh::eccdh_p256::SS_LEN;
use bouncycastle_eccdh::keys_p256::{ECCDHP256PrivateKey, ECCDHP256PublicKey, PK_LEN, SK_LEN};

#[test]
fn ecdh_secp256r1_test() {
    wycheproof_common::run::<ECCDHP256PublicKey, ECCDHP256PrivateKey, PK_LEN, SK_LEN, SS_LEN>(
        "ecdh_secp256r1_test.json",
        "secp256r1",
        612,
        331,
    );
}

#[test]
fn ecdh_secp256r1_ecpoint_test() {
    wycheproof_common::run::<ECCDHP256PublicKey, ECCDHP256PrivateKey, PK_LEN, SK_LEN, SS_LEN>(
        "ecdh_secp256r1_ecpoint_test.json",
        "secp256r1",
        355,
        331,
    );
}
