//! Wycheproof ECDH vectors for P-521: see `wycheproof_common` for the files, the SPKI
//! handling and the verdict rules.

mod wycheproof_common;

use bouncycastle_eccdh::eccdh_p521::SS_LEN;
use bouncycastle_eccdh::keys_p521::{ECCDHP521PrivateKey, ECCDHP521PublicKey, PK_LEN, SK_LEN};

#[test]
fn ecdh_secp521r1_test() {
    wycheproof_common::run::<ECCDHP521PublicKey, ECCDHP521PrivateKey, PK_LEN, SK_LEN, SS_LEN>(
        "ecdh_secp521r1_test.json",
        "secp521r1",
        916,
        633,
    );
}

#[test]
fn ecdh_secp521r1_ecpoint_test() {
    wycheproof_common::run::<ECCDHP521PublicKey, ECCDHP521PrivateKey, PK_LEN, SK_LEN, SS_LEN>(
        "ecdh_secp521r1_ecpoint_test.json",
        "secp521r1",
        661,
        633,
    );
}
