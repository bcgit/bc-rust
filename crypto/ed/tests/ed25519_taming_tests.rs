//! The twelve vectors of "Taming the many EdDSAs" (Chalkias, Garillot and Nikolaenko,
//! <https://ia.cr/2020/1244>), through the public API. The table was lifted by script from
//! `cases.json` of the paper's repository (github.com/novifinancial/ed25519-speccheck).
//!
//! Every one is refused. This crate validates a public key in full when it is decoded, so a
//! vector whose key is not a canonically encoded point of the prime-order subgroup never
//! reaches verification:
//!
//! | Vector | The paper's description                     | Refused at |
//! |--------|---------------------------------------------|------------|
//! | 0, 1   | A of small order                            | key decode |
//! | 2 to 5 | A of mixed order                            | key decode |
//! | 6, 7   | A of order L, S not below L                 | verify     |
//! | 8, 9   | A of mixed order (and a non-canonical R)    | key decode |
//! | 10, 11 | A of small order, non-canonically encoded   | key decode |
//!
//! The paper's table has 0 to 5 satisfying the cofactored equation, so their refusal is the
//! difference full key validation makes; 6 to 11 fail a decoding of RFC 8032 Section 5.1.7,
//! step 1.

use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::signature_key::OneShotVerifyingKey;
use bouncycastle_core::traits::PublicKey;
use bouncycastle_ed::ed25519::Ed25519PublicKey;

// (number, message, public key, signature)
const TAMING: &[(usize, &str, &str, &str)] = &[
    (
        0,
        "8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        concat!(
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
    ),
    (
        1,
        "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        concat!(
            "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
            "a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
        ),
    ),
    (
        2,
        "aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab",
        "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
        concat!(
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
            "8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e",
        ),
    ),
    (
        3,
        "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
        "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
        concat!(
            "9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f",
            "87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009",
        ),
    ),
    (
        4,
        "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
        "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
        concat!(
            "160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed512",
            "5ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09",
        ),
    ),
    (
        5,
        "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
        "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
        concat!(
            "21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7",
            "e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405",
        ),
    ),
    (
        6,
        "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
        "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
        concat!(
            "e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e",
            "547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514",
        ),
    ),
    (
        7,
        "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
        "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
        concat!(
            "8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa1942",
            "7e71f98a473474f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c22",
        ),
    ),
    (
        8,
        "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
        "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
        concat!(
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f",
        ),
    ),
    (
        9,
        "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
        "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
        concat!(
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "ca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908",
        ),
    ),
    (
        10,
        "e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        concat!(
            "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dc",
            "a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
        ),
    ),
    (
        11,
        "39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        concat!(
            "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dc",
            "a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
        ),
    ),
];

/// Vectors whose public key decodes.
const KEY_DECODES: [usize; 2] = [6, 7];

#[test]
fn taming_vectors() {
    assert_eq!(TAMING.len(), 12);
    let (mut at_decode, mut at_verify) = (0, 0);
    for (number, msg, pk, sig) in TAMING {
        let msg = bouncycastle_hex::decode(msg).unwrap();
        let sig = bouncycastle_hex::decode(sig).unwrap();
        assert_eq!(sig.len(), 64, "vector {number}");
        let pk = Ed25519PublicKey::from_bytes(&bouncycastle_hex::decode(pk).unwrap());
        assert_eq!(pk.is_ok(), KEY_DECODES.contains(number), "vector {number}: key decode");
        match pk {
            Err(_) => at_decode += 1,
            Ok(pk) => {
                assert_eq!(
                    pk.verify(&msg, None, &sig),
                    Err(SignatureError::SignatureVerificationFailed),
                    "vector {number}"
                );
                assert_eq!(
                    pk.as_prehash().verify(&msg, None, &sig),
                    Err(SignatureError::SignatureVerificationFailed),
                    "vector {number}"
                );
                at_verify += 1;
            }
        }
    }
    assert_eq!((at_decode, at_verify), (10, 2));
}
