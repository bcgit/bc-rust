//! Known-answer tests for [`SM2::verify`] against `draft-shen-sm2-ecdsa-02` Appendix D's actual
//! "recommended parameters" curve (the curve `bouncycastle-ec`'s `sm2` module implements) -- unlike
//! this crate's [`crate::za`]-validation notes, which cross-check against the draft's own Appendix
//! A.2 worked example (a *different*, illustrative curve), these vectors were independently
//! generated in Python from scratch, against the real production curve, using: a from-scratch
//! affine-coordinate implementation of the group law (not ported from any Rust code here), Python's
//! `hashlib.new("sm3", ...)` (OpenSSL-backed) for the hash, and this crate's already-verified `ZA`
//! and signing-equation logic (steps A1-A7/B1-B7, matched against the draft's Appendix A.2 example
//! before any Rust was written). `d`, `k` below are arbitrary fixed test-only integers, not real
//! keys.
//!
//! These tests exercise [`SM2::verify`] (not `sign`): this crate's `k` is drawn through
//! [`bouncycastle_ec`]'s wide-DRBG-output reduction ([`crate::extra_bits`]), whose output for a
//! given raw DRBG string does not equal the raw `k` these Python vectors used directly, so signing
//! with a matching `k` isn't reproducible through the public API. Verification has no such
//! constraint: it only needs a public key and a signature, both computed once in Python and fixed
//! here.
//!
//! `bc_java_sm2p256v1_vector_verifies` below is the exception, and the only vector here whose
//! expected values did not originate with this workspace at all: it is BouncyCastle Java's own
//! `SM2SignerTest.doSignerTestFpStandardSM3` case (`core/src/test/java/org/bouncycastle/crypto/
//! test/SM2SignerTest.java`), on the same `sm2p256v1` curve with SM3. A separate implementation
//! produced it, so it cross-checks this crate's domain constants, `ZA`, `e = SM3(ZA || M)` and the
//! §5.2.3 verification equation against something external -- which the Python-generated vectors
//! above, sharing this crate's own `ZA` and signing logic, cannot do. It was additionally
//! reproduced from scratch (in Python, not checked in: affine group law, `hashlib.new("sm3")`,
//! and the draft's published domain parameters) before being written here, so it rests on two
//! independent derivations rather than on trusting either one.

use bouncycastle_core::traits::{SignaturePrivateKey, SignaturePublicKey, SignatureVerifier};
use bouncycastle_ec::sm2_sec1;
use bouncycastle_sm2::keys::{SM2PrivateKey, SM2PublicKey};
use bouncycastle_sm2::sm2::SM2;

fn pubkey_from_hex(x_hex: &str, y_hex: &str) -> SM2PublicKey {
    let mut bytes = [0u8; 65];
    bytes[0] = 0x04;
    bytes[1..33].copy_from_slice(&bouncycastle_hex::decode(x_hex).unwrap());
    bytes[33..65].copy_from_slice(&bouncycastle_hex::decode(y_hex).unwrap());
    SM2PublicKey::from_bytes(&bytes).unwrap()
}

fn sig_from_hex(r_hex: &str, s_hex: &str) -> [u8; 64] {
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&bouncycastle_hex::decode(r_hex).unwrap());
    sig[32..].copy_from_slice(&bouncycastle_hex::decode(s_hex).unwrap());
    sig
}

struct Vector {
    qx: &'static str,
    qy: &'static str,
    id: &'static [u8],
    msg_hex: &'static str,
    r: &'static str,
    s: &'static str,
}

const V1: Vector = Vector {
    qx: "17b937e7b5d2d00ceaec4ff25c6b74eaa57c8b67518fb630ec28ac04faf97f24",
    qy: "71fa5c9eb79214b79568b2597a3c87fe8d3c0fb9a96b3cc36594bff402218fb1",
    id: b"ALICE123@YAHOO.COM",
    msg_hex: "6d65737361676520646967657374",
    r: "250273e780744ebc1578119e0d1355e16ed1a75233ccae4c897fdab262908b05",
    s: "1203d8c1b8341f5a668ff87979ba89cae12300a170849a2d47cf9d57a9d19362",
};

const V2_EMPTY_ID_AND_MSG: Vector = Vector {
    qx: "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
    qy: "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0",
    id: b"",
    msg_hex: "",
    r: "12c8bbc33bb8ebed2883e559dd4a26a4720659b025dc8c1414a3d6c00305b9e7",
    s: "769ba21de2238a096bbe0d53115aecad7ffec2dd7df4bc8b9f8c0ea49b67c39f",
};

const V3_LONGER_MESSAGE: Vector = Vector {
    qx: "6d06baebf91d46e720c2a37f59ae6a070efdc56aa79be2c992e9bed2af4706bf",
    qy: "8a8c2b9d86f05a6fb94ba694cf0ea5bcaf48020fcd22cdef90c118b522b3a9d1",
    id: b"user@example.com",
    msg_hex: "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f6754686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f6754686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
    r: "f8824e311760a45e6ea155514ec7a09260058657911c4ea8d86febfe002f5d9c",
    s: "9016d56b07b2acb2677869e049a4d99cc33e0352d9cbf8f6dd86bead038c29fa",
};

const VECTORS: [Vector; 3] = [V1, V2_EMPTY_ID_AND_MSG, V3_LONGER_MESSAGE];

#[test]
fn known_answer_vectors_verify() {
    for v in VECTORS {
        let pk = pubkey_from_hex(v.qx, v.qy);
        let msg = bouncycastle_hex::decode(v.msg_hex).unwrap();
        let sig = sig_from_hex(v.r, v.s);
        SM2::verify(&pk, &msg, Some(v.id), &sig)
            .unwrap_or_else(|e| panic!("KAT vector failed to verify: {e:?}"));
    }
}

#[test]
fn known_answer_vectors_reject_tampered_r() {
    for v in VECTORS {
        let pk = pubkey_from_hex(v.qx, v.qy);
        let msg = bouncycastle_hex::decode(v.msg_hex).unwrap();
        let mut sig = sig_from_hex(v.r, v.s);
        sig[0] ^= 0xFF;
        assert!(SM2::verify(&pk, &msg, Some(v.id), &sig).is_err());
    }
}

#[test]
fn known_answer_vectors_reject_wrong_id() {
    for v in VECTORS {
        let pk = pubkey_from_hex(v.qx, v.qy);
        let msg = bouncycastle_hex::decode(v.msg_hex).unwrap();
        let sig = sig_from_hex(v.r, v.s);
        assert!(SM2::verify(&pk, &msg, Some(b"wrong identity"), &sig).is_err());
    }
}

#[test]
fn known_answer_za_matches_independent_python_computation() {
    // Cross-checks crate::za::compute directly, not just the end-to-end verify result -- pins the
    // intermediate ZA value itself (draft-shen-sm2-ecdsa-02 S5.1.2), independent of e/r/s.
    let expected: [(&str, &str, &[u8], &str); 3] = [
        (V1.qx, V1.qy, V1.id, "bab69c9204aadd3d49ff244e8fdffb204e1d4249e36855f06a912abd81ddf167"),
        (
            V2_EMPTY_ID_AND_MSG.qx,
            V2_EMPTY_ID_AND_MSG.qy,
            V2_EMPTY_ID_AND_MSG.id,
            "c13adcc1829f563f2a01ef3c4e0685647bf32a650a35273443150d44f5809ff8",
        ),
        (
            V3_LONGER_MESSAGE.qx,
            V3_LONGER_MESSAGE.qy,
            V3_LONGER_MESSAGE.id,
            "65052e995e872be0fb904d14ba6c2550a70d751e4dccf3c7a700c4588852e215",
        ),
    ];
    for (qx, qy, id, za_hex) in expected {
        let x_limbs = sm2_sec1::limbs_from_be_bytes(
            &bouncycastle_hex::decode(qx).unwrap().try_into().unwrap(),
        );
        let y_limbs = sm2_sec1::limbs_from_be_bytes(
            &bouncycastle_hex::decode(qy).unwrap().try_into().unwrap(),
        );
        let x = bouncycastle_ec::sm2::Sm2FieldElement::from_limbs(x_limbs);
        let y = bouncycastle_ec::sm2::Sm2FieldElement::from_limbs(y_limbs);
        let za = bouncycastle_sm2::za::compute(id, &x, &y).unwrap();
        assert_eq!(bouncycastle_hex::encode(za), za_hex);
    }
}

/// BouncyCastle Java's `SM2SignerTest.doSignerTestFpStandardSM3` vector -- see this file's module
/// docs for its provenance and why it is the one externally-sourced case here.
///
/// Unlike the vectors above it comes with its private key, so this also pins
/// [`SM2PrivateKey::derive_pk`] (`PA = [dA]G`) and [`bouncycastle_sm2::za::compute`] against the
/// same external source, not just the end-to-end verify result.
#[test]
fn bc_java_sm2p256v1_vector_verifies() {
    const D_HEX: &str = "110e7973206f68c19ee5f7328c036f26911c8c73b4e4f36ae3291097f8984ffc";
    const PA_X: &str = "d03d30dd01ca3422aeaccf9b88043b554659d3092b0a9e8cce3e8c4530a98cb7";
    const PA_Y: &str = "9d705e6213eee145b748e36e274e5f101dc10d7bbc9dab9a04022e73b76e02cd";
    const ZA_HEX: &str = "ad1c1335ec4bd951cbb4a2144b8247b78fbe47efce2203086f968be8b730393d";
    const ID: &[u8] = b"sm2test@example.com";
    const MSG: &[u8] = b"hi chappy";
    const R: &str = "05890b9077b92e47b17a1ff42a814280e556afd92b4a98b9670bf8b1a274c2fa";
    const S: &str = "e3abbb8db2b6ecd9b24eccea7f679fb9a4b1db52f4aa985e443ad73237fa1993";

    let sk = SM2PrivateKey::from_bytes(&bouncycastle_hex::decode(D_HEX).unwrap())
        .expect("bc-java's dA is in [1, n-1]");
    let pk = sk.derive_pk();
    assert_eq!(pk, pubkey_from_hex(PA_X, PA_Y), "PA = [dA]G disagrees with the external vector");

    let (x, y) = (pk.encode()[1..33].to_vec(), pk.encode()[33..65].to_vec());
    let x = bouncycastle_ec::sm2::Sm2FieldElement::from_limbs(sm2_sec1::limbs_from_be_bytes(
        &x.try_into().unwrap(),
    ));
    let y = bouncycastle_ec::sm2::Sm2FieldElement::from_limbs(sm2_sec1::limbs_from_be_bytes(
        &y.try_into().unwrap(),
    ));
    assert_eq!(
        bouncycastle_hex::encode(bouncycastle_sm2::za::compute(ID, &x, &y).unwrap()),
        ZA_HEX,
        "ZA disagrees with the external vector"
    );

    let sig = sig_from_hex(R, S);
    SM2::verify(&pk, MSG, Some(ID), &sig).expect("bc-java's signature must verify");

    // and it must be specific to that identity and message
    assert!(SM2::verify(&pk, MSG, Some(b"someone-else"), &sig).is_err());
    assert!(SM2::verify(&pk, b"hi chappy!", Some(ID), &sig).is_err());
}
