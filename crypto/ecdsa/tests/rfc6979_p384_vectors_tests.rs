//! RFC 6979 Appendix A.2.6 ("ECDSA, 384 Bits (Prime Field)") known-answer tests: the key pair, the
//! deterministic per-message secret `k`, and the resulting signature `(r, s)`, for `curve: NIST
//! P-384` with SHA-384, messages `"sample"` and `"test"`.

use bouncycastle_core::signature_key::{DeterministicSigningKey, VerifyingKey};
use bouncycastle_core::traits::{SignaturePrivateKey, SignaturePublicKey};
use bouncycastle_ec::hazmat::p384_comb::comb_multiply_base_point;
use bouncycastle_ec::hazmat::p384_scalar::P384Scalar;
use bouncycastle_ecdsa::keys_p384::{ECDSAP384PrivateKey, ECDSAP384PublicKey};
use bouncycastle_hex::decode as hex_decode;

const X: &str = "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5";
const UX: &str = "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13";
const UY: &str = "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720";

struct Vector {
    msg: &'static [u8],
    r: &'static str,
    s: &'static str,
}

const SAMPLE: Vector = Vector {
    msg: b"sample",
    r: "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C81A648152E44ACF96E36DD1E80FABE46",
    s: "99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94FA329C145786E679E7B82C71A38628AC8",
};

const TEST: Vector = Vector {
    msg: b"test",
    r: "8203B63D3C853E8D77227FB377BCF7B7B772E97892A80F36AB775D509D7A5FEB0542A7F0812998DA8F1DD3CA3CF023DB",
    s: "DDD0760448D42D8A43AF45AF836FCE4DE8BE06B485E9B61B827C2F13173923E06A739F040649A667BF3B828246BAA5A5",
};

fn bytes48(hex: &str) -> [u8; 48] {
    hex_decode(hex).unwrap().try_into().unwrap()
}

fn private_key() -> ECDSAP384PrivateKey {
    ECDSAP384PrivateKey::from_bytes(&bytes48(X)).unwrap()
}

#[test]
fn public_key_matches_vector() {
    let d = P384Scalar::from_be_bytes(&bytes48(X));
    let q = comb_multiply_base_point(&d);
    let (x, y) = q.to_affine().unwrap();
    assert_eq!(x.to_limbs(), bouncycastle_ec::hazmat::p384_sec1::limbs_from_be_bytes(&bytes48(UX)));
    assert_eq!(y.to_limbs(), bouncycastle_ec::hazmat::p384_sec1::limbs_from_be_bytes(&bytes48(UY)));
}

#[test]
fn deterministic_sign_matches_vectors() {
    let sk = private_key();
    for v in [&SAMPLE, &TEST] {
        let sig = sk.sign_deterministic(v.msg, None).unwrap();
        let mut expected = [0u8; 96];
        expected[..48].copy_from_slice(&bytes48(v.r));
        expected[48..].copy_from_slice(&bytes48(v.s));
        assert_eq!(sig, expected, "signature for message {:?}", v.msg);
    }
}

#[test]
fn deterministic_signature_verifies() {
    let sk = private_key();
    let mut uncompressed = [0u8; 97];
    uncompressed[0] = 0x04;
    uncompressed[1..49].copy_from_slice(&bytes48(UX));
    uncompressed[49..97].copy_from_slice(&bytes48(UY));
    let pk = ECDSAP384PublicKey::from_bytes(&uncompressed).unwrap();

    for v in [&SAMPLE, &TEST] {
        let sig = sk.sign_deterministic(v.msg, None).unwrap();
        pk.verify(v.msg, None, &sig).unwrap();
    }
}
