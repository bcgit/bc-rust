//! Cross-check against an independent Python implementation of RFC 6979 §3.2 (using Python's own
//! `hmac`/`hashlib`, not derived from this crate) for secp256k1/SHA-256: RFC 6979 has no official
//! Appendix A.2.x vectors for this curve (its appendix only covers the NIST curves P-192 through
//! P-521), so this is the closest equivalent -- five independently-generated `(d, msg)` pairs
//! (empty, short ASCII, longer ASCII, all-zero, all-`0xff`), each with the deterministic `k`, the
//! resulting `(r, s)`, and `Q = [d]G` computed via the standard affine group law, `random.seed
//! 1234567`.

use bouncycastle_core::traits::Hash;
use bouncycastle_core::traits::{
    SignaturePrivateKey, SignaturePublicKey, SignatureVerifier, Signer,
};
use bouncycastle_ec::p256k1_comb::comb_multiply_base_point;
use bouncycastle_ec::p256k1_scalar::P256K1Scalar;
use bouncycastle_ecdsa::ecdsa_p256k1::ECDSASecp256K1;
use bouncycastle_ecdsa::keys_p256k1::{ECDSASecp256K1PrivateKey, ECDSASecp256K1PublicKey};
use bouncycastle_ecdsa::rfc6979_p256k1::generate_k;
use bouncycastle_hex::decode as hex_decode;
use bouncycastle_sha2::SHA256;

struct Vector {
    d: &'static str,
    msg: &'static [u8],
    k: &'static str,
    r: &'static str,
    s: &'static str,
    ux: &'static str,
    uy: &'static str,
}

const CASE_0: Vector = Vector {
    d: "1201AF823A0A4FE05170CFF294DC13FC115AC6CB3C58FD846EC5C07FF6908E54",
    msg: b"",
    k: "CD78A8941915185A2FE30B89C7C20F0D48D1BE5FCF610FD1BE5685E98ED94D08",
    r: "E9492B86659F129207FD328BE2A8306B7AE55191F281000F233C5D65E538F1BB",
    s: "185A99E918626EC188FE2F2A46F47668DEAE837557BDE9BDFE65216BDC708ABA",
    ux: "1F2193519AB30887B47ADC572A873070806D5D074D8FFAA4CC0972E97F7EE7E9",
    uy: "D637FBA4435057B89F571C622121B125380E7433215130120D8208478A99C547",
};

const CASE_1: Vector = Vector {
    d: "E84644DE88C3D52B0C43F62912F8A9A50A3ECED49C8BE3E693AF8A68F77282BE",
    msg: b"sample",
    k: "28C982F2D681B65DC8CA126205D5864A6ADEC5CC3FCF2B30BF89DCC83AD348F6",
    r: "2E55A9673BCFB47B7F224B3D6C7643113E11954AC6542885B14501DD99ACB72C",
    s: "FB86608F25CA76A8A9961E8DB1A925505A768214512EEC9DB130AE90CAB11017",
    ux: "2BE0FFB78E3BCD795B5B08679C2BC7128B8D8F08803B24B86BBB02209C73ECBD",
    uy: "52D6692A25601A426D88AE8DD507D44763AC213A8A9957A1C4C7646DA8C24E64",
};

const CASE_2: Vector = Vector {
    d: "DE05EF1E2CD6AD8E3FF33516D38E5432EB355B52C8FA65AB0E3605CD9AB15D0C",
    msg: b"test message for RFC 6979 secp256k1 cross-check",
    k: "ECB953D84E41FF5B14980018BF1776BAA052A9249F2A4662294EA1CB2E82EC25",
    r: "405B6868BF58AEFD479747434DFF86B0DF24A71E4EF27179E104757654017D18",
    s: "2EA4999F9BE624D880317A9A06E7E96A4DDAB8CEAE0AF3188249734B81D49520",
    ux: "63A46AA9E76D052ECD957F41253F5CA04E5CC509D6F15426174DB239B61110B8",
    uy: "64FC9614DE8D40FFD02A73F3DA1DBBA240FF49A835D1A84A3BB780EFE29A7A37",
};

const CASE_3: Vector = Vector {
    d: "AC2C81558B8DF6D7A58A40E3AEC4FAA16DFD4602CC3F525D91DA942BF2F44204",
    msg: &[0u8; 32],
    k: "AD82D09CD81EA99ACCBC33E55DD46F0401F2C2FF0A984C33FF6EA2A048FFB103",
    r: "DEE53E887C06D65D6F47C86D7FA947033666FBC57B32F0BE0E47E580DE1BADAB",
    s: "6984C174EFF22BAAC48FE6BCAB4A95927E720894E31304970B2FDB82E3D3CA7E",
    ux: "4E4CEC72F06A61EB1024B996901A31F66BF3D54BB4046AD007AA19747253D58A",
    uy: "7121A6621BFA0C238EB02CFCB7DBCB985A42317C8D5417F03CA8BC72B5148740",
};

const CASE_4: Vector = Vector {
    d: "7E7B91BCA9655DC7AA94AFFD753150AEAF395DDF588590D1CB31A5A541346EC1",
    msg: &[0xffu8; 10],
    k: "429AB5983FEFEF2BA0C58EB6AC48FD5C5E9BB9E283665D360959E377ABCFF2EE",
    r: "9F6DC42E943A9815B5AFF764A79EA85EC5C0584DE5C86E96CEB1C4089146E945",
    s: "D536E3D82BF405282FB688CA3DF3CDD5DD520075735E9A19E8878E0CF4277F70",
    ux: "56587EF8DED5FD2BDE4F00C559C52CB307AD8171568F2028803195E667622833",
    uy: "A8513344175B03B64CDD5A72BE2B9A3434215C740FAB01F6906473CB7806BC4C",
};

const CASES: [&Vector; 5] = [&CASE_0, &CASE_1, &CASE_2, &CASE_3, &CASE_4];

fn bytes32(hex: &str) -> [u8; 32] {
    hex_decode(hex).unwrap().try_into().unwrap()
}

fn public_key_for(v: &Vector) -> ECDSASecp256K1PublicKey {
    let mut uncompressed = [0u8; 65];
    uncompressed[0] = 0x04;
    uncompressed[1..33].copy_from_slice(&bytes32(v.ux));
    uncompressed[33..65].copy_from_slice(&bytes32(v.uy));
    ECDSASecp256K1PublicKey::from_bytes(&uncompressed).unwrap()
}

#[test]
fn public_key_matches_vectors() {
    for v in CASES {
        let d = P256K1Scalar::from_be_bytes(&bytes32(v.d));
        let q = comb_multiply_base_point(&d);
        let (x, y) = q.to_affine().unwrap();
        assert_eq!(
            x.to_limbs(),
            bouncycastle_ec::p256k1_sec1::limbs_from_be_bytes(&bytes32(v.ux)),
            "Qx for d = {}",
            v.d
        );
        assert_eq!(
            y.to_limbs(),
            bouncycastle_ec::p256k1_sec1::limbs_from_be_bytes(&bytes32(v.uy)),
            "Qy for d = {}",
            v.d
        );
    }
}

#[test]
fn generate_k_matches_vectors() {
    for v in CASES {
        let d = P256K1Scalar::from_be_bytes(&bytes32(v.d));
        let h: [u8; 32] = SHA256::default().hash(v.msg)[..32].try_into().unwrap();
        let k = generate_k(&d, &h);
        assert_eq!(k, P256K1Scalar::from_be_bytes(&bytes32(v.k)), "k for message {:?}", v.msg);
    }
}

#[test]
fn deterministic_sign_matches_vectors() {
    for v in CASES {
        let sk = ECDSASecp256K1PrivateKey::from_bytes(&bytes32(v.d)).unwrap();
        let sig = ECDSASecp256K1::sign(&sk, v.msg, None).unwrap();
        let mut expected = [0u8; 64];
        expected[..32].copy_from_slice(&bytes32(v.r));
        expected[32..].copy_from_slice(&bytes32(v.s));
        assert_eq!(sig, expected, "signature for message {:?}", v.msg);
    }
}

#[test]
fn deterministic_signature_verifies() {
    for v in CASES {
        let sk = ECDSASecp256K1PrivateKey::from_bytes(&bytes32(v.d)).unwrap();
        let pk = public_key_for(v);
        let sig = ECDSASecp256K1::sign(&sk, v.msg, None).unwrap();
        ECDSASecp256K1::verify(&pk, v.msg, None, &sig).unwrap();
    }
}
