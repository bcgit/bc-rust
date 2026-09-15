//! RFC 6979 Appendix A.2.7 ("ECDSA, 521 Bits (Prime Field)") known-answer tests: the key pair, the
//! deterministic per-message secret `k`, and the resulting signature `(r, s)`, for `curve: NIST
//! P-521` with SHA-512, messages `"sample"` and `"test"`. Values extracted programmatically from
//! a fresh copy of the RFC text (not hand-transcribed) to avoid the line-wrap transcription error
//! this crate's P-384 vectors hit; each is 131 hex digits in the RFC (`ceil(521/4)`), zero-padded
//! here with a leading `0` to the fixed 132-digit (66-byte) SEC 1 width.

use bouncycastle_core::traits::Hash;
use bouncycastle_core::traits::{
    SignaturePrivateKey, SignaturePublicKey, SignatureVerifier, Signer,
};
use bouncycastle_ec::p521_comb::comb_multiply_base_point;
use bouncycastle_ec::p521_scalar::P521Scalar;
use bouncycastle_ecdsa::ecdsa_p521::ECDSAP521;
use bouncycastle_ecdsa::keys_p521::{ECDSAP521PrivateKey, ECDSAP521PublicKey};
use bouncycastle_ecdsa::rfc6979_p521::generate_k;
use bouncycastle_hex::decode as hex_decode;
use bouncycastle_sha2::SHA512;

const X: &str = "00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538";
const UX: &str = "01894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4";
const UY: &str = "00493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5";

struct Vector {
    msg: &'static [u8],
    k: &'static str,
    r: &'static str,
    s: &'static str,
}

const SAMPLE: Vector = Vector {
    msg: b"sample",
    k: "01DAE2EA071F8110DC26882D4D5EAE0621A3256FC8847FB9022E2B7D28E6F10198B1574FDD03A9053C08A1854A168AA5A57470EC97DD5CE090124EF52A2F7ECBFFD3",
    r: "00C328FAFCBD79DD77850370C46325D987CB525569FB63C5D3BC53950E6D4C5F174E25A1EE9017B5D450606ADD152B534931D7D4E8455CC91F9B15BF05EC36E377FA",
    s: "00617CCE7CF5064806C467F678D3B4080D6F1CC50AF26CA209417308281B68AF282623EAA63E5B5C0723D8B8C37FF0777B1A20F8CCB1DCCC43997F1EE0E44DA4A67A",
};

const TEST: Vector = Vector {
    msg: b"test",
    k: "016200813020EC986863BEDFC1B121F605C1215645018AEA1A7B215A564DE9EB1B38A67AA1128B80CE391C4FB71187654AAA3431027BFC7F395766CA988C964DC56D",
    r: "013E99020ABF5CEE7525D16B69B229652AB6BDF2AFFCAEF38773B4B7D08725F10CDB93482FDCC54EDCEE91ECA4166B2A7C6265EF0CE2BD7051B7CEF945BABD47EE6D",
    s: "01FBD0013C674AA79CB39849527916CE301C66EA7CE8B80682786AD60F98F7E78A19CA69EFF5C57400E3B3A0AD66CE0978214D13BAF4E9AC60752F7B155E2DE4DCE3",
};

fn bytes66(hex: &str) -> [u8; 66] {
    hex_decode(hex).unwrap().try_into().unwrap()
}

fn private_key() -> ECDSAP521PrivateKey {
    ECDSAP521PrivateKey::from_bytes(&bytes66(X)).unwrap()
}

#[test]
fn public_key_matches_vector() {
    let d = P521Scalar::from_be_bytes(&bytes66(X));
    let q = comb_multiply_base_point(&d);
    let (x, y) = q.to_affine().unwrap();
    assert_eq!(x.to_limbs(), bouncycastle_ec::p521_sec1::limbs_from_be_bytes(&bytes66(UX)));
    assert_eq!(y.to_limbs(), bouncycastle_ec::p521_sec1::limbs_from_be_bytes(&bytes66(UY)));
}

#[test]
fn generate_k_matches_vectors() {
    let d = P521Scalar::from_be_bytes(&bytes66(X));
    for v in [&SAMPLE, &TEST] {
        let h: [u8; 64] = SHA512::default().hash(v.msg)[..64].try_into().unwrap();
        let k = generate_k(&d, &h);
        assert_eq!(k, P521Scalar::from_be_bytes(&bytes66(v.k)), "k for message {:?}", v.msg);
    }
}

#[test]
fn deterministic_sign_matches_vectors() {
    let sk = private_key();
    for v in [&SAMPLE, &TEST] {
        let sig = ECDSAP521::sign(&sk, v.msg, None).unwrap();
        let mut expected = [0u8; 132];
        expected[..66].copy_from_slice(&bytes66(v.r));
        expected[66..].copy_from_slice(&bytes66(v.s));
        assert_eq!(sig, expected, "signature for message {:?}", v.msg);
    }
}

#[test]
fn deterministic_signature_verifies() {
    let sk = private_key();
    let mut uncompressed = [0u8; 133];
    uncompressed[0] = 0x04;
    uncompressed[1..67].copy_from_slice(&bytes66(UX));
    uncompressed[67..133].copy_from_slice(&bytes66(UY));
    let pk = ECDSAP521PublicKey::from_bytes(&uncompressed).unwrap();

    for v in [&SAMPLE, &TEST] {
        let sig = ECDSAP521::sign(&sk, v.msg, None).unwrap();
        ECDSAP521::verify(&pk, v.msg, None, &sig).unwrap();
    }
}
