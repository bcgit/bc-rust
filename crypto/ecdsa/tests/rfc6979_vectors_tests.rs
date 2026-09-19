//! RFC 6979 Appendix A.2.5 ("ECDSA, 256 Bits (Prime Field)") known-answer tests: the key pair, the
//! deterministic per-message secret `k`, and the resulting signature `(r, s)`, for `curve: NIST
//! P-256` with SHA-256, messages `"sample"` and `"test"`.

use bouncycastle_core::traits::Hash;
use bouncycastle_core::traits::{
    SignaturePrivateKey, SignaturePublicKey, SignatureVerifier, Signer,
};
use bouncycastle_ec::p256_comb::comb_multiply_base_point;
use bouncycastle_ec::p256_scalar::P256Scalar;
use bouncycastle_ecdsa::ecdsa_p256::ECDSAP256;
use bouncycastle_ecdsa::keys::{ECDSAP256PrivateKey, ECDSAP256PublicKey};
use bouncycastle_ecdsa::rfc6979::generate_k;
use bouncycastle_hex::decode as hex_decode;
use bouncycastle_sha2::SHA256;

const X: &str = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
const UX: &str = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
const UY: &str = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";

struct Vector {
    msg: &'static [u8],
    k: &'static str,
    r: &'static str,
    s: &'static str,
}

const SAMPLE: Vector = Vector {
    msg: b"sample",
    k: "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60",
    r: "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
    s: "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
};

const TEST: Vector = Vector {
    msg: b"test",
    k: "D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0",
    r: "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367",
    s: "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083",
};

fn bytes32(hex: &str) -> [u8; 32] {
    hex_decode(hex).unwrap().try_into().unwrap()
}

fn private_key() -> ECDSAP256PrivateKey {
    ECDSAP256PrivateKey::from_bytes(&bytes32(X)).unwrap()
}

#[test]
fn public_key_matches_vector() {
    let d = P256Scalar::from_be_bytes(&bytes32(X));
    let q = comb_multiply_base_point(&d);
    let (x, y) = q.to_affine().unwrap();
    assert_eq!(x.to_limbs(), bouncycastle_ec::p256_sec1::limbs_from_be_bytes(&bytes32(UX)));
    assert_eq!(y.to_limbs(), bouncycastle_ec::p256_sec1::limbs_from_be_bytes(&bytes32(UY)));
}

#[test]
fn generate_k_matches_vectors() {
    let d = P256Scalar::from_be_bytes(&bytes32(X));
    for v in [&SAMPLE, &TEST] {
        let h: [u8; 32] = SHA256::default().hash(v.msg)[..32].try_into().unwrap();
        let k = generate_k(&d, &h);
        assert_eq!(k, P256Scalar::from_be_bytes(&bytes32(v.k)), "k for message {:?}", v.msg);
    }
}

#[test]
fn deterministic_sign_matches_vectors() {
    let sk = private_key();
    for v in [&SAMPLE, &TEST] {
        let sig = ECDSAP256::sign(&sk, v.msg, None).unwrap();
        let mut expected = [0u8; 64];
        expected[..32].copy_from_slice(&bytes32(v.r));
        expected[32..].copy_from_slice(&bytes32(v.s));
        assert_eq!(sig, expected, "signature for message {:?}", v.msg);
    }
}

#[test]
fn deterministic_signature_verifies() {
    let sk = private_key();
    let mut uncompressed = [0u8; 65];
    uncompressed[0] = 0x04;
    uncompressed[1..33].copy_from_slice(&bytes32(UX));
    uncompressed[33..65].copy_from_slice(&bytes32(UY));
    let pk = ECDSAP256PublicKey::from_bytes(&uncompressed).unwrap();

    for v in [&SAMPLE, &TEST] {
        let sig = ECDSAP256::sign(&sk, v.msg, None).unwrap();
        ECDSAP256::verify(&pk, v.msg, None, &sig).unwrap();
    }
}
