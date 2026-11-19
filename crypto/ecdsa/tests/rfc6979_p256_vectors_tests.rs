//! RFC 6979 Appendix A.2.5 ("ECDSA, 256 Bits (Prime Field)") known-answer tests: the
//! key pair and, for each of SHA-224, SHA-256, SHA-384 and SHA-512 (SHA-1 is not implemented
//! here), the deterministic signature `(r, s)` over the messages `"sample"` and `"test"`, as
//! [`ECDSA<P256, H>`] signs them. The appendix's `k` is not asserted directly: it is the one
//! value that gives this `r`, so the signature pins it.

use bouncycastle_core::signature_key::{DeterministicSigningKey, VerifyingKey};
use bouncycastle_core::traits::{Algorithm, SignaturePrivateKey, SignaturePublicKey};
use bouncycastle_ec::P256;
use bouncycastle_ecdsa::ecdsa::ECDSA;
use bouncycastle_ecdsa::ecdsa::EcdsaHash;
use bouncycastle_ecdsa::keys::{ECDSAPrivateKey, ECDSAPublicKey};
use bouncycastle_ecdsa::keys_common::DerivePublicKey;
use bouncycastle_hex::decode as hex_decode;
use bouncycastle_sha2::{SHA224, SHA256, SHA384, SHA512};

const SCALAR_LEN: usize = 32;
const SIG_LEN: usize = 64;

const X: &str = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
const UX: &str = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
const UY: &str = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";

/// `(message, r, s)` for one hash.
struct Vector {
    msg: &'static [u8],
    r: &'static str,
    s: &'static str,
}

const SHA224_VECTORS: [Vector; 2] = [
    Vector {
        msg: b"sample",
        r: "53B2FFF5D1752B2C689DF257C04C40A587FABABB3F6FC2702F1343AF7CA9AA3F",
        s: "B9AFB64FDC03DC1A131C7D2386D11E349F070AA432A4ACC918BEA988BF75C74C",
    },
    Vector {
        msg: b"test",
        r: "C37EDB6F0AE79D47C3C27E962FA269BB4F441770357E114EE511F662EC34A692",
        s: "C820053A05791E521FCAAD6042D40AEA1D6B1A540138558F47D0719800E18F2D",
    },
];

const SHA256_VECTORS: [Vector; 2] = [
    Vector {
        msg: b"sample",
        r: "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
        s: "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
    },
    Vector {
        msg: b"test",
        r: "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367",
        s: "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083",
    },
];

const SHA384_VECTORS: [Vector; 2] = [
    Vector {
        msg: b"sample",
        r: "0EAFEA039B20E9B42309FB1D89E213057CBF973DC0CFC8F129EDDDC800EF7719",
        s: "4861F0491E6998B9455193E34E7B0D284DDD7149A74B95B9261F13ABDE940954",
    },
    Vector {
        msg: b"test",
        r: "83910E8B48BB0C74244EBDF7F07A1C5413D61472BD941EF3920E623FBCCEBEB6",
        s: "8DDBEC54CF8CD5874883841D712142A56A8D0F218F5003CB0296B6B509619F2C",
    },
];

const SHA512_VECTORS: [Vector; 2] = [
    Vector {
        msg: b"sample",
        r: "8496A60B5E9B47C825488827E0495B0E3FA109EC4568FD3F8D1097678EB97F00",
        s: "2362AB1ADBE2B8ADF9CB9EDAB740EA6049C028114F2460F96554F61FAE3302FE",
    },
    Vector {
        msg: b"test",
        r: "461D93F31B6540894788FD206C07CFA0CC35F46FA3C91816FFF1040AD1581A04",
        s: "39AF9F15DE0DB8D97E72719C74820D304CE5226E32DEDAE67519E840D1194E55",
    },
];

fn bytes(hex: &str) -> [u8; SCALAR_LEN] {
    hex_decode(hex).unwrap().try_into().unwrap()
}

fn key_pair<H: EcdsaHash>() -> (ECDSAPublicKey<P256, H>, ECDSAPrivateKey<P256, H>) {
    let sk = ECDSAPrivateKey::<P256, H>::from_bytes(&bytes(X)).unwrap();
    let mut uncompressed = [0u8; 1 + 2 * SCALAR_LEN];
    uncompressed[0] = 0x04;
    uncompressed[1..1 + SCALAR_LEN].copy_from_slice(&bytes(UX));
    uncompressed[1 + SCALAR_LEN..].copy_from_slice(&bytes(UY));
    let pk = ECDSAPublicKey::<P256, H>::from_bytes(&uncompressed).unwrap();
    (pk, sk)
}

#[test]
fn public_key_matches_vector() {
    let (pk, sk) = key_pair::<SHA256>();
    assert_eq!(sk.derive_pk(), pk, "U = xG");
}

/// The deterministic signature under `H` is the appendix's `(r, s)`, and verifies.
fn check<H: EcdsaHash>(vectors: &[Vector]) {
    let (pk, sk) = key_pair::<H>();
    for v in vectors {
        let sig = sk.sign_deterministic(v.msg, None).unwrap();
        let mut expected = [0u8; SIG_LEN];
        expected[..SCALAR_LEN].copy_from_slice(&bytes(v.r));
        expected[SCALAR_LEN..].copy_from_slice(&bytes(v.s));
        assert_eq!(sig, expected, "{} over {:?}", ECDSA::<P256, H>::ALG_NAME, v.msg);
        pk.verify(v.msg, None, &sig).unwrap();
    }
}

#[test]
fn sha224() {
    check::<SHA224>(&SHA224_VECTORS);
}

#[test]
fn sha256() {
    check::<SHA256>(&SHA256_VECTORS);
}

#[test]
fn sha384() {
    check::<SHA384>(&SHA384_VECTORS);
}

#[test]
fn sha512() {
    check::<SHA512>(&SHA512_VECTORS);
}
