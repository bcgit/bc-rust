//! RFC 6979 Appendix A.2.6 ("ECDSA, 384 Bits (Prime Field)") known-answer tests: the
//! key pair and, for each of SHA-224, SHA-256, SHA-384 and SHA-512 (SHA-1 is not implemented
//! here), the deterministic signature `(r, s)` over the messages `"sample"` and `"test"`, as
//! [`ECDSA<P384, H>`] signs them. The appendix's `k` is not asserted directly: it is the one
//! value that gives this `r`, so the signature pins it.

use bouncycastle_core::signature_key::{DeterministicSigningKey, VerifyingKey};
use bouncycastle_core::traits::{Algorithm, SignaturePrivateKey, SignaturePublicKey};
use bouncycastle_ec::P384;
use bouncycastle_ecdsa::ecdsa::ECDSA;
use bouncycastle_ecdsa::ecdsa::EcdsaHash;
use bouncycastle_ecdsa::keys::{ECDSAPrivateKey, ECDSAPublicKey};
use bouncycastle_ecdsa::keys_common::DerivePublicKey;
use bouncycastle_hex::decode as hex_decode;
use bouncycastle_sha2::{SHA224, SHA256, SHA384, SHA512};

const SCALAR_LEN: usize = 48;
const SIG_LEN: usize = 96;

const X: &str = "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5";
const UX: &str = "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13";
const UY: &str = "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720";

/// `(message, r, s)` for one hash.
struct Vector {
    msg: &'static [u8],
    r: &'static str,
    s: &'static str,
}

const SHA224_VECTORS: [Vector; 2] = [
    Vector {
        msg: b"sample",
        r: "42356E76B55A6D9B4631C865445DBE54E056D3B3431766D0509244793C3F9366450F76EE3DE43F5A125333A6BE060122",
        s: "9DA0C81787064021E78DF658F2FBB0B042BF304665DB721F077A4298B095E4834C082C03D83028EFBF93A3C23940CA8D",
    },
    Vector {
        msg: b"test",
        r: "E8C9D0B6EA72A0E7837FEA1D14A1A9557F29FAA45D3E7EE888FC5BF954B5E62464A9A817C47FF78B8C11066B24080E72",
        s: "07041D4A7A0379AC7232FF72E6F77B6DDB8F09B16CCE0EC3286B2BD43FA8C6141C53EA5ABEF0D8231077A04540A96B66",
    },
];

const SHA256_VECTORS: [Vector; 2] = [
    Vector {
        msg: b"sample",
        r: "21B13D1E013C7FA1392D03C5F99AF8B30C570C6F98D4EA8E354B63A21D3DAA33BDE1E888E63355D92FA2B3C36D8FB2CD",
        s: "F3AA443FB107745BF4BD77CB3891674632068A10CA67E3D45DB2266FA7D1FEEBEFDC63ECCD1AC42EC0CB8668A4FA0AB0",
    },
    Vector {
        msg: b"test",
        r: "6D6DEFAC9AB64DABAFE36C6BF510352A4CC27001263638E5B16D9BB51D451559F918EEDAF2293BE5B475CC8F0188636B",
        s: "2D46F3BECBCC523D5F1A1256BF0C9B024D879BA9E838144C8BA6BAEB4B53B47D51AB373F9845C0514EEFB14024787265",
    },
];

const SHA384_VECTORS: [Vector; 2] = [
    Vector {
        msg: b"sample",
        r: "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C81A648152E44ACF96E36DD1E80FABE46",
        s: "99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94FA329C145786E679E7B82C71A38628AC8",
    },
    Vector {
        msg: b"test",
        r: "8203B63D3C853E8D77227FB377BCF7B7B772E97892A80F36AB775D509D7A5FEB0542A7F0812998DA8F1DD3CA3CF023DB",
        s: "DDD0760448D42D8A43AF45AF836FCE4DE8BE06B485E9B61B827C2F13173923E06A739F040649A667BF3B828246BAA5A5",
    },
];

const SHA512_VECTORS: [Vector; 2] = [
    Vector {
        msg: b"sample",
        r: "ED0959D5880AB2D869AE7F6C2915C6D60F96507F9CB3E047C0046861DA4A799CFE30F35CC900056D7C99CD7882433709",
        s: "512C8CCEEE3890A84058CE1E22DBC2198F42323CE8ACA9135329F03C068E5112DC7CC3EF3446DEFCEB01A45C2667FDD5",
    },
    Vector {
        msg: b"test",
        r: "A0D5D090C9980FAF3C2CE57B7AE951D31977DD11C775D314AF55F76C676447D06FB6495CD21B4B6E340FC236584FB277",
        s: "976984E59B4C77B0E8E4460DCA3D9F20E07B9BB1F63BEEFAF576F6B2E8B224634A2092CD3792E0159AD9CEE37659C736",
    },
];

fn bytes(hex: &str) -> [u8; SCALAR_LEN] {
    hex_decode(hex).unwrap().try_into().unwrap()
}

fn key_pair<H: EcdsaHash>() -> (ECDSAPublicKey<P384, H>, ECDSAPrivateKey<P384, H>) {
    let sk = ECDSAPrivateKey::<P384, H>::from_bytes(&bytes(X)).unwrap();
    let mut uncompressed = [0u8; 1 + 2 * SCALAR_LEN];
    uncompressed[0] = 0x04;
    uncompressed[1..1 + SCALAR_LEN].copy_from_slice(&bytes(UX));
    uncompressed[1 + SCALAR_LEN..].copy_from_slice(&bytes(UY));
    let pk = ECDSAPublicKey::<P384, H>::from_bytes(&uncompressed).unwrap();
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
        assert_eq!(sig, expected, "{} over {:?}", ECDSA::<P384, H>::ALG_NAME, v.msg);
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
