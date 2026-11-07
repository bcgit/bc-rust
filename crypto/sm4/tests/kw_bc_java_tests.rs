//! SM4-KW and SM4-KWP against Bouncy Castle Java.
//!
//! bc-java publishes no SM4 key-wrap vectors, so these were produced on 2026-11-06 with its
//! `RFC3394WrapEngine(new SM4Engine())` and `RFC5649WrapEngine(new SM4Engine())`
//! (bcprov-jdk18on 1.87-SNAPSHOT): `init(true, new KeyParameter(kek))` then `wrap`, with the
//! unwrap checked there too. The plaintext of `len` bytes is `i * 0x9D` at byte `i`, as in
//! `kw_reference_tests.rs`, which pins the same answers against RFC 3394 and RFC 5649 written out
//! over the raw permutation; this file asserts agreement with the source implementation in its
//! own terms.

use bouncycastle_cipher::modes::{KW, KWP};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{FromKeyMaterial, KeyUnwrappingKey, KeyWrappingKey};
use bouncycastle_hex as hex;
use bouncycastle_sm4::{KEY_LEN, SM4Key};

/// `KeyParameter(Hex.decode(..))`, the KEK of every case.
const KEK: &str = "0123456789abcdeffedcba9876543210";

/// `(plaintext, RFC3394WrapEngine output)` for 16, 24, 32 and 64 bytes.
const KW_VECTORS: [(&str, &str); 4] = [
    ("009d3ad77411ae4be88522bf5cf99633", "87187bd3525ca0fe9a53f9fe26a8fbdf4de538405edc78f8"),
    (
        "009d3ad77411ae4be88522bf5cf99633d06d0aa744e17e1b",
        "7a8c028ee8708001d5874024247b8bec278bebb527d8d52b063bca2935105183",
    ),
    (
        "009d3ad77411ae4be88522bf5cf99633d06d0aa744e17e1bb855f28f2cc96603",
        "2e4637da989f5321c230a058dade89c37d3323b7140b473ac7f0165062e06a35e51658bae618cc59",
    ),
    (
        "009d3ad77411ae4be88522bf5cf99633d06d0aa744e17e1bb855f28f2cc96603a03dda7714b14eeb8825c25ffc9936d3700daa47e4811ebb58f5922fcc6906a3",
        "25c66134a1dd90471eadbff6b7139ceb11e130f04bcb13b948a4409e5f0af4cf92478f5d4141382d327979a87abe2b3e7c7d79107a6295362be4c805a2e55e251cb2336452df38d9",
    ),
];

/// `(plaintext, RFC5649WrapEngine output)` for 1, 7, 8, 9, 20 and 64 bytes: the single-block
/// cases, the first that needs the wrapping function, an unaligned and an aligned long one.
const KWP_VECTORS: [(&str, &str); 6] = [
    ("00", "0482fb1dd5e8c08df5a3092af1ef0436"),
    ("009d3ad77411ae", "44b4235e92b28ff70836d1faf1859b62"),
    ("009d3ad77411ae4b", "21807178bab0016e4a84d674e6b2640a"),
    ("009d3ad77411ae4be8", "ac875f63c59d28e09a2cb0e98bfffa69649bff518f343287"),
    (
        "009d3ad77411ae4be88522bf5cf99633d06d0aa7",
        "f08f8252da5987d259211cdc3cabafb3915228e220488c936c836fcbdc420374",
    ),
    (
        "009d3ad77411ae4be88522bf5cf99633d06d0aa744e17e1bb855f28f2cc96603a03dda7714b14eeb8825c25ffc9936d3700daa47e4811ebb58f5922fcc6906a3",
        "3b5031dfc613e9a7f6d062072388c6fe1409d8bd0efce9acc582a155028e83950f033d5b6d1ebdddbfbb11aeab6bc5d5d950dfcde7b1d8bb229f994bd7c6e368f4312b4bff22cfe3",
    ),
];

fn material() -> KeyMaterial<KEY_LEN> {
    let kek: [u8; KEY_LEN] = hex::decode(KEK).expect("valid hex").try_into().expect("16 bytes");
    KeyMaterial::<KEY_LEN>::from_bytes_as_type(&kek, KeyType::SymmetricCipherKey)
        .expect("a valid symmetric cipher key")
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

#[test]
fn rfc3394_wrap_engine_over_sm4() {
    let kek = SM4Key::<KW>::from_key_material(&material()).expect("a valid SM4 KEK");
    for (pt, ct) in KW_VECTORS {
        assert_eq!(kek.wrap(&unhex(pt)).unwrap(), unhex(ct), "wrap of {} bytes", pt.len() / 2);
        assert_eq!(kek.unwrap(&unhex(ct)).unwrap(), unhex(pt), "unwrap to {} bytes", pt.len() / 2);
    }
}

#[test]
fn rfc5649_wrap_engine_over_sm4() {
    let kek = SM4Key::<KWP>::from_key_material(&material()).expect("a valid SM4 KEK");
    for (pt, ct) in KWP_VECTORS {
        assert_eq!(kek.wrap(&unhex(pt)).unwrap(), unhex(ct), "wrap of {} bytes", pt.len() / 2);
        assert_eq!(kek.unwrap(&unhex(ct)).unwrap(), unhex(pt), "unwrap to {} bytes", pt.len() / 2);
    }
}
