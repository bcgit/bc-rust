//! What the scrypt test files share.

use bouncycastle_core::key_material::{KeyMaterial, KeyType};

/// RFC 7914 Section 12: (P, S, log2(N), r, p, DK), with dkLen = 64. N is 16, 1024, 16384 and
/// 1048576.
pub const RFC_7914: [(&[u8], &[u8], u8, u32, u32, &str); 4] = [
    (
        b"",
        b"",
        4,
        1,
        1,
        "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
    ),
    (
        b"password",
        b"NaCl",
        10,
        8,
        16,
        "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
    ),
    (
        b"pleaseletmein",
        b"SodiumChloride",
        14,
        8,
        1,
        "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887",
    ),
    (
        b"pleaseletmein",
        b"SodiumChloride",
        20,
        8,
        1,
        "2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4",
    ),
];

/// A password: bytes of unknown entropy.
pub fn password(bytes: &[u8]) -> KeyMaterial<64> {
    KeyMaterial::<64>::from_bytes_as_type(bytes, KeyType::Unknown).unwrap()
}
