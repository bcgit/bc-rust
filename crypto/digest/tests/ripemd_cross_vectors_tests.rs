//! Cross-check against BC Java 1.84's four RIPEMD digests (and, for RIPEMD-128 and RIPEMD-160,
//! the designers' reference C code, which agrees with it) on 262 messages, 1048 vectors over the
//! four functions: every length from 0 to 255 bytes and a few longer ones, so that every padding
//! residue and both one- and two-block finals are covered. See `ripemd_cross_vectors_data/mod.rs`.

#[path = "ripemd_cross_vectors_data/mod.rs"]
mod cross_vectors_data;

use bouncycastle_core::hex;
use bouncycastle_core::traits::HashOneShot;
use bouncycastle_digest::ripemd::{RIPEMD128, RIPEMD160, RIPEMD256, RIPEMD320};
use cross_vectors_data::VECTORS;

/// The xorshift32 stream the vectors were generated from.
fn stream(len: usize) -> Vec<u8> {
    let mut s: u32 = 0x5249_5045;
    (0..len)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            (s >> 24) as u8
        })
        .collect()
}

fn digest(name: &str, msg: &[u8]) -> Vec<u8> {
    match name {
        "RIPEMD128" => RIPEMD128::hash(msg),
        "RIPEMD160" => RIPEMD160::hash(msg),
        "RIPEMD256" => RIPEMD256::hash(msg),
        "RIPEMD320" => RIPEMD320::hash(msg),
        other => panic!("unknown digest {other}"),
    }
}

#[test]
fn all_cross_vectors() {
    let data = stream(4096);
    let mut counts = [0usize; 4];
    for (name, n, expected) in VECTORS {
        assert_eq!(digest(name, &data[..n]), hex::decode(expected).unwrap(), "{name} n={n}");
        counts[match name {
            "RIPEMD128" => 0,
            "RIPEMD160" => 1,
            "RIPEMD256" => 2,
            _ => 3,
        }] += 1;
    }
    assert_eq!(counts, [262; 4]);
}

/// The stream's first bytes, so a regenerated data module cannot silently use another seed.
#[test]
fn stream_is_the_documented_one() {
    // From a separate (Python) run of xorshift32 on the seed 0x52495045.
    assert_eq!(stream(8), [0x70, 0x74, 0x9a, 0xc0, 0xb2, 0x5b, 0x16, 0xef]);
    // And the empty-message entries are the designers' published values.
    assert_eq!(VECTORS[0], ("RIPEMD128", 0, "cdf26213a150dc3ecb610f18f6b38b46"));
    assert!(VECTORS.contains(&("RIPEMD160", 0, "9c1185a5c5e9fc54612808977ee8f548b2258d31")));
}
