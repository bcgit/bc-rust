//! NIST CAVP SHAVS test vectors for SHA-1.
//!
//! Vectors are read from the bc-test-data repo (https://github.com/bcgit/bc-test-data), which must be
//! cloned alongside this repo at "../bc-test-data", under `crypto/sha1/{bit-oriented,byte-oriented}/`:
//! the `SHA1*.rsp` files of NIST's `shabittestvectors.zip` and `shabytetestvectors.zip`. If it is not
//! present, the tests print a warning and pass vacuously.
//!
//! The three SHAVS test types (ShortMsg, LongMsg and Monte) are run as the SHA-2 crate runs them;
//! see `crypto/sha2/tests/sha2_bc-test-data.rs` for what each is.

use bouncycastle_core::traits::HashOneShot;
use bouncycastle_core_test_framework::test_data_loaders::bc_test_data;
use bouncycastle_digest::sha1::SHA1;
use bouncycastle_hex as hex;

/// Splits a `Key = value` line from a `.rsp` file.
fn kv(line: &str) -> Option<(&str, &str)> {
    let (k, v) = line.split_once('=')?;
    Some((k.trim(), v.trim()))
}

struct MsgCase {
    len_bits: usize,
    msg: Vec<u8>,
    md: Vec<u8>,
}

/// Parses a ShortMsg/LongMsg `.rsp` file into `(Len, Msg, MD)` triples.
fn parse_msg_file(content: &str) -> Vec<MsgCase> {
    let mut cases = vec![];
    let (mut len_bits, mut msg) = (None, None);
    for line in content.lines() {
        let Some((k, v)) = kv(line) else { continue };
        match k {
            "Len" => len_bits = Some(v.parse::<usize>().expect("bad Len")),
            "Msg" => msg = Some(hex::decode(v).expect("bad Msg hex")),
            "MD" => cases.push(MsgCase {
                len_bits: len_bits.take().expect("MD without Len"),
                msg: msg.take().expect("MD without Msg"),
                md: hex::decode(v).expect("bad MD hex"),
            }),
            _ => {}
        }
    }
    cases
}

/// Hashes the first `len_bits` bits of `msg` (CAVP MSB-first packing, as the API takes it) with `H`.
fn hash_bits<H: HashOneShot>(msg: &[u8], len_bits: usize) -> Vec<u8> {
    let whole_bytes = len_bits / 8;
    let partial_bits = len_bits % 8;
    if partial_bits == 0 {
        // Note: CAVP writes `Msg = 00` for Len = 0, so always slice rather than using msg directly.
        H::hash(&msg[..whole_bytes])
    } else {
        let mut h = H::default();
        h.do_update(&msg[..whole_bytes]);
        // CAVP left-justifies the trailing bits in the last byte, which is the order the API takes.
        h.do_final_partial_bits(msg[whole_bytes], partial_bits).expect("partial_bits is in 1..=7")
    }
}

fn run_msg_file<H: HashOneShot>(orientation: &str, filename: &str) {
    let Some(content) = bc_test_data(&format!("crypto/sha1/{orientation}"), filename) else {
        return;
    };
    let cases = parse_msg_file(&content);
    assert!(!cases.is_empty(), "{orientation}/{filename}: no test cases parsed");
    let mut partial_cases = 0;
    for c in &cases {
        if c.len_bits % 8 != 0 {
            partial_cases += 1;
        }
        assert_eq!(
            hash_bits::<H>(&c.msg, c.len_bits),
            c.md,
            "{orientation}/{filename}: Len = {}",
            c.len_bits
        );
        // Whole-byte messages are also fed through the streaming API in uneven chunks.
        if c.len_bits % 8 == 0 {
            let mut h = H::default();
            for chunk in c.msg[..c.len_bits / 8].chunks(37) {
                h.do_update(chunk);
            }
            assert_eq!(
                h.do_final(),
                c.md,
                "{orientation}/{filename}: Len = {} (streamed)",
                c.len_bits
            );
        }
    }
    if orientation == "bit-oriented" {
        assert!(partial_cases > 0, "{orientation}/{filename}: expected bit-length cases");
    }
    println!("{orientation}/{filename}: {} cases ({partial_cases} bit-length)", cases.len());
}

struct MonteFile {
    seed: Vec<u8>,
    mds: Vec<Vec<u8>>,
}

/// Parses a Monte `.rsp` file into the seed and the per-COUNT expected digests.
fn parse_monte_file(content: &str) -> MonteFile {
    let mut seed = None;
    let mut mds = vec![];
    for line in content.lines() {
        let Some((k, v)) = kv(line) else { continue };
        match k {
            "Seed" => seed = Some(hex::decode(v).expect("bad Seed hex")),
            "MD" => mds.push(hex::decode(v).expect("bad MD hex")),
            _ => {}
        }
    }
    MonteFile { seed: seed.expect("Monte file without Seed"), mds }
}

/// SHAVS s. 6.4 Monte Carlo test.
fn run_monte_file<H: HashOneShot>(orientation: &str, filename: &str) {
    let Some(content) = bc_test_data(&format!("crypto/sha1/{orientation}"), filename) else {
        return;
    };
    let MonteFile { mut seed, mds } = parse_monte_file(&content);
    assert_eq!(mds.len(), 100, "{orientation}/{filename}: expected 100 COUNTs");
    for (count, expected) in mds.iter().enumerate() {
        // MD0 = MD1 = MD2 = Seed
        let mut md = [seed.clone(), seed.clone(), seed.clone()];
        // for i = 3 to 1002: Mi = MDi-3 || MDi-2 || MDi-1; MDi = SHA(Mi)
        for _ in 3..=1002 {
            let mut m = Vec::with_capacity(3 * seed.len());
            m.extend_from_slice(&md[0]);
            m.extend_from_slice(&md[1]);
            m.extend_from_slice(&md[2]);
            let next = H::hash(&m);
            md.rotate_left(1);
            md[2] = next;
        }
        // MDj = MD1002; Seed = MDj
        assert_eq!(&md[2], expected, "{orientation}/{filename}: COUNT = {count}");
        seed = md[2].clone();
    }
    println!("{orientation}/{filename}: {} counts", mds.len());
}

macro_rules! cavp_tests {
    ($mod:ident, $hash:ty, $prefix:literal) => {
        mod $mod {
            use super::*;

            #[test]
            fn bit_oriented_short_msg() {
                run_msg_file::<$hash>("bit-oriented", concat!($prefix, "ShortMsg.rsp"));
            }
            #[test]
            fn bit_oriented_long_msg() {
                run_msg_file::<$hash>("bit-oriented", concat!($prefix, "LongMsg.rsp"));
            }
            #[test]
            fn bit_oriented_monte() {
                run_monte_file::<$hash>("bit-oriented", concat!($prefix, "Monte.rsp"));
            }
            #[test]
            fn byte_oriented_short_msg() {
                run_msg_file::<$hash>("byte-oriented", concat!($prefix, "ShortMsg.rsp"));
            }
            #[test]
            fn byte_oriented_long_msg() {
                run_msg_file::<$hash>("byte-oriented", concat!($prefix, "LongMsg.rsp"));
            }
            #[test]
            fn byte_oriented_monte() {
                run_monte_file::<$hash>("byte-oriented", concat!($prefix, "Monte.rsp"));
            }
        }
    };
}

cavp_tests!(sha1, SHA1, "SHA1");
