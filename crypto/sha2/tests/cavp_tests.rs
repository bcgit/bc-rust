//! NIST CAVP SHAVS test vectors for SHA-224/256/384/512.
//!
//! Vectors are read from the bc-test-data repo (https://github.com/bcgit/bc-test-data), which must be
//! cloned alongside this repo at "../bc-test-data" (same convention as the mldsa/mlkem/sha3 crates),
//! under `crypto/sha2/{bit-oriented,byte-oriented}/`. If it is not present the tests print a warning
//! and pass vacuously.
//!
//! Three SHAVS test types are exercised (SHAVS s. 6):
//!
//!  * ShortMsg / LongMsg — `Len` (bits), `Msg`, `MD`. In the bit-oriented files `Len` is not a
//!    multiple of 8 for most cases; the trailing bits are packed MSB-first in the final `Msg` byte
//!    (SHAVS s. 6.2, "the message is left-justified"), whereas [`Hash::do_final_partial_bits`] takes
//!    them in the least significant bits, hence the `>> (8 - n)` when feeding the last byte.
//!  * Monte — SHAVS s. 6.4 pseudo-random message test: `MD0 = MD1 = MD2 = Seed`,
//!    `MDi = SHA(MDi-3 || MDi-2 || MDi-1)` for i in 3..=1002, `MD = MD1002`, then reseed with `MD`
//!    for the next COUNT. 100 counts per file.
//!
//! SHA-512/224 and SHA-512/256 files are present in bc-test-data but those algorithms are not
//! implemented by this crate, so they are not exercised here.

use bouncycastle_core::traits::Hash;
use bouncycastle_hex as hex;
use bouncycastle_sha2::{SHA224, SHA256, SHA384, SHA512};
use std::fs;
use std::path::Path;
use std::sync::Once;

const TEST_DATA_PATH_RELATIVE: &str = "../../../bc-test-data/crypto/sha2";
const TEST_DATA_PATH: &str = "../bc-test-data/crypto/sha2";

static TEST_DATA_CHECK: Once = Once::new();

/// Returns the contents of `<orientation>/<filename>` from bc-test-data, or `None` (after a one-time
/// warning) if the repo is not checked out.
fn get_test_data(orientation: &str, filename: &str) -> Option<String> {
    let dir = [TEST_DATA_PATH_RELATIVE, TEST_DATA_PATH].into_iter().find(|d| Path::new(d).exists());
    TEST_DATA_CHECK.call_once(|| match dir {
        Some(d) => println!("bc-test-data found at: {d:?}"),
        None => println!("WARNING: bc-test-data directory not found; CAVP tests will be skipped"),
    });
    let dir = dir?;
    Some(
        fs::read_to_string(format!("{dir}/{orientation}/{filename}"))
            .expect("failed to read CAVP test vector file"),
    )
}

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

/// Hashes the first `len_bits` bits of `msg` (CAVP MSB-first packing) with `H`.
fn hash_bits<H: Hash + Default>(msg: &[u8], len_bits: usize) -> Vec<u8> {
    let whole_bytes = len_bits / 8;
    let partial_bits = len_bits % 8;
    if partial_bits == 0 {
        // Note: CAVP writes `Msg = 00` for Len = 0, so always slice rather than using msg directly.
        H::default().hash(&msg[..whole_bytes])
    } else {
        let mut h = H::default();
        h.do_update(&msg[..whole_bytes]);
        // CAVP left-justifies the trailing bits in the last byte; the API wants them in the LSBs.
        let partial_byte = msg[whole_bytes] >> (8 - partial_bits);
        h.do_final_partial_bits(partial_byte, partial_bits).expect("partial_bits is in 1..=7")
    }
}

fn run_msg_file<H: Hash + Default>(orientation: &str, filename: &str) {
    let Some(content) = get_test_data(orientation, filename) else { return };
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
fn run_monte_file<H: Hash + Default>(orientation: &str, filename: &str) {
    let Some(content) = get_test_data(orientation, filename) else { return };
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
            let next = H::default().hash(&m);
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

cavp_tests!(sha224, SHA224, "SHA224");
cavp_tests!(sha256, SHA256, "SHA256");
cavp_tests!(sha384, SHA384, "SHA384");
cavp_tests!(sha512, SHA512, "SHA512");
