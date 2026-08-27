//! NIST CAVP SHA3VS test vectors for SHA3-224/256/384/512 and SHAKE128/256.
//!
//! Vectors are read from the bc-test-data repo (https://github.com/bcgit/bc-test-data), which must be
//! cloned alongside this repo at "../bc-test-data" (same convention as the mldsa/mlkem/sha2 crates),
//! under `crypto/sha3/{bit-oriented,byte-oriented}/`. If it is not present the tests print a warning
//! and pass vacuously.
//!
//! Bit ordering: unlike the SHA-2 CAVP files, SHA-3 CAVP follows FIPS 202 Appendix B.1 — the excess
//! bits of a `Len`-bit message occupy the *least significant* bits of the final `Msg` byte, and the
//! excess bits of an `Outputlen`-bit SHAKE output occupy the least significant bits of the final
//! `Output` byte (verified over every partial case in the files: all high bits are zero). This is
//! exactly the convention of [`Hash::do_final_partial_bits`] / [`XOF::absorb_last_partial_byte`] /
//! [`XOF::squeeze_partial_byte_final`], so no shifting is needed.
//!
//! Test types exercised (SHA3VS s. 6):
//!
//!  * SHA3 ShortMsg / LongMsg — `Len` (bits), `Msg`, `MD`.
//!  * SHA3 Monte (s. 6.2.2) — `MD0 = Seed`; for i in 1..=1000: `MDi = SHA3(MDi-1)`; report `MD1000`
//!    per COUNT and reseed with it.
//!  * SHAKE ShortMsg / LongMsg — `Len` (bits), `Msg`, `Output` at the fixed `[Outputlen]` of the file.
//!  * SHAKE VariableOut — `Outputlen` (bits, not necessarily a multiple of 8), `Msg`, `Output`.
//!  * SHAKE Monte (s. 6.2.3) — `Outputlen = maxoutlen`; for i in 1..=1000: `Msg = leftmost 128 bits
//!    of the previous Output (zero-padded)`, `Output = SHAKE(Msg, Outputlen)`, then
//!    `Outputlen = minoutbytes + (rightmost 16 bits of Output as big-endian integer) mod
//!    (maxoutbytes - minoutbytes + 1)` bytes; report `Output`/`Outputlen` per COUNT.

use bouncycastle_core::traits::{Hash, XOF};
use bouncycastle_hex as hex;
use bouncycastle_sha3::{SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256};
use std::fs;
use std::path::Path;
use std::sync::Once;

const TEST_DATA_PATH_RELATIVE: &str = "../../../bc-test-data/crypto/sha3";
const TEST_DATA_PATH: &str = "../bc-test-data/crypto/sha3";

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

/// Splits a `Key = value` or `[Key = value]` line from a `.rsp` file.
fn kv(line: &str) -> Option<(&str, &str)> {
    let line = line.trim().trim_start_matches('[').trim_end_matches(']');
    let (k, v) = line.split_once('=')?;
    Some((k.trim(), v.trim()))
}

fn parse_hex(v: &str) -> Vec<u8> {
    hex::decode(v).expect("bad hex")
}

fn parse_num(v: &str) -> usize {
    v.parse().expect("bad number")
}

// ---------------------------------------------------------------------------------------------
// SHA3 (fixed-length) tests
// ---------------------------------------------------------------------------------------------

struct MsgCase {
    len_bits: usize,
    msg: Vec<u8>,
    md: Vec<u8>,
}

/// Parses a SHA3 ShortMsg/LongMsg or SHAKE ShortMsg/LongMsg file into `(Len, Msg, MD|Output)`.
fn parse_msg_file(content: &str) -> Vec<MsgCase> {
    let mut cases = vec![];
    let (mut len_bits, mut msg) = (None, None);
    for line in content.lines() {
        let Some((k, v)) = kv(line) else { continue };
        match k {
            "Len" => len_bits = Some(parse_num(v)),
            "Msg" => msg = Some(parse_hex(v)),
            "MD" | "Output" => cases.push(MsgCase {
                len_bits: len_bits.take().expect("digest without Len"),
                msg: msg.take().expect("digest without Msg"),
                md: parse_hex(v),
            }),
            _ => {}
        }
    }
    cases
}

/// Hashes the first `len_bits` bits of `msg` (FIPS 202 B.1 packing: excess bits in the LSBs).
fn sha3_bits<H: Hash + Default>(msg: &[u8], len_bits: usize) -> Vec<u8> {
    let whole_bytes = len_bits / 8;
    let partial_bits = len_bits % 8;
    if partial_bits == 0 {
        // CAVP writes `Msg = 00` for Len = 0, so always slice rather than using msg directly.
        H::default().hash(&msg[..whole_bytes])
    } else {
        let mut h = H::default();
        h.do_update(&msg[..whole_bytes]);
        h.do_final_partial_bits(msg[whole_bytes], partial_bits).expect("partial_bits is in 1..=7")
    }
}

fn run_sha3_msg_file<H: Hash + Default>(orientation: &str, filename: &str) {
    let Some(content) = get_test_data(orientation, filename) else { return };
    let cases = parse_msg_file(&content);
    assert!(!cases.is_empty(), "{orientation}/{filename}: no test cases parsed");
    let mut partial_cases = 0;
    for c in &cases {
        partial_cases += usize::from(c.len_bits % 8 != 0);
        assert_eq!(
            sha3_bits::<H>(&c.msg, c.len_bits),
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

/// SHA3VS s. 6.2.2 Monte Carlo test for the fixed-length SHA3 functions.
fn run_sha3_monte_file<H: Hash + Default>(orientation: &str, filename: &str) {
    let Some(content) = get_test_data(orientation, filename) else { return };
    let mut seed = None;
    let mut mds = vec![];
    for line in content.lines() {
        let Some((k, v)) = kv(line) else { continue };
        match k {
            "Seed" => seed = Some(parse_hex(v)),
            "MD" => mds.push(parse_hex(v)),
            _ => {}
        }
    }
    let mut md = seed.expect("Monte file without Seed");
    assert_eq!(mds.len(), 100, "{orientation}/{filename}: expected 100 COUNTs");
    for (count, expected) in mds.iter().enumerate() {
        // MD0 = Seed; for i = 1 to 1000: MDi = SHA3(MDi-1); MDj = MD1000; Seed = MDj
        for _ in 1..=1000 {
            md = H::default().hash(&md);
        }
        assert_eq!(&md, expected, "{orientation}/{filename}: COUNT = {count}");
    }
    println!("{orientation}/{filename}: {} counts", mds.len());
}

// ---------------------------------------------------------------------------------------------
// SHAKE tests
// ---------------------------------------------------------------------------------------------

/// SHAKE of the first `len_bits` bits of `msg`, producing `out_bits` bits of output (FIPS 202 B.1
/// packing on both sides: excess bits in the LSBs of the final byte).
fn shake_bits<X: XOF + Default>(msg: &[u8], len_bits: usize, out_bits: usize) -> Vec<u8> {
    let mut x = X::default();
    let (whole, partial) = (len_bits / 8, len_bits % 8);
    x.absorb(&msg[..whole]).expect("absorb before squeeze is infallible");
    if partial != 0 {
        x.absorb_last_partial_byte(msg[whole], partial).expect("partial is in 1..=7");
    }
    let (out_whole, out_partial) = (out_bits / 8, out_bits % 8);
    let mut out = x.squeeze(out_whole);
    if out_partial != 0 {
        out.push(x.squeeze_partial_byte_final(out_partial).expect("out_partial is in 1..=7"));
    }
    out
}

fn run_shake_msg_file<X: XOF + Default>(orientation: &str, filename: &str) {
    let Some(content) = get_test_data(orientation, filename) else { return };
    let out_bits = content
        .lines()
        .filter_map(kv)
        .find(|(k, _)| *k == "Outputlen")
        .map(|(_, v)| parse_num(v))
        .expect("missing [Outputlen = N] header");
    let cases = parse_msg_file(&content);
    assert!(!cases.is_empty(), "{orientation}/{filename}: no test cases parsed");
    let mut partial_cases = 0;
    for c in &cases {
        partial_cases += usize::from(c.len_bits % 8 != 0);
        assert_eq!(c.md.len() * 8, out_bits);
        assert_eq!(
            shake_bits::<X>(&c.msg, c.len_bits, out_bits),
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

struct VarOutCase {
    out_bits: usize,
    msg: Vec<u8>,
    output: Vec<u8>,
}

fn run_shake_variable_out_file<X: XOF + Default>(orientation: &str, filename: &str) {
    let Some(content) = get_test_data(orientation, filename) else { return };
    let mut cases = vec![];
    let (mut out_bits, mut msg) = (None, None);
    for line in content.lines() {
        let Some((k, v)) = kv(line) else { continue };
        match k {
            "Outputlen" => out_bits = Some(parse_num(v)),
            "Msg" => msg = Some(parse_hex(v)),
            "Output" => cases.push(VarOutCase {
                out_bits: out_bits.take().expect("Output without Outputlen"),
                msg: msg.take().expect("Output without Msg"),
                output: parse_hex(v),
            }),
            _ => {}
        }
    }
    assert!(!cases.is_empty(), "{orientation}/{filename}: no test cases parsed");
    let mut partial_cases = 0;
    for (i, c) in cases.iter().enumerate() {
        partial_cases += usize::from(c.out_bits % 8 != 0);
        assert_eq!(c.output.len(), c.out_bits.div_ceil(8));
        assert_eq!(
            shake_bits::<X>(&c.msg, c.msg.len() * 8, c.out_bits),
            c.output,
            "{orientation}/{filename}: COUNT = {i}, Outputlen = {}",
            c.out_bits
        );
    }
    if orientation == "bit-oriented" {
        assert!(partial_cases > 0, "{orientation}/{filename}: expected bit-length outputs");
    }
    println!(
        "{orientation}/{filename}: {} cases ({partial_cases} bit-length outputs)",
        cases.len()
    );
}

/// SHA3VS s. 6.2.3 Monte Carlo test for SHAKE.
fn run_shake_monte_file<X: XOF + Default>(orientation: &str, filename: &str) {
    let Some(content) = get_test_data(orientation, filename) else { return };
    let (mut min_bits, mut max_bits, mut msg) = (None, None, None);
    let mut expected: Vec<(usize, Vec<u8>)> = vec![];
    let mut out_len = None;
    for line in content.lines() {
        let Some((k, v)) = kv(line) else { continue };
        match k {
            "Minimum Output Length (bits)" => min_bits = Some(parse_num(v)),
            "Maximum Output Length (bits)" => max_bits = Some(parse_num(v)),
            "Msg" => msg = Some(parse_hex(v)),
            "Outputlen" => out_len = Some(parse_num(v)),
            "Output" => {
                expected.push((out_len.take().expect("Output without Outputlen"), parse_hex(v)))
            }
            _ => {}
        }
    }
    let min_bytes = min_bits.expect("missing min output length") / 8;
    let max_bytes = max_bits.expect("missing max output length") / 8;
    let range = max_bytes - min_bytes + 1;
    let mut output = msg.expect("Monte file without Msg");
    assert_eq!(output.len(), 16, "seed Msg must be 128 bits");
    assert_eq!(expected.len(), 100, "{orientation}/{filename}: expected 100 COUNTs");

    // Outputlen = maxoutlen (initially)
    let mut out_bytes = max_bytes;
    for (count, (exp_bits, exp_output)) in expected.iter().enumerate() {
        for _ in 1..=1000 {
            // Msg = leftmost 128 bits of Output, zero-padded if Output is shorter
            let mut m = [0u8; 16];
            let n = output.len().min(16);
            m[..n].copy_from_slice(&output[..n]);
            // Output = SHAKE(Msg, Outputlen)
            output = X::default().hash_xof(&m, out_bytes);
            // Rightmost_Output_bits = rightmost 16 bits of Output (big-endian integer)
            let l = output.len();
            let rightmost = u16::from_be_bytes([output[l - 2], output[l - 1]]) as usize;
            // Outputlen = minoutbytes + (Rightmost_Output_bits mod Range)
            out_bytes = min_bytes + (rightmost % range);
        }
        assert_eq!(
            output.len() * 8,
            *exp_bits,
            "{orientation}/{filename}: COUNT = {count} Outputlen"
        );
        assert_eq!(&output, exp_output, "{orientation}/{filename}: COUNT = {count}");
    }
    println!("{orientation}/{filename}: {} counts", expected.len());
}

// ---------------------------------------------------------------------------------------------
// Test matrix
// ---------------------------------------------------------------------------------------------

macro_rules! sha3_cavp_tests {
    ($mod:ident, $hash:ty, $prefix:literal) => {
        mod $mod {
            use super::*;

            #[test]
            fn bit_oriented_short_msg() {
                run_sha3_msg_file::<$hash>("bit-oriented", concat!($prefix, "ShortMsg.rsp"));
            }
            #[test]
            fn bit_oriented_long_msg() {
                run_sha3_msg_file::<$hash>("bit-oriented", concat!($prefix, "LongMsg.rsp"));
            }
            #[test]
            fn bit_oriented_monte() {
                run_sha3_monte_file::<$hash>("bit-oriented", concat!($prefix, "Monte.rsp"));
            }
            #[test]
            fn byte_oriented_short_msg() {
                run_sha3_msg_file::<$hash>("byte-oriented", concat!($prefix, "ShortMsg.rsp"));
            }
            #[test]
            fn byte_oriented_long_msg() {
                run_sha3_msg_file::<$hash>("byte-oriented", concat!($prefix, "LongMsg.rsp"));
            }
            #[test]
            fn byte_oriented_monte() {
                run_sha3_monte_file::<$hash>("byte-oriented", concat!($prefix, "Monte.rsp"));
            }
        }
    };
}

macro_rules! shake_cavp_tests {
    ($mod:ident, $xof:ty, $prefix:literal) => {
        mod $mod {
            use super::*;

            #[test]
            fn bit_oriented_short_msg() {
                run_shake_msg_file::<$xof>("bit-oriented", concat!($prefix, "ShortMsg.rsp"));
            }
            #[test]
            fn bit_oriented_long_msg() {
                run_shake_msg_file::<$xof>("bit-oriented", concat!($prefix, "LongMsg.rsp"));
            }
            #[test]
            fn bit_oriented_variable_out() {
                run_shake_variable_out_file::<$xof>(
                    "bit-oriented",
                    concat!($prefix, "VariableOut.rsp"),
                );
            }
            #[test]
            fn bit_oriented_monte() {
                run_shake_monte_file::<$xof>("bit-oriented", concat!($prefix, "Monte.rsp"));
            }
            #[test]
            fn byte_oriented_short_msg() {
                run_shake_msg_file::<$xof>("byte-oriented", concat!($prefix, "ShortMsg.rsp"));
            }
            #[test]
            fn byte_oriented_long_msg() {
                run_shake_msg_file::<$xof>("byte-oriented", concat!($prefix, "LongMsg.rsp"));
            }
            #[test]
            fn byte_oriented_variable_out() {
                run_shake_variable_out_file::<$xof>(
                    "byte-oriented",
                    concat!($prefix, "VariableOut.rsp"),
                );
            }
            #[test]
            fn byte_oriented_monte() {
                run_shake_monte_file::<$xof>("byte-oriented", concat!($prefix, "Monte.rsp"));
            }
        }
    };
}

sha3_cavp_tests!(sha3_224, SHA3_224, "SHA3_224");
sha3_cavp_tests!(sha3_256, SHA3_256, "SHA3_256");
sha3_cavp_tests!(sha3_384, SHA3_384, "SHA3_384");
sha3_cavp_tests!(sha3_512, SHA3_512, "SHA3_512");
shake_cavp_tests!(shake128, SHAKE128, "SHAKE128");
shake_cavp_tests!(shake256, SHAKE256, "SHAKE256");
