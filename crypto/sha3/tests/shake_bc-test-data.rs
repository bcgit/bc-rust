//! NIST SHA3VS and FIPS 202 example vectors for SHAKE128/256.
//!
//! Vectors are read from the bc-test-data repo (https://github.com/bcgit/bc-test-data), which must be
//! cloned alongside this repo at "../bc-test-data" (same convention as the other `*_bc-test-data.rs`
//! suites). If it is not present the tests print a warning and pass vacuously.
//!
//! Two vector sets are used:
//!
//!  * NIST CAVP SHA3VS, under `crypto/sha3/{bit-oriented,byte-oriented}/`.
//!  * The NIST FIPS 202 example values, `crypto/SHAKETestVectors.txt`.
//!
//! The SHA3VS files pack bit strings per FIPS 202 Appendix B.1 (Algorithms 10/11, h2b/b2h): the
//! excess bits of a `Len`-bit message occupy the *least significant* bits of the final `Msg` byte,
//! first bit in the LSB, and likewise the excess bits of an `Outputlen`-bit SHAKE output occupy the
//! least significant bits of the final `Output` byte. The API takes and returns partial bytes in
//! ASN.1 BIT STRING order (X.690 s. 8.6.2.1: first bit in the MSB, unused low bits), so the harness
//! bit-reverses the final message byte before absorbing it and the final output byte after squeezing
//! it (`u8::reverse_bits`).
//!
//! SHA3VS test types exercised (SHA3VS s. 6):
//!
//!  * ShortMsg / LongMsg — `Len` (bits), `Msg`, `Output` at the fixed `[Outputlen]` of the file.
//!  * VariableOut — `Outputlen` (bits, not necessarily a multiple of 8), `Msg`, `Output`.
//!  * Monte (s. 6.2.3) — `Outputlen = maxoutlen`; for i in 1..=1000: `Msg = leftmost 128 bits
//!    of the previous Output (zero-padded)`, `Output = SHAKE(Msg, Outputlen)`, then
//!    `Outputlen = minoutbytes + (rightmost 16 bits of Output as big-endian integer) mod
//!    (maxoutbytes - minoutbytes + 1)` bytes; report `Output`/`Outputlen` per COUNT.

use bouncycastle_core::traits::{XOF, XOFSqueezer};
use bouncycastle_core_test_framework::test_data_loaders::bc_test_data;
use bouncycastle_hex as hex;
use bouncycastle_sha3::{SHAKE128, SHAKE256};

// ---------------------------------------------------------------------------------------------
// NIST CAVP SHA3VS (`crypto/sha3/{bit-oriented,byte-oriented}/`)
// ---------------------------------------------------------------------------------------------

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

/// SHAKE of the first `len_bits` bits of `msg`, producing `out_bits` bits of output (FIPS 202 B.1
/// packing on both sides: excess bits in the LSBs of the final byte, so the final input byte is
/// bit-reversed into the API's MSB-first order and the final output byte is bit-reversed back).
fn shake_bits<X: XOF + Default>(msg: &[u8], len_bits: usize, out_bits: usize) -> Vec<u8> {
    let mut x = X::default();
    let (whole, partial) = (len_bits / 8, len_bits % 8);
    x.do_update(&msg[..whole]);
    let mut out_stream = if partial != 0 {
        x.into_squeezer_partial_bits(msg[whole].reverse_bits(), partial)
            .expect("partial is in 1..=7")
    } else {
        x.into_squeezer()
    };
    let (out_whole, out_partial) = (out_bits / 8, out_bits % 8);
    let mut out = out_stream.do_output(out_whole + usize::from(out_partial != 0));
    if out_partial != 0 {
        // FIPS 202 B.1: an output of `out_bits` bits occupies the low `out_partial` bits of its
        // final octet, so the unused high bits of the byte the sponge gave us are dropped.
        let last = out.len() - 1;
        out[last] &= (1u8 << out_partial) - 1;
    }
    out
}

fn run_shake_msg_file<X: XOF + Default>(orientation: &str, filename: &str) {
    let Some(content) = bc_test_data(&format!("crypto/sha3/{orientation}"), filename) else {
        return;
    };
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
    let Some(content) = bc_test_data(&format!("crypto/sha3/{orientation}"), filename) else {
        return;
    };
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
    let Some(content) = bc_test_data(&format!("crypto/sha3/{orientation}"), filename) else {
        return;
    };
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
            output = X::default().xof(&m, out_bytes);
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

shake_cavp_tests!(shake128, SHAKE128, "SHAKE128");
shake_cavp_tests!(shake256, SHAKE256, "SHAKE256");

// ---------------------------------------------------------------------------------------------
// NIST FIPS 202 example values (`crypto/SHAKETestVectors.txt`)
// ---------------------------------------------------------------------------------------------

const SAMPLE_OF: &str = " sample of ";
const MSG_HEADER: &str = "Msg as bit string";
const OUTPUT_HEADER: &str = "Output val is";

struct TestCase {
    algorithm: usize,
    bits: usize,
    msg: Vec<u8>,
    output: Vec<u8>,
}

/// Parses a NIST FIPS 202 example-vector file.
fn parse_test_vectors(content: &str) -> Vec<TestCase> {
    let mut test_vectors: Vec<TestCase> = vec![];
    let string_content: Vec<String> = content.lines().map(String::from).collect();

    let mut i = 0;
    while i < string_content.len() {
        if string_content[i].contains(SAMPLE_OF) {
            let header = string_content[i].split(SAMPLE_OF).collect::<Vec<&str>>();

            let algorithm =
                header[0].split("-").collect::<Vec<&str>>()[1].parse::<usize>().unwrap();
            let bits = header[1].split("-").collect::<Vec<&str>>()[0].parse::<usize>().unwrap();

            i += 2;
            if !string_content[i].contains(MSG_HEADER) {
                panic!("Missing header {}", MSG_HEADER);
            }

            i += 1;
            let mut block: Vec<u8> = vec![];
            while string_content[i].len() != 0 {
                if string_content[i].trim().eq("#(empty message)") {
                    i += 1;
                    break;
                }
                let line = string_content[i].replace(" ", "");
                block.append(&mut Vec::from(line));
                i += 1;
            }
            if block.len() != bits {
                panic!("Test vector length mismatch: block len = {}, bits = {}", block.len(), bits)
            }
            let msg = decode_binary(&mut block);

            i += 1;
            if !string_content[i].contains(OUTPUT_HEADER) {
                panic!("Missing header {}", OUTPUT_HEADER);
            }

            i += 1;
            let mut block: Vec<u8> = vec![];
            while string_content[i].len() != 0 {
                let line = string_content[i].replace(" ", "");
                block.append(&mut Vec::from(line));
                i += 1;
            }
            let output = hex::decode(&*String::from_utf8(block).unwrap()).unwrap();

            let v = TestCase { algorithm, bits, msg, output };
            test_vectors.push(v);
        }
        i += 1;
    }

    test_vectors
}

fn decode_binary(block: &mut Vec<u8>) -> Vec<u8> {
    let bits = block.len();
    let full_bytes = bits / 8;
    let total_bytes = (bits + 7) / 8;
    let mut result = vec![0u8; total_bytes];

    // Whole bytes are packed per FIPS 202 Appendix B.1 (Algorithm 11, b2h: message bit 8i + j has
    // weight 2^j in byte i, i.e. the first bit is the LSB), which is how SHA-3 reads a byte-oriented
    // message.
    for i in 0..full_bytes {
        let index = i * 8;
        block[index..(index + 8)].reverse();
        result[i] = parse_binary(&block[index..(index + 8)]);
    }

    // The trailing partial byte is packed the way the API takes it: the remaining message bits
    // in order from the most significant bit down (ASN.1 BIT STRING order, X.690 s. 8.6.2.1),
    // with the unused low bits zero.
    if total_bytes > full_bytes {
        let partial_bits = bits - full_bytes * 8;
        result[full_bytes] = parse_binary(&block[(full_bytes * 8)..]) << (8 - partial_bits);
    }

    result
}

fn parse_binary(block: &[u8]) -> u8 {
    let str = std::str::from_utf8(block).unwrap();
    isize::from_str_radix(str, 2).unwrap() as u8
}

#[test]
fn run_kats() {
    let Some(content) = bc_test_data("crypto", "SHAKETestVectors.txt") else { return };
    run_test_vectors(parse_test_vectors(&content));
}

fn run_test_vectors(test_vectors: Vec<TestCase>) {
    for tc in test_vectors {
        //println!("SHA3-{} {}-bits", &tc.algorithm, &tc.bits);
        //println!("msg {}", hex::encode_upper(&tc.msg));
        //println!("hashes {}", hex::encode_upper(&tc.hashes));

        match tc.algorithm {
            128 => run_test_case(tc, SHAKE128::new()),
            256 => run_test_case(tc, SHAKE256::new()),
            _ => panic!("Unsupported algorithm {}", tc.algorithm),
        }
    }
}

fn run_test_case(tc: TestCase, mut shake: impl XOF) {
    let partial_bits = tc.bits % 8;
    let output: Vec<u8>;

    if partial_bits == 0 {
        shake.do_update(tc.msg.as_slice());
        let mut shake = shake.into_squeezer();
        output = shake.do_output(tc.output.len());
    } else {
        shake.do_update(&tc.msg[..(tc.msg.len() - 1)]);
        let mut shake = shake
            .into_squeezer_partial_bits(tc.msg[tc.msg.len() - 1], partial_bits)
            .expect("partial_bits is in 1..=7");
        output = shake.do_output(tc.output.len());
    }

    assert_eq!(tc.output, output);
}
