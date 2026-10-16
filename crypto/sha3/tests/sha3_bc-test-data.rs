//! NIST SHA3VS and FIPS 202 example vectors for SHA3-224/256/384/512.
//!
//! Vectors are read from the bc-test-data repo (https://github.com/bcgit/bc-test-data), which must be
//! cloned alongside this repo at "../bc-test-data" (same convention as the other `*_bc-test-data.rs`
//! suites). If it is not present the tests print a warning and pass vacuously.
//!
//! Two vector sets are used:
//!
//!  * NIST CAVP SHA3VS, under `crypto/sha3/{bit-oriented,byte-oriented}/`.
//!  * The NIST FIPS 202 example values, `crypto/SHA3TestVectors.txt`.
//!
//! The SHA3VS files pack bit strings per FIPS 202 Appendix B.1 (Algorithms 10/11, h2b/b2h): the
//! excess bits of a `Len`-bit message occupy the *least significant* bits of the final `Msg` byte,
//! first bit in the LSB. The API takes partial bytes in ASN.1 BIT STRING order (X.690 s. 8.6.2.1:
//! first bit in the MSB, unused low bits), so the harness bit-reverses the final message byte
//! before absorbing it (`u8::reverse_bits`).
//!
//! SHA3VS test types exercised (SHA3VS s. 6):
//!
//!  * ShortMsg / LongMsg — `Len` (bits), `Msg`, `MD`.
//!  * Monte (s. 6.2.2) — `MD0 = Seed`; for i in 1..=1000: `MDi = SHA3(MDi-1)`; report `MD1000`
//!    per COUNT and reseed with it.

use bouncycastle_core::traits::Hash;
use bouncycastle_core_test_framework::test_data_loaders::bc_test_data;
use bouncycastle_hex as hex;
use bouncycastle_sha3::{SHA3_224, SHA3_256, SHA3_384, SHA3_512};

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

/// Hashes the first `len_bits` bits of `msg` (FIPS 202 B.1 packing: excess bits in the LSBs, so the
/// final byte is bit-reversed into the API's MSB-first order).
fn sha3_bits<H: Hash + Default>(msg: &[u8], len_bits: usize) -> Vec<u8> {
    let whole_bytes = len_bits / 8;
    let partial_bits = len_bits % 8;
    if partial_bits == 0 {
        // CAVP writes `Msg = 00` for Len = 0, so always slice rather than using msg directly.
        H::default().hash(&msg[..whole_bytes])
    } else {
        let mut h = H::default();
        h.do_update(&msg[..whole_bytes]);
        h.do_final_partial_bits(msg[whole_bytes].reverse_bits(), partial_bits)
            .expect("partial_bits is in 1..=7")
    }
}

fn run_sha3_msg_file<H: Hash + Default>(orientation: &str, filename: &str) {
    let Some(content) = bc_test_data(&format!("crypto/sha3/{orientation}"), filename) else {
        return;
    };
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
    let Some(content) = bc_test_data(&format!("crypto/sha3/{orientation}"), filename) else {
        return;
    };
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

sha3_cavp_tests!(sha3_224, SHA3_224, "SHA3_224");
sha3_cavp_tests!(sha3_256, SHA3_256, "SHA3_256");
sha3_cavp_tests!(sha3_384, SHA3_384, "SHA3_384");
sha3_cavp_tests!(sha3_512, SHA3_512, "SHA3_512");

// ---------------------------------------------------------------------------------------------
// NIST FIPS 202 example values (`crypto/SHA3TestVectors.txt`)
// ---------------------------------------------------------------------------------------------

const SAMPLE_OF: &str = " sample of ";
const MSG_HEADER: &str = "Msg as bit string";
const HASH_HEADER: &str = "Hash val is";

struct TestCase {
    algorithm: usize,
    bits: usize,
    msg: Vec<u8>,
    hash: Vec<u8>,
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
            if !string_content[i].contains(HASH_HEADER) {
                panic!("Missing header {}", HASH_HEADER);
            }

            i += 1;
            let mut block: Vec<u8> = vec![];
            while string_content[i].len() != 0 {
                let line = string_content[i].replace(" ", "");
                block.append(&mut Vec::from(line));
                i += 1;
            }
            let hash = hex::decode(&*String::from_utf8(block).unwrap()).unwrap();

            let v = TestCase { algorithm, bits, msg, hash };
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
    let Some(content) = bc_test_data("crypto", "SHA3TestVectors.txt") else { return };
    run_test_vectors(parse_test_vectors(&content));
}

fn run_test_vectors(test_vectors: Vec<TestCase>) {
    for tc in test_vectors {
        match tc.algorithm {
            224 => run_test_case(tc, SHA3_224::new()),
            256 => run_test_case(tc, SHA3_256::new()),
            384 => run_test_case(tc, SHA3_384::new()),
            512 => run_test_case(tc, SHA3_512::new()),
            _ => panic!("Unsupported algorithm {}", tc.algorithm),
        }
    }
}

fn run_test_case(tc: TestCase, mut sha3: impl Hash) {
    let partial_bits = tc.bits % 8;
    let output: Vec<u8>;

    if partial_bits == 0 {
        sha3.do_update(tc.msg.as_slice());
        output = sha3.do_final();
    } else {
        sha3.do_update(&tc.msg[..(tc.msg.len() - 1)]);
        output = sha3.do_final_partial_bits(tc.msg[tc.msg.len() - 1], partial_bits).unwrap();
    }

    assert_eq!(tc.hash, output);
}
