use bouncycastle::core::traits::{Hash, XOF, XOFOutput};
use std::io;
use std::io::{Read, Write};

use bouncycastle::hex;
use bouncycastle::sha3::{
    CSHAKE128, CSHAKE256, PARALLELHASH128, PARALLELHASH256, SHA3_224, SHA3_256, SHA3_384, SHA3_512,
    SHAKE128, SHAKE256, TUPLEHASH128, TUPLEHASH256,
};
use std::process::exit;

pub(crate) fn sha3_cmd(bit_len: usize, output_hex: bool) {
    match bit_len {
        224 => do_sha3(SHA3_224::new(), output_hex),
        256 => do_sha3(SHA3_256::new(), output_hex),
        384 => do_sha3(SHA3_384::new(), output_hex),
        512 => do_sha3(SHA3_512::new(), output_hex),
        _ => panic!("Unsupported algorithm: SHA3-{}", bit_len),
    }
}

fn do_sha3(mut sha3: impl Hash, output_hex: bool) {
    let mut buf: [u8; 1024] = [0u8; 1024];

    // read from stdin
    let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    while bytes_read != 0 {
        sha3.do_update(&buf[..bytes_read]);
        bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    }

    let out = sha3.do_final();

    if output_hex {
        for b in out.iter() {
            print!("{b:02x}");
        }
    } else {
        io::stdout().write(&out).unwrap();
    }
    println!();
}

pub(crate) fn shake_cmd(bit_len: usize, output_len: usize, output_hex: bool) {
    match bit_len {
        128 => do_shake(SHAKE128::new(), output_len, output_hex),
        256 => do_shake(SHAKE256::new(), output_len, output_hex),
        _ => panic!("Unsupported algorithm: SHAKE-{}", bit_len),
    }
}

/// cSHAKE (NIST SP 800-185 Sec 3): SHAKE bound to a function name and a customization string.
///
/// Both strings default to empty, and with both empty cSHAKE is defined to be plain SHAKE
/// (Sec 3.3 step 1), so `cshake128 32` and `shake128 32` agree.
pub(crate) fn cshake_cmd(
    bit_len: usize,
    output_len: usize,
    function_name: &Option<String>,
    customization: &Option<String>,
    output_hex: bool,
) {
    let n = function_name.as_deref().unwrap_or("").as_bytes();
    let s = customization.as_deref().unwrap_or("").as_bytes();
    match bit_len {
        128 => do_shake(CSHAKE128::new(n, s), output_len, output_hex),
        256 => do_shake(CSHAKE256::new(n, s), output_len, output_hex),
        _ => panic!("Unsupported algorithm: cSHAKE-{}", bit_len),
    }
}

/// TupleHash (NIST SP 800-185 Sec 5): hashes a *tuple* of strings unambiguously.
///
/// The tuple comes from repeated `--element` flags, each a hex string. With none given, stdin is
/// hashed as a single-element tuple -- which is not the same as hashing those bytes with SHAKE,
/// because the element is length-prefixed.
pub(crate) fn tuplehash_cmd(
    bit_len: usize,
    output_len: usize,
    elements: &[String],
    customization: &Option<String>,
    output_hex: bool,
) {
    let s = customization.as_deref().unwrap_or("").as_bytes();

    // Either the tuple came from flags, or stdin is the single element.
    let tuple: Vec<Vec<u8>> = if elements.is_empty() {
        vec![read_stdin()]
    } else {
        elements
            .iter()
            .map(|e| {
                hex::decode(e).unwrap_or_else(|_| {
                    eprintln!("Error: --element must be hex.");
                    exit(-1);
                })
            })
            .collect()
    };
    let refs: Vec<&[u8]> = tuple.iter().map(|v| v.as_slice()).collect();

    let out = match bit_len {
        128 => TUPLEHASH128::new(s, output_len).hash_tuple(&refs),
        256 => TUPLEHASH256::new(s, output_len).hash_tuple(&refs),
        _ => panic!("Unsupported algorithm: TupleHash-{bit_len}"),
    };
    write_out(&out, output_hex);
}

/// ParallelHash (NIST SP 800-185 Sec 6): hashes stdin in `block_size`-byte blocks.
///
/// The block size is part of the function, not a tuning knob -- the same input under a different
/// block size gives an unrelated hash, so it must match on both sides.
pub(crate) fn parallelhash_cmd(
    bit_len: usize,
    output_len: usize,
    block_size: usize,
    customization: &Option<String>,
    output_hex: bool,
) {
    if block_size == 0 {
        eprintln!("Error: --block-size must be greater than zero (SP 800-185 Sec 6.2).");
        exit(-1);
    }
    let s = customization.as_deref().unwrap_or("").as_bytes();
    match bit_len {
        128 => {
            let mut p = PARALLELHASH128::new(block_size, s, output_len);
            stream_stdin(|chunk| p.do_update(chunk));
            write_out(&p.do_final(), output_hex);
        }
        256 => {
            let mut p = PARALLELHASH256::new(block_size, s, output_len);
            stream_stdin(|chunk| p.do_update(chunk));
            write_out(&p.do_final(), output_hex);
        }
        _ => panic!("Unsupported algorithm: ParallelHash-{bit_len}"),
    }
}

/// Reads all of stdin. Used where the whole input must be held anyway (a tuple element).
fn read_stdin() -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        let n = io::stdin().read(&mut buf).expect("Failed to read from stdin");
        if n == 0 {
            return out;
        }
        out.extend_from_slice(&buf[..n]);
    }
}

/// Feeds stdin to `sink` in 1 KiB pieces, so a long input is never held in memory.
fn stream_stdin(mut sink: impl FnMut(&[u8])) {
    let mut buf = [0u8; 1024];
    loop {
        let n = io::stdin().read(&mut buf).expect("Failed to read from stdin");
        if n == 0 {
            return;
        }
        sink(&buf[..n]);
    }
}

/// Writes the digest as raw bytes or hex, with the trailing newline the other commands emit.
fn write_out(out: &[u8], output_hex: bool) {
    if output_hex {
        for b in out {
            print!("{b:02x}");
        }
    } else {
        io::stdout().write_all(out).expect("Failed to write to stdout");
    }
    println!();
}

fn do_shake(mut shake: impl XOF, output_len: usize, output_hex: bool) {
    let mut buf: [u8; 1024] = [0u8; 1024];
    // read from stdin
    let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    while bytes_read != 0 {
        shake.do_update(&buf[..bytes_read]);
        bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    }

    let mut shake = shake.into_output();
    let out = shake.do_output(output_len);
    if output_hex {
        for b in out.iter() {
            print!("{b:02x}");
        }
    } else {
        io::stdout().write(&out).unwrap();
    }
    println!();
}
