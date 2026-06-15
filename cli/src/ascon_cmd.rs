use std::io::{Read, Write};
use std::process::exit;
use std::{fs, io};

use bouncycastle::ascon::ascon_aead128::AsconAead128;
use bouncycastle::ascon::ascon_cxof128::AsconCXof128;
use bouncycastle::ascon::ascon_hash256::AsconHash256;
use bouncycastle::ascon::ascon_xof128::AsconXof128;
use bouncycastle::core::traits::{Hash, XOF};
use bouncycastle::hex;

/// Write `data` to stdout, either as hex or raw binary, followed by a newline.
fn emit(data: &[u8], output_hex: bool) {
    if output_hex {
        for b in data.iter() {
            print!("{b:02x}");
        }
    } else {
        io::stdout().write_all(data).unwrap();
    }
    println!();
}

/// Read all of stdin into a Vec.
fn read_stdin() -> Vec<u8> {
    let mut data = Vec::new();
    io::stdin().read_to_end(&mut data).expect("Failed to read from stdin");
    data
}

/// Load a hex string or a binary file into bytes; exits with an error if neither is supplied.
fn load_bytes(value: &Option<String>, value_file: &Option<String>, label: &str) -> Vec<u8> {
    if let Some(file) = value_file {
        fs::read(file).unwrap_or_else(|e| {
            eprintln!("Error: failed to read {label} file: {e}");
            exit(-1)
        })
    } else if let Some(v) = value {
        hex::decode(v).unwrap_or_else(|_| {
            eprintln!("Error: {label} is not valid hex.");
            exit(-1)
        })
    } else {
        eprintln!("Error: {label} must be supplied.");
        exit(-1)
    }
}

fn require_16(bytes: Vec<u8>, label: &str) -> [u8; 16] {
    bytes.try_into().unwrap_or_else(|_: Vec<u8>| {
        eprintln!("Error: {label} must be exactly 16 bytes.");
        exit(-1)
    })
}

/// Ascon-Hash256 of stdin. Streaming update; 256-bit digest.
pub(crate) fn hash256_cmd(output_hex: bool) {
    let mut h = AsconHash256::new();
    let mut buf = [0u8; 1024];
    let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    while bytes_read != 0 {
        h.do_update(&buf[..bytes_read]);
        bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    }
    let out = h.do_final();
    emit(&out, output_hex);
}

/// Ascon-XOF128 of stdin, producing `output_len` bytes. Streaming absorb.
pub(crate) fn xof128_cmd(output_len: usize, output_hex: bool) {
    let mut x = AsconXof128::new();
    let mut buf = [0u8; 1024];
    let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    while bytes_read != 0 {
        x.absorb(&buf[..bytes_read]);
        bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    }
    let out = x.squeeze(output_len);
    emit(&out, output_hex);
}

/// Ascon-CXOF128 of stdin with a hex customization string, producing `output_len` bytes.
pub(crate) fn cxof128_cmd(customization: &Option<String>, output_len: usize, output_hex: bool) {
    let z = match customization {
        Some(v) => hex::decode(v).unwrap_or_else(|_| {
            eprintln!("Error: customization is not valid hex.");
            exit(-1)
        }),
        None => Vec::new(),
    };
    let mut x = AsconCXof128::with_customization(&z);
    let mut buf = [0u8; 1024];
    let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    while bytes_read != 0 {
        x.absorb(&buf[..bytes_read]);
        bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    }
    let out = x.squeeze(output_len);
    emit(&out, output_hex);
}

/// Ascon-AEAD128 of stdin. Encrypts (stdin = plaintext, output = ciphertext||tag) or, with
/// `decrypt`, decrypts (stdin = ciphertext||tag, output = plaintext). Decryption exits with a
/// non-zero status if the authentication tag does not verify.
#[allow(clippy::too_many_arguments)]
pub(crate) fn aead128_cmd(
    key: &Option<String>,
    key_file: &Option<String>,
    nonce: &Option<String>,
    nonce_file: &Option<String>,
    ad: &Option<String>,
    decrypt: bool,
    output_hex: bool,
) {
    let key = require_16(load_bytes(key, key_file, "key"), "key");
    let nonce = require_16(load_bytes(nonce, nonce_file, "nonce"), "nonce");
    let ad_bytes = match ad {
        Some(v) => hex::decode(v).unwrap_or_else(|_| {
            eprintln!("Error: associated data is not valid hex.");
            exit(-1)
        }),
        None => Vec::new(),
    };
    let ad_opt = if ad_bytes.is_empty() { None } else { Some(ad_bytes.as_slice()) };

    let input = read_stdin();

    if decrypt {
        if input.len() < 16 {
            eprintln!("Error: ciphertext is shorter than the 16-byte tag.");
            exit(-1);
        }
        let mut out = vec![0u8; input.len() - 16];
        match AsconAead128::decrypt(&key, &nonce, ad_opt, &input, &mut out) {
            Ok(n) => {
                out.truncate(n);
                emit(&out, output_hex);
            }
            Err(_) => {
                eprintln!("Error: Ascon-AEAD128 authentication failed.");
                exit(-1);
            }
        }
    } else {
        let mut out = vec![0u8; input.len() + 16];
        let n = AsconAead128::encrypt(&key, &nonce, ad_opt, &input, &mut out);
        out.truncate(n);
        emit(&out, output_hex);
    }
}
