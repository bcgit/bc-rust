use std::io::{self, Read};
use std::process::exit;

use bouncycastle::ascon::ascon_aead128::AsconAead128;
use bouncycastle::ascon::ascon_cxof128::AsconCXof128;
use bouncycastle::ascon::ascon_hash256::AsconHash256;
use bouncycastle::ascon::ascon_xof128::AsconXof128;
use bouncycastle::core::key_material::{
    KeyMaterial, KeyMaterialTrait, KeyType, do_hazardous_operations,
};
use bouncycastle::core::traits::SecurityStrength;
use bouncycastle::hex;

use crate::helpers;

/// Load a hex string or a binary/hex file into bytes; exits with an error if neither is supplied.
fn load_bytes(value: &Option<String>, value_file: &Option<String>, label: &str) -> Vec<u8> {
    if let Some(file) = value_file {
        helpers::read_from_file(file)
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

/// Build a `KeyMaterial<16>` for the AEAD key, warning (and forcing usable metadata) only if the
/// key turns out to be low-entropy (e.g. all-zero), the same way `helpers::parse_seed` does.
fn load_key_material(key_bytes: &[u8; 16]) -> KeyMaterial<16> {
    let mut key =
        KeyMaterial::<16>::from_bytes_as_type(key_bytes, KeyType::SymmetricCipherKey).unwrap();
    if key.key_type() == KeyType::Zeroized || key.security_strength() < SecurityStrength::_128bit {
        eprintln!(
            "Warning: low entropy key provided. We'll still process it, but it may be insecure."
        );
        do_hazardous_operations(&mut key, |k| {
            k.set_key_type(KeyType::SymmetricCipherKey)?;
            k.set_security_strength(SecurityStrength::_128bit)
        })
        .unwrap();
    }
    key
}

/// Ascon-Hash256 of stdin. Streaming update; 256-bit digest.
pub(crate) fn hash256_cmd(output_hex: bool) {
    helpers::stream_hash(AsconHash256::new(), output_hex);
}

/// Ascon-XOF128 of stdin, producing `output_len` bytes. Streaming absorb.
pub(crate) fn xof128_cmd(output_len: usize, output_hex: bool) {
    helpers::stream_xof(AsconXof128::new(), output_len, output_hex);
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
    let x = AsconCXof128::with_customization(&z).unwrap_or_else(|_| {
        eprintln!("Error: customization string exceeds 256 bytes.");
        exit(-1)
    });
    helpers::stream_xof(x, output_len, output_hex);
}

/// Ascon-AEAD128 of stdin. Encrypts (stdin = plaintext, output = ciphertext||tag) or, with
/// `decrypt`, decrypts (stdin = ciphertext||tag, output = plaintext). Decryption exits with a
/// non-zero status if the authentication tag does not verify.
///
/// Both directions stream stdin in fixed-size chunks (no full-buffer slurp). Encryption emits
/// ciphertext eagerly, before the tag is known; note that in the decryption direction, plaintext
/// is likewise emitted before the tag has been checked, so it should not be treated as
/// authentic until this command exits with status 0 (see the crate's "Security Considerations").
pub(crate) fn aead128_cmd(
    key: &Option<String>,
    key_file: &Option<String>,
    nonce: &Option<String>,
    nonce_file: &Option<String>,
    ad: &Option<String>,
    decrypt: bool,
    output_hex: bool,
) {
    let key = load_key_material(&require_16(load_bytes(key, key_file, "key"), "key"));
    let nonce = require_16(load_bytes(nonce, nonce_file, "nonce"), "nonce");
    let ad_bytes = match ad {
        Some(v) => hex::decode(v).unwrap_or_else(|_| {
            eprintln!("Error: associated data is not valid hex.");
            exit(-1)
        }),
        None => Vec::new(),
    };
    let ad_opt = if ad_bytes.is_empty() { None } else { Some(ad_bytes.as_slice()) };

    if decrypt {
        aead128_decrypt_stream(&key, &nonce, ad_opt, output_hex);
    } else {
        aead128_encrypt_stream(&key, &nonce, ad_opt, output_hex);
    }
}

fn aead128_encrypt_stream(
    key: &KeyMaterial<16>,
    nonce: &[u8; 16],
    ad_opt: Option<&[u8]>,
    output_hex: bool,
) {
    let mut cipher = AsconAead128::new(key, nonce, ad_opt, true).unwrap();
    let mut buf = [0u8; 1024];
    loop {
        let n = io::stdin().read(&mut buf).expect("Failed to read from stdin");
        if n == 0 {
            break;
        }
        cipher.do_encrypt_update(&mut buf[..n]);
        helpers::write_bytes_or_hex(&buf[..n], output_hex);
    }
    let tag = cipher.do_encrypt_final();
    helpers::write_bytes_or_hex(&tag, output_hex);
    if output_hex {
        println!();
    }
}

/// Decrypts a stream whose final 16 bytes are the tag, which is only known once EOF is reached.
/// Holds back at most 16 bytes (the current tag candidate) in `tail`; every other byte is
/// released to `do_decrypt_update` (and written out) as soon as it is known not to be part of the
/// tag.
fn aead128_decrypt_stream(
    key: &KeyMaterial<16>,
    nonce: &[u8; 16],
    ad_opt: Option<&[u8]>,
    output_hex: bool,
) {
    const TAG_LEN: usize = 16;
    const CHUNK: usize = 1024;

    let mut cipher = AsconAead128::new(key, nonce, ad_opt, false).unwrap();
    let mut tail = [0u8; TAG_LEN];
    let mut tail_len = 0usize;
    let mut work = [0u8; TAG_LEN + CHUNK];

    loop {
        let n = io::stdin().read(&mut work[TAG_LEN..]).expect("Failed to read from stdin");
        if n == 0 {
            break;
        }
        work[TAG_LEN - tail_len..TAG_LEN].copy_from_slice(&tail[..tail_len]);
        let total = tail_len + n;

        if total > TAG_LEN {
            let releasable = total - TAG_LEN;
            let window = &mut work[TAG_LEN - tail_len..TAG_LEN - tail_len + total];
            cipher.do_decrypt_update(&mut window[..releasable]);
            helpers::write_bytes_or_hex(&window[..releasable], output_hex);
            tail.copy_from_slice(&window[releasable..releasable + TAG_LEN]);
            tail_len = TAG_LEN;
        } else {
            tail[..total].copy_from_slice(&work[TAG_LEN - tail_len..TAG_LEN - tail_len + total]);
            tail_len = total;
        }
    }

    if tail_len < TAG_LEN {
        eprintln!("Error: ciphertext is shorter than the 16-byte tag.");
        exit(-1);
    }
    match cipher.do_decrypt_final(&tail) {
        Ok(()) => {
            if output_hex {
                println!();
            }
        }
        Err(_) => {
            eprintln!("Error: Ascon-AEAD128 authentication failed.");
            exit(-1);
        }
    }
}
