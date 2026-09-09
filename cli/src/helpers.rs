use bouncycastle::core::key_material::{
    KeyMaterial, KeyMaterialTrait, KeyType, do_hazardous_operations,
};
use bouncycastle::core::traits::{Hash, SecurityStrength, XOF};
use bouncycastle::hex;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::process::exit;

/// Reads either bin or hex
pub(crate) fn read_from_file(filename: &str) -> Vec<u8> {
    let file = File::open(&filename);
    if file.is_ok() {
        let mut buf = Vec::<u8>::new();
        match file.unwrap().read_to_end(&mut buf) {
            Ok(_bytes_read) => {
                // try hex decoding it
                match hex::decode(&buf) {
                    Ok(decoded) => decoded,
                    Err(_) => {
                        // it's not hex, so return it raw
                        buf
                    }
                }
            }
            Err(_) => {
                eprintln!("Error: couldn't open file '{}'", &filename);
                exit(-1);
            }
        }
    } else {
        eprintln!("Error: couldn't open file '{}'", &filename);
        exit(-1);
    }
}

/// Reads either bin or hex
pub(crate) fn read_from_file_or_stdin(filename: &Option<String>) -> Vec<u8> {
    if filename.is_some() {
        // This already reads either bin or hex
        return read_from_file(filename.as_ref().unwrap());
    }

    let mut buf = Vec::<u8>::new();
    io::stdin().read_to_end(&mut buf).expect("Failed to read from stdin");

    // try hex decoding it
    match hex::decode(&buf) {
        Ok(decoded) => decoded,
        Err(_) => {
            // it's not hex, so return it raw
            buf
        }
    }
}

pub(crate) fn write_bytes_or_hex(bytes: &[u8], output_hex: bool) {
    // first flush stdout to ensure any buffered data is written
    io::stdout().flush().unwrap();
    if output_hex {
        for b in bytes.iter() {
            print!("{b:02x}");
        }
    } else {
        io::stdout().write_all(bytes).unwrap();
    }
}

pub(crate) fn write_bytes_or_hex_to_file(bytes: &[u8], filename: &str, output_hex: bool) {
    let mut file = File::create(filename).expect("Failed to create file");
    if output_hex {
        for b in bytes.iter() {
            file.write_all(format!("{b:02x}").as_bytes()).unwrap();
        }
    } else {
        file.write_all(bytes).unwrap();
    }
}

/// Loads it as either hex or bytes
pub(crate) fn parse_seed<const SEED_LEN: usize>(bytes: &[u8]) -> Result<KeyMaterial<SEED_LEN>, ()> {
    let bytes = if bytes.len() == 65 { &bytes[..64] } else { bytes };

    // try decoding it as hex first
    let seed_bytes: [u8; SEED_LEN] = match &hex::decode(&bytes) {
        Ok(decoded_bytes) => {
            if decoded_bytes.len() < SEED_LEN || decoded_bytes.len() > SEED_LEN + 1 {
                // it was valid hex, but the wrong length
                return Err(());
            }
            decoded_bytes[..SEED_LEN].try_into().unwrap()
        }
        Err(_) => {
            // it's not hex, so take the fist SEED_LEN bytes of the raw binary
            if bytes.len() < SEED_LEN || bytes.len() > SEED_LEN + 1 {
                return Err(());
            }
            bytes[..SEED_LEN].try_into().unwrap()
        }
    };

    // TODO: Verify that all error conditions have been checked
    let mut seed = KeyMaterial::<SEED_LEN>::from_bytes_as_type(&seed_bytes, KeyType::Seed).unwrap();

    if seed.key_type() == KeyType::Zeroized || seed.security_strength() < SecurityStrength::_256bit
    {
        eprintln!(
            "Warning: low entropy seed provided. We'll still process it, but it may be insecure."
        );
        do_hazardous_operations(&mut seed, |seed| {
            seed.set_key_type(KeyType::Seed)?;
            seed.set_security_strength(SecurityStrength::_256bit)
        })
        .unwrap();
    }
    Ok(seed)
}

/// Stream stdin through a [`Hash`] and write the digest to stdout (hex or binary), followed by a
/// newline. Used by both the SHA-3 and Ascon-Hash256 subcommands.
pub(crate) fn stream_hash(mut hasher: impl Hash, output_hex: bool) {
    let mut buf: [u8; 1024] = [0u8; 1024];

    let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    while bytes_read != 0 {
        hasher.do_update(&buf[..bytes_read]);
        bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    }

    let out = hasher.do_final();
    write_bytes_or_hex(&out, output_hex);
    println!();
}

/// Stream stdin through an [`XOF`] and squeeze `output_len` bytes to stdout (hex or binary),
/// followed by a newline. Used by both the SHAKE and Ascon-XOF128/CXOF128 subcommands.
pub(crate) fn stream_xof(mut xof: impl XOF, output_len: usize, output_hex: bool) {
    let mut buf: [u8; 1024] = [0u8; 1024];

    let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    while bytes_read != 0 {
        xof.absorb(&buf[..bytes_read]).expect("absorb before squeeze is infallible");
        bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    }

    let out = xof.squeeze(output_len);
    write_bytes_or_hex(&out, output_hex);
    println!();
}
