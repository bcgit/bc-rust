use std::io;
use std::io::{Read, Write};

use bouncycastle::hex;
use bouncycastle::base64;

pub(crate) fn hex_encode_cmd() {
    // Stream from stdin to stdout in chunks of 1 kb
    let mut buf: [u8; 1024] = [0u8; 1024];
    let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    while bytes_read != 0 {
        io::stdout().write_all(
            hex::encode(&buf[..bytes_read]).as_bytes()
        ).expect("Failed to write to stdout");

        bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    }
}

pub(crate) fn hex_decode_cmd() {
    // Stream from stdin to stdout in chunks of 1 kb
    let mut buf: [u8; 1024] = [0u8; 1024];
    let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    while bytes_read != 0 {
        let chunk_str: String = String::from_utf8(
            Vec::from(&buf[..bytes_read])
        ).expect("Input was not valid utf8.");

        io::stdout().write_all(
            &*hex::decode(chunk_str.as_str()).expect("Input was not valid hex.")
        ).expect("Failed to write to stdout");

        bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    }
}

pub(crate) fn base64_encode_cmd() {
    let mut encoder = base64::Base64Encoder::new();
    // Stream from stdin to stdout in chunks of 1 kb
    let mut buf: [u8; 1024] = [0u8; 1024];
    let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    while bytes_read != 0 {
        io::stdout().write_all(
            encoder.do_update(&buf[..bytes_read]).as_bytes()
        ).expect("Failed to write to stdout");

        bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    }
}

pub(crate) fn base64_decode_cmd() {
    // Stream from stdin to stdout in chunks of 1 kb
    let mut buf: [u8; 1024] = [0u8; 1024];
    let mut decoder = base64::Base64Decoder::new(true);
    let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    while bytes_read != 0 {
        let chunk_str: String = String::from_utf8(
            Vec::from(&buf[..bytes_read])
        ).expect("Input was not valid utf8.");

        io::stdout().write_all(
            decoder.do_update(chunk_str.as_str()).expect("Input was not valid base64.").as_slice()
        ).expect("Failed to write to stdout");

        bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    }
}