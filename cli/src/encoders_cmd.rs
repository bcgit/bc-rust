use std::io;
use std::io::Read;
use std::process::exit;

use bouncycastle::base64;
use bouncycastle::hex;

pub(crate) fn hex_encode_cmd() {
    // Stream from stdin to stdout in chunks of 1 kb. Hex has no state to carry: every byte
    // becomes exactly two characters, so the chunking is invisible.
    let mut buf = [0u8; 1024];
    loop {
        let n = io::stdin().read(&mut buf).unwrap_or_else(|e| {
            eprintln!("Error: failed to read from stdin: {e}");
            exit(-1);
        });
        if n == 0 {
            return;
        }
        crate::helpers::write_stdout(hex::encode(&buf[..n]).as_bytes());
    }
}

/// Streams hex from stdin to raw bytes on stdout.
///
/// A read from a pipe can end anywhere, including between the two digits of one byte, so each
/// chunk is decoded only as far as it forms whole bytes and the remainder is carried into the next
/// one. [`hex::decode`] already skips whitespace and `\x` prefixes, which is what lets the output
/// of `-x` (hex plus a newline) and `\x41`-style dumps be piped straight in.
pub(crate) fn hex_decode_cmd() {
    fn fail(e: hex::HexError) -> ! {
        eprintln!("Error: input is not valid hex: {e:?}");
        exit(-1);
    }

    let mut buf = [0u8; 1024];
    let mut pending: Vec<u8> = Vec::new();
    loop {
        let n = io::stdin().read(&mut buf).unwrap_or_else(|e| {
            eprintln!("Error: failed to read from stdin: {e}");
            exit(-1);
        });
        if n == 0 {
            break;
        }
        pending.extend_from_slice(&buf[..n]);

        // A trailing backslash may be the start of a `\x` that continues in the next chunk, so
        // backslashes at the end are never handed to the decoder on their own.
        let mut decodable = pending.len();
        while pending[..decodable].last() == Some(&b'\\') {
            decodable -= 1;
        }
        let decoded = match hex::decode(&pending[..decodable]) {
            Ok(bytes) => bytes,
            Err(hex::HexError::OddLengthInput) => {
                // The chunk ended between two digits. Hold the unpaired digit -- the last hex
                // digit present, since everything after it is skippable -- back for the next chunk.
                let last_digit = pending[..decodable]
                    .iter()
                    .rposition(|b| b.is_ascii_hexdigit())
                    .expect("OddLengthInput means at least one digit was seen");
                decodable = last_digit;
                hex::decode(&pending[..decodable]).unwrap_or_else(|e| fail(e))
            }
            Err(e) => fail(e),
        };
        crate::helpers::write_stdout(&decoded);
        pending.drain(..decodable);
    }

    // Whatever is still held back at end of input has to decode on its own: an unpaired digit or
    // a dangling backslash here is a malformed input, not a chunk boundary.
    if pending.last() == Some(&b'\\') {
        eprintln!("Error: input is not valid hex: it ends in a lone backslash");
        exit(-1);
    }
    if !pending.is_empty() {
        crate::helpers::write_stdout(&hex::decode(&pending).unwrap_or_else(|e| fail(e)));
    }
}

/// Streams raw bytes from stdin to base64 on stdout.
///
/// [`base64::Base64Encoder`] holds an incomplete 3-byte group across `do_update` calls, so the
/// chunking of the input is invisible; `do_final` at end of input emits the last group with its
/// padding, which is what makes the output decodable by anything.
pub(crate) fn base64_encode_cmd() {
    let mut encoder = base64::Base64Encoder::new();
    let mut buf = [0u8; 1024];
    loop {
        let n = io::stdin().read(&mut buf).unwrap_or_else(|e| {
            eprintln!("Error: failed to read from stdin: {e}");
            exit(-1);
        });
        if n == 0 {
            crate::helpers::write_stdout(encoder.do_final(&[]).as_bytes());
            return;
        }
        crate::helpers::write_stdout(encoder.do_update(&buf[..n]).as_bytes());
    }
}

/// Streams base64 from stdin to raw bytes on stdout.
///
/// [`base64::Base64Decoder`] is a streaming decoder, so a read from a pipe may end anywhere: it
/// carries a partial quartet across `do_update` calls itself. What it will not do is accept
/// padding through `do_update`; a chunk containing `=` is handed to `do_final` instead, which
/// also tolerates missing padding, so input that simply ends is finished the same way.
pub(crate) fn base64_decode_cmd() {
    fn fail(e: base64::Base64Error) -> ! {
        eprintln!("Error: input is not valid base64: {e:?}");
        exit(-1);
    }
    fn read_chunk(buf: &mut [u8]) -> usize {
        io::stdin().read(buf).unwrap_or_else(|e| {
            eprintln!("Error: failed to read from stdin: {e}");
            exit(-1);
        })
    }

    let mut buf = [0u8; 1024];
    let mut decoder = base64::Base64Decoder::new(true);
    loop {
        let n = read_chunk(&mut buf);
        if n == 0 {
            // End of input with no padding seen: finish whatever partial block is held.
            crate::helpers::write_stdout(&decoder.do_final(&[]).unwrap_or_else(|e| fail(e)));
            return;
        }
        match decoder.do_update(&buf[..n]) {
            Ok(bytes) => crate::helpers::write_stdout(&bytes),
            Err(base64::Base64Error::PaddingEncounteredDuringDoUpdate) => {
                // The chunk holds the padded final block; the decoder has not consumed it.
                crate::helpers::write_stdout(
                    &decoder.do_final(&buf[..n]).unwrap_or_else(|e| fail(e)),
                );
                // Padding ends the message. Anything but whitespace after it is not base64.
                loop {
                    let n = read_chunk(&mut buf);
                    if n == 0 {
                        return;
                    }
                    if buf[..n].iter().any(|b| !b.is_ascii_whitespace()) {
                        eprintln!("Error: input is not valid base64: data follows the padding");
                        exit(-1);
                    }
                }
            }
            Err(e) => fail(e),
        }
    }
}
