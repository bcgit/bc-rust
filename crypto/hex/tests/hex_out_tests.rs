//! The `_out` forms: the same bytes as the allocating forms, the buffer sizes their `_out_len`
//! functions give, and the output buffer's contract (zeroized first, left zeroized on an error).
// They compare with the allocating forms.
#![cfg(feature = "std")]

use bouncycastle_hex::{self as hex, HexError, decode_out_len, encode_out_len};

const BYTES: &[u8] = b"\x00\x01\x7f\x80\xab\xcd\xef\xff";

#[test]
fn out_forms_match_the_allocating_ones_and_clear_an_oversized_buffer() {
    for len in 0..=BYTES.len() {
        let bin = &BYTES[..len];
        let text = hex::encode(bin);

        let mut out = [0xFFu8; 24];
        let n = hex::encode_out(bin, &mut out).unwrap();
        assert_eq!(&out[..n], text.as_bytes());
        assert_eq!(n, encode_out_len(len));
        assert!(out[n..].iter().all(|&b| b == 0), "the rest of the buffer is zeroized");

        let mut out = [0xFFu8; 24];
        let n = hex::decode_out(&text, &mut out).unwrap();
        assert_eq!(&out[..n], bin);
        assert_eq!(n, decode_out_len(text.len()), "exact without whitespace");
        assert!(out[n..].iter().all(|&b| b == 0));
    }
}

#[test]
fn an_unrepresentable_encoding_length_saturates() {
    assert_eq!(encode_out_len(usize::MAX), usize::MAX);
}

#[test]
fn a_short_buffer_is_refused_and_zeroized() {
    let mut short = [0xFFu8; 3];
    assert!(matches!(
        hex::encode_out(b"\x01\x02", &mut short),
        Err(HexError::InsufficientOutputBufferSize)
    ));
    assert_eq!(short, [0; 3]);

    let mut short = [0xFFu8; 1];
    assert!(matches!(
        hex::decode_out("0102", &mut short),
        Err(HexError::InsufficientOutputBufferSize)
    ));
    assert_eq!(short, [0; 1]);
}

#[test]
fn a_decoding_error_leaves_the_buffer_zeroized() {
    // Each input decodes at least one byte before the error.
    let mut out = [0xFFu8; 8];
    assert!(matches!(hex::decode_out("abcdzz", &mut out), Err(HexError::InvalidHexCharacter(4))));
    assert_eq!(out, [0; 8]);

    let mut out = [0xFFu8; 8];
    assert!(matches!(hex::decode_out("abcd e", &mut out), Err(HexError::OddLengthInput)));
    assert_eq!(out, [0; 8]);
}

#[test]
fn whitespace_and_escapes_make_the_decode_bound_an_over_estimate() {
    let text = "\\xab \\xcd\0";
    let mut out = [0u8; 8];
    let n = hex::decode_out(text, &mut out).unwrap();
    assert_eq!(&out[..n], b"\xab\xcd");
    assert!(n < decode_out_len(text.len()));
}
