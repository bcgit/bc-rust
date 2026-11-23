//! The `_out` forms of `core::base64`: the same bytes as the allocating forms, the buffer sizes
//! their `_out_len` functions give, and the output buffer's contract (zeroized first, left
//! zeroized on an error, the state untouched when it is too short).

use bouncycastle_core::base64::{
    self, Base64Decoder, Base64Encoder, Base64Error, decode_out_len, encode_out_len,
};

/// RFC 4648 Section 10.
const RFC4648: [(&[u8], &str); 7] = [
    (b"", ""),
    (b"f", "Zg=="),
    (b"fo", "Zm8="),
    (b"foo", "Zm9v"),
    (b"foob", "Zm9vYg=="),
    (b"fooba", "Zm9vYmE="),
    (b"foobar", "Zm9vYmFy"),
];

const TEXT: &[u8] =
    b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor.";

#[test]
fn one_shots_match_rfc4648_and_clear_an_oversized_buffer() {
    for (bin, b64) in RFC4648 {
        let mut out = [0xFFu8; 16];
        let n = base64::encode_out(bin, &mut out).unwrap();
        assert_eq!(&out[..n], b64.as_bytes());
        assert!(out[n..].iter().all(|&b| b == 0), "the rest of the buffer is zeroized");
        assert_eq!(n, encode_out_len(bin.len()));

        let mut out = [0xFFu8; 16];
        let n = base64::decode_out(b64, &mut out).unwrap();
        assert_eq!(&out[..n], bin);
        assert!(out[n..].iter().all(|&b| b == 0));
        assert!(n <= decode_out_len(b64.len()));
    }
}

#[test]
fn a_buffer_of_exactly_the_out_len_is_enough_and_one_less_is_refused() {
    for len in 0..=10 {
        let bin = &TEXT[..len];
        let b64 = base64::encode(bin);

        let mut out = vec![0u8; encode_out_len(len)];
        assert_eq!(base64::encode_out(bin, &mut out).unwrap(), out.len());
        let mut out = vec![0u8; decode_out_len(b64.len())];
        let n = base64::decode_out(&b64, &mut out).unwrap();
        assert_eq!(&out[..n], bin);
        // Without padding the bound is exact.
        let unpadded = b64.trim_end_matches('=');
        assert_eq!(decode_out_len(unpadded.len()), len, "{unpadded}");

        if len > 0 {
            let mut short = vec![0xFFu8; encode_out_len(len) - 1];
            assert!(matches!(
                base64::encode_out(bin, &mut short),
                Err(Base64Error::InsufficientOutputBufferSize)
            ));
            assert!(short.iter().all(|&b| b == 0), "zeroized before the length check");

            let mut short = vec![0xFFu8; decode_out_len(b64.len()) - 1];
            assert!(matches!(
                base64::decode_out(&b64, &mut short),
                Err(Base64Error::InsufficientOutputBufferSize)
            ));
            assert!(short.iter().all(|&b| b == 0));
        }
    }
}

#[test]
fn streaming_out_forms_match_the_one_shots_for_every_chunk_size() {
    let b64 = base64::encode(TEXT);
    for chunk in 1..=8 {
        let mut encoder = Base64Encoder::new();
        let mut encoded = Vec::new();
        let mut rest = TEXT;
        while rest.len() > chunk {
            let mut out = vec![0u8; encoder.update_out_len(chunk)];
            let n = encoder.do_update_out(&rest[..chunk], &mut out).unwrap();
            assert_eq!(n, out.len(), "the encoder's update length is exact");
            encoded.extend_from_slice(&out[..n]);
            rest = &rest[chunk..];
        }
        let mut out = vec![0u8; encoder.final_out_len(rest.len())];
        let n = encoder.do_final_out(rest, &mut out).unwrap();
        encoded.extend_from_slice(&out[..n]);
        assert_eq!(encoded, b64.as_bytes(), "chunk {chunk}");

        let mut decoder = Base64Decoder::new(false);
        let mut decoded = Vec::new();
        let mut rest = b64.as_bytes();
        // Stop short of the padding, which only do_final takes.
        while rest.len() > chunk + 4 {
            let mut out = vec![0u8; decoder.update_out_len(chunk)];
            let n = decoder.do_update_out(&rest[..chunk], &mut out).unwrap();
            decoded.extend_from_slice(&out[..n]);
            rest = &rest[chunk..];
        }
        let mut out = vec![0u8; decoder.final_out_len(rest.len())];
        let n = decoder.do_final_out(rest, &mut out).unwrap();
        decoded.extend_from_slice(&out[..n]);
        assert_eq!(decoded, TEXT, "chunk {chunk}");
    }
}

#[test]
fn a_short_buffer_leaves_the_streaming_state_as_it_was() {
    let mut encoder = Base64Encoder::new();
    let mut out = [0u8; 8];
    assert_eq!(encoder.do_update_out(b"fo", &mut out).unwrap(), 0);
    let mut short = [0xFFu8; 3];
    assert!(matches!(
        encoder.do_update_out(b"ob", &mut short),
        Err(Base64Error::InsufficientOutputBufferSize)
    ));
    assert_eq!(short, [0; 3]);
    let n = encoder.do_final_out(b"ob", &mut out).unwrap();
    assert_eq!(&out[..n], b"Zm9vYg==");

    let mut decoder = Base64Decoder::new(false);
    assert_eq!(decoder.do_update_out(b"Zm", &mut out).unwrap(), 0);
    let mut short = [0xFFu8; 2];
    assert!(matches!(
        decoder.do_update_out(b"9vYm", &mut short),
        Err(Base64Error::InsufficientOutputBufferSize)
    ));
    assert_eq!(short, [0; 2]);
    // A successful update clears what it does not write.
    let mut out = [0xFFu8; 8];
    assert_eq!(decoder.do_update_out(b"9v", &mut out).unwrap(), 3);
    assert_eq!(&out[..3], b"foo");
    assert_eq!(out[3..], [0; 5]);
    let n = decoder.do_final_out(b"YmFy", &mut out).unwrap();
    assert_eq!(&out[..n], b"bar");
}

#[test]
fn padding_in_do_update_out_clears_the_buffer_and_rolls_back() {
    let mut decoder = Base64Decoder::new(false);
    let mut out = [0xFFu8; 16];
    // A whole block decodes before the padding is reached; none of it may be left behind.
    assert!(matches!(
        decoder.do_update_out(b"Zm9vYg==", &mut out),
        Err(Base64Error::PaddingEncounteredDuringDoUpdate)
    ));
    assert_eq!(out, [0; 16]);
    let n = decoder.do_final_out(b"Zm9vYg==", &mut out).unwrap();
    assert_eq!(&out[..n], b"foob");
}

#[test]
fn a_decoding_error_leaves_the_buffer_zeroized() {
    // Each input decodes a whole block before the error.
    let cases: [(&[u8], fn(&Base64Error) -> bool); 3] = [
        (b"Zm9v!", |e| matches!(e, Base64Error::InvalidB64Character(4))),
        (b"Zm9vY", |e| matches!(e, Base64Error::TruncatedInput)),
        (b"Zm9vYg==Zg", |e| matches!(e, Base64Error::InvalidPadding(8))),
    ];
    for (input, expected) in cases {
        let mut out = [0xFFu8; 16];
        let err = base64::decode_out(input, &mut out).unwrap_err();
        assert!(expected(&err), "{input:?}: {err:?}");
        assert_eq!(out, [0; 16], "{input:?}");
    }

    // The same from a streaming update, after a whole block has been decoded.
    let mut out = [0xFFu8; 16];
    let err = Base64Decoder::new(false).do_update_out(b"Zm9v!", &mut out).unwrap_err();
    assert!(matches!(err, Base64Error::InvalidB64Character(4)));
    assert_eq!(out, [0; 16]);
}
