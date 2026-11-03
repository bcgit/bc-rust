extern crate core;

use bouncycastle_base64 as base64;
use bouncycastle_base64::{Base64Decoder, Base64Encoder};

const LOREM_IPSUM: &[u8] = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
const LOREM_IPSUM_B64: &str = "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCwgc2VkIGRvIGVpdXNtb2QgdGVtcG9yIGluY2lkaWR1bnQgdXQgbGFib3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWEuIFV0IGVuaW0gYWQgbWluaW0gdmVuaWFtLCBxdWlzIG5vc3RydWQgZXhlcmNpdGF0aW9uIHVsbGFtY28gbGFib3JpcyBuaXNpIHV0IGFsaXF1aXAgZXggZWEgY29tbW9kbyBjb25zZXF1YXQuIER1aXMgYXV0ZSBpcnVyZSBkb2xvciBpbiByZXByZWhlbmRlcml0IGluIHZvbHVwdGF0ZSB2ZWxpdCBlc3NlIGNpbGx1bSBkb2xvcmUgZXUgZnVnaWF0IG51bGxhIHBhcmlhdHVyLiBFeGNlcHRldXIgc2ludCBvY2NhZWNhdCBjdXBpZGF0YXQgbm9uIHByb2lkZW50LCBzdW50IGluIGN1bHBhIHF1aSBvZmZpY2lhIGRlc2VydW50IG1vbGxpdCBhbmltIGlkIGVzdCBsYWJvcnVtLg==";

#[cfg(test)]
mod ctbase64_test {
    use super::*;

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64::encode(b"\x00"), "AA==");
        assert_eq!(base64::encode(b"Hello, World!"), "SGVsbG8sIFdvcmxkIQ==");
        assert_eq!(base64::encode(b"\x00\x01\x02\x03\x04\x05\x06"), "AAECAwQFBg==");
        assert_eq!(base64::encode(b"\x00\x01\x02\x03\x04\x05\x06\x07"), "AAECAwQFBgc=");
        assert_eq!(base64::encode(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08"), "AAECAwQFBgcI");
        assert_eq!(base64::encode(LOREM_IPSUM), LOREM_IPSUM_B64);
    }

    #[test]
    fn test_streamed_encode() {
        let mut encoder = Base64Encoder::new();
        let mut out: String = String::new();

        let mut i: usize = 0;
        while i < LOREM_IPSUM.len() - 10 {
            out.push_str(encoder.do_update(&LOREM_IPSUM[i..i + 10]).as_str());
            i += 10;
        }
        out.push_str(encoder.do_final(&LOREM_IPSUM[i..]).as_str());
        assert_eq!(LOREM_IPSUM_B64, out.as_str());
    }

    #[test]
    fn test_base64_decode() {
        assert_eq!(base64::decode("AA==").unwrap(), b"\x00");
        assert_eq!(base64::decode("SGVsbG8sIFdvcmxkIQ==").unwrap(), b"Hello, World!");
        assert_eq!(base64::decode("AAECAwQFBg==").unwrap(), b"\x00\x01\x02\x03\x04\x05\x06");
        assert_eq!(base64::decode("AAECAwQFBgc=").unwrap(), b"\x00\x01\x02\x03\x04\x05\x06\x07");
        assert_eq!(
            base64::decode("AAECAwQFBgcI").unwrap(),
            b"\x00\x01\x02\x03\x04\x05\x06\x07\x08"
        );

        // test some whitespace
        // failure case
        let decoder = Base64Decoder::new(/*skip_whitespace=*/ false);
        match decoder.do_final("  AAE CA wQF \nBgcI") {
            Ok(_) => panic!("expected decode to fail"),
            Err(_) => {}
        }

        // success case
        let decoder = Base64Decoder::new(/*skip_whitespace=*/ true);
        assert_eq!(
            decoder.do_final("  AAE CA wQF BgcI").unwrap(),
            b"\x00\x01\x02\x03\x04\x05\x06\x07\x08"
        );
        assert_eq!(
            base64::decode("  AAE CA wQF BgcI").unwrap(),
            b"\x00\x01\x02\x03\x04\x05\x06\x07\x08"
        );

        // test invalid base64
        match base64::decode("AAECAwQF&?nBgcI") {
            Ok(_) => panic!("expected decode to fail"),
            Err(_) => {}
        }

        // test missing padding
        assert_eq!(base64::decode("AAECAwQFBg").unwrap(), b"\x00\x01\x02\x03\x04\x05\x06");
        assert_eq!(base64::decode("AAECAwQFBgc").unwrap(), b"\x00\x01\x02\x03\x04\x05\x06\x07");
    }

    #[test]
    fn test_streamed_decode() {
        let mut decoder = Base64Decoder::new(/*skip_whitespace*/ false);
        let mut out: Vec<u8> = Vec::new();

        let mut i: usize = 0;
        while i < LOREM_IPSUM_B64.len() - 10 {
            out.extend(decoder.do_update(&LOREM_IPSUM_B64[i..i + 10]).unwrap());
            i += 10;
        }
        out.extend(decoder.do_final(&LOREM_IPSUM_B64[i..]).unwrap());
        assert_eq!(LOREM_IPSUM, out);
    }
}

/// `do_update` must refuse a chunk containing padding as its docs say: the state is restored to
/// what it was at entry and nothing is returned, so passing the same chunk to `do_final` yields
/// every byte exactly once. It used to return `Ok` with the bytes decoded before the padding while
/// rolling the block state back, so a block held from the previous call was emitted twice and the
/// padded block itself was lost.
#[test]
fn do_update_refuses_padding_and_leaves_the_state_restorable() {
    use bouncycastle_base64::{Base64Decoder, Base64Error};

    // The padded block completes a quartet begun in the previous call.
    let mut decoder = Base64Decoder::new(true);
    assert_eq!(decoder.do_update("QUJ").unwrap(), b"");
    assert!(matches!(
        decoder.do_update("DRA=="),
        Err(Base64Error::PaddingEncounteredDuringDoUpdate)
    ));
    assert_eq!(decoder.do_final("DRA==").unwrap(), b"ABCD");

    // The padded block arrives whole, with complete blocks before it in the same chunk.
    let mut decoder = Base64Decoder::new(true);
    assert!(matches!(
        decoder.do_update("QUJDRA=="),
        Err(Base64Error::PaddingEncounteredDuringDoUpdate)
    ));
    assert_eq!(decoder.do_final("QUJDRA==").unwrap(), b"ABCD");

    // Padding alone, after everything else went through `do_update`.
    let mut decoder = Base64Decoder::new(true);
    assert_eq!(decoder.do_update("QUJDRA").unwrap(), b"ABC");
    assert!(matches!(decoder.do_update("=="), Err(Base64Error::PaddingEncounteredDuringDoUpdate)));
    assert_eq!(decoder.do_final("==").unwrap(), b"D");
}

/// RFC 4648 Section 10's test vectors, each also with its padding dropped (which `do_final`
/// tolerates) and with whitespace around and inside it. The two- and three-symbol tails carry
/// low bits in their last sextet.
#[test]
fn rfc4648_section_10_vectors() {
    let vectors: [(&[u8], &str); 7] = [
        (b"", ""),
        (b"f", "Zg=="),
        (b"fo", "Zm8="),
        (b"foo", "Zm9v"),
        (b"foob", "Zm9vYg=="),
        (b"fooba", "Zm9vYmE="),
        (b"foobar", "Zm9vYmFy"),
    ];
    for (raw, enc) in vectors {
        assert_eq!(base64::encode(raw), enc);
        assert_eq!(base64::decode(enc).unwrap(), raw, "{enc}");
        assert_eq!(base64::decode(enc.trim_end_matches('=')).unwrap(), raw, "{enc} unpadded");
        let spaced = format!(" {} \n", enc.replace('=', " = "));
        assert_eq!(base64::decode(&spaced).unwrap(), raw, "{spaced:?}");
    }
}

/// A block of 4k + 1 symbols ends six bits into a byte, which is no whole byte: it is refused
/// rather than finished from whatever an earlier block left in the decoder.
#[test]
fn a_single_trailing_symbol_is_truncated_input() {
    for input in ["R", "QUJDR", "QUJDR ", "QUJD R", "R="] {
        assert!(
            matches!(
                base64::decode(input),
                Err(base64::Base64Error::TruncatedInput | base64::Base64Error::InvalidPadding(_))
            ),
            "{input:?}"
        );
    }
    assert!(matches!(base64::decode("QUJDR"), Err(base64::Base64Error::TruncatedInput)));
}

/// Padding ends the data: RFC 4648 Section 3.3 requires rejecting anything after it other than
/// the rest of the padding, and padding is only valid after two or three symbols of a block.
#[test]
fn nothing_but_padding_and_whitespace_may_follow_the_padding() {
    use base64::Base64Error::InvalidPadding;

    // (input, index of the offending character)
    let cases = [
        ("QQ==garbage!!", 4),
        ("QQ==QQ==", 4),
        ("QUJD=RA==", 4),
        ("QQ===", 4),
        ("QUI==", 4),
        ("=", 0),
        ("QUJD=", 4),
        ("Q=", 1),
    ];
    for (input, at) in cases {
        match base64::decode(input) {
            Err(InvalidPadding(i)) => assert_eq!(i, at, "{input:?}"),
            other => panic!("{input:?}: expected InvalidPadding({at}), got {other:?}"),
        }
    }

    // Whitespace after the padding is fine only when whitespace is skipped.
    assert_eq!(base64::decode("QQ== \n").unwrap(), b"A");
    assert!(matches!(
        Base64Decoder::new(false).do_final("QQ==\n"),
        Err(base64::Base64Error::InvalidPadding(4))
    ));
}
