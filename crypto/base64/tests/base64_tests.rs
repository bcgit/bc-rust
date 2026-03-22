extern crate core;

use bouncycastle_base64 as base64;
use bouncycastle_base64::{Base64Encoder, Base64Decoder};

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
        assert_eq!(base64::decode("AAECAwQFBgcI").unwrap(), b"\x00\x01\x02\x03\x04\x05\x06\x07\x08");

        // test some whitespace
        // failure case
        let decoder = Base64Decoder::new(/*skip_whitespace=*/false);
        match decoder.do_final("  AAE CA wQF \nBgcI") {
            Ok(_) => panic!("expected decode to fail"),
            Err(_) => {}
        }

        // success case
        let decoder = Base64Decoder::new(/*skip_whitespace=*/true);
        assert_eq!(decoder.do_final("  AAE CA wQF BgcI").unwrap(), b"\x00\x01\x02\x03\x04\x05\x06\x07\x08");
        assert_eq!(base64::decode("  AAE CA wQF BgcI").unwrap(), b"\x00\x01\x02\x03\x04\x05\x06\x07\x08");

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
            out.extend(decoder.do_update(&LOREM_IPSUM_B64[i..i+10]).unwrap());
            i += 10;
        }
        out.extend(decoder.do_final(&LOREM_IPSUM_B64[i..]).unwrap());
        assert_eq!(LOREM_IPSUM, out);
    }
}