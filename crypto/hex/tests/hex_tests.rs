use bouncycastle_hex as hex;
use bouncycastle_hex::HexError;

#[test]
fn encode_test() {
    /* test encode_out */
    let mut out = [0u8; 2];
    let bytes_written = hex::encode_out(&[0x01], &mut out).unwrap();
    assert_eq!(bytes_written, 2);
    assert_eq!(String::from_utf8(Vec::<u8>::from(out)).unwrap(), "01");

    // error case: undersized output buffer
    let mut out = [0u8; 2];
    match hex::encode_out(&[0x00, 0x01, 0x02, 0x03], &mut out) {
        Ok(_) => {
            panic!("Expected a HexError::InsufficientOutputBufferSize");
        }
        Err(HexError::InsufficientOutputBufferSize) => { /* good */ }
        Err(_) => {
            panic!("Expected a HexError::InsufficientOutputBufferSize");
        }
    }

    /* test encode */
    assert_eq!(hex::encode(&[0x00, 0x01, 0x02, 0x03]), "00010203");
    assert_eq!(hex::encode(&[0x0F, 0x0E, 0x0D, 0x0C]), "0f0e0d0c");
    assert_eq!(hex::encode(&[0xF0, 0xE0, 0xD0, 0xC0]), "f0e0d0c0");

    /* test other bytes-like input formats */
    assert_eq!(hex::encode(b"\x00\x01\x02\x03"), "00010203");

    let mut v = vec![0u8; 0];
    v.push(0x00);
    v.push(0x01);
    v.push(0x02);
    v.push(0x03);
    assert_eq!(hex::encode(&v), "00010203");

    // This one is expected to fail because it takes the ascii values of the String,
    // so "00" becomes "\x30\x30", not "\x00".
    assert_ne!(hex::encode("00010203"), "00010203");
}

#[test]
fn decode_test() {
    /* test decode_out */
    let mut out = [0u8; 2];
    let bytes_written = hex::decode_out("01", &mut out).unwrap();
    assert_eq!(bytes_written, 1);
    assert_eq!(&out[..1], &[0x01]);

    // error case: undersized output buffer
    let mut out = [0u8; 2];
    match hex::decode_out("00010203", &mut out) {
        Ok(_) => {
            panic!("Expected a HexError::InsufficientOutputBufferSize");
        }
        Err(HexError::InsufficientOutputBufferSize) => { /* good */ }
        Err(_) => {
            panic!("Expected a HexError::InsufficientOutputBufferSize");
        }
    }

    // success cases
    assert_eq!(hex::decode("01").unwrap(), &[0x01]);
    assert_eq!(hex::decode("00010203").unwrap(), &[0x00, 0x01, 0x02, 0x03]);
    assert_eq!(hex::decode("0f0e0d0c").unwrap(), &[0x0F, 0x0E, 0x0D, 0x0C]);
    assert_eq!(hex::decode("0F0E0D0C").unwrap(), &[0x0F, 0x0E, 0x0D, 0x0C]);
    assert_eq!(hex::decode("f0e0d0c0").unwrap(), &[0xF0, 0xE0, 0xD0, 0xC0]);
    assert_eq!(hex::decode("F0E0D0C0").unwrap(), &[0xF0, 0xE0, 0xD0, 0xC0]);

    // whitespace and hex escape chars should be skipped
    assert_eq!(hex::decode("00 01 02 03 ").unwrap(), &[0x00, 0x01, 0x02, 0x03]);
    assert_eq!(hex::decode("\\x00\\x01\\x02\\x03").unwrap(), &[0x00, 0x01, 0x02, 0x03]);
    assert_eq!(hex::decode(" \\x00 \\x01 \\x 02 \\x03").unwrap(), &[0x00, 0x01, 0x02, 0x03]);

    /* error cases */

    // odd length input
    match hex::decode("1") {
        Ok(_) => panic!("expected decode to fail"),
        Err(HexError::OddLengthInput) => { /* good */ }
        Err(_) => {}
    }

    match hex::decode("101") {
        Ok(_) => panic!("expected decode to fail"),
        Err(HexError::OddLengthInput) => { /* good */ }
        Err(_) => {}
    }

    // invalid char
    match hex::decode("1x1") {
        Ok(_) => panic!("expected decode to fail"),
        Err(HexError::InvalidHexCharacter(i)) => {
            assert_eq!(i, 1);
        }
        Err(_) => {}
    }

    /* test other bytes-like input formats */
    assert_eq!(
        hex::decode(b"\x30\x30\x30\x31\x30\x32\x30\x33").unwrap(),
        &[0x00, 0x01, 0x02, 0x03]
    );
}
