//! Tests for PKCS7 against the rule of RFC 5652 §6.3:
//! "the input shall be padded at the trailing end with k-(lth mod k) octets all having value
//! k-(lth mod k)". There are no official test vectors for this scheme; expected values below are
//! computed directly from that rule.

use bouncycastle_core::errors::PaddingError;
use bouncycastle_core::traits::Padding;
use bouncycastle_padding::PKCS7;

fn roundtrip_all_lengths<const K: usize>() {
    for data_len in 0..K {
        let mut block = [0xA5u8; K];
        for (i, b) in block.iter_mut().enumerate().take(data_len) {
            *b = i as u8;
        }
        let original = block;

        <PKCS7 as Padding<K>>::pad(&mut block, data_len).unwrap();

        // data untouched
        assert_eq!(&block[..data_len], &original[..data_len]);
        // RFC 5652 §6.3: k - (lth mod k) octets, each of value k - (lth mod k)
        let expected_pad = K - data_len;
        assert_eq!(block[data_len..].len(), expected_pad);
        assert!(block[data_len..].iter().all(|&b| b as usize == expected_pad));

        assert_eq!(<PKCS7 as Padding<K>>::unpad(&block), Ok(data_len));
    }
}

#[test]
fn roundtrip_16() {
    roundtrip_all_lengths::<16>();
}

#[test]
fn roundtrip_8() {
    roundtrip_all_lengths::<8>();
}

#[test]
fn roundtrip_boundary_block_lengths() {
    roundtrip_all_lengths::<1>();
    roundtrip_all_lengths::<255>();
}

#[test]
fn rfc5652_worked_examples() {
    // RFC 5652 §6.3 lists the padding strings: "01 -- if lth mod k = k-1", "02 02 -- if lth mod k = k-2",
    // ..., "k k ... k k -- if lth mod k = 0".
    const K: usize = 16;
    let mut b = [0xFFu8; K];
    <PKCS7 as Padding<K>>::pad(&mut b, K - 1).unwrap();
    assert_eq!(b[K - 1], 0x01);

    let mut b = [0xFFu8; K];
    <PKCS7 as Padding<K>>::pad(&mut b, K - 2).unwrap();
    assert_eq!(&b[K - 2..], &[0x02, 0x02]);

    let mut b = [0xFFu8; K];
    <PKCS7 as Padding<K>>::pad(&mut b, 0).unwrap();
    assert_eq!(b, [K as u8; K]);
}

#[test]
fn pad_rejects_full_block() {
    let mut b = [0u8; 16];
    assert_eq!(<PKCS7 as Padding<16>>::pad(&mut b, 16), Err(PaddingError::DataLengthTooLong(15)));
    assert_eq!(<PKCS7 as Padding<16>>::pad(&mut b, 17), Err(PaddingError::DataLengthTooLong(15)));
    // block untouched on error
    assert_eq!(b, [0u8; 16]);
}

#[test]
fn unpad_rejects_malformed() {
    const K: usize = 16;

    // last byte zero: no such padding string
    let mut b = [0x00u8; K];
    assert_eq!(<PKCS7 as Padding<K>>::unpad(&b), Err(PaddingError::InvalidPadding));

    // last byte greater than k
    b[K - 1] = (K + 1) as u8;
    assert_eq!(<PKCS7 as Padding<K>>::unpad(&b), Err(PaddingError::InvalidPadding));
    b[K - 1] = 0xFF;
    assert_eq!(<PKCS7 as Padding<K>>::unpad(&b), Err(PaddingError::InvalidPadding));

    // claims 4 bytes of padding but one of them is wrong, at every possible position
    for bad in 0..4 {
        let mut b = [0x11u8; K];
        b[K - 4..].copy_from_slice(&[0x04; 4]);
        b[K - 4 + bad] ^= 0x01;
        if bad == 3 {
            // corrupting the length byte itself turns it into 0x05; the preceding bytes are 0x04, so
            // still invalid
            assert_eq!(b[K - 1], 0x05);
        }
        assert_eq!(
            <PKCS7 as Padding<K>>::unpad(&b),
            Err(PaddingError::InvalidPadding),
            "bad position {bad}"
        );
    }

    // a full padding block with a single wrong byte anywhere is invalid
    for pos in 0..K {
        let mut b = [K as u8; K];
        b[pos] ^= 0x80;
        assert_eq!(<PKCS7 as Padding<K>>::unpad(&b), Err(PaddingError::InvalidPadding));
    }
}

#[test]
fn unpad_ignores_data_bytes_that_happen_to_equal_pad_value() {
    // data bytes equal to the pad value must not confuse the length recovery
    const K: usize = 16;
    let mut b = [0x03u8; K]; // 13 data bytes all 0x03, then 3 bytes of 0x03 padding
    <PKCS7 as Padding<K>>::pad(&mut b, 13).unwrap();
    assert_eq!(b, [0x03u8; K]);
    assert_eq!(<PKCS7 as Padding<K>>::unpad(&b), Ok(13));
}
