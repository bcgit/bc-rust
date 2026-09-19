//! Tests for `NoPadding`: a `Padding` scheme that adds nothing and refuses to.
//!
//! There is no rule to transcribe; the contract is that `pad` is an error whenever it is called
//! (being called means a partial block existed), `unpad` reports a whole block of data, and the
//! scheme declares that it does not pad aligned data, so the adapters emit no final block.

use bouncycastle_core::errors::PaddingError;
use bouncycastle_core::traits::Padding;
use bouncycastle_padding::{NoPadding, PKCS7};

fn pad_always_refuses<const K: usize>() {
    for data_len in 0..K {
        let mut block: [u8; K] = core::array::from_fn(|i| i as u8 ^ 0xA5);
        let original = block;
        assert_eq!(
            <NoPadding as Padding<K>>::pad(&mut block, data_len),
            Err(PaddingError::PaddingNotPermitted),
            "K={K} data_len={data_len}"
        );
        assert_eq!(block, original, "K={K} data_len={data_len}: nothing may be written");
    }
    // Beyond the block is the same error every scheme gives.
    let mut block = [0u8; K];
    assert_eq!(
        <NoPadding as Padding<K>>::pad(&mut block, K),
        Err(PaddingError::DataLengthTooLong(K - 1))
    );
}

#[test]
fn pad_refuses_every_data_length() {
    pad_always_refuses::<1>();
    pad_always_refuses::<8>();
    pad_always_refuses::<16>();
    pad_always_refuses::<255>();
}

#[test]
fn unpad_reports_the_whole_block_as_data() {
    for fill in [0x00u8, 0x01, 0x10, 0x7f, 0xff] {
        assert_eq!(<NoPadding as Padding<16>>::unpad(&[fill; 16]), Ok(16));
        assert_eq!(<NoPadding as Padding<8>>::unpad(&[fill; 8]), Ok(8));
    }
    // ...including blocks that would be well-formed PKCS7 padding: there is nothing to strip.
    let mut pkcs7 = [0u8; 16];
    <PKCS7 as Padding<16>>::pad(&mut pkcs7, 5).unwrap();
    assert_eq!(<NoPadding as Padding<16>>::unpad(&pkcs7), Ok(16));
}

/// The flag the adapters key off: PKCS7 always appends a block to aligned data, NoPadding never.
#[test]
fn always_pads_flags() {
    assert!(<PKCS7 as Padding<16>>::ALWAYS_PADS);
    assert!(!<NoPadding as Padding<16>>::ALWAYS_PADS);
}
