//! [`Direction`] must select `Enc` for [`Encrypting`] and `Dec` for [`Decrypting`]. Both checks
//! hold at compile time, so a regression fails the build of this test crate; the `#[test]` is the
//! runtime half that a test runner can report.

use bouncycastle_core::stream_cipher::{Decrypting, Direction, Encrypting};

/// Two types that cannot be confused with each other, or with anything else.
struct Enc([u8; 1]);
struct Dec([u8; 2]);

/// Compiles only when both arguments are the same type.
const fn same_type<T>(_: &T, _: &T) {}

const _: () = {
    let enc: <Encrypting as Direction>::Select<Enc, Dec> = Enc([0]);
    same_type(&enc, &Enc([0]));
    let dec: <Decrypting as Direction>::Select<Enc, Dec> = Dec([0; 2]);
    same_type(&dec, &Dec([0; 2]));
};

#[test]
fn encrypting_selects_enc_and_decrypting_selects_dec() {
    let enc: <Encrypting as Direction>::Select<Enc, Dec> = Enc([7]);
    assert_eq!(enc.0, [7]);
    let dec: <Decrypting as Direction>::Select<Enc, Dec> = Dec([8, 9]);
    assert_eq!(dec.0, [8, 9]);
    assert_eq!(size_of::<<Encrypting as Direction>::Select<Enc, Dec>>(), 1);
    assert_eq!(size_of::<<Decrypting as Direction>::Select<Enc, Dec>>(), 2);
}
