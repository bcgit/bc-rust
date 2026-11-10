//! The padded CBC mode through the SM4 keys, via the shared suite: the padding parameter selects
//! the scheme, the schemes are not interchangeable, and the IV is fresh per encryption. Which type
//! each alias resolves to is pinned in `alg_name_tests.rs`.

use bouncycastle_cipher_test_framework::padded;
use bouncycastle_sm4::hazmat::SM4Internal;

#[test]
fn every_key_length_round_trips() {
    padded::round_trips::<SM4Internal, 16>("SM4");
}

#[test]
fn the_padding_parameter_selects_the_scheme() {
    padded::padding_selects_the_scheme::<SM4Internal, 16>();
}

#[test]
fn each_encryption_gets_a_fresh_iv() {
    padded::fresh_iv::<SM4Internal, 16>();
}
