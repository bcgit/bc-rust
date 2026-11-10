//! The padded CBC mode through the AES keys, via the shared suite: the padding parameter selects
//! the scheme, the schemes are not interchangeable, and the IV is fresh per encryption. Which type
//! each alias resolves to is pinned in `alg_name_tests.rs`.

use bouncycastle_aes::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_cipher_test_framework::padded;

#[test]
fn every_key_length_round_trips() {
    padded::round_trips::<AES128Internal, 16>("AES-128");
    padded::round_trips::<AES192Internal, 24>("AES-192");
    padded::round_trips::<AES256Internal, 32>("AES-256");
}

#[test]
fn the_padding_parameter_selects_the_scheme() {
    padded::padding_selects_the_scheme::<AES128Internal, 16>();
    padded::padding_selects_the_scheme::<AES192Internal, 24>();
    padded::padding_selects_the_scheme::<AES256Internal, 32>();
}

#[test]
fn each_encryption_gets_a_fresh_iv() {
    padded::fresh_iv::<AES128Internal, 16>();
    padded::fresh_iv::<AES192Internal, 24>();
    padded::fresh_iv::<AES256Internal, 32>();
}
