//! The padded CBC mode through the Camellia keys, via the shared suite: the padding parameter selects
//! the scheme, the schemes are not interchangeable, and the IV is fresh per encryption. Which type
//! each alias resolves to is pinned in `alg_name_tests.rs`.

use bouncycastle_camellia::hazmat::{
    Camellia128Internal, Camellia192Internal, Camellia256Internal,
};
use bouncycastle_cipher_test_framework::padded;

#[test]
fn every_key_length_round_trips() {
    padded::round_trips::<Camellia128Internal, 16>("Camellia-128");
    padded::round_trips::<Camellia192Internal, 24>("Camellia-192");
    padded::round_trips::<Camellia256Internal, 32>("Camellia-256");
}

#[test]
fn the_padding_parameter_selects_the_scheme() {
    padded::padding_selects_the_scheme::<Camellia128Internal, 16>();
    padded::padding_selects_the_scheme::<Camellia192Internal, 24>();
    padded::padding_selects_the_scheme::<Camellia256Internal, 32>();
}

#[test]
fn each_encryption_gets_a_fresh_iv() {
    padded::fresh_iv::<Camellia128Internal, 16>();
    padded::fresh_iv::<Camellia192Internal, 24>();
    padded::fresh_iv::<Camellia256Internal, 32>();
}
