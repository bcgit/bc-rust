//! The padded CBC mode through the ARIA keys, via the shared suite: the padding parameter selects
//! the scheme, the schemes are not interchangeable, and the IV is fresh per encryption. Which type
//! each alias resolves to is pinned in `alg_name_tests.rs`.

use bouncycastle_aria::hazmat::{ARIA128Internal, ARIA192Internal, ARIA256Internal};
use bouncycastle_cipher_test_framework::padded;

#[test]
fn every_key_length_round_trips() {
    padded::round_trips::<ARIA128Internal, 16>("ARIA-128");
    padded::round_trips::<ARIA192Internal, 24>("ARIA-192");
    padded::round_trips::<ARIA256Internal, 32>("ARIA-256");
}

#[test]
fn the_padding_parameter_selects_the_scheme() {
    padded::padding_selects_the_scheme::<ARIA128Internal, 16>();
    padded::padding_selects_the_scheme::<ARIA192Internal, 24>();
    padded::padding_selects_the_scheme::<ARIA256Internal, 32>();
}

#[test]
fn each_encryption_gets_a_fresh_iv() {
    padded::fresh_iv::<ARIA128Internal, 16>();
    padded::fresh_iv::<ARIA192Internal, 24>();
    padded::fresh_iv::<ARIA256Internal, 32>();
}
