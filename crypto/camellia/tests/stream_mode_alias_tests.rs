//! The stream modes CFB, CFB8 and CTR through the Camellia keys, via the shared suite: any length,
//! any chunking, fresh init data per encryption, and the three modes distinct from each other.
//! The known answers are in the vector suites beside this file, and which type each alias
//! resolves to is pinned in `alg_name_tests.rs`.

use bouncycastle_camellia::hazmat::{
    Camellia128Internal, Camellia192Internal, Camellia256Internal,
};
use bouncycastle_cipher_test_framework::stream;

#[test]
fn every_stream_key_round_trips_at_any_length() {
    stream::round_trips_at_any_length::<Camellia128Internal, 16>("Camellia-128");
    stream::round_trips_at_any_length::<Camellia192Internal, 24>("Camellia-192");
    stream::round_trips_at_any_length::<Camellia256Internal, 32>("Camellia-256");
}

#[test]
fn chunking_does_not_change_the_ciphertext() {
    stream::chunking_does_not_change_the_ciphertext::<Camellia128Internal, 16>("Camellia-128");
    stream::chunking_does_not_change_the_ciphertext::<Camellia192Internal, 24>("Camellia-192");
    stream::chunking_does_not_change_the_ciphertext::<Camellia256Internal, 32>("Camellia-256");
}

#[test]
fn each_encryption_gets_fresh_init_data() {
    stream::each_encryption_gets_fresh_init_data::<Camellia128Internal, 16>("Camellia-128");
    stream::each_encryption_gets_fresh_init_data::<Camellia192Internal, 24>("Camellia-192");
    stream::each_encryption_gets_fresh_init_data::<Camellia256Internal, 32>("Camellia-256");
}

#[test]
fn cfb128_and_cfb8_are_not_interchangeable() {
    stream::cfb128_and_cfb8_are_not_interchangeable::<Camellia128Internal, 16>();
    stream::cfb128_and_cfb8_are_not_interchangeable::<Camellia192Internal, 24>();
    stream::cfb128_and_cfb8_are_not_interchangeable::<Camellia256Internal, 32>();
}

#[test]
fn ctr_is_not_cfb() {
    stream::ctr_is_not_cfb::<Camellia128Internal, 16>();
    stream::ctr_is_not_cfb::<Camellia192Internal, 24>();
    stream::ctr_is_not_cfb::<Camellia256Internal, 32>();
}
