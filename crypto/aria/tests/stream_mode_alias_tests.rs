//! The stream modes CFB, CFB8 and CTR through the ARIA keys, via the shared suite: any length,
//! any chunking, fresh init data per encryption, and the three modes distinct from each other.
//! The known answers are in the vector suites beside this file, and which type each alias
//! resolves to is pinned in `alg_name_tests.rs`.

use bouncycastle_aria::hazmat::{ARIA128Internal, ARIA192Internal, ARIA256Internal};
use bouncycastle_cipher_test_framework::stream;

#[test]
fn every_stream_key_round_trips_at_any_length() {
    stream::round_trips_at_any_length::<ARIA128Internal, 16>("ARIA-128");
    stream::round_trips_at_any_length::<ARIA192Internal, 24>("ARIA-192");
    stream::round_trips_at_any_length::<ARIA256Internal, 32>("ARIA-256");
}

#[test]
fn chunking_does_not_change_the_ciphertext() {
    stream::chunking_does_not_change_the_ciphertext::<ARIA128Internal, 16>("ARIA-128");
    stream::chunking_does_not_change_the_ciphertext::<ARIA192Internal, 24>("ARIA-192");
    stream::chunking_does_not_change_the_ciphertext::<ARIA256Internal, 32>("ARIA-256");
}

#[test]
fn each_encryption_gets_fresh_init_data() {
    stream::each_encryption_gets_fresh_init_data::<ARIA128Internal, 16>("ARIA-128");
    stream::each_encryption_gets_fresh_init_data::<ARIA192Internal, 24>("ARIA-192");
    stream::each_encryption_gets_fresh_init_data::<ARIA256Internal, 32>("ARIA-256");
}

#[test]
fn cfb128_and_cfb8_are_not_interchangeable() {
    stream::cfb128_and_cfb8_are_not_interchangeable::<ARIA128Internal, 16>();
    stream::cfb128_and_cfb8_are_not_interchangeable::<ARIA192Internal, 24>();
    stream::cfb128_and_cfb8_are_not_interchangeable::<ARIA256Internal, 32>();
}

#[test]
fn ctr_is_not_cfb() {
    stream::ctr_is_not_cfb::<ARIA128Internal, 16>();
    stream::ctr_is_not_cfb::<ARIA192Internal, 24>();
    stream::ctr_is_not_cfb::<ARIA256Internal, 32>();
}
