//! The stream modes CFB, CFB8 and CTR through the SM4 keys, via the shared suite: any length,
//! any chunking, fresh init data per encryption, and the three modes distinct from each other.
//! The known answers are in the vector suites beside this file, and which type each alias
//! resolves to is pinned in `alg_name_tests.rs`.

use bouncycastle_cipher_test_framework::stream;
use bouncycastle_sm4::hazmat::SM4Internal;

#[test]
fn every_stream_key_round_trips_at_any_length() {
    stream::round_trips_at_any_length::<SM4Internal, 16>("SM4");
}

#[test]
fn chunking_does_not_change_the_ciphertext() {
    stream::chunking_does_not_change_the_ciphertext::<SM4Internal, 16>("SM4");
}

#[test]
fn each_encryption_gets_fresh_init_data() {
    stream::each_encryption_gets_fresh_init_data::<SM4Internal, 16>("SM4");
}

#[test]
fn cfb128_and_cfb8_are_not_interchangeable() {
    stream::cfb128_and_cfb8_are_not_interchangeable::<SM4Internal, 16>();
}

#[test]
fn ctr_is_not_cfb() {
    stream::ctr_is_not_cfb::<SM4Internal, 16>();
}
