//! The SM4 keys through the shared block cipher key suites of
//! `bouncycastle-cipher-test-framework`: construction policy for every mode a key can carry, the
//! block, symmetric, stream, AEAD and key-wrap conformance suites, what tells the modes apart on
//! the key path, equality, and the MAC keys' material policy and round trips, at the 128-bit
//! key length. The known answers are in the vector suites beside this file.

use bouncycastle_cipher_test_framework::mode_keys;
use bouncycastle_sm4::hazmat::SM4Internal;

#[test]
fn every_mode_key_enforces_the_material_policy() {
    mode_keys::construction::<SM4Internal, 16>();
}

#[test]
fn kw_and_kwp_keys_pass_the_key_wrap_framework() {
    mode_keys::key_wrap::<SM4Internal, 16>();
}

#[test]
fn block_mode_keys_pass_the_block_cipher_framework() {
    mode_keys::block_modes::<SM4Internal, 16>();
}

#[test]
fn padded_keys_pass_the_symmetric_cipher_framework() {
    mode_keys::padded_modes::<SM4Internal, 16>();
}

#[test]
fn stream_mode_keys_pass_the_stream_cipher_framework() {
    mode_keys::stream_modes::<SM4Internal, 16>();
}

#[test]
fn aead_keys_pass_the_aead_frameworks() {
    mode_keys::aead_modes::<SM4Internal, 16>();
}

#[test]
fn each_gcm_encryption_gets_a_fresh_nonce() {
    mode_keys::gcm_draws_a_fresh_nonce::<SM4Internal, 16>();
}

#[test]
fn ecb_keys_take_no_init_data() {
    mode_keys::ecb_takes_no_init_data::<SM4Internal, 16>();
}

#[test]
fn cbc_blocks_in_place_agrees_with_cbc_no_padding_out() {
    mode_keys::cbc_blocks_agrees_with_no_padding::<SM4Internal, 16>();
}

#[test]
fn keys_compare_equal_exactly_when_their_material_does() {
    mode_keys::equality::<SM4Internal, 16>();
}

#[test]
fn a_mac_mode_key_takes_mac_material_and_refuses_cipher_material() {
    mode_keys::mac_material_policy::<SM4Internal, 16>();
}

#[test]
fn cmac_keys_tag_and_verify() {
    mode_keys::cmac_round_trip::<SM4Internal, 16>();
}

#[test]
fn gmac_keys_tag_and_verify_under_a_nonce() {
    mode_keys::gmac_round_trip::<SM4Internal, 16>();
}

/// The sizes the docs quote: the schedule alone for the unauthenticated modes, plus the hash
/// subkey under `GCM`.
#[test]
fn key_sizes_are_the_documented_ones() {
    use bouncycastle_cipher::modes::{CTR, GCM};
    use bouncycastle_sm4::SM4Key;
    use core::mem::size_of;
    assert_eq!(size_of::<SM4Key<CTR>>(), 128);
    assert_eq!(size_of::<SM4Key<GCM>>(), 144);
}
