//! The AES keys through the shared block cipher key suites of
//! `bouncycastle-cipher-test-framework`: construction policy for every mode a key can carry, the
//! block, symmetric, stream, AEAD and key-wrap conformance suites, what tells the modes apart on
//! the key path, equality, and the MAC keys' material policy and round trips, at the 128-bit and 192-bit and 256-bit
//! key lengths. The known answers are in the vector suites beside this file.

use bouncycastle_aes::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_cipher_test_framework::mode_keys;

#[test]
fn every_mode_key_enforces_the_material_policy() {
    mode_keys::construction::<AES128Internal, 16>();
    mode_keys::construction::<AES192Internal, 24>();
    mode_keys::construction::<AES256Internal, 32>();
}

#[test]
fn kw_and_kwp_keys_pass_the_key_wrap_framework() {
    mode_keys::key_wrap::<AES128Internal, 16>();
    mode_keys::key_wrap::<AES192Internal, 24>();
    mode_keys::key_wrap::<AES256Internal, 32>();
}

#[test]
fn block_mode_keys_pass_the_block_cipher_framework() {
    mode_keys::block_modes::<AES128Internal, 16>();
    mode_keys::block_modes::<AES192Internal, 24>();
    mode_keys::block_modes::<AES256Internal, 32>();
}

#[test]
fn padded_keys_pass_the_symmetric_cipher_framework() {
    mode_keys::padded_modes::<AES128Internal, 16>();
    mode_keys::padded_modes::<AES192Internal, 24>();
    mode_keys::padded_modes::<AES256Internal, 32>();
}

#[test]
fn stream_mode_keys_pass_the_stream_cipher_framework() {
    mode_keys::stream_modes::<AES128Internal, 16>();
    mode_keys::stream_modes::<AES192Internal, 24>();
    mode_keys::stream_modes::<AES256Internal, 32>();
}

#[test]
fn aead_keys_pass_the_aead_frameworks() {
    mode_keys::aead_modes::<AES128Internal, 16>();
    mode_keys::aead_modes::<AES192Internal, 24>();
    mode_keys::aead_modes::<AES256Internal, 32>();
}

#[test]
fn each_gcm_encryption_gets_a_fresh_nonce() {
    mode_keys::gcm_draws_a_fresh_nonce::<AES128Internal, 16>();
    mode_keys::gcm_draws_a_fresh_nonce::<AES192Internal, 24>();
    mode_keys::gcm_draws_a_fresh_nonce::<AES256Internal, 32>();
}

#[test]
fn ecb_keys_take_no_init_data() {
    mode_keys::ecb_takes_no_init_data::<AES128Internal, 16>();
    mode_keys::ecb_takes_no_init_data::<AES192Internal, 24>();
    mode_keys::ecb_takes_no_init_data::<AES256Internal, 32>();
}

#[test]
fn cbc_blocks_in_place_agrees_with_cbc_no_padding_out() {
    mode_keys::cbc_blocks_agrees_with_no_padding::<AES128Internal, 16>();
    mode_keys::cbc_blocks_agrees_with_no_padding::<AES192Internal, 24>();
    mode_keys::cbc_blocks_agrees_with_no_padding::<AES256Internal, 32>();
}

#[test]
fn keys_compare_equal_exactly_when_their_material_does() {
    mode_keys::equality::<AES128Internal, 16>();
    mode_keys::equality::<AES192Internal, 24>();
    mode_keys::equality::<AES256Internal, 32>();
}

#[test]
fn a_mac_mode_key_takes_mac_material_and_refuses_cipher_material() {
    mode_keys::mac_material_policy::<AES128Internal, 16>();
    mode_keys::mac_material_policy::<AES192Internal, 24>();
    mode_keys::mac_material_policy::<AES256Internal, 32>();
}

#[test]
fn cmac_keys_tag_and_verify() {
    mode_keys::cmac_round_trip::<AES128Internal, 16>();
    mode_keys::cmac_round_trip::<AES192Internal, 24>();
    mode_keys::cmac_round_trip::<AES256Internal, 32>();
}

#[test]
fn gmac_keys_tag_and_verify_under_a_nonce() {
    mode_keys::gmac_round_trip::<AES128Internal, 16>();
    mode_keys::gmac_round_trip::<AES192Internal, 24>();
    mode_keys::gmac_round_trip::<AES256Internal, 32>();
}
