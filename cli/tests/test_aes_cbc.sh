#!/usr/bin/env bash
# The aes128-cbc / aes192-cbc / aes256-cbc subcommands, end to end through the binary.
#
# Framing: encrypt writes a fresh IV as the first 16 bytes of its output, decrypt reads it back
# from the first 16 bytes of its input, and neither applies padding, so input must be a whole
# number of 16-byte blocks. Keys and data come from `bc-rust rng`; the one fixed input is the
# SP 800-38A Appendix F.2 known-answer set.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# One subcommand per key length: `cbc 128` prints "aes128-cbc".
cbc() { echo "aes$1-cbc"; }

# ---- round trips --------------------------------------------------------------------------

test_round_trip_through_files() {
    local bits
    for bits in 128 192 256; do
        rng "$(keylen $bits)" >"$TMP/key"
        rng 1024 >"$TMP/pt"

        "$BC_RUST" "$(cbc $bits)" -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
        assert_size "$TMP/ct" $((16 + 1024)) "$bits: ciphertext is the IV plus the plaintext length"
        assert_differs "$TMP/pt" "$TMP/ct" "$bits: the data must actually be encrypted"

        "$BC_RUST" "$(cbc $bits)" -d decrypt --key-file "$TMP/key" <"$TMP/ct" >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "$bits: decrypt must recover the plaintext"
    done
}

test_round_trip_through_a_pipe_larger_than_the_pipe_buffer() {
    rng 16 >"$TMP/key"
    rng $((1024 * 1024)) >"$TMP/pt"
    "$BC_RUST" aes128-cbc -d encrypt --key-file "$TMP/key" <"$TMP/pt" \
        | "$BC_RUST" aes128-cbc -d decrypt --key-file "$TMP/key" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "1 MiB must survive encrypt | decrypt with no file in between"
}

test_hex_output_composes_through_hex_decode() {
    rng 16 >"$TMP/key"
    rng 4096 >"$TMP/pt"
    "$BC_RUST" aes128-cbc -d encrypt --key-file "$TMP/key" -x <"$TMP/pt" >"$TMP/ct.hex"
    assert_size "$TMP/ct.hex" $((2 * (16 + 4096) + 1)) "-x emits two hex characters per byte, then a newline"
    "$BC_RUST" hex-decode <"$TMP/ct.hex" \
        | "$BC_RUST" aes128-cbc -d decrypt --key-file "$TMP/key" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "-x output must decrypt after hex-decode"
}

test_each_invocation_uses_a_fresh_iv() {
    rng 16 >"$TMP/key"
    rng 64 >"$TMP/pt"
    "$BC_RUST" aes128-cbc -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct1"
    "$BC_RUST" aes128-cbc -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct2"
    head -c 16 "$TMP/ct1" >"$TMP/iv1"
    head -c 16 "$TMP/ct2" >"$TMP/iv2"
    assert_differs "$TMP/iv1" "$TMP/iv2" "two encryptions must draw different IVs"
    "$BC_RUST" aes128-cbc -d decrypt --key-file "$TMP/key" <"$TMP/ct2" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "the second ciphertext still decrypts"
}

test_empty_input_produces_only_the_iv() {
    rng 16 >"$TMP/key"
    : >"$TMP/empty"
    "$BC_RUST" aes128-cbc -d encrypt --key-file "$TMP/key" <"$TMP/empty" >"$TMP/ct"
    assert_size "$TMP/ct" 16 "an empty message encrypts to just the IV"
    "$BC_RUST" aes128-cbc -d decrypt --key-file "$TMP/key" <"$TMP/ct" >"$TMP/rec"
    assert_size "$TMP/rec" 0 "and decrypts back to nothing"
}

# ---- keys -----------------------------------------------------------------------------------

test_key_file_accepts_binary_hex_and_a_trailing_newline() {
    rng 16 >"$TMP/key.bin"
    hex "$TMP/key.bin" >"$TMP/key.hex"
    { cat "$TMP/key.hex"; printf '\n'; } >"$TMP/key.hex.nl"
    { cat "$TMP/key.bin"; printf '\n'; } >"$TMP/key.bin.nl"
    rng 256 >"$TMP/pt"
    "$BC_RUST" aes128-cbc -d encrypt --key-file "$TMP/key.bin" <"$TMP/pt" >"$TMP/ct"

    local form
    for form in key.hex key.hex.nl key.bin.nl; do
        "$BC_RUST" aes128-cbc -d decrypt --key-file "$TMP/$form" <"$TMP/ct" >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "$form must load as the same key as key.bin"
    done
}

test_key_on_the_command_line_matches_the_key_file() {
    rng 16 >"$TMP/key"
    rng 256 >"$TMP/pt"
    "$BC_RUST" aes128-cbc -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
    "$BC_RUST" aes128-cbc -d decrypt --key "$(hex "$TMP/key")" <"$TMP/ct" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "--key in hex must decrypt what --key-file encrypted"
}

test_the_wrong_key_gives_the_wrong_plaintext() {
    rng 16 >"$TMP/key"
    rng 16 >"$TMP/other"
    rng 256 >"$TMP/pt"
    "$BC_RUST" aes128-cbc -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
    # CBC is unauthenticated: a wrong key succeeds and produces garbage, never the plaintext.
    "$BC_RUST" aes128-cbc -d decrypt --key-file "$TMP/other" <"$TMP/ct" >"$TMP/rec"
    assert_differs "$TMP/pt" "$TMP/rec" "a different key must not recover the plaintext"
}

test_an_all_zero_key_warns_but_proceeds() {
    head -c 16 /dev/zero >"$TMP/key"
    rng 64 >"$TMP/pt"
    expect_ok "an all-zero key is accepted" \
        "$BC_RUST" aes128-cbc -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
    assert_stderr_has "arning"
    assert_size "$TMP/ct" $((16 + 64)) "and the output is complete"
}

# ---- known answers --------------------------------------------------------------------------

# SP 800-38A Appendix F.2.2, F.2.4 and F.2.6 (CBC decrypt at each key length), transcribed in
# the Rust suite this file replaces. The CLI takes the IV as the first 16 bytes of its input, so
# the input here is IV || ciphertext, and the output must be the appendix's four plaintext blocks.
F2_IV=000102030405060708090a0b0c0d0e0f
F2_PLAINTEXT=6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
F2_KEY_128=2b7e151628aed2a6abf7158809cf4f3c
F2_KEY_192=8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
F2_KEY_256=603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
F2_CT_128=7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7
F2_CT_192=4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd
F2_CT_256=f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b

test_decrypt_matches_sp800_38a_f2_vectors() {
    local bits key ct got
    for bits in 128 192 256; do
        key="F2_KEY_$bits"
        ct="F2_CT_$bits"
        unhex "$F2_IV${!ct}" >"$TMP/ct"
        got=$("$BC_RUST" "$(cbc $bits)" -d decrypt --key "${!key}" <"$TMP/ct" | "$BC_RUST" hex-encode)
        assert_eq "$got" "$F2_PLAINTEXT" "$bits: F.2 decrypt vector"
    done
}

# ---- rejected inputs ------------------------------------------------------------------------

test_unaligned_input_is_rejected() {
    rng 16 >"$TMP/key"
    rng 1025 >"$TMP/pt"
    expect_fail "1025 bytes is not a whole number of blocks" \
        "$BC_RUST" aes128-cbc -d encrypt --key-file "$TMP/key" <"$TMP/pt"
    assert_stderr_has "whole number of 16-byte blocks"

    rng $((16 + 1025)) >"$TMP/ct"
    expect_fail "an unaligned body after the IV is rejected on decrypt too" \
        "$BC_RUST" aes128-cbc -d decrypt --key-file "$TMP/key" <"$TMP/ct"
    assert_stderr_has "whole number of 16-byte blocks"
}

test_decrypt_input_shorter_than_the_iv_is_rejected() {
    rng 16 >"$TMP/key"
    rng 8 >"$TMP/short"
    expect_fail "8 bytes cannot hold a 16-byte IV" \
        "$BC_RUST" aes128-cbc -d decrypt --key-file "$TMP/key" <"$TMP/short"
}

test_a_key_of_the_wrong_length_is_rejected() {
    rng 15 >"$TMP/key"
    rng 64 >"$TMP/pt"
    expect_fail "a 15-byte key is not an AES-128 key" \
        "$BC_RUST" aes128-cbc -d encrypt --key-file "$TMP/key" <"$TMP/pt"
    assert_stderr_has "16-byte key"
}

test_a_missing_key_is_rejected() {
    rng 64 >"$TMP/pt"
    expect_fail "neither --key nor --key-file" \
        "$BC_RUST" aes128-cbc -d encrypt <"$TMP/pt"
    assert_stderr_has "key"
}

test_a_missing_direction_is_rejected() {
    rng 16 >"$TMP/key"
    rng 64 >"$TMP/pt"
    expect_fail "--direction is required" \
        "$BC_RUST" aes128-cbc --key-file "$TMP/key" <"$TMP/pt"
    assert_stderr_has "direction"
}

run_all
