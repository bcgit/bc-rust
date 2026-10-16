#!/usr/bin/env bash
# The aes128-ctr / aes192-ctr / aes256-ctr subcommands, end to end through the binary.
#
# Framing: encrypt writes a fresh 12-byte nonce (not the 16-byte IV the other modes write) as the
# first bytes of its output, decrypt reads it back from the first 12 bytes of its input, and CTR
# accepts any input length with a ciphertext body exactly as long as the plaintext. Keys and data
# come from `bc-rust rng`; the one fixed input is the OpenSSL-generated vector set, the same one
# `crypto/aes/tests/ctr_vector_tests.rs` uses.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# One subcommand per key length: `ctr 128` prints "aes128-ctr".
ctr() { echo "aes$1-ctr"; }
NONCE_LEN=12

# ---- the OpenSSL vectors ---------------------------------------------------------------------

# `openssl enc -aes-*-ctr -K <key> -iv 000102030405060708090a0b00000000`, OpenSSL 3.0.13,
# transcribed in the Rust suite this file replaces. The nonce is the leading 12 bytes of that
# initial counter block, and the message is four SP 800-38A Appendix F blocks plus five bytes:
# five counter blocks, the last partial.
V_NONCE=000102030405060708090a0b
V_PLAINTEXT=6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c37100011223344
V_KEY_128=2b7e151628aed2a6abf7158809cf4f3c
V_KEY_192=8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
V_KEY_256=603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
V_CT_128=ffd8816338abebca17491bc67fe6751c093833c279e946d49804c6b03df09f9d6b0727101b346a530523d59fb883e678fda525b39296cfc5a821d4dcda5a622706efd63405
V_CT_192=c85f24d60a6fd4593209730ecd1ed507deae5f770708a1e162d04d42fe3dd6e6acf360f5c5f25e53a09396547d8b7f9b9d12dc684df141cd0b5462450a8d19004a271f6e8e
V_CT_256=b66c7ac8885c5ff473855203b36048ff5e7e0746b6e3ad4c2b84aaf440b1b98738a9ad1527187f6f435b83b09734cb04b3e3a2a77d2a02c4759cbd9b8fc822b31223c7e590

test_decrypt_matches_the_openssl_vectors() {
    local bits key ct got
    for bits in 128 192 256; do
        key="V_KEY_$bits"
        ct="V_CT_$bits"
        unhex "$V_NONCE${!ct}" >"$TMP/ct"
        got=$("$BC_RUST" "$(ctr $bits)" -d decrypt --key "${!key}" <"$TMP/ct" | "$BC_RUST" hex-encode)
        assert_eq "$got" "$V_PLAINTEXT" "$bits: OpenSSL decrypt vector"
    done
}

test_hex_output_matches_binary_output() {
    unhex "$V_NONCE$V_CT_128" >"$TMP/ct"
    "$BC_RUST" aes128-ctr -d decrypt --key "$V_KEY_128" <"$TMP/ct" >"$TMP/bin"
    "$BC_RUST" aes128-ctr -d decrypt --key "$V_KEY_128" -x <"$TMP/ct" >"$TMP/hex"
    assert_eq "$(tr -d '\n' <"$TMP/hex")" "$(hex "$TMP/bin")" "-x output is the hex of the binary output"
    assert_eq "$(tr -d '\n' <"$TMP/hex")" "$V_PLAINTEXT" "and both are the vector's plaintext"
}

# ---- the nonce is 12 bytes -------------------------------------------------------------------

test_the_nonce_is_twelve_bytes_not_sixteen() {
    rng 16 >"$TMP/key"
    rng 69 >"$TMP/pt"
    "$BC_RUST" aes128-ctr -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
    assert_size "$TMP/ct" $((69 + 12)) "output is a 12-byte nonce plus a body as long as the plaintext"
    "$BC_RUST" aes128-ctr -d decrypt --key-file "$TMP/key" <"$TMP/ct" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "decrypt consumes exactly 12 bytes of nonce"
}

test_decrypt_input_shorter_than_the_nonce_is_rejected() {
    rng 16 >"$TMP/key"
    local len
    for len in 0 1 11; do
        rng "$len" >"$TMP/short"
        expect_fail "$len bytes cannot hold a 12-byte nonce" \
            "$BC_RUST" aes128-ctr -d decrypt --key-file "$TMP/key" <"$TMP/short"
        assert_stderr_has "IV"
    done
}

test_empty_input_produces_only_the_nonce() {
    rng 16 >"$TMP/key"
    : >"$TMP/empty"
    "$BC_RUST" aes128-ctr -d encrypt --key-file "$TMP/key" <"$TMP/empty" >"$TMP/ct"
    assert_size "$TMP/ct" $NONCE_LEN "an empty message encrypts to just the nonce"
    "$BC_RUST" aes128-ctr -d decrypt --key-file "$TMP/key" <"$TMP/ct" >"$TMP/rec"
    assert_size "$TMP/rec" 0 "and decrypts back to nothing"
}

# ---- round trips -----------------------------------------------------------------------------

test_round_trip_through_files() {
    local bits
    for bits in 128 192 256; do
        rng "$(keylen $bits)" >"$TMP/key"
        rng 1000 >"$TMP/pt"
        "$BC_RUST" "$(ctr $bits)" -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
        assert_size "$TMP/ct" $((NONCE_LEN + 1000)) "$bits: nonce plus ciphertext"
        assert_differs "$TMP/pt" "$TMP/ct" "$bits: the data must actually be encrypted"
        "$BC_RUST" "$(ctr $bits)" -d decrypt --key-file "$TMP/key" <"$TMP/ct" >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "$bits: round trip"
    done
}

test_round_trip_through_a_pipe_larger_than_the_pipe_buffer() {
    rng 16 >"$TMP/key"
    rng $((1024 * 1024)) >"$TMP/pt"
    "$BC_RUST" aes128-ctr -d encrypt --key-file "$TMP/key" <"$TMP/pt" \
        | "$BC_RUST" aes128-ctr -d decrypt --key-file "$TMP/key" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "1 MiB must survive encrypt | decrypt with no file in between"
}

test_any_input_length_is_accepted_and_round_trips() {
    rng 16 >"$TMP/key"
    local len
    for len in $(seq 0 33); do
        rng "$len" >"$TMP/pt"
        "$BC_RUST" aes128-ctr -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
        assert_size "$TMP/ct" $((len + NONCE_LEN)) "len $len: nonce plus an equal-length body"
        "$BC_RUST" aes128-ctr -d decrypt --key-file "$TMP/key" <"$TMP/ct" >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "len $len: round trip"
    done
}

test_round_trips_across_chunk_boundaries() {
    rng 16 >"$TMP/key"
    local size
    for size in 16 1023 1024 1025 4096 4099 65536; do
        rng "$size" >"$TMP/pt"
        "$BC_RUST" aes128-ctr -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
        "$BC_RUST" aes128-ctr -d decrypt --key-file "$TMP/key" <"$TMP/ct" >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "$size bytes should round trip"
    done
}

test_hex_output_composes_through_hex_decode() {
    rng 16 >"$TMP/key"
    rng 4099 >"$TMP/pt"
    "$BC_RUST" aes128-ctr -d encrypt --key-file "$TMP/key" -x <"$TMP/pt" >"$TMP/ct.hex"
    assert_size "$TMP/ct.hex" $((2 * (NONCE_LEN + 4099) + 1)) "-x emits two hex characters per byte, then a newline"
    "$BC_RUST" hex-decode <"$TMP/ct.hex" \
        | "$BC_RUST" aes128-ctr -d decrypt --key-file "$TMP/key" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "-x output must decrypt after hex-decode"
}

# A fresh nonce per invocation. For CTR this is the whole security argument: a repeated nonce
# under one key repeats the keystream and leaks the XOR of the two messages.
test_each_invocation_uses_a_fresh_nonce() {
    rng 16 >"$TMP/key"
    rng 64 >"$TMP/pt"
    local i
    : >"$TMP/nonces"
    for i in $(seq 1 8); do
        "$BC_RUST" aes128-ctr -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
        head -c $NONCE_LEN "$TMP/ct" | "$BC_RUST" hex-encode >>"$TMP/nonces"
        echo >>"$TMP/nonces"
        "$BC_RUST" aes128-ctr -d decrypt --key-file "$TMP/key" <"$TMP/ct" >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "run $i still decrypts"
    done
    assert_eq "$(sort -u "$TMP/nonces" | wc -l)" 8 "eight encryptions must draw eight distinct nonces"
}

# ---- keys ------------------------------------------------------------------------------------

test_key_file_accepts_binary_hex_and_a_trailing_newline() {
    rng 16 >"$TMP/key.bin"
    hex "$TMP/key.bin" >"$TMP/key.hex"
    { cat "$TMP/key.hex"; printf '\n'; } >"$TMP/key.hex.nl"
    { cat "$TMP/key.bin"; printf '\n'; } >"$TMP/key.bin.nl"
    rng 256 >"$TMP/pt"
    "$BC_RUST" aes128-ctr -d encrypt --key-file "$TMP/key.bin" <"$TMP/pt" >"$TMP/ct"

    local form
    for form in key.hex key.hex.nl key.bin.nl; do
        "$BC_RUST" aes128-ctr -d decrypt --key-file "$TMP/$form" <"$TMP/ct" >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "$form must load as the same key as key.bin"
    done
}

test_key_on_the_command_line_matches_the_key_file() {
    rng 16 >"$TMP/key"
    rng 256 >"$TMP/pt"
    "$BC_RUST" aes128-ctr -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
    "$BC_RUST" aes128-ctr -d decrypt --key "$(hex "$TMP/key")" <"$TMP/ct" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "--key in hex must decrypt what --key-file encrypted"
}

test_a_key_of_the_wrong_length_is_rejected() {
    rng 16 >"$TMP/key"
    rng 64 >"$TMP/pt"
    expect_fail "a 16-byte key is not an AES-256 key" \
        "$BC_RUST" aes256-ctr -d encrypt --key-file "$TMP/key" <"$TMP/pt"
    assert_stderr_has "32-byte key"
    assert_stderr_has "16 bytes"
}

test_a_missing_key_is_rejected() {
    rng 64 >"$TMP/pt"
    expect_fail "neither --key nor --key-file" \
        "$BC_RUST" aes128-ctr -d encrypt <"$TMP/pt"
    assert_stderr_has -- "--key"
}

test_an_all_zero_key_warns_but_proceeds() {
    head -c 16 /dev/zero >"$TMP/key"
    rng 69 >"$TMP/pt"
    expect_ok "an all-zero key is accepted" \
        "$BC_RUST" aes128-ctr -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
    assert_stderr_has "arning"
    assert_size "$TMP/ct" $((NONCE_LEN + 69)) "nonce plus the 69 ciphertext bytes"
}

# ---- CTR-specific behaviour ------------------------------------------------------------------

# Encryption and decryption are the same operation (SP 800-38A Sec 6.5): the keystream depends on
# nothing but key and nonce, so presenting the nonce followed by a *plaintext* to `decrypt` gives
# exactly the ciphertext body that `encrypt` produced under that nonce.
test_encrypt_and_decrypt_are_the_same_operation() {
    rng 16 >"$TMP/key"
    rng 69 >"$TMP/pt"
    "$BC_RUST" aes128-ctr -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
    head -c $NONCE_LEN "$TMP/ct" >"$TMP/nonce"
    tail -c +$((NONCE_LEN + 1)) "$TMP/ct" >"$TMP/body"
    cat "$TMP/nonce" "$TMP/pt" | "$BC_RUST" aes128-ctr -d decrypt --key-file "$TMP/key" >"$TMP/again"
    assert_same "$TMP/body" "$TMP/again" "decrypt of nonce || plaintext must be the ciphertext body"
}

# Appendix D, Table D.2 for CTR: "SBE in the decryption of Cj", and nothing else affected. A
# flipped ciphertext bit flips exactly the corresponding plaintext bit, with no garbling anywhere
# to signal the tampering.
test_a_ciphertext_bit_flip_flips_exactly_that_plaintext_bit_and_nothing_else() {
    unhex "$V_NONCE$V_CT_128" >"$TMP/ct"
    unhex "$V_PLAINTEXT" >"$TMP/expected"
    # Byte 3 of the second block. The body starts after the 12-byte nonce.
    flip_byte "$TMP/ct" $((12 + 16 + 3)) 32
    flip_byte "$TMP/expected" $((16 + 3)) 32
    "$BC_RUST" aes128-ctr -d decrypt --key "$V_KEY_128" <"$TMP/ct" >"$TMP/got"
    assert_same "$TMP/expected" "$TMP/got" "exactly one plaintext bit should change, and nothing else"
}

test_a_wrong_key_does_not_recover_the_plaintext() {
    rng 16 >"$TMP/key"
    rng 16 >"$TMP/other"
    rng 69 >"$TMP/pt"
    "$BC_RUST" aes128-ctr -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
    # CTR is unauthenticated: a wrong key succeeds, with output the same length and wrong.
    "$BC_RUST" aes128-ctr -d decrypt --key-file "$TMP/other" <"$TMP/ct" >"$TMP/rec"
    assert_differs "$TMP/pt" "$TMP/rec" "a wrong key must not recover the plaintext"
    assert_size "$TMP/rec" 69 "but the length is unchanged"
}

test_ctr_and_cfb_are_not_interchangeable() {
    rng 16 >"$TMP/key"
    rng 69 >"$TMP/pt"
    "$BC_RUST" aes128-ctr -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ctr"
    "$BC_RUST" aes128-cfb -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/cfb"
    assert_size "$TMP/ctr" $((69 + 12)) "CTR prepends 12 bytes"
    assert_size "$TMP/cfb" $((69 + 16)) "CFB prepends 16"
    "$BC_RUST" aes128-cfb -d decrypt --key-file "$TMP/key" <"$TMP/ctr" >"$TMP/rec"
    assert_differs "$TMP/pt" "$TMP/rec" "CFB must not decrypt a CTR ciphertext"
}

# ---- discoverability -------------------------------------------------------------------------

test_the_subcommands_are_listed_in_help() {
    "$BC_RUST" --help >"$TMP/help"
    local cmd
    for cmd in aes128-ctr aes192-ctr aes256-ctr; do
        grep -q "$cmd" "$TMP/help" || fail "--help should list $cmd"
    done
}

# The per-command help must state the 12-byte nonce, the counter limit and the malleability
# warning, because all three differ from the other modes.
test_per_command_help_documents_the_nonce_and_the_counter() {
    "$BC_RUST" aes128-ctr --help >"$TMP/help"
    grep -q "encrypt" "$TMP/help" || fail "help should list the encrypt direction"
    grep -q "decrypt" "$TMP/help" || fail "help should list the decrypt direction"
    grep -qi "first 12 bytes" "$TMP/help" || fail "help should say the nonce is 12 bytes"
    grep -q "counter" "$TMP/help" || fail "help should mention the counter"
    grep -qiE "malleable|flipping" "$TMP/help" || fail "help should warn about malleability"
}

run_all
