#!/usr/bin/env bash
# The aes128-ofb / aes192-ofb / aes256-ofb subcommands, end to end through the binary.
#
# Framing: encrypt writes a fresh IV as the first 16 bytes of its output and decrypt reads it back
# from the first 16 bytes of its input, as for CFB; OFB is a stream cipher, so input of any length
# is accepted and the ciphertext body is exactly as long as the plaintext. Keys and data come from
# `bc-rust rng`; the fixed inputs are the SP 800-38A Appendix F.4 known-answer set and the F.3.13
# CFB ciphertext used for the cross-mode guard.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# One subcommand per key length: `ofb 128` prints "aes128-ofb".
ofb() { echo "aes$1-ofb"; }

# ---- round trips --------------------------------------------------------------------------

test_round_trip_through_files() {
    local bits
    for bits in 128 192 256; do
        rng "$(keylen $bits)" >"$TMP/key"
        rng 1024 >"$TMP/pt"

        "$BC_RUST" "$(ofb $bits)" -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
        assert_size "$TMP/ct" $((16 + 1024)) "$bits: ciphertext is the IV plus the plaintext length"
        assert_differs "$TMP/pt" "$TMP/ct" "$bits: the data must actually be encrypted"

        "$BC_RUST" "$(ofb $bits)" -d decrypt --key-file "$TMP/key" <"$TMP/ct" >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "$bits: decrypt must recover the plaintext"
    done
}

test_round_trip_through_a_pipe_larger_than_the_pipe_buffer() {
    rng 16 >"$TMP/key"
    rng $((1024 * 1024)) >"$TMP/pt"
    "$BC_RUST" aes128-ofb -d encrypt --key-file "$TMP/key" <"$TMP/pt" \
        | "$BC_RUST" aes128-ofb -d decrypt --key-file "$TMP/key" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "1 MiB must survive encrypt | decrypt with no file in between"
}

# Every length from empty to just past two blocks: OFB pads nothing and rejects nothing, and the
# body of the ciphertext is exactly as long as the plaintext.
test_any_input_length_is_accepted_and_round_trips() {
    rng 16 >"$TMP/key"
    local len
    for len in $(seq 0 33); do
        rng "$len" >"$TMP/pt"
        "$BC_RUST" aes128-ofb -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
        assert_size "$TMP/ct" $((16 + len)) "len $len: IV plus a body as long as the plaintext"
        "$BC_RUST" aes128-ofb -d decrypt --key-file "$TMP/key" <"$TMP/ct" >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "len $len: round trip"
    done
}

# Sizes that straddle the 1 KiB streaming chunk and the block boundary: 1024 is one chunk, 1040 a
# chunk plus a block, 4112 four chunks plus a block; the odd sizes leave a partial final block
# and put a chunk boundary in the middle of one.
test_round_trips_across_chunk_boundaries() {
    rng 16 >"$TMP/key"
    local size
    for size in 16 32 1023 1024 1025 1040 4096 4112 65535 65536; do
        rng "$size" >"$TMP/pt"
        "$BC_RUST" aes128-ofb -d encrypt --key-file "$TMP/key" <"$TMP/pt" \
            | "$BC_RUST" aes128-ofb -d decrypt --key-file "$TMP/key" >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "$size bytes should round trip"
    done
}

test_hex_output_composes_through_hex_decode() {
    rng 16 >"$TMP/key"
    rng 4097 >"$TMP/pt"
    "$BC_RUST" aes128-ofb -d encrypt --key-file "$TMP/key" -x <"$TMP/pt" >"$TMP/ct.hex"
    assert_size "$TMP/ct.hex" $((2 * (16 + 4097) + 1)) "-x emits two hex characters per byte, then a newline"
    "$BC_RUST" hex-decode <"$TMP/ct.hex" \
        | "$BC_RUST" aes128-ofb -d decrypt --key-file "$TMP/key" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "-x output must decrypt after hex-decode"
}

# A fresh IV per invocation is OFB's one requirement (SP 800-38A Appendix C): a repeated key-and-IV
# pair repeats the whole keystream.
test_each_invocation_uses_a_fresh_iv() {
    rng 16 >"$TMP/key"
    rng 64 >"$TMP/pt"
    "$BC_RUST" aes128-ofb -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct1"
    "$BC_RUST" aes128-ofb -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct2"
    slice "$TMP/ct1" 0 16 >"$TMP/iv1"
    slice "$TMP/ct2" 0 16 >"$TMP/iv2"
    assert_differs "$TMP/iv1" "$TMP/iv2" "two encryptions must draw different IVs"
    slice "$TMP/ct1" 16 64 >"$TMP/body1"
    slice "$TMP/ct2" 16 64 >"$TMP/body2"
    assert_differs "$TMP/body1" "$TMP/body2" "and the bodies differ too, not just the IV"
    "$BC_RUST" aes128-ofb -d decrypt --key-file "$TMP/key" <"$TMP/ct2" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "the second ciphertext still decrypts"
}

test_empty_input_produces_only_the_iv() {
    rng 16 >"$TMP/key"
    : >"$TMP/empty"
    "$BC_RUST" aes128-ofb -d encrypt --key-file "$TMP/key" <"$TMP/empty" >"$TMP/ct"
    assert_size "$TMP/ct" 16 "an empty message encrypts to just the IV"
    "$BC_RUST" aes128-ofb -d decrypt --key-file "$TMP/key" <"$TMP/ct" >"$TMP/rec"
    assert_size "$TMP/rec" 0 "and decrypts back to nothing"
}

# Anything past the IV is ciphertext, whatever its length.
test_decrypt_accepts_an_unaligned_body() {
    rng 16 >"$TMP/key"
    rng $((16 + 20)) >"$TMP/ct"
    "$BC_RUST" aes128-ofb -d decrypt --key-file "$TMP/key" <"$TMP/ct" >"$TMP/rec"
    assert_size "$TMP/rec" 20 "the plaintext is exactly as long as the ciphertext body"
}

# ---- keys -----------------------------------------------------------------------------------

test_key_file_accepts_binary_hex_and_a_trailing_newline() {
    rng 16 >"$TMP/key.bin"
    hex "$TMP/key.bin" >"$TMP/key.hex"
    { cat "$TMP/key.hex"; printf '\n'; } >"$TMP/key.hex.nl"
    { cat "$TMP/key.bin"; printf '\n'; } >"$TMP/key.bin.nl"
    rng 256 >"$TMP/pt"
    "$BC_RUST" aes128-ofb -d encrypt --key-file "$TMP/key.bin" <"$TMP/pt" >"$TMP/ct"

    local form
    # The hex forms need --hex-input: a key file is raw bytes unless the flag says otherwise.
    for form in key.hex key.hex.nl; do
        "$BC_RUST" --hex-input aes128-ofb -d decrypt --key-file "$TMP/$form" <"$TMP/ct" >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "$form must load as the same key as key.bin"
    done
    "$BC_RUST" aes128-ofb -d decrypt --key-file "$TMP/key.bin.nl" <"$TMP/ct" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "key.bin.nl must load as the same key as key.bin"
}

test_key_on_the_command_line_matches_the_key_file() {
    rng 16 >"$TMP/key"
    rng 256 >"$TMP/pt"
    "$BC_RUST" aes128-ofb -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
    "$BC_RUST" aes128-ofb -d decrypt --key "$(hex "$TMP/key")" <"$TMP/ct" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "--key in hex must decrypt what --key-file encrypted"
}

# OFB is unauthenticated: a wrong key succeeds and produces garbage of the same length, never the
# plaintext -- which is exactly why the crate docs insist on authenticating separately.
test_the_wrong_key_gives_the_wrong_plaintext() {
    rng 16 >"$TMP/key"
    rng 16 >"$TMP/other"
    rng 256 >"$TMP/pt"
    "$BC_RUST" aes128-ofb -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
    "$BC_RUST" aes128-ofb -d decrypt --key-file "$TMP/other" <"$TMP/ct" >"$TMP/rec"
    assert_differs "$TMP/pt" "$TMP/rec" "a different key must not recover the plaintext"
    assert_size "$TMP/rec" 256 "but the length is unchanged"
}

test_an_all_zero_key_warns_but_proceeds() {
    head -c 16 /dev/zero >"$TMP/key"
    rng 64 >"$TMP/pt"
    expect_ok "an all-zero key is accepted" \
        "$BC_RUST" aes128-ofb -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
    assert_stderr_has "arning"
    assert_size "$TMP/ct" $((16 + 64)) "and the output is complete"
}

# ---- known answers --------------------------------------------------------------------------

# SP 800-38A Appendix F.4.1, F.4.3 and F.4.5 (OFB at each key length), plus F.3.13 (CFB128-AES128)
# for the cross-mode guard. Encrypt takes the IV through --iv and must print only the ciphertext;
# decrypt takes IV || ciphertext and must print the appendix's four plaintext blocks.
F4_IV=000102030405060708090a0b0c0d0e0f
F4_PLAINTEXT=6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
F4_KEY_128=2b7e151628aed2a6abf7158809cf4f3c
F4_KEY_192=8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
F4_KEY_256=603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
F4_CT_128=3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed8259740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e
F4_CT_192=cdc80d6fddf18cab34c25909c99a4174fcc28b8d4c63837c09e81700c11004018d9a9aeac0f6596f559c6d4daf59a5f26d9f200857ca6c3e9cac524bd9acc92a
F4_CT_256=dc7e84bfda79164b7ecd8486985d38604febdc6740d20b3ac88f6ad82a4fb08d71ab47a086e86eedf39d1c5bba97c4080126141d67f37be8538f5a8be740e484
F3_CFB_CT_128=3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6

test_encrypt_matches_sp800_38a_f4_vectors() {
    local bits key ct got
    for bits in 128 192 256; do
        key="F4_KEY_$bits"
        ct="F4_CT_$bits"
        unhex "$F4_PLAINTEXT" >"$TMP/pt"
        got=$("$BC_RUST" "$(ofb $bits)" -d encrypt --key "${!key}" --iv "$F4_IV" -x <"$TMP/pt")
        assert_eq "$got" "${!ct}" "$bits: F.4 encrypt vector"
    done
}

test_decrypt_matches_sp800_38a_f4_vectors() {
    local bits key ct got
    for bits in 128 192 256; do
        key="F4_KEY_$bits"
        ct="F4_CT_$bits"
        unhex "$F4_IV${!ct}" >"$TMP/ct"
        got=$("$BC_RUST" "$(ofb $bits)" -d decrypt --key "${!key}" <"$TMP/ct" | "$BC_RUST" hex-encode)
        assert_eq "$got" "$F4_PLAINTEXT" "$bits: F.4 decrypt vector"
    done
}

# Appendix D, Table D.2 for OFB: a bit error in Cj gives specific bit errors in the decryption of
# Cj -- the same bit position -- and nothing else. Under CFB the next block would be randomised
# too, so this also checks that the CLI is running OFB.
test_a_ciphertext_bit_flip_flips_that_bit_and_nothing_else() {
    # Byte 3 of the second ciphertext block: input is IV | C1 | C2 | C3 | C4, so C2 starts at 32.
    local offset=$((32 + 3)) mask=$((0x20))
    unhex "$(flip_hex "$F4_IV$F4_CT_128" $offset $mask)" >"$TMP/ct"
    "$BC_RUST" aes128-ofb -d decrypt --key "$F4_KEY_128" <"$TMP/ct" >"$TMP/out"
    # Plaintext byte 19 is byte 3 of P2.
    unhex "$(flip_hex "$F4_PLAINTEXT" 19 $mask)" >"$TMP/expected"
    assert_same "$TMP/out" "$TMP/expected" "exactly the flipped bit of P2 changes"
}

# OFB and CFB take the same arguments, and under the same key, IV and plaintext they agree on the
# first block (both are P1 XOR CIPH_K(IV)) and nothing after it, so a mix-up decrypts the first
# block and silently garbles the rest. Each must reproduce the plaintext only from its own
# ciphertext.
test_ofb_and_cfb_are_not_interchangeable() {
    assert_eq "${F4_CT_128:0:32}" "${F3_CFB_CT_128:0:32}" "F.4.1 and F.3.13 share C1"
    unhex "$F4_IV$F4_CT_128" >"$TMP/ofb_ct"
    unhex "$F4_IV$F3_CFB_CT_128" >"$TMP/cfb_ct"
    unhex "$F4_PLAINTEXT" >"$TMP/pt"

    "$BC_RUST" aes128-ofb -d decrypt --key "$F4_KEY_128" <"$TMP/ofb_ct" >"$TMP/own"
    assert_same "$TMP/own" "$TMP/pt" "OFB decrypts its own ciphertext"
    "$BC_RUST" aes128-ofb -d decrypt --key "$F4_KEY_128" <"$TMP/cfb_ct" >"$TMP/cross_ofb"
    assert_differs "$TMP/cross_ofb" "$TMP/pt" "OFB must not decrypt a CFB ciphertext"
    "$BC_RUST" aes128-cfb -d decrypt --key "$F4_KEY_128" <"$TMP/ofb_ct" >"$TMP/cross_cfb"
    assert_differs "$TMP/cross_cfb" "$TMP/pt" "CFB must not decrypt an OFB ciphertext"
}

# ---- rejected inputs ------------------------------------------------------------------------

test_decrypt_input_shorter_than_the_iv_is_rejected() {
    rng 16 >"$TMP/key"
    local len
    for len in 0 1 15; do
        rng "$len" >"$TMP/short"
        expect_fail "$len bytes cannot hold a 16-byte IV" \
            "$BC_RUST" aes128-ofb -d decrypt --key-file "$TMP/key" <"$TMP/short"
        assert_stderr_has "IV"
    done
}

test_a_key_of_the_wrong_length_is_rejected() {
    rng 16 >"$TMP/key"
    rng 64 >"$TMP/pt"
    expect_fail "a 16-byte key is not an AES-256 key" \
        "$BC_RUST" aes256-ofb -d encrypt --key-file "$TMP/key" <"$TMP/pt"
    assert_stderr_has "32-byte key"
    assert_stderr_has "16 bytes"
}

test_a_missing_key_is_rejected() {
    rng 64 >"$TMP/pt"
    expect_fail "neither --key nor --key-file" \
        "$BC_RUST" aes128-ofb -d encrypt <"$TMP/pt"
    assert_stderr_has "key"
}

test_a_missing_direction_is_rejected() {
    rng 16 >"$TMP/key"
    rng 64 >"$TMP/pt"
    expect_fail "--direction is required" \
        "$BC_RUST" aes128-ofb --key-file "$TMP/key" <"$TMP/pt"
    assert_stderr_has "direction"
}

# ---- discoverability ------------------------------------------------------------------------

test_the_subcommands_are_listed_in_help() {
    "$BC_RUST" --help >"$TMP/help"
    local cmd
    for cmd in aes128-ofb aes192-ofb aes256-ofb; do
        grep -q "$cmd" "$TMP/help" || fail "--help should list $cmd"
    done
}

test_per_command_help_documents_the_iv_convention() {
    "$BC_RUST" aes128-ofb --help >"$TMP/help"
    grep -q "encrypt" "$TMP/help" || fail "help should list the encrypt direction"
    grep -q "decrypt" "$TMP/help" || fail "help should list the decrypt direction"
    grep -qi "first 16 bytes" "$TMP/help" || fail "help should explain where the IV goes"
    grep -qi "never be reused" "$TMP/help" || fail "help should say a supplied IV is a nonce"
}

run_all
