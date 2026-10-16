#!/usr/bin/env bash
# The aes128-cfb8 / aes192-cfb8 / aes256-cfb8 subcommands, end to end through the binary.
#
# Framing: encrypt writes a fresh IV as the first 16 bytes of its output and decrypt reads it back
# from the first 16 bytes of its input. CFB8's segment is one byte, so any input length is
# accepted and the ciphertext is exactly as long as the plaintext. Keys and data come from
# `bc-rust rng`; the fixed inputs are the SP 800-38A Appendix F.3 known-answer set.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# One subcommand per key length: `cfb8 128` prints "aes128-cfb8".
cfb8() { echo "aes$1-cfb8"; }

# ---- round trips --------------------------------------------------------------------------

test_round_trip_through_files() {
    local bits
    for bits in 128 192 256; do
        rng "$(keylen $bits)" >"$TMP/key"
        rng 1000 >"$TMP/pt"

        "$BC_RUST" "$(cfb8 $bits)" -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
        assert_size "$TMP/ct" $((16 + 1000)) "$bits: ciphertext is the IV plus an equal-length body"
        assert_differs "$TMP/pt" "$TMP/ct" "$bits: the data must actually be encrypted"

        "$BC_RUST" "$(cfb8 $bits)" -d decrypt --key-file "$TMP/key" <"$TMP/ct" >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "$bits: decrypt must recover the plaintext"
    done
}

# Smaller than the other modes' pipe test because CFB8 spends a full AES call per byte.
test_round_trip_through_a_pipe_larger_than_the_pipe_buffer() {
    rng 16 >"$TMP/key"
    rng $((256 * 1024)) >"$TMP/pt"
    "$BC_RUST" aes128-cfb8 -d encrypt --key-file "$TMP/key" <"$TMP/pt" \
        | "$BC_RUST" aes128-cfb8 -d decrypt --key-file "$TMP/key" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "256 KiB must survive encrypt | decrypt with no file in between"
}

test_any_input_length_is_accepted_and_round_trips() {
    rng 16 >"$TMP/key"
    local len
    for len in $(seq 0 33); do
        rng "$len" >"$TMP/pt"
        "$BC_RUST" aes128-cfb8 -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
        assert_size "$TMP/ct" $((16 + len)) "len $len: IV plus an equal-length ciphertext"
        "$BC_RUST" aes128-cfb8 -d decrypt --key-file "$TMP/key" <"$TMP/ct" >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "len $len: round trip"
    done
}

# Sizes that straddle the 1 KiB streaming chunk, including ones that leave the chunk boundary in
# the middle of the batch the decryptor uses.
test_round_trips_across_chunk_boundaries() {
    rng 16 >"$TMP/key"
    local size
    for size in 1 8 9 1023 1024 1025 4096 4099; do
        rng "$size" >"$TMP/pt"
        "$BC_RUST" aes128-cfb8 -d encrypt --key-file "$TMP/key" <"$TMP/pt" \
            | "$BC_RUST" aes128-cfb8 -d decrypt --key-file "$TMP/key" >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "$size bytes should round trip"
    done
}

test_hex_output_composes_through_hex_decode() {
    rng 16 >"$TMP/key"
    rng 777 >"$TMP/pt"
    "$BC_RUST" aes128-cfb8 -d encrypt --key-file "$TMP/key" -x <"$TMP/pt" >"$TMP/ct.hex"
    assert_size "$TMP/ct.hex" $((2 * (16 + 777) + 1)) "-x emits two hex characters per byte and a newline"
    "$BC_RUST" hex-decode <"$TMP/ct.hex" \
        | "$BC_RUST" aes128-cfb8 -d decrypt --key-file "$TMP/key" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "-x output must decrypt after hex-decode"
}

test_each_invocation_uses_a_fresh_iv() {
    rng 16 >"$TMP/key"
    rng 64 >"$TMP/pt"
    "$BC_RUST" aes128-cfb8 -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct1"
    "$BC_RUST" aes128-cfb8 -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct2"
    head -c 16 "$TMP/ct1" >"$TMP/iv1"
    head -c 16 "$TMP/ct2" >"$TMP/iv2"
    assert_differs "$TMP/iv1" "$TMP/iv2" "two encryptions must draw different IVs"
    "$BC_RUST" aes128-cfb8 -d decrypt --key-file "$TMP/key" <"$TMP/ct2" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "the second ciphertext still decrypts"
}

test_empty_input_produces_only_the_iv() {
    rng 16 >"$TMP/key"
    : >"$TMP/empty"
    "$BC_RUST" aes128-cfb8 -d encrypt --key-file "$TMP/key" <"$TMP/empty" >"$TMP/ct"
    assert_size "$TMP/ct" 16 "an empty message encrypts to just the IV"
    "$BC_RUST" aes128-cfb8 -d decrypt --key-file "$TMP/key" <"$TMP/ct" >"$TMP/rec"
    assert_size "$TMP/rec" 0 "and decrypts back to nothing"
}

# ---- keys -----------------------------------------------------------------------------------

test_key_file_accepts_binary_hex_and_a_trailing_newline() {
    rng 16 >"$TMP/key.bin"
    hex "$TMP/key.bin" >"$TMP/key.hex"
    { cat "$TMP/key.hex"; printf '\n'; } >"$TMP/key.hex.nl"
    { cat "$TMP/key.bin"; printf '\n'; } >"$TMP/key.bin.nl"
    rng 200 >"$TMP/pt"
    "$BC_RUST" aes128-cfb8 -d encrypt --key-file "$TMP/key.bin" <"$TMP/pt" >"$TMP/ct"

    local form
    for form in key.hex key.hex.nl key.bin.nl; do
        "$BC_RUST" aes128-cfb8 -d decrypt --key-file "$TMP/$form" <"$TMP/ct" >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "$form must load as the same key as key.bin"
    done
}

test_key_on_the_command_line_matches_the_key_file() {
    rng 16 >"$TMP/key"
    rng 200 >"$TMP/pt"
    "$BC_RUST" aes128-cfb8 -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
    "$BC_RUST" aes128-cfb8 -d decrypt --key "$(hex "$TMP/key")" <"$TMP/ct" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "--key in hex must decrypt what --key-file encrypted"
}

test_a_wrong_key_does_not_recover_the_plaintext() {
    rng 16 >"$TMP/key"
    rng 16 >"$TMP/other"
    rng 200 >"$TMP/pt"
    "$BC_RUST" aes128-cfb8 -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
    # CFB8 is unauthenticated: a wrong key succeeds and produces garbage of the same length.
    "$BC_RUST" aes128-cfb8 -d decrypt --key-file "$TMP/other" <"$TMP/ct" >"$TMP/rec"
    assert_differs "$TMP/pt" "$TMP/rec" "a different key must not recover the plaintext"
    assert_size "$TMP/rec" 200 "but the length is unchanged"
}

test_an_all_zero_key_warns_but_proceeds() {
    head -c 16 /dev/zero >"$TMP/key"
    rng 18 >"$TMP/pt"
    expect_ok "an all-zero key is accepted" \
        "$BC_RUST" aes128-cfb8 -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
    assert_stderr_has "arning"
    assert_size "$TMP/ct" $((16 + 18)) "and the output is complete"
}

# ---- known answers --------------------------------------------------------------------------

# SP 800-38A Appendix F.3.7, F.3.9 and F.3.11 (CFB8 encrypt at each key length), transcribed in
# the Rust suite this file replaces. `decrypt` is the direction that can be pinned, since
# `encrypt` draws its own IV; the input here is IV || ciphertext, and the output must be the
# appendix's 18 plaintext bytes.
F3_IV=000102030405060708090a0b0c0d0e0f
F3_PLAINTEXT=6bc1bee22e409f96e93d7e117393172aae2d
F3_KEY_128=2b7e151628aed2a6abf7158809cf4f3c
F3_KEY_192=8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
F3_KEY_256=603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
F3_CT_128=3b79424c9c0dd436bace9e0ed4586a4f32b9
F3_CT_192=cda2521ef0a905ca44cd057cbf0d47a0678a
F3_CT_256=dc1f1a8520a64db55fcc8ac554844e889700
# F.3.13 CFB128-AES128.Encrypt, first 18 bytes: same key, IV and plaintext as F3_CT_128, for the
# cross-mode guard.
F3_CFB128_CT_128=3b3fd92eb72dad20333449f8e83cfb4ac8a6

test_decrypt_matches_sp800_38a_f3_vectors() {
    local bits key ct got
    for bits in 128 192 256; do
        key="F3_KEY_$bits"
        ct="F3_CT_$bits"
        unhex "$F3_IV${!ct}" >"$TMP/ct"
        got=$("$BC_RUST" "$(cfb8 $bits)" -d decrypt --key "${!key}" <"$TMP/ct" | "$BC_RUST" hex-encode)
        assert_eq "$got" "$F3_PLAINTEXT" "$bits: F.3 decrypt vector"
    done
}

test_hex_output_matches_binary_output() {
    unhex "$F3_IV$F3_CT_128" >"$TMP/ct"
    local binary_as_hex hex_out
    binary_as_hex=$("$BC_RUST" aes128-cfb8 -d decrypt --key "$F3_KEY_128" <"$TMP/ct" | "$BC_RUST" hex-encode)
    hex_out=$("$BC_RUST" aes128-cfb8 -d decrypt --key "$F3_KEY_128" -x <"$TMP/ct")
    assert_eq "$hex_out" "$binary_as_hex" "-x must be the hex of the binary output"
    assert_eq "$hex_out" "$F3_PLAINTEXT" "-x must be the F.3.7 plaintext"
}

# Both spec ciphertexts are for the same key, IV and plaintext, so each mode must reproduce the
# plaintext only from its own ciphertext. They agree on the first byte -- P1 XOR MSB_8(CIPH_K(IV))
# in both -- and diverge immediately after; neither mode is authenticated, so the mismatch is
# silent.
test_cfb8_and_cfb128_are_not_interchangeable() {
    unhex "$F3_PLAINTEXT" >"$TMP/pt"
    unhex "$F3_IV$F3_CT_128" >"$TMP/cfb8.ct"
    unhex "$F3_IV$F3_CFB128_CT_128" >"$TMP/cfb128.ct"

    "$BC_RUST" aes128-cfb8 -d decrypt --key "$F3_KEY_128" <"$TMP/cfb8.ct" >"$TMP/own8"
    assert_same "$TMP/pt" "$TMP/own8" "CFB8 decrypts its own ciphertext"
    "$BC_RUST" aes128-cfb -d decrypt --key "$F3_KEY_128" <"$TMP/cfb128.ct" >"$TMP/own128"
    assert_same "$TMP/pt" "$TMP/own128" "CFB128 decrypts its own ciphertext"

    "$BC_RUST" aes128-cfb8 -d decrypt --key "$F3_KEY_128" <"$TMP/cfb128.ct" >"$TMP/cross8"
    assert_differs "$TMP/pt" "$TMP/cross8" "CFB8 must not decrypt a CFB128 ciphertext"
    assert_eq "$(byte_at "$TMP/cross8" 0)" "$(byte_at "$TMP/pt" 0)" "...though the first byte necessarily agrees"

    "$BC_RUST" aes128-cfb -d decrypt --key "$F3_KEY_128" <"$TMP/cfb8.ct" >"$TMP/cross128"
    assert_differs "$TMP/pt" "$TMP/cross128" "CFB128 must not decrypt a CFB8 ciphertext"
}

# ---- SP 800-38A Appendix D ------------------------------------------------------------------

# Table D.2 for CFB: "SBE in the decryption of Cj" plus "RBE in the decryption of Cj+1,...,Cj+b/s".
# With s = 8 on a 16-byte block, b/s is 16: a flipped ciphertext bit flips the same bit of the same
# plaintext byte, corrupts the next 16 bytes, and then decryption resynchronises exactly. That is
# also a sharp check that the CLI is running CFB8 and not CFB128, whose window is one block.
test_a_ciphertext_bit_flip_damages_exactly_sixteen_following_bytes() {
    rng 16 >"$TMP/key"
    rng 48 >"$TMP/pt"
    "$BC_RUST" aes128-cfb8 -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"

    # Byte 8 of the body, which starts after the 16-byte IV; flip bit 5.
    local j=8 mask=32
    cp "$TMP/ct" "$TMP/corrupt"
    flip_byte "$TMP/corrupt" $((16 + j)) $mask
    "$BC_RUST" aes128-cfb8 -d decrypt --key-file "$TMP/key" <"$TMP/corrupt" >"$TMP/out"
    assert_size "$TMP/out" 48 "the output length is unchanged"

    head -c $j "$TMP/pt" >"$TMP/pt.head"
    head -c $j "$TMP/out" >"$TMP/out.head"
    assert_same "$TMP/pt.head" "$TMP/out.head" "earlier bytes are unaffected"

    assert_eq "$(byte_at "$TMP/out" $j)" "$(( $(byte_at "$TMP/pt" $j) ^ mask ))" \
        "SBE: exactly the flipped bit, in the targeted byte"

    tail -c +$((j + 2)) "$TMP/pt" | head -c 16 >"$TMP/pt.window"
    tail -c +$((j + 2)) "$TMP/out" | head -c 16 >"$TMP/out.window"
    assert_differs "$TMP/pt.window" "$TMP/out.window" "the next b/s = 16 bytes should be randomised"

    tail -c +$((j + 18)) "$TMP/pt" >"$TMP/pt.tail"
    tail -c +$((j + 18)) "$TMP/out" >"$TMP/out.tail"
    assert_same "$TMP/pt.tail" "$TMP/out.tail" "byte j + 17 onwards must be exactly right again"
}

# ---- rejected inputs ------------------------------------------------------------------------

test_decrypt_input_shorter_than_the_iv_is_rejected() {
    rng 16 >"$TMP/key"
    local len
    for len in 0 1 15; do
        rng "$len" >"$TMP/short"
        expect_fail "$len bytes cannot hold a 16-byte IV" \
            "$BC_RUST" aes128-cfb8 -d decrypt --key-file "$TMP/key" <"$TMP/short"
        assert_stderr_has "IV"
    done
}

test_a_key_of_the_wrong_length_is_rejected() {
    rng 16 >"$TMP/key"
    rng 18 >"$TMP/pt"
    expect_fail "a 16-byte key is not an AES-256 key" \
        "$BC_RUST" aes256-cfb8 -d encrypt --key-file "$TMP/key" <"$TMP/pt"
    assert_stderr_has "32-byte key"
    assert_stderr_has "16 bytes"
}

test_a_missing_key_is_rejected() {
    rng 18 >"$TMP/pt"
    expect_fail "neither --key nor --key-file" \
        "$BC_RUST" aes128-cfb8 -d encrypt <"$TMP/pt"
    assert_stderr_has -- "--key"
}

# A rejected key with a large stdin behind it: the error must still be the CLI's own, not a pipe
# failure.
test_a_large_payload_on_an_error_path_is_still_reported() {
    rng $((256 * 1024)) >"$TMP/pt"
    expect_fail "no key, large input" \
        "$BC_RUST" aes128-cfb8 -d encrypt <"$TMP/pt"
    assert_stderr_has -- "--key"
}

# ---- discoverability ------------------------------------------------------------------------

test_the_subcommands_are_listed_in_help() {
    local help cmd
    help=$("$BC_RUST" --help)
    for cmd in aes128-cfb8 aes192-cfb8 aes256-cfb8; do
        echo "$help" | grep -q "$cmd" || fail "--help should list $cmd"
    done
}

test_per_command_help_documents_the_segment_size_and_the_cost() {
    local help
    help=$("$BC_RUST" aes128-cfb8 --help)
    echo "$help" | grep -q "encrypt" || fail "help should list the encrypt direction"
    echo "$help" | grep -q "decrypt" || fail "help should list the decrypt direction"
    echo "$help" | grep -qi "first 16 bytes" || fail "help should explain where the IV goes"
    echo "$help" | grep -q "CFB8" || fail "help should say which CFB variant this is"
    echo "$help" | grep -qi "non-interoperable" || fail "help should warn that CFB8 is not CFB128"
}

run_all
