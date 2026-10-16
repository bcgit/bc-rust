#!/usr/bin/env bash
# The aes128-cfb / aes192-cfb / aes256-cfb subcommands, end to end through the binary.
#
# Framing: encrypt writes a fresh IV as the first 16 bytes of its output and decrypt reads it back
# from the first 16 bytes of its input, as for CBC -- but CFB is a stream cipher, so input of any
# length is accepted and the ciphertext body is exactly as long as the plaintext. Keys and data
# come from `bc-rust rng`; the fixed inputs are the SP 800-38A Appendix F.3 known-answer set and
# the F.2.1 CBC ciphertext used for the cross-mode guard.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# One subcommand per key length: `cfb 128` prints "aes128-cfb".
cfb() { echo "aes$1-cfb"; }

# ---- round trips --------------------------------------------------------------------------

test_round_trip_through_files() {
    local bits
    for bits in 128 192 256; do
        rng "$(keylen $bits)" >"$TMP/key"
        rng 1024 >"$TMP/pt"

        "$BC_RUST" "$(cfb $bits)" -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
        assert_size "$TMP/ct" $((16 + 1024)) "$bits: ciphertext is the IV plus the plaintext length"
        assert_differs "$TMP/pt" "$TMP/ct" "$bits: the data must actually be encrypted"

        "$BC_RUST" "$(cfb $bits)" -d decrypt --key-file "$TMP/key" <"$TMP/ct" >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "$bits: decrypt must recover the plaintext"
    done
}

test_round_trip_through_a_pipe_larger_than_the_pipe_buffer() {
    rng 16 >"$TMP/key"
    rng $((1024 * 1024)) >"$TMP/pt"
    "$BC_RUST" aes128-cfb -d encrypt --key-file "$TMP/key" <"$TMP/pt" \
        | "$BC_RUST" aes128-cfb -d decrypt --key-file "$TMP/key" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "1 MiB must survive encrypt | decrypt with no file in between"
}

# Every length from empty to just past two blocks: CFB pads nothing and rejects nothing, and the
# body of the ciphertext is exactly as long as the plaintext.
test_any_input_length_is_accepted_and_round_trips() {
    rng 16 >"$TMP/key"
    local len
    for len in $(seq 0 33); do
        rng "$len" >"$TMP/pt"
        "$BC_RUST" aes128-cfb -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
        assert_size "$TMP/ct" $((16 + len)) "len $len: IV plus a body as long as the plaintext"
        "$BC_RUST" aes128-cfb -d decrypt --key-file "$TMP/key" <"$TMP/ct" >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "len $len: round trip"
    done
}

# Sizes that straddle the 1 KiB streaming chunk and the block boundary: 1024 is one chunk, 1040 a
# chunk plus a block, 4112 four chunks plus a block; the odd sizes leave a partial final segment
# and put a chunk boundary in the middle of one.
test_round_trips_across_chunk_boundaries() {
    rng 16 >"$TMP/key"
    local size
    for size in 16 32 1023 1024 1025 1040 4096 4112 65535 65536; do
        rng "$size" >"$TMP/pt"
        "$BC_RUST" aes128-cfb -d encrypt --key-file "$TMP/key" <"$TMP/pt" \
            | "$BC_RUST" aes128-cfb -d decrypt --key-file "$TMP/key" >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "$size bytes should round trip"
    done
}

test_hex_output_composes_through_hex_decode() {
    rng 16 >"$TMP/key"
    rng 4097 >"$TMP/pt"
    "$BC_RUST" aes128-cfb -d encrypt --key-file "$TMP/key" -x <"$TMP/pt" >"$TMP/ct.hex"
    assert_size "$TMP/ct.hex" $((2 * (16 + 4097) + 1)) "-x emits two hex characters per byte, then a newline"
    "$BC_RUST" hex-decode <"$TMP/ct.hex" \
        | "$BC_RUST" aes128-cfb -d decrypt --key-file "$TMP/key" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "-x output must decrypt after hex-decode"
}

# A fresh IV per invocation matters even more for CFB than for CBC: a repeated key-and-IV pair
# leaks the XOR of the two plaintexts outright.
test_each_invocation_uses_a_fresh_iv() {
    rng 16 >"$TMP/key"
    rng 64 >"$TMP/pt"
    "$BC_RUST" aes128-cfb -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct1"
    "$BC_RUST" aes128-cfb -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct2"
    slice "$TMP/ct1" 0 16 >"$TMP/iv1"
    slice "$TMP/ct2" 0 16 >"$TMP/iv2"
    assert_differs "$TMP/iv1" "$TMP/iv2" "two encryptions must draw different IVs"
    slice "$TMP/ct1" 16 64 >"$TMP/body1"
    slice "$TMP/ct2" 16 64 >"$TMP/body2"
    assert_differs "$TMP/body1" "$TMP/body2" "and the bodies differ too, not just the IV"
    "$BC_RUST" aes128-cfb -d decrypt --key-file "$TMP/key" <"$TMP/ct2" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "the second ciphertext still decrypts"
}

test_empty_input_produces_only_the_iv() {
    rng 16 >"$TMP/key"
    : >"$TMP/empty"
    "$BC_RUST" aes128-cfb -d encrypt --key-file "$TMP/key" <"$TMP/empty" >"$TMP/ct"
    assert_size "$TMP/ct" 16 "an empty message encrypts to just the IV"
    "$BC_RUST" aes128-cfb -d decrypt --key-file "$TMP/key" <"$TMP/ct" >"$TMP/rec"
    assert_size "$TMP/rec" 0 "and decrypts back to nothing"
}

# Anything past the IV is ciphertext, whatever its length.
test_decrypt_accepts_an_unaligned_body() {
    rng 16 >"$TMP/key"
    rng $((16 + 20)) >"$TMP/ct"
    "$BC_RUST" aes128-cfb -d decrypt --key-file "$TMP/key" <"$TMP/ct" >"$TMP/rec"
    assert_size "$TMP/rec" 20 "the plaintext is exactly as long as the ciphertext body"
}

# ---- keys -----------------------------------------------------------------------------------

test_key_file_accepts_binary_hex_and_a_trailing_newline() {
    rng 16 >"$TMP/key.bin"
    hex "$TMP/key.bin" >"$TMP/key.hex"
    { cat "$TMP/key.hex"; printf '\n'; } >"$TMP/key.hex.nl"
    { cat "$TMP/key.bin"; printf '\n'; } >"$TMP/key.bin.nl"
    rng 256 >"$TMP/pt"
    "$BC_RUST" aes128-cfb -d encrypt --key-file "$TMP/key.bin" <"$TMP/pt" >"$TMP/ct"

    local form
    for form in key.hex key.hex.nl key.bin.nl; do
        "$BC_RUST" aes128-cfb -d decrypt --key-file "$TMP/$form" <"$TMP/ct" >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "$form must load as the same key as key.bin"
    done
}

test_key_on_the_command_line_matches_the_key_file() {
    rng 16 >"$TMP/key"
    rng 256 >"$TMP/pt"
    "$BC_RUST" aes128-cfb -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
    "$BC_RUST" aes128-cfb -d decrypt --key "$(hex "$TMP/key")" <"$TMP/ct" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "--key in hex must decrypt what --key-file encrypted"
}

# CFB is unauthenticated: a wrong key succeeds and produces garbage of the same length, never the
# plaintext -- which is exactly why the crate docs insist on authenticating separately.
test_the_wrong_key_gives_the_wrong_plaintext() {
    rng 16 >"$TMP/key"
    rng 16 >"$TMP/other"
    rng 256 >"$TMP/pt"
    "$BC_RUST" aes128-cfb -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
    "$BC_RUST" aes128-cfb -d decrypt --key-file "$TMP/other" <"$TMP/ct" >"$TMP/rec"
    assert_differs "$TMP/pt" "$TMP/rec" "a different key must not recover the plaintext"
    assert_size "$TMP/rec" 256 "but the length is unchanged"
}

test_an_all_zero_key_warns_but_proceeds() {
    head -c 16 /dev/zero >"$TMP/key"
    rng 64 >"$TMP/pt"
    expect_ok "an all-zero key is accepted" \
        "$BC_RUST" aes128-cfb -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
    assert_stderr_has "arning"
    assert_size "$TMP/ct" $((16 + 64)) "and the output is complete"
}

# ---- known answers --------------------------------------------------------------------------

# SP 800-38A Appendix F.3.13, F.3.15 and F.3.17 (CFB128 at each key length), transcribed in the
# Rust suite this file replaces, plus F.2.1 (CBC-AES128) for the cross-mode guard. The CLI takes
# the IV as the first 16 bytes of its input, so the input is IV || ciphertext, and the output must
# be the appendix's four plaintext blocks.
F3_IV=000102030405060708090a0b0c0d0e0f
F3_PLAINTEXT=6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
F3_KEY_128=2b7e151628aed2a6abf7158809cf4f3c
F3_KEY_192=8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
F3_KEY_256=603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
F3_CT_128=3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6
F3_CT_192=cdc80d6fddf18cab34c25909c99a417467ce7f7f81173621961a2b70171d3d7a2e1e8a1dd59b88b1c8e60fed1efac4c9c05f9f9ca9834fa042ae8fba584b09ff
F3_CT_256=dc7e84bfda79164b7ecd8486985d386039ffed143b28b1c832113c6331e5407bdf10132415e54b92a13ed0a8267ae2f975a385741ab9cef82031623d55b1e471
F2_CBC_CT_128=7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7

test_decrypt_matches_sp800_38a_f3_vectors() {
    local bits key ct got
    for bits in 128 192 256; do
        key="F3_KEY_$bits"
        ct="F3_CT_$bits"
        unhex "$F3_IV${!ct}" >"$TMP/ct"
        got=$("$BC_RUST" "$(cfb $bits)" -d decrypt --key "${!key}" <"$TMP/ct" | "$BC_RUST" hex-encode)
        assert_eq "$got" "$F3_PLAINTEXT" "$bits: F.3 decrypt vector"
    done
}

# -x gives the identical answer in hex, plus a trailing newline.
test_hex_output_matches_binary_output() {
    unhex "$F3_IV$F3_CT_128" >"$TMP/ct"
    local got
    got=$("$BC_RUST" aes128-cfb -d decrypt --key "$F3_KEY_128" -x <"$TMP/ct")
    assert_eq "$got" "$F3_PLAINTEXT" "-x decrypt of the F.3.13 vector"
}

# Appendix D, Table D.2 for CFB: a bit error in Cj gives *specific* bit errors in the decryption of
# Cj -- the very same bit position -- plus random bit errors in Cj+1, and nothing beyond that (with
# s = b, b/s is 1). This is what makes CFB tampering directly exploitable, and it is also a sharp
# check that the CLI is running CFB rather than CBC: under CBC the controlled flip would land in
# Pj+1, not Pj.
test_a_ciphertext_bit_flip_flips_the_same_plaintext_bit() {
    # Byte 3 of the second ciphertext block: input is IV | C1 | C2 | C3 | C4, so C2 starts at 32.
    local offset=$((32 + 3)) mask=$((0x20))
    unhex "$(flip_hex "$F3_IV$F3_CT_128" $offset $mask)" >"$TMP/ct"
    "$BC_RUST" aes128-cfb -d decrypt --key "$F3_KEY_128" <"$TMP/ct" >"$TMP/out"
    assert_size "$TMP/out" 64 "four plaintext blocks"

    unhex "$F3_PLAINTEXT" >"$TMP/pt"
    # Plaintext byte 19 is byte 3 of P2.
    unhex "$(flip_hex "$F3_PLAINTEXT" 19 $mask)" >"$TMP/pt_flipped"

    slice "$TMP/out" 0 16 >"$TMP/p1"; slice "$TMP/pt" 0 16 >"$TMP/e1"
    assert_same "$TMP/p1" "$TMP/e1" "P1 depends only on the IV, so it is unaffected"
    slice "$TMP/out" 16 16 >"$TMP/p2"; slice "$TMP/pt_flipped" 16 16 >"$TMP/e2"
    assert_same "$TMP/p2" "$TMP/e2" "P2 should show exactly the flipped bit"
    slice "$TMP/out" 32 16 >"$TMP/p3"; slice "$TMP/pt" 32 16 >"$TMP/e3"
    assert_differs "$TMP/p3" "$TMP/e3" "P3 is randomised: C2 feeds the next cipher call"
    slice "$TMP/out" 48 16 >"$TMP/p4"; slice "$TMP/pt" 48 16 >"$TMP/e4"
    assert_same "$TMP/p4" "$TMP/e4" "P4 is unaffected: with s = b, damage stops at P3"
}

# CFB and CBC take the same arguments and produce the same-shaped output, so nothing but this
# stops a caller pairing them up by mistake. Both spec ciphertexts are for the same key, IV and
# plaintext, so each mode must reproduce the plaintext only from its own ciphertext; neither is
# authenticated, so the mismatch is silent garbage rather than an error.
test_cfb_and_cbc_are_not_interchangeable() {
    unhex "$F3_IV$F3_CT_128" >"$TMP/cfb_ct"
    unhex "$F3_IV$F2_CBC_CT_128" >"$TMP/cbc_ct"
    unhex "$F3_PLAINTEXT" >"$TMP/pt"

    "$BC_RUST" aes128-cfb -d decrypt --key "$F3_KEY_128" <"$TMP/cfb_ct" >"$TMP/own_cfb"
    assert_same "$TMP/own_cfb" "$TMP/pt" "CFB decrypts its own ciphertext"
    "$BC_RUST" aes128-cbc -d decrypt --key "$F3_KEY_128" <"$TMP/cbc_ct" >"$TMP/own_cbc"
    assert_same "$TMP/own_cbc" "$TMP/pt" "CBC decrypts its own ciphertext"

    "$BC_RUST" aes128-cfb -d decrypt --key "$F3_KEY_128" <"$TMP/cbc_ct" >"$TMP/cross_cfb"
    assert_differs "$TMP/cross_cfb" "$TMP/pt" "CFB must not decrypt a CBC ciphertext"
    "$BC_RUST" aes128-cbc -d decrypt --key "$F3_KEY_128" <"$TMP/cfb_ct" >"$TMP/cross_cbc"
    assert_differs "$TMP/cross_cbc" "$TMP/pt" "CBC must not decrypt a CFB ciphertext"
}

# ---- rejected inputs ------------------------------------------------------------------------

test_decrypt_input_shorter_than_the_iv_is_rejected() {
    rng 16 >"$TMP/key"
    local len
    for len in 0 1 15; do
        rng "$len" >"$TMP/short"
        expect_fail "$len bytes cannot hold a 16-byte IV" \
            "$BC_RUST" aes128-cfb -d decrypt --key-file "$TMP/key" <"$TMP/short"
        assert_stderr_has "IV"
    done
}

test_a_key_of_the_wrong_length_is_rejected() {
    rng 16 >"$TMP/key"
    rng 64 >"$TMP/pt"
    expect_fail "a 16-byte key is not an AES-256 key" \
        "$BC_RUST" aes256-cfb -d encrypt --key-file "$TMP/key" <"$TMP/pt"
    assert_stderr_has "32-byte key"
    assert_stderr_has "16 bytes"
}

test_a_missing_key_is_rejected() {
    rng 64 >"$TMP/pt"
    expect_fail "neither --key nor --key-file" \
        "$BC_RUST" aes128-cfb -d encrypt <"$TMP/pt"
    assert_stderr_has "key"
}

test_a_missing_direction_is_rejected() {
    rng 16 >"$TMP/key"
    rng 64 >"$TMP/pt"
    expect_fail "--direction is required" \
        "$BC_RUST" aes128-cfb --key-file "$TMP/key" <"$TMP/pt"
    assert_stderr_has "direction"
}

# ---- discoverability ------------------------------------------------------------------------

test_the_subcommands_are_listed_in_help() {
    "$BC_RUST" --help >"$TMP/help"
    local cmd
    for cmd in aes128-cfb aes192-cfb aes256-cfb; do
        grep -q "$cmd" "$TMP/help" || fail "--help should list $cmd"
    done
}

# Each subcommand's own help names the two directions, the IV convention, and -- because CFB8 and
# CFB1 are different, non-interoperable modes -- the segment size.
test_per_command_help_documents_the_iv_convention_and_the_segment_size() {
    "$BC_RUST" aes128-cfb --help >"$TMP/help"
    grep -q "encrypt" "$TMP/help" || fail "help should list the encrypt direction"
    grep -q "decrypt" "$TMP/help" || fail "help should list the decrypt direction"
    grep -qi "first 16 bytes" "$TMP/help" || fail "help should explain where the IV goes"
    grep -q "CFB128" "$TMP/help" || fail "help should say which CFB variant this is"
}

run_all
