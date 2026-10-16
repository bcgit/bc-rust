#!/usr/bin/env bash
# The aes128-ecb / aes192-ecb / aes256-ecb subcommands, end to end through the binary.
#
# Framing: none. ECB writes no IV, so output is exactly as long as input in both directions, and
# with nothing to vary it `encrypt` is reproducible -- which is why the SP 800-38A Appendix F.1
# vectors can be pinned in both directions here, and why the help text warns against using ECB for
# data. Neither direction applies padding, so input must be a whole number of 16-byte blocks. Keys
# and data come from `bc-rust rng`; the fixed inputs are the F.1 vectors and, for the cross-mode
# guard, the F.2.1 CBC vector.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# One subcommand per key length: `ecb 128` prints "aes128-ecb".
ecb() { echo "aes$1-ecb"; }

# ---- known answers --------------------------------------------------------------------------

# SP 800-38A Appendix F.1: the four plaintext blocks, the three keys, and the F.1.1 / F.1.3 /
# F.1.5 ciphertexts (F.1.2 / F.1.4 / F.1.6 are the same pairs decrypted). Transcribed in the Rust
# suite this file replaces.
F1_PLAINTEXT=6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
F1_KEY_128=2b7e151628aed2a6abf7158809cf4f3c
F1_KEY_192=8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
F1_KEY_256=603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
F1_CT_128=3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4
F1_CT_192=bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eefef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e
F1_CT_256=f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7

# SP 800-38A Appendix F.2.1, CBC-AES128.Encrypt: the IV and ciphertext, for the cross-mode guard.
F2_CBC_IV=000102030405060708090a0b0c0d0e0f
F2_CBC_CT_128=7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7

test_both_directions_match_sp800_38a_f1_vectors() {
    local bits key ct got
    for bits in 128 192 256; do
        key="F1_KEY_$bits"
        ct="F1_CT_$bits"
        got=$(unhex "$F1_PLAINTEXT" | "$BC_RUST" "$(ecb $bits)" -d encrypt --key "${!key}" | "$BC_RUST" hex-encode)
        assert_eq "$got" "${!ct}" "$bits: F.1 encrypt vector"
        got=$(unhex "${!ct}" | "$BC_RUST" "$(ecb $bits)" -d decrypt --key "${!key}" | "$BC_RUST" hex-encode)
        assert_eq "$got" "$F1_PLAINTEXT" "$bits: F.1 decrypt vector"
    done
}

test_hex_output_matches_binary_output() {
    local hex_out
    unhex "$F1_PLAINTEXT" >"$TMP/pt"
    "$BC_RUST" aes128-ecb -d encrypt --key "$F1_KEY_128" <"$TMP/pt" >"$TMP/ct"
    hex_out=$("$BC_RUST" aes128-ecb -d encrypt --key "$F1_KEY_128" -x <"$TMP/pt")
    assert_eq "$hex_out" "$(hex "$TMP/ct")" "-x must be the hex of the binary output"
    assert_eq "$hex_out" "$F1_CT_128" "and both are the F.1.1 ciphertext"
}

# ---- round trips and framing ----------------------------------------------------------------

test_round_trip_through_files_with_no_iv() {
    local bits
    for bits in 128 192 256; do
        rng $((bits / 8)) >"$TMP/key"
        rng 1024 >"$TMP/pt"

        "$BC_RUST" "$(ecb $bits)" -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
        assert_size "$TMP/ct" 1024 "$bits: no IV is written, so the ciphertext is the plaintext length"
        assert_differs "$TMP/pt" "$TMP/ct" "$bits: the data must actually be encrypted"

        "$BC_RUST" "$(ecb $bits)" -d decrypt --key-file "$TMP/key" <"$TMP/ct" >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "$bits: decrypt must recover the plaintext"
    done
}

test_round_trip_through_a_pipe_larger_than_the_pipe_buffer() {
    rng 16 >"$TMP/key"
    rng $((4 * 1024 * 1024)) >"$TMP/pt"
    "$BC_RUST" aes128-ecb -d encrypt --key-file "$TMP/key" <"$TMP/pt" \
        | "$BC_RUST" aes128-ecb -d decrypt --key-file "$TMP/key" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "4 MiB must survive encrypt | decrypt with no file in between"
}

# Sizes that straddle the 1 KiB streaming chunk, the four-block batch and the block boundary: 128
# is two fours; 144 is two fours plus one block; 1040 is a chunk plus a block.
test_round_trips_across_chunk_and_batch_boundaries() {
    local size
    rng 16 >"$TMP/key"
    for size in 16 32 128 144 1024 1040 4096 4112 65536; do
        rng "$size" >"$TMP/pt"
        "$BC_RUST" aes128-ecb -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
        assert_size "$TMP/ct" "$size" "$size bytes: ciphertext length"
        "$BC_RUST" aes128-ecb -d decrypt --key-file "$TMP/key" <"$TMP/ct" >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "$size bytes should round trip"
    done
}

test_hex_output_composes_through_hex_decode() {
    rng 16 >"$TMP/key"
    rng 4096 >"$TMP/pt"
    "$BC_RUST" aes128-ecb -d encrypt --key-file "$TMP/key" -x <"$TMP/pt" >"$TMP/ct.hex"
    assert_size "$TMP/ct.hex" $((2 * 4096 + 1)) "-x emits two hex characters per byte, then a newline"
    "$BC_RUST" hex-decode <"$TMP/ct.hex" \
        | "$BC_RUST" aes128-ecb -d decrypt --key-file "$TMP/key" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "-x output must decrypt after hex-decode"
}

test_empty_input_produces_empty_output() {
    rng 16 >"$TMP/key"
    : >"$TMP/empty"
    "$BC_RUST" aes128-ecb -d encrypt --key-file "$TMP/key" <"$TMP/empty" >"$TMP/ct"
    assert_size "$TMP/ct" 0 "no IV to emit: an empty message encrypts to nothing"
    "$BC_RUST" aes128-ecb -d decrypt --key-file "$TMP/key" <"$TMP/empty" >"$TMP/rec"
    assert_size "$TMP/rec" 0 "no IV to require: an empty ciphertext decrypts to nothing"
}

# ---- the codebook property, visible on the wire ---------------------------------------------

# SP 800-38A Sec 6.1: the same plaintext block under the same key always gives the same
# ciphertext block. Across invocations the output is identical (no IV to vary it), and within a
# message equal blocks stay equal -- the reason the help text warns against using ECB for data.
test_ecb_is_deterministic_and_shows_repeated_blocks() {
    rng 16 >"$TMP/key"
    unhex 00112233445566778899aabbccddeeffffeeddccbbaa9988776655443322110000112233445566778899aabbccddeeff >"$TMP/pt"
    "$BC_RUST" aes128-ecb -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct1"
    "$BC_RUST" aes128-ecb -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct2"
    assert_same "$TMP/ct1" "$TMP/ct2" "the same input gives the same output every time"
    slice "$TMP/ct1" 0 16 >"$TMP/c1"
    slice "$TMP/ct1" 16 16 >"$TMP/c2"
    slice "$TMP/ct1" 32 16 >"$TMP/c3"
    assert_same "$TMP/c1" "$TMP/c3" "equal plaintext blocks give equal ciphertext blocks"
    assert_differs "$TMP/c1" "$TMP/c2" "different plaintext blocks give different ciphertext blocks"
}

# ---- keys -----------------------------------------------------------------------------------

test_key_file_accepts_hex_and_binary() {
    local form
    printf '%s' "$F1_KEY_128" >"$TMP/key.hex"
    unhex "$F1_KEY_128" >"$TMP/key.bin"
    unhex "$F1_CT_128" >"$TMP/ct"
    unhex "$F1_PLAINTEXT" >"$TMP/pt"
    for form in key.hex key.bin; do
        "$BC_RUST" aes128-ecb -d decrypt --key-file "$TMP/$form" <"$TMP/ct" >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "--key-file $form must decrypt the F.1.1 ciphertext"
    done
}

test_a_key_of_the_wrong_length_is_rejected() {
    unhex "$F1_PLAINTEXT" >"$TMP/pt"
    expect_fail "a 16-byte key is not an AES-256 key" \
        "$BC_RUST" aes256-ecb -d encrypt --key "$F1_KEY_128" <"$TMP/pt"
    assert_stderr_has "32-byte key"
    assert_stderr_has "16 bytes"
}

test_a_missing_key_is_rejected() {
    unhex "$F1_PLAINTEXT" >"$TMP/pt"
    expect_fail "neither --key nor --key-file" \
        "$BC_RUST" aes128-ecb -d encrypt <"$TMP/pt"
    assert_stderr_has "\-\-key"
}

# A rejected key must still be reported when stdin is far larger than any pipe buffer: the
# command exits before reading, and the harness must not hang on the write.
test_a_large_payload_on_an_error_path_is_still_rejected() {
    rng $((4 * 1024 * 1024)) >"$TMP/pt"
    expect_fail "no key, 4 MiB of stdin" \
        "$BC_RUST" aes128-ecb -d encrypt <"$TMP/pt"
    assert_stderr_has "\-\-key"
}

test_an_all_zero_key_warns_but_proceeds() {
    unhex "$F1_PLAINTEXT" >"$TMP/pt"
    expect_ok "an all-zero key is accepted" \
        "$BC_RUST" aes128-ecb -d encrypt --key "$(printf '0%.0s' {1..32})" <"$TMP/pt" >"$TMP/ct"
    assert_stderr_has "arning"
    assert_size "$TMP/ct" 64 "four ciphertext blocks and no IV"
}

# ---- rejected inputs ------------------------------------------------------------------------

test_unaligned_input_is_rejected_in_both_directions() {
    local extra direction
    rng 16 >"$TMP/key"
    for extra in 1 7 15; do
        rng $((32 + extra)) >"$TMP/data"
        for direction in encrypt decrypt; do
            expect_fail "$((32 + extra)) bytes is not a whole number of blocks ($direction)" \
                "$BC_RUST" aes128-ecb -d "$direction" --key-file "$TMP/key" <"$TMP/data"
            assert_stderr_has "whole number of 16-byte blocks"
            assert_stderr_has "ECB"
        done
    done
}

# ---- SP 800-38A Appendix D, through the CLI -------------------------------------------------

# Table D.2 for ECB: a bit error in `Cj` gives "RBE in the decryption of Cj" -- random bit errors
# in that block -- and Appendix D adds that ECB bit errors "do not affect the decryption of any
# other blocks". So the corrupted block is randomised and every other block is intact. This is
# also an end-to-end check that the CLI is running ECB and not CBC (where the next block would
# show the flipped bit) or CFB (where the same block would).
test_a_ciphertext_bit_flip_randomises_only_its_own_block() {
    unhex "$F1_PLAINTEXT" >"$TMP/pt"
    unhex "$F1_CT_128" >"$TMP/ct"
    flip_byte "$TMP/ct" $((16 + 3)) 32 # bit 5 of byte 3 of C2
    "$BC_RUST" aes128-ecb -d decrypt --key "$F1_KEY_128" <"$TMP/ct" >"$TMP/rec"
    assert_size "$TMP/rec" 64 "the length is unchanged"

    local i
    for i in 0 32 48; do
        slice "$TMP/pt" $i 16 >"$TMP/want"
        slice "$TMP/rec" $i 16 >"$TMP/got"
        assert_same "$TMP/want" "$TMP/got" "the block at $i is unaffected: nothing chains"
    done
    slice "$TMP/pt" 16 16 >"$TMP/p2"
    slice "$TMP/rec" 16 16 >"$TMP/got"
    assert_differs "$TMP/p2" "$TMP/got" "P2 must change"
    flip_byte "$TMP/p2" 3 32
    assert_differs "$TMP/p2" "$TMP/got" "P2 must be randomised, not flipped in place as CBC would"
}

# ---- cross-variant and cross-mode behaviour -------------------------------------------------

test_a_wrong_key_does_not_recover_the_plaintext() {
    rng 16 >"$TMP/key"
    rng 16 >"$TMP/other"
    rng 256 >"$TMP/pt"
    "$BC_RUST" aes128-ecb -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
    # ECB is unauthenticated: a wrong key succeeds and produces garbage of the same length.
    "$BC_RUST" aes128-ecb -d decrypt --key-file "$TMP/other" <"$TMP/ct" >"$TMP/rec"
    assert_differs "$TMP/pt" "$TMP/rec" "a different key must not recover the plaintext"
    assert_size "$TMP/rec" 256 "but the length is unchanged"
}

# ECB and CBC ciphertexts are not interchangeable. The CBC command frames an IV and the ECB
# command does not: the CBC body run through ECB is not the plaintext, and the ECB ciphertext run
# through CBC (its first block consumed as an IV) is neither the plaintext nor the right length.
test_ecb_and_cbc_are_not_interchangeable() {
    unhex "$F1_PLAINTEXT" >"$TMP/pt"
    unhex "$F1_CT_128" >"$TMP/ecb_ct"
    unhex "$F2_CBC_CT_128" >"$TMP/cbc_body"
    unhex "$F2_CBC_IV$F2_CBC_CT_128" >"$TMP/cbc_input"

    "$BC_RUST" aes128-ecb -d decrypt --key "$F1_KEY_128" <"$TMP/ecb_ct" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "ECB decrypts its own ciphertext"
    "$BC_RUST" aes128-cbc -d decrypt --key "$F1_KEY_128" <"$TMP/cbc_input" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "CBC decrypts its own ciphertext"

    "$BC_RUST" aes128-ecb -d decrypt --key "$F1_KEY_128" <"$TMP/cbc_body" >"$TMP/rec"
    assert_differs "$TMP/pt" "$TMP/rec" "ECB must not decrypt a CBC ciphertext"

    "$BC_RUST" aes128-cbc -d decrypt --key "$F1_KEY_128" <"$TMP/ecb_ct" >"$TMP/rec"
    assert_size "$TMP/rec" 48 "CBC consumes the first block as an IV"
    tail -c 48 "$TMP/pt" >"$TMP/pt_tail"
    assert_differs "$TMP/pt_tail" "$TMP/rec" "CBC must not decrypt an ECB ciphertext"
}

# ---- discoverability ------------------------------------------------------------------------

test_the_subcommands_are_listed_in_help() {
    local cmd
    "$BC_RUST" --help >"$TMP/help"
    for cmd in aes128-ecb aes192-ecb aes256-ecb; do
        grep -q "$cmd" "$TMP/help" || fail "--help should list $cmd"
    done
}

# Each subcommand's own help names the two directions, says there is no IV, and carries the
# warning that ECB is not for data.
test_per_command_help_warns_and_documents_the_missing_iv() {
    local word
    "$BC_RUST" aes128-ecb --help >"$TMP/help"
    for word in encrypt decrypt "NO IV" WARNING ECB; do
        grep -q "$word" "$TMP/help" || fail "aes128-ecb --help should mention '$word'"
    done
}

run_all
