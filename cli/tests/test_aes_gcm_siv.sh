#!/usr/bin/env bash
# The aes128-gcm-siv / aes256-gcm-siv subcommands (RFC 8452), end to end through the binary.
#
# Framing is aes*-gcm's: encrypt writes a fresh 12-byte nonce, then the ciphertext (as long as the
# plaintext), then the 16-byte tag, and with `--nonce` only `ciphertext || tag`. Unlike aes*-gcm
# the command reads all of stdin first, and a failed tag check writes no plaintext at all. The
# fixed inputs are RFC 8452 Appendix C.1 and C.2, copied from
# crypto/aes/tests/gcm_siv_rfc8452_tests.rs; everything else comes from `bc-rust rng`.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

NONCE_LEN=12
TAG_LEN=16

# ---- known answers --------------------------------------------------------------------------

# Appendix C.1 and C.2, the vector of each with an 18-byte plaintext and 20 bytes of AAD. The
# RFC's "Result" is the ciphertext followed by the tag, exactly what `--nonce` makes the command
# write.
test_encrypt_and_decrypt_match_rfc_8452_appendix_c() {
    local pt=030000000000000000000000000000000400 aad=0100000000000000000000000000000002000000
    local nonce=030000000000000000000000 bits key result got
    for bits in 128 256; do
        if [ "$bits" = 128 ]; then
            key=01000000000000000000000000000000
            result=44d0aaf6fb2f1f34add5e8064e83e12a2adabff9b2ef00fb47920cc72a0c0f13b9fd
        else
            key=0100000000000000000000000000000000000000000000000000000000000000
            result=462401724b5ce6588d5a54aae5375513a075cfcdf5042112aa29685c912fc2056543
        fi
        got=$(unhex "$pt" | "$BC_RUST" "aes$bits-gcm-siv" -d encrypt --key "$key" --nonce "$nonce" --aad "$aad" \
            | "$BC_RUST" hex-encode)
        assert_eq "$got" "$result" "$bits: the appendix's Result"
        got=$(unhex "$result" | "$BC_RUST" "aes$bits-gcm-siv" -d decrypt --key "$key" --nonce "$nonce" --aad "$aad" \
            | "$BC_RUST" hex-encode)
        assert_eq "$got" "$pt" "$bits: the appendix's Plaintext"
    done
}

# The same vectors with every input from a file (raw bytes) and the output as hex with `-x`.
test_the_appendix_vectors_through_the_file_flags_and_hex_output() {
    local pt=030000000000000000000000000000000400 aad=0100000000000000000000000000000002000000
    local nonce=030000000000000000000000 bits key result got
    unhex "$nonce" >"$TMP/nonce"
    unhex "$aad" >"$TMP/aad"
    unhex "$pt" >"$TMP/pt"
    for bits in 128 256; do
        if [ "$bits" = 128 ]; then
            key=01000000000000000000000000000000
            result=44d0aaf6fb2f1f34add5e8064e83e12a2adabff9b2ef00fb47920cc72a0c0f13b9fd
        else
            key=0100000000000000000000000000000000000000000000000000000000000000
            result=462401724b5ce6588d5a54aae5375513a075cfcdf5042112aa29685c912fc2056543
        fi
        unhex "$key" >"$TMP/key"
        unhex "$result" >"$TMP/ct"
        got=$(hex_out "$BC_RUST" "aes$bits-gcm-siv" -d encrypt --key-file "$TMP/key" \
            --nonce-file "$TMP/nonce" --aad-file "$TMP/aad" -x <"$TMP/pt")
        assert_eq "$got" "$result" "$bits: the appendix's Result, from files, as hex"
        got=$(hex_out "$BC_RUST" "aes$bits-gcm-siv" -d decrypt --key-file "$TMP/key" \
            --nonce-file "$TMP/nonce" --aad-file "$TMP/aad" -x <"$TMP/ct")
        assert_eq "$got" "$pt" "$bits: the appendix's Plaintext, from files, as hex"
        # A different AAD file is a different message.
        printf 'x' >>"$TMP/aad"
        # Not `expect_fail`, which sends stdout to /dev/null: the output is what is checked.
        if "$BC_RUST" "aes$bits-gcm-siv" -d decrypt --key-file "$TMP/key" \
            --nonce-file "$TMP/nonce" --aad-file "$TMP/aad" <"$TMP/ct" >"$TMP/out" 2>"$LAST_STDERR"; then
            fail "$bits: an AAD file with one more byte must be rejected"
        fi
        assert_stderr_has "authentication failed"
        assert_size "$TMP/out" 0 "$bits: nothing is written on a failed tag"
        unhex "$aad" >"$TMP/aad"
    done
}

# ---- round trips --------------------------------------------------------------------------

test_a_drawn_nonce_round_trips_at_both_key_lengths() {
    local bits
    for bits in 128 256; do
        rng "$(keylen $bits)" >"$TMP/key"
        rng 201 >"$TMP/pt"
        "$BC_RUST" "aes$bits-gcm-siv" -d encrypt --key-file "$TMP/key" --aad cafebabe <"$TMP/pt" >"$TMP/ct"
        assert_size "$TMP/ct" $((201 + NONCE_LEN + TAG_LEN)) "$bits: nonce, ciphertext and tag"
        "$BC_RUST" "aes$bits-gcm-siv" -d decrypt --key-file "$TMP/key" --aad cafebabe <"$TMP/ct" >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "$bits: round trip"
    done
}

test_each_invocation_draws_a_fresh_nonce() {
    rng 16 >"$TMP/key"
    rng 69 >"$TMP/pt"
    "$BC_RUST" aes128-gcm-siv -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct1"
    "$BC_RUST" aes128-gcm-siv -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct2"
    assert_differs "$TMP/ct1" "$TMP/ct2" "two encryptions of one message"
}

# The nonce may come from a file, and `--iv` spells the same flag. A supplied nonce is not written.
test_a_supplied_nonce_is_not_written_and_is_needed_to_decrypt() {
    rng 32 >"$TMP/key"
    rng 12 >"$TMP/nonce"
    rng 27 >"$TMP/pt"
    "$BC_RUST" aes256-gcm-siv -d encrypt --key-file "$TMP/key" --nonce-file "$TMP/nonce" <"$TMP/pt" >"$TMP/ct"
    assert_size "$TMP/ct" $((27 + TAG_LEN)) "ciphertext and tag only"
    "$BC_RUST" aes256-gcm-siv -d decrypt --key-file "$TMP/key" --iv "$(hex "$TMP/nonce")" <"$TMP/ct" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "--nonce-file and --iv name the same nonce"
    expect_fail "without the nonce the first 12 bytes are taken for it" \
        "$BC_RUST" aes256-gcm-siv -d decrypt --key-file "$TMP/key" <"$TMP/ct"
    assert_stderr_has "authentication failed"
}

# 256 KiB, past the usual 64 KiB pipe buffer: the read-all-of-stdin loop must not deadlock against
# its own output.
test_a_payload_larger_than_the_pipe_buffer_round_trips() {
    rng 16 >"$TMP/key"
    rng $((256 * 1024)) >"$TMP/pt"
    "$BC_RUST" aes128-gcm-siv -d encrypt --key-file "$TMP/key" <"$TMP/pt" \
        | "$BC_RUST" aes128-gcm-siv -d decrypt --key-file "$TMP/key" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "256 KiB round trip through a pipe"
}

test_hex_output_composes_through_hex_decode() {
    rng 16 >"$TMP/key"
    rng 69 >"$TMP/pt"
    "$BC_RUST" aes128-gcm-siv -d encrypt --key-file "$TMP/key" -x <"$TMP/pt" >"$TMP/ct.hex"
    assert_size "$TMP/ct.hex" $((2 * (69 + NONCE_LEN + TAG_LEN) + 1)) "-x emits two hex characters per byte, then a newline"
    "$BC_RUST" hex-decode <"$TMP/ct.hex" \
        | "$BC_RUST" aes128-gcm-siv -d decrypt --key-file "$TMP/key" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "-x output must decrypt after hex-decode"
}

# ---- tamper detection -----------------------------------------------------------------------

# A flipped nonce, ciphertext or tag byte, or other AAD, fails the tag check, and unlike aes*-gcm
# nothing at all reaches stdout.
test_a_failed_tag_check_writes_no_plaintext() {
    rng 16 >"$TMP/key"
    rng 4096 >"$TMP/pt"
    "$BC_RUST" aes128-gcm-siv -d encrypt --key-file "$TMP/key" --aad deadbeef <"$TMP/pt" >"$TMP/ct"
    local offset
    for offset in 0 $NONCE_LEN $(($(wc -c <"$TMP/ct") - 1)); do
        cp "$TMP/ct" "$TMP/bad"
        flip_byte "$TMP/bad" "$offset"
        if "$BC_RUST" aes128-gcm-siv -d decrypt --key-file "$TMP/key" --aad deadbeef <"$TMP/bad" >"$TMP/out" 2>"$LAST_STDERR"; then
            fail "a flipped byte at $offset must be rejected"
        fi
        assert_stderr_has "authentication failed"
        assert_size "$TMP/out" 0 "offset $offset: no plaintext before the tag has verified"
    done
    expect_fail "a different AAD must not verify" \
        "$BC_RUST" aes128-gcm-siv -d decrypt --key-file "$TMP/key" --aad 00112233 <"$TMP/ct"
    assert_stderr_has "authentication failed"
}

test_the_two_variants_are_not_interchangeable() {
    rng 16 >"$TMP/key16"
    rng 32 >"$TMP/key32"
    rng 15 >"$TMP/pt"
    "$BC_RUST" aes128-gcm-siv -d encrypt --key-file "$TMP/key16" <"$TMP/pt" >"$TMP/ct"
    expect_fail "aes256-gcm-siv must reject an aes128-gcm-siv ciphertext" \
        "$BC_RUST" aes256-gcm-siv -d decrypt --key-file "$TMP/key32" <"$TMP/ct"
    assert_stderr_has "authentication failed"
    expect_fail "a 32-byte key is not an AES-128 key" \
        "$BC_RUST" aes128-gcm-siv -d decrypt --key-file "$TMP/key32" <"$TMP/ct"
    assert_stderr_has "needs a 16-byte key"
}

# ---- short input and bad flags --------------------------------------------------------------

test_decrypt_input_too_short_for_the_framing_is_rejected() {
    rng 16 >"$TMP/key"
    rng 11 >"$TMP/short"
    expect_fail "11 bytes cannot hold a 12-byte nonce" \
        "$BC_RUST" aes128-gcm-siv -d decrypt --key-file "$TMP/key" <"$TMP/short"
    assert_stderr_has "12-byte nonce"
    rng 27 >"$TMP/short"
    expect_fail "a nonce and 15 bytes cannot hold a tag" \
        "$BC_RUST" aes128-gcm-siv -d decrypt --key-file "$TMP/key" <"$TMP/short"
    assert_stderr_has "16-byte tag"
}

test_a_nonce_of_the_wrong_length_is_rejected() {
    rng 16 >"$TMP/key"
    rng 4 >"$TMP/pt"
    expect_fail "RFC 8452 fixes the nonce at 12 bytes" \
        "$BC_RUST" aes128-gcm-siv -d encrypt --key-file "$TMP/key" --nonce 000102030405060708090a <"$TMP/pt"
    assert_stderr_has "nonce is 11 bytes; this mode requires exactly 12"
    # The message names the command's primary flag, `--nonce`, of which `--iv` is an alias.
    expect_fail "a nonce that is not hex" \
        "$BC_RUST" aes128-gcm-siv -d encrypt --key-file "$TMP/key" --nonce zz <"$TMP/pt"
    assert_stderr_has "\`--nonce\` must be hex"
}

# RFC 8452 Section 6 defines two AEADs, over AES-128 and AES-256, and there are no other commands.
test_there_is_no_command_for_aes192_or_another_cipher() {
    local cmd
    for cmd in aes192-gcm-siv aria128-gcm-siv camellia128-gcm-siv sm4-gcm-siv; do
        expect_fail "$cmd must not exist" "$BC_RUST" "$cmd" --help
        assert_stderr_has "unrecognized subcommand"
    done
}

run_all
