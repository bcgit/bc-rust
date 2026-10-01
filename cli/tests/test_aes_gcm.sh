#!/usr/bin/env bash
# The aes128-gcm / aes192-gcm / aes256-gcm subcommands, end to end through the binary.
#
# Framing: encrypt writes a fresh 12-byte nonce, then the ciphertext (as long as the plaintext),
# then the 16-byte tag; decrypt reads the same layout back. `--aad` (hex) or `--aad-file` (raw
# bytes) is authenticated but not encrypted and must match on both sides. GCM's algorithm
# correctness is pinned by the known-answer suites in the aes crate; what is tested here is the
# wiring: that AAD reaches the tag, that tampering is rejected with a non-zero exit, and that
# decrypt still writes whatever plaintext it had released before the failure. Keys, AAD and data
# all come from `bc-rust rng`.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

NONCE_LEN=12
TAG_LEN=16

# One subcommand per key length: `gcm 128` prints "aes128-gcm".
gcm() { echo "aes$1-gcm"; }

# ---- round trips --------------------------------------------------------------------------

test_round_trip_with_aad_at_every_key_length() {
    local bits aad
    for bits in 128 192 256; do
        rng "$(keylen $bits)" >"$TMP/key"
        rng 8 >"$TMP/aad"
        aad=$(hex "$TMP/aad")
        rng 69 >"$TMP/pt"

        "$BC_RUST" "$(gcm $bits)" -d encrypt --key-file "$TMP/key" --aad "$aad" <"$TMP/pt" >"$TMP/ct"
        assert_size "$TMP/ct" $((69 + NONCE_LEN + TAG_LEN)) "$bits: nonce, ciphertext and tag"
        "$BC_RUST" "$(gcm $bits)" -d decrypt --key-file "$TMP/key" --aad "$aad" <"$TMP/ct" >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "$bits: round trip"
    done
}

test_round_trips_with_no_aad() {
    rng 16 >"$TMP/key"
    rng 69 >"$TMP/pt"
    "$BC_RUST" aes128-gcm -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
    "$BC_RUST" aes128-gcm -d decrypt --key-file "$TMP/key" <"$TMP/ct" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "AAD is optional on both sides"
}

test_any_input_length_is_accepted_and_round_trips() {
    rng 16 >"$TMP/key"
    local len
    for len in $(seq 0 33); do
        rng "$len" >"$TMP/pt"
        "$BC_RUST" aes128-gcm -d encrypt --key-file "$TMP/key" --aad deadbeef <"$TMP/pt" >"$TMP/ct"
        assert_size "$TMP/ct" $((len + NONCE_LEN + TAG_LEN)) "len $len: nonce, equal-length body, tag"
        "$BC_RUST" aes128-gcm -d decrypt --key-file "$TMP/key" --aad deadbeef <"$TMP/ct" >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "len $len: round trip"
    done
}

test_round_trips_across_chunk_boundaries() {
    rng 16 >"$TMP/key"
    local size
    for size in 0 1 15 16 17 1023 1024 1025 4096 4099 65536; do
        rng "$size" >"$TMP/pt"
        "$BC_RUST" aes128-gcm -d encrypt --key-file "$TMP/key" --aad deadbeef <"$TMP/pt" \
            | "$BC_RUST" aes128-gcm -d decrypt --key-file "$TMP/key" --aad deadbeef >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "$size bytes should round trip through a pipe"
    done
}

test_each_invocation_uses_a_fresh_nonce() {
    rng 16 >"$TMP/key"
    rng 69 >"$TMP/pt"
    local i
    : >"$TMP/nonces"
    for i in $(seq 1 8); do
        "$BC_RUST" aes128-gcm -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
        head -c $NONCE_LEN "$TMP/ct" | "$BC_RUST" hex-encode >>"$TMP/nonces"
        echo >>"$TMP/nonces"
        "$BC_RUST" aes128-gcm -d decrypt --key-file "$TMP/key" <"$TMP/ct" >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "run $i still decrypts"
    done
    assert_eq "$(sort -u "$TMP/nonces" | wc -l)" 8 "eight encryptions must draw eight distinct nonces"
}

test_hex_output_composes_through_hex_decode() {
    rng 16 >"$TMP/key"
    rng 69 >"$TMP/pt"
    "$BC_RUST" aes128-gcm -d encrypt --key-file "$TMP/key" -x <"$TMP/pt" >"$TMP/ct.hex"
    assert_size "$TMP/ct.hex" $((2 * (69 + NONCE_LEN + TAG_LEN) + 1)) "-x emits two hex characters per byte, then a newline"
    "$BC_RUST" hex-decode <"$TMP/ct.hex" \
        | "$BC_RUST" aes128-gcm -d decrypt --key-file "$TMP/key" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "-x output must decrypt after hex-decode"
}

# ---- AAD ------------------------------------------------------------------------------------

test_wrong_aad_fails_authentication() {
    rng 16 >"$TMP/key"
    rng 69 >"$TMP/pt"
    "$BC_RUST" aes128-gcm -d encrypt --key-file "$TMP/key" --aad deadbeef <"$TMP/pt" >"$TMP/ct"
    expect_fail "a different AAD must not verify" \
        "$BC_RUST" aes128-gcm -d decrypt --key-file "$TMP/key" --aad 00112233 <"$TMP/ct"
    assert_stderr_has "authentication failed"
}

test_missing_aad_on_one_side_fails_authentication() {
    rng 16 >"$TMP/key"
    rng 69 >"$TMP/pt"
    "$BC_RUST" aes128-gcm -d encrypt --key-file "$TMP/key" --aad deadbeef <"$TMP/pt" >"$TMP/ct"
    expect_fail "AAD on encrypt but none on decrypt must not verify" \
        "$BC_RUST" aes128-gcm -d decrypt --key-file "$TMP/key" <"$TMP/ct"
    assert_stderr_has "authentication failed"
}

# `--aad-file` is raw bytes, never hex-or-raw guessed like `--key-file`: the file's exact bytes
# are what any other GCM implementation would authenticate. Each case encrypts with the file and
# decrypts with `--aad` set to the hex of those bytes.
test_aad_file_is_raw_bytes_not_hex_decoded() {
    rng 16 >"$TMP/key"
    rng 69 >"$TMP/pt"
    # ASCII that is also valid hex text: hex-decoding would authenticate 2 bytes, not 4.
    printf 'cafe' >"$TMP/ascii_hex"
    # Sixteen zero bytes, which the hex decoder skips entirely: decoding would authenticate nothing.
    head -c 16 /dev/zero >"$TMP/zeros"
    # A trailing backslash, which once sent the hex decoder's `\x` handling past the end.
    printf 'header\\' >"$TMP/trailing_backslash"

    local name
    for name in ascii_hex zeros trailing_backslash; do
        "$BC_RUST" aes128-gcm -d encrypt --key-file "$TMP/key" --aad-file "$TMP/$name" <"$TMP/pt" >"$TMP/ct"
        "$BC_RUST" aes128-gcm -d decrypt --key-file "$TMP/key" --aad "$(hex "$TMP/$name")" <"$TMP/ct" >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "case $name: the file's bytes are the AAD"
    done
}

# ---- tamper detection -----------------------------------------------------------------------

test_a_tampered_ciphertext_byte_is_rejected() {
    rng 16 >"$TMP/key"
    rng 69 >"$TMP/pt"
    "$BC_RUST" aes128-gcm -d encrypt --key-file "$TMP/key" --aad deadbeef <"$TMP/pt" >"$TMP/ct"
    flip_byte "$TMP/ct" $NONCE_LEN
    expect_fail "a flipped ciphertext bit must not verify" \
        "$BC_RUST" aes128-gcm -d decrypt --key-file "$TMP/key" --aad deadbeef <"$TMP/ct"
    assert_stderr_has "authentication failed"
}

test_a_tampered_tag_byte_is_rejected() {
    rng 16 >"$TMP/key"
    rng 69 >"$TMP/pt"
    "$BC_RUST" aes128-gcm -d encrypt --key-file "$TMP/key" --aad deadbeef <"$TMP/pt" >"$TMP/ct"
    flip_byte "$TMP/ct" $(($(wc -c <"$TMP/ct") - 1))
    expect_fail "a flipped tag bit must not verify" \
        "$BC_RUST" aes128-gcm -d decrypt --key-file "$TMP/key" --aad deadbeef <"$TMP/ct"
    assert_stderr_has "authentication failed"
}

# The streaming trade-off: on a tag failure, whatever plaintext the decryptor had already released
# before the tag check stands on stdout. For a message longer than the tag that is everything but
# at most the last 16 bytes, and it must be the genuine plaintext, not garbage. The exit code is
# the signal a script must check.
test_decrypt_still_writes_the_plaintext_it_had_released_on_forgery() {
    rng 16 >"$TMP/key"
    rng 4096 >"$TMP/pt"
    "$BC_RUST" aes128-gcm -d encrypt --key-file "$TMP/key" --aad deadbeef <"$TMP/pt" >"$TMP/ct"
    flip_byte "$TMP/ct" $(($(wc -c <"$TMP/ct") - 1)) # the tag only; the body is intact
    if "$BC_RUST" aes128-gcm -d decrypt --key-file "$TMP/key" --aad deadbeef <"$TMP/ct" >"$TMP/out" 2>/dev/null; then
        fail "a corrupted tag must be rejected"
    fi
    local released
    released=$(wc -c <"$TMP/out")
    [ "$released" -ge $((4096 - TAG_LEN)) ] \
        || fail "most of the plaintext should already have reached stdout: got $released of 4096 bytes"
    cmp -s -n "$released" "$TMP/out" "$TMP/pt" || fail "the released bytes must be the genuine plaintext"
}

# ---- short input ----------------------------------------------------------------------------

test_decrypt_input_shorter_than_the_nonce_is_rejected() {
    rng 16 >"$TMP/key"
    local len
    for len in 0 1 11; do
        rng "$len" >"$TMP/short"
        expect_fail "$len bytes cannot hold a 12-byte nonce" \
            "$BC_RUST" aes128-gcm -d decrypt --key-file "$TMP/key" <"$TMP/short"
        assert_stderr_has "12-byte nonce"
    done
}

# A nonce but not a full tag: there is nothing to check the tag against, so it is an
# authentication failure.
test_decrypt_input_with_a_nonce_but_no_full_tag_is_rejected() {
    rng 16 >"$TMP/key"
    : >"$TMP/empty"
    "$BC_RUST" aes128-gcm -d encrypt --key-file "$TMP/key" <"$TMP/empty" >"$TMP/ct"
    assert_size "$TMP/ct" $((NONCE_LEN + TAG_LEN)) "an empty message encrypts to nonce || tag"
    head -c $((NONCE_LEN + TAG_LEN - 1)) "$TMP/ct" >"$TMP/short"
    expect_fail "one tag byte short must not verify" \
        "$BC_RUST" aes128-gcm -d decrypt --key-file "$TMP/key" <"$TMP/short"
    assert_stderr_has "authentication failed"
}

# ---- keys -----------------------------------------------------------------------------------

test_a_key_of_the_wrong_length_is_rejected() {
    rng 16 >"$TMP/key"
    rng 69 >"$TMP/pt"
    expect_fail "a 16-byte key is not an AES-256 key" \
        "$BC_RUST" aes256-gcm -d encrypt --key-file "$TMP/key" <"$TMP/pt"
    assert_stderr_has "32-byte key"
    assert_stderr_has "16 bytes"
}

test_a_missing_key_is_rejected() {
    rng 69 >"$TMP/pt"
    expect_fail "neither --key nor --key-file" \
        "$BC_RUST" aes128-gcm -d encrypt <"$TMP/pt"
    assert_stderr_has -- "--key"
}

# ---- discoverability ------------------------------------------------------------------------

test_the_subcommands_are_listed_in_help() {
    "$BC_RUST" --help >"$TMP/help"
    local cmd
    for cmd in aes128-gcm aes192-gcm aes256-gcm; do
        grep -q "$cmd" "$TMP/help" || fail "--help should list $cmd"
    done
}

test_per_command_help_documents_aad_and_authentication() {
    "$BC_RUST" aes128-gcm --help >"$TMP/help"
    grep -q "aad" "$TMP/help" || fail "help should mention AAD"
    grep -qi "authenticat" "$TMP/help" || fail "help should mention authentication"
}

run_all
