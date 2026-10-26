#!/usr/bin/env bash
# The poly1305 subcommand, end to end through the binary: a tag over random data under a random
# one-time key must verify with `-v`, and must stop verifying when the tag, the message or the key
# changes; RFC 8439's Appendix A.3 vectors must come out exactly; and a key that is not 32 bytes is
# refused. `-v` reports through the exit status alone.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# ---- RFC 8439 Appendix A.3 -------------------------------------------------------------------

# Test Vector #1.
A3_1_KEY=0000000000000000000000000000000000000000000000000000000000000000
A3_1_TEXT=00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
A3_1_TAG=00000000000000000000000000000000

# Test Vector #4.
A3_4_KEY=1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0
A3_4_TEXT=2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e
A3_4_TAG=4541669a7eaaee61e708dc7cbcc5eb62

test_round_trip() {
    local tag
    rng 32 >"$TMP/key"
    rng 32 >"$TMP/other_key"
    rng 100 >"$TMP/msg"
    cp "$TMP/msg" "$TMP/other_msg"
    flip_byte "$TMP/other_msg" 50

    tag=$(hex_out "$BC_RUST" poly1305 -k "$TMP/key" -x <"$TMP/msg")
    assert_eq "${#tag}" 32 "a 16-byte tag, as 32 hex characters"

    expect_ok "the tag must verify" "$BC_RUST" poly1305 -k "$TMP/key" -v "$tag" <"$TMP/msg"
    expect_fail "a modified tag must not verify" \
        "$BC_RUST" poly1305 -k "$TMP/key" -v "$(flip_hex "$tag" 0 1)" <"$TMP/msg"
    expect_fail "a modified message must not verify" \
        "$BC_RUST" poly1305 -k "$TMP/key" -v "$tag" <"$TMP/other_msg"
    expect_fail "another key must not verify" \
        "$BC_RUST" poly1305 -k "$TMP/other_key" -v "$tag" <"$TMP/msg"
}

# Test vector #1 is the all-zero key, which load_mac_key takes through its zeroized-key path: with
# r = 0 and s = 0 every tag is zero.
test_rfc8439_a3_vector_1_the_all_zero_key() {
    local got
    unhex "$A3_1_TEXT" >"$TMP/msg"
    got=$(hex_out "$BC_RUST" poly1305 --key "$A3_1_KEY" -x <"$TMP/msg")
    assert_eq "$got" "$A3_1_TAG" "A.3 #1 through --key"
    unhex "$A3_1_KEY" >"$TMP/key"
    got=$(hex_out "$BC_RUST" poly1305 -k "$TMP/key" -x <"$TMP/msg")
    assert_eq "$got" "$A3_1_TAG" "A.3 #1 through --key-file"
    expect_ok "the RFC's tag must verify" "$BC_RUST" poly1305 -k "$TMP/key" -v "$A3_1_TAG" <"$TMP/msg"
}

# Test vector #4: both halves of the key non-zero, and a message ending in a partial block.
test_rfc8439_a3_vector_4() {
    local got
    unhex "$A3_4_TEXT" >"$TMP/msg"
    got=$(hex_out "$BC_RUST" poly1305 --key "$A3_4_KEY" -x <"$TMP/msg")
    assert_eq "$got" "$A3_4_TAG" "A.3 #4"
    expect_ok "the RFC's tag must verify" \
        "$BC_RUST" poly1305 --key "$A3_4_KEY" -v "$A3_4_TAG" <"$TMP/msg"
    expect_fail "the RFC's tag with its last bit flipped must not verify" \
        "$BC_RUST" poly1305 --key "$A3_4_KEY" -v "$(flip_hex "$A3_4_TAG" 15 128)" <"$TMP/msg"
}

# A one-time key is exactly 32 bytes: 31 and 33 are refused by the subcommand's own check, and 65
# by load_mac_key, which takes nothing over 64 bytes.
test_a_key_that_is_not_32_bytes_is_refused() {
    rng 100 >"$TMP/msg"
    local len
    for len in 31 33; do
        rng "$len" >"$TMP/key"
        expect_fail "a $len-byte key" "$BC_RUST" poly1305 -k "$TMP/key" -x <"$TMP/msg"
        assert_stderr_has "32-byte one-time key"
    done
    rng 65 >"$TMP/key"
    expect_fail "a 65-byte key" "$BC_RUST" poly1305 -k "$TMP/key" -x <"$TMP/msg"
    assert_stderr_has "64 bytes"
}

run_all
