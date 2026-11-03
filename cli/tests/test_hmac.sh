#!/usr/bin/env bash
# The hmac-* subcommands, end to end through the binary: for each variant, a MAC computed over
# random data under a random key must verify with `-v`, and must stop verifying when the tag, the
# message or the key changes. `-v` reports through the exit status alone.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# `hmac_round_trip SUBCOMMAND TAG_LEN` runs the round trip for one variant.
hmac_round_trip() {
    local sub=$1 tag_len=$2 tag
    rng 32 >"$TMP/key"
    rng 32 >"$TMP/other_key"
    rng 100 >"$TMP/msg"
    cp "$TMP/msg" "$TMP/other_msg"
    flip_byte "$TMP/other_msg" 50

    tag=$(hex_out "$BC_RUST" "$sub" -k "$TMP/key" -x <"$TMP/msg")
    assert_eq "${#tag}" $((2 * tag_len)) "$sub tag length"

    expect_ok "the tag must verify" "$BC_RUST" "$sub" -k "$TMP/key" -v "$tag" <"$TMP/msg"
    expect_fail "a modified tag must not verify" \
        "$BC_RUST" "$sub" -k "$TMP/key" -v "$(flip_hex "$tag" 0 1)" <"$TMP/msg"
    expect_fail "a modified message must not verify" \
        "$BC_RUST" "$sub" -k "$TMP/key" -v "$tag" <"$TMP/other_msg"
    expect_fail "another key must not verify" \
        "$BC_RUST" "$sub" -k "$TMP/other_key" -v "$tag" <"$TMP/msg"
}

test_hmac_sha256_round_trip() {
    hmac_round_trip hmac-sha256 32
}

test_hmac_sha512_round_trip() {
    hmac_round_trip hmac-sha512 64
}

test_hmac_sha512_224_round_trip() {
    hmac_round_trip hmac-sha512-224 28
}

test_hmac_sha512_256_round_trip() {
    hmac_round_trip hmac-sha512-256 32
}

test_hmac_sm3_round_trip() {
    hmac_round_trip hmac-sm3 32
}

# When both `--key` and `--key-file` are given, the file is used, as the help text says.
test_hmac_sha256_key_file_wins_over_key() {
    local from_file with_both from_hex other
    rng 32 >"$TMP/key"
    rng 32 >"$TMP/other_key"
    rng 100 >"$TMP/msg"
    other=$(hex "$TMP/other_key")
    from_file=$(hex_out "$BC_RUST" hmac-sha256 -k "$TMP/key" -x <"$TMP/msg")
    with_both=$(hex_out "$BC_RUST" hmac-sha256 --key "$other" -k "$TMP/key" -x <"$TMP/msg")
    from_hex=$(hex_out "$BC_RUST" hmac-sha256 --key "$other" -x <"$TMP/msg")
    assert_eq "$with_both" "$from_file" "the key file must win over the hex key"
    [ "$from_hex" != "$from_file" ] || fail "the two keys must give different tags"
}

run_all
