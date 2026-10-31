#!/usr/bin/env bash
# The kmac128 / kmac256 subcommands, end to end through the binary: a MAC computed over random
# data under a random key must verify with `-v`, must stop verifying when the tag, the message,
# the key, the customization string or the tag length changes, and a tag length the key refuses
# must be reported as an error rather than through a panic.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# `kmac_round_trip SUBCOMMAND` runs the round trip for one variant at a 32-byte tag.
kmac_round_trip() {
    local sub=$1 tag
    rng 32 >"$TMP/key"
    rng 32 >"$TMP/other_key"
    rng 100 >"$TMP/msg"
    cp "$TMP/msg" "$TMP/other_msg"
    flip_byte "$TMP/other_msg" 50

    tag=$(hex_out "$BC_RUST" "$sub" 32 --key-file "$TMP/key" -x <"$TMP/msg")
    assert_eq "${#tag}" 64 "$sub tag length"

    expect_ok "the tag must verify" "$BC_RUST" "$sub" 32 --key-file "$TMP/key" -v "$tag" <"$TMP/msg"
    expect_fail "a modified tag must not verify" \
        "$BC_RUST" "$sub" 32 --key-file "$TMP/key" -v "$(flip_hex "$tag" 0 1)" <"$TMP/msg"
    expect_fail "a modified message must not verify" \
        "$BC_RUST" "$sub" 32 --key-file "$TMP/key" -v "$tag" <"$TMP/other_msg"
    expect_fail "another key must not verify" \
        "$BC_RUST" "$sub" 32 --key-file "$TMP/other_key" -v "$tag" <"$TMP/msg"
    expect_fail "another customization string must not verify" \
        "$BC_RUST" "$sub" 32 -s other --key-file "$TMP/key" -v "$tag" <"$TMP/msg"
    expect_fail "another tag length must not verify" \
        "$BC_RUST" "$sub" 16 --key-file "$TMP/key" -v "${tag:0:32}" <"$TMP/msg"
}

# `kmac_refused_length SUBCOMMAND LENGTH` checks that LENGTH is refused with an error message,
# not a panic trace, whether computing or verifying.
kmac_refused_length() {
    local sub=$1 length=$2
    rng 32 >"$TMP/key"
    rng 100 >"$TMP/msg"

    expect_fail "tag length $length must be refused" \
        "$BC_RUST" "$sub" "$length" --key-file "$TMP/key" -x <"$TMP/msg"
    assert_stderr_has "Error: couldn't build the KMAC key"
    ! grep -q panicked "$LAST_STDERR" || fail "a refused tag length must not panic"

    expect_fail "tag length $length must be refused on verify" \
        "$BC_RUST" "$sub" "$length" --key-file "$TMP/key" -v "" <"$TMP/msg"
    assert_stderr_has "Error: couldn't build the KMAC key"
    ! grep -q panicked "$LAST_STDERR" || fail "a refused tag length must not panic"
}

test_kmac128_round_trip() {
    kmac_round_trip kmac128
}

test_kmac256_round_trip() {
    kmac_round_trip kmac256
}

test_kmac128_refuses_a_short_tag() {
    kmac_refused_length kmac128 0
}

test_kmac256_refuses_a_short_tag() {
    kmac_refused_length kmac256 3
}

test_kmac128_refuses_a_tag_that_does_not_fit() {
    kmac_refused_length kmac128 9223372036854775808
}

test_kmac256_refuses_a_tag_that_does_not_fit() {
    kmac_refused_length kmac256 9223372036854775808
}

run_all
