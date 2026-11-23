#!/usr/bin/env bash
# The sha1 subcommand against RFC 3174 Section 7.3's test results.
#
# Every expected value is copied from the RFC, none is typed by hand. Follows lib.sh's
# conventions: each test_* runs in its own subshell under `set -e`.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# RFC 3174 Section 7.3, TEST1: "abc".
test_sha1_matches_rfc_3174_test1() {
    local got
    got=$(printf 'abc' | hex_out "$BC_RUST" sha1 -x)
    assert_eq "$got" "a9993e364706816aba3e25717850c26c9cd0d89d" "SHA-1 of abc"
}

# TEST2: 56 bytes, so the padding takes a second block.
test_sha1_matches_rfc_3174_test2() {
    local got
    got=$(printf 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq' | hex_out "$BC_RUST" sha1 -x)
    assert_eq "$got" "84983e441c3bd26ebaae4aa1f95129e5e54670f1" "SHA-1 of TEST2"
}

# TEST4: "01234567" repeated 80 times, ten blocks.
test_sha1_matches_rfc_3174_test4() {
    local got
    got=$(printf '01234567%.0s' $(seq 80) | hex_out "$BC_RUST" sha1 -x)
    assert_eq "$got" "dea356a2cddd90c7a7ecedc5ebb563934f460452" "SHA-1 of TEST4"
}

test_sha1_binary_output_matches_hex_output() {
    rng 3000 >"$TMP/msg"
    "$BC_RUST" sha1 <"$TMP/msg" >"$TMP/bin"
    assert_size "$TMP/bin" 21 "20 digest bytes plus a newline"
    assert_eq "$(head -c 20 "$TMP/bin" | "$BC_RUST" hex-encode)" "$(hex_out "$BC_RUST" sha1 -x <"$TMP/msg")" "binary and hex agree across chunk boundaries"
}

run_all
