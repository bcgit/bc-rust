#!/usr/bin/env bash
# The sm3 subcommand against the draft-sca-cfrg-sm3-02 examples.
#
# Generated for the 2026-11-03 CLI review (plan 15) from the vector files named in each test;
# every expected value is copied from that file, none is typed by hand. Follows lib.sh's
# conventions: each test_* runs in its own subshell under `set -e`.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# draft-sca-cfrg-sm3-02 Appendix A.1 (standards/SM3-draft-sca-cfrg-sm3-02.txt l.1865): SM3("abc").
test_sm3_matches_the_draft_example_1() {
    local got
    got=$(printf 'abc' | hex_out "$BC_RUST" sm3 -x)
    assert_eq "$got" "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0" "SM3 of abc"
}

# Appendix A.2 (l.2149): the 512-bit message "abcd" repeated 16 times, which is exactly one block.
test_sm3_matches_the_draft_example_2() {
    local got
    got=$(printf 'abcd%.0s' $(seq 16) | hex_out "$BC_RUST" sm3 -x)
    assert_eq "$got" "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732" "SM3 of abcd x16"
}

test_sm3_binary_output_matches_hex_output() {
    rng 3000 >"$TMP/msg"
    "$BC_RUST" sm3 <"$TMP/msg" >"$TMP/bin"
    assert_size "$TMP/bin" 33 "32 digest bytes plus a newline"
    assert_eq "$(head -c 32 "$TMP/bin" | "$BC_RUST" hex-encode)" "$(hex_out "$BC_RUST" sm3 -x <"$TMP/msg")" "binary and hex agree across chunk boundaries"
}

run_all
