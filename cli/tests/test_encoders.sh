#!/usr/bin/env bash
# The hex-encode / hex-decode / base64-encode / base64-decode subcommands against RFC 4648 Sec 10 and the streaming boundaries.
#
# Generated for the 2026-11-03 CLI review (plan 15) from the vector files named in each test;
# every expected value is copied from that file, none is typed by hand. Follows lib.sh's
# conventions: each test_* runs in its own subshell under `set -e`.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# RFC 4648 Sec 10 (standards/RFC-4648-base64-hex.txt l.652-664): BASE64 of "" .. "foobar", both ways.
test_base64_matches_rfc4648_section_10() {
    local got
    got=$(printf '%s' '' | "$BC_RUST" base64-encode)
    assert_eq "$got" '' "BASE64('')"
    got=$(printf '%s' '' | "$BC_RUST" base64-decode)
    assert_eq "$got" '' "BASE64 decode of ''"
    got=$(printf '%s' 'f' | "$BC_RUST" base64-encode)
    assert_eq "$got" 'Zg==' "BASE64('f')"
    got=$(printf '%s' 'Zg==' | "$BC_RUST" base64-decode)
    assert_eq "$got" 'f' "BASE64 decode of 'Zg=='"
    got=$(printf '%s' 'fo' | "$BC_RUST" base64-encode)
    assert_eq "$got" 'Zm8=' "BASE64('fo')"
    got=$(printf '%s' 'Zm8=' | "$BC_RUST" base64-decode)
    assert_eq "$got" 'fo' "BASE64 decode of 'Zm8='"
    got=$(printf '%s' 'foo' | "$BC_RUST" base64-encode)
    assert_eq "$got" 'Zm9v' "BASE64('foo')"
    got=$(printf '%s' 'Zm9v' | "$BC_RUST" base64-decode)
    assert_eq "$got" 'foo' "BASE64 decode of 'Zm9v'"
    got=$(printf '%s' 'foob' | "$BC_RUST" base64-encode)
    assert_eq "$got" 'Zm9vYg==' "BASE64('foob')"
    got=$(printf '%s' 'Zm9vYg==' | "$BC_RUST" base64-decode)
    assert_eq "$got" 'foob' "BASE64 decode of 'Zm9vYg=='"
    got=$(printf '%s' 'fooba' | "$BC_RUST" base64-encode)
    assert_eq "$got" 'Zm9vYmE=' "BASE64('fooba')"
    got=$(printf '%s' 'Zm9vYmE=' | "$BC_RUST" base64-decode)
    assert_eq "$got" 'fooba' "BASE64 decode of 'Zm9vYmE='"
    got=$(printf '%s' 'foobar' | "$BC_RUST" base64-encode)
    assert_eq "$got" 'Zm9vYmFy' "BASE64('foobar')"
    got=$(printf '%s' 'Zm9vYmFy' | "$BC_RUST" base64-decode)
    assert_eq "$got" 'foobar' "BASE64 decode of 'Zm9vYmFy'"
}

# RFC 4648 Sec 10 (l.701-713): BASE16 of "" .. "foobar". The RFC prints upper-case digits; the CLI
# emits lower-case (RFC 4648 Sec 8: "The encoded output ... case-insensitive" on decode), so the
# comparison lower-cases the RFC value and the decoder is given the upper-case form as printed.
test_base16_matches_rfc4648_section_10() {
    local got
    got=$(printf '%s' '' | "$BC_RUST" hex-encode)
    assert_eq "$got" '' "BASE16('')"
    got=$(printf '%s' '' | "$BC_RUST" hex-decode)
    assert_eq "$got" '' "BASE16 decode of ''"
    got=$(printf '%s' 'f' | "$BC_RUST" hex-encode)
    assert_eq "$got" '66' "BASE16('f')"
    got=$(printf '%s' '66' | "$BC_RUST" hex-decode)
    assert_eq "$got" 'f' "BASE16 decode of '66'"
    got=$(printf '%s' 'fo' | "$BC_RUST" hex-encode)
    assert_eq "$got" '666f' "BASE16('fo')"
    got=$(printf '%s' '666F' | "$BC_RUST" hex-decode)
    assert_eq "$got" 'fo' "BASE16 decode of '666F'"
    got=$(printf '%s' 'foo' | "$BC_RUST" hex-encode)
    assert_eq "$got" '666f6f' "BASE16('foo')"
    got=$(printf '%s' '666F6F' | "$BC_RUST" hex-decode)
    assert_eq "$got" 'foo' "BASE16 decode of '666F6F'"
    got=$(printf '%s' 'foob' | "$BC_RUST" hex-encode)
    assert_eq "$got" '666f6f62' "BASE16('foob')"
    got=$(printf '%s' '666F6F62' | "$BC_RUST" hex-decode)
    assert_eq "$got" 'foob' "BASE16 decode of '666F6F62'"
    got=$(printf '%s' 'fooba' | "$BC_RUST" hex-encode)
    assert_eq "$got" '666f6f6261' "BASE16('fooba')"
    got=$(printf '%s' '666F6F6261' | "$BC_RUST" hex-decode)
    assert_eq "$got" 'fooba' "BASE16 decode of '666F6F6261'"
    got=$(printf '%s' 'foobar' | "$BC_RUST" hex-encode)
    assert_eq "$got" '666f6f626172' "BASE16('foobar')"
    got=$(printf '%s' '666F6F626172' | "$BC_RUST" hex-decode)
    assert_eq "$got" 'foobar' "BASE16 decode of '666F6F626172'"
}

# A chunk boundary (1 KiB reads) may fall between the two digits of a byte, inside a `\x` escape
# or after a backslash; the decoder must carry the partial token into the next read.
test_hex_decode_carries_partial_tokens_across_the_chunk_boundary() {
    local got
    { printf '00%.0s' $(seq 511); printf '41'; } >"$TMP/pair-split"          # '4' ends the first read
    got=$("$BC_RUST" hex-decode <"$TMP/pair-split" | tail -c 1 | "$BC_RUST" hex-encode)
    assert_eq "$got" "41" "digit pair split across reads"
    { printf '00%.0s' $(seq 511); printf ' \\x41'; } >"$TMP/bs-last"        # '\' ends the first read
    got=$("$BC_RUST" hex-decode <"$TMP/bs-last" | tail -c 1 | "$BC_RUST" hex-encode)
    assert_eq "$got" "41" "backslash last in a read"
    { printf '00%.0s' $(seq 511); printf '\\x41'; } >"$TMP/x-last"          # '\x' ends the first read
    got=$("$BC_RUST" hex-decode <"$TMP/x-last" | tail -c 1 | "$BC_RUST" hex-encode)
    assert_eq "$got" "41" "escape split after the x"
    { printf '00%.0s' $(seq 510); printf ' \\x4'; printf '1'; } >"$TMP/digit-split"  # '\x4' ends the first read
    got=$("$BC_RUST" hex-decode <"$TMP/digit-split" | tail -c 1 | "$BC_RUST" hex-encode)
    assert_eq "$got" "41" "escape split inside its digits"
}

# Round trips of random data through both encoders at sizes around the 1 KiB read and the
# 3-byte / 2-digit group boundaries.
test_round_trips_across_chunk_boundaries() {
    local size
    for size in 0 1 2 3 4 1023 1024 1025 1026 3071 3072 3073 65536; do
        rng "$size" >"$TMP/in"
        "$BC_RUST" base64-encode <"$TMP/in" | "$BC_RUST" base64-decode >"$TMP/out"
        assert_same "$TMP/in" "$TMP/out" "base64 round trip of $size bytes"
        "$BC_RUST" hex-encode <"$TMP/in" | "$BC_RUST" hex-decode >"$TMP/out"
        assert_same "$TMP/in" "$TMP/out" "hex round trip of $size bytes"
    done
}

test_malformed_hex_is_rejected() {
    expect_fail "odd digit count" "$BC_RUST" hex-decode < <(printf '0')
    assert_stderr_has "OddLengthInput"
    expect_fail "non-hex character" "$BC_RUST" hex-decode < <(printf 'zz')
    assert_stderr_has "InvalidHexCharacter"
    expect_fail "lone trailing backslash" "$BC_RUST" hex-decode < <(printf '\\')
    assert_stderr_has "backslash"
}

# RFC 4648 Sec 3.3: "non-alphabet characters ... should be rejected"; and after the padding the
# message is over. Both must be rejected whether the offending bytes arrive in a later read or in
# the same read as the padding.
test_base64_rejects_data_after_the_padding() {
    expect_fail "data after padding, next read" "$BC_RUST" base64-decode < <(printf 'QUJD%.0s' $(seq 256); printf 'QUI='; printf 'ZZZZ')
    assert_stderr_has "not valid base64"
    expect_fail "data after padding, same read" "$BC_RUST" base64-decode < <(printf 'QUI=XXXX')
    assert_stderr_has "not valid base64"
    expect_fail "two padded blocks in one read" "$BC_RUST" base64-decode < <(printf 'QUI=\nQUI=')
}

# RFC 4648 Sec 3.3: a final quantum of a single symbol cannot be valid; it must be rejected rather
# than decoded to bytes made from stale bits.
test_base64_rejects_a_single_trailing_symbol() {
    expect_fail "one symbol" "$BC_RUST" base64-decode < <(printf 'Q')
    expect_fail "one symbol then padding" "$BC_RUST" base64-decode < <(printf 'Q===')
}

run_all
