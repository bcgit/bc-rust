#!/usr/bin/env bash
# The rng subcommand: lengths, hex rendering and the streaming contract (no known answer exists; see the file header).
#
# Written for the 2026-11-03 CLI review (report 15) from the vector files named in each test;
# every expected value is copied from that file, none is typed by hand. Follows lib.sh's
# conventions: each test_* runs in its own subshell under `set -e`.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# There is no known answer for `rng` seeded from the OS. What can be pinned is the contract of
# the command: exact lengths, the hex rendering, that successive draws differ, and that a seed
# file gives a reproducible stream.
test_raw_output_is_exactly_len_bytes() {
    local len
    for len in 0 1 2 1023 1024 1025 4096 10000; do
        "$BC_RUST" rng --len "$len" >"$TMP/out"
        assert_size "$TMP/out" "$len" "rng --len $len"
    done
}

test_hex_output_is_two_chars_per_byte_plus_a_newline() {
    local len
    for len in 0 1 1024 1025; do
        "$BC_RUST" rng --len "$len" -x >"$TMP/out"
        assert_size "$TMP/out" $((2 * len + 1)) "rng --len $len -x"
        [ "$(tail -c 1 "$TMP/out" | od -An -c | tr -d ' ')" = '\n' ] || fail "hex output must end in a newline"
        [ "$(head -c $((2 * len)) "$TMP/out" | tr -d '0-9a-f' | wc -c | tr -d ' ')" -eq 0 ] || fail "hex output must be lower-case hex"
    done
}

test_successive_draws_differ() {
    "$BC_RUST" rng --len 32 >"$TMP/a"
    "$BC_RUST" rng --len 32 >"$TMP/b"
    assert_differs "$TMP/a" "$TMP/b" "two 32-byte draws"
}

test_len_is_validated_by_clap() {
    expect_fail "negative" "$BC_RUST" rng --len -1
    expect_fail "non-numeric" "$BC_RUST" rng --len abc
    expect_fail "over u32" "$BC_RUST" rng --len 4294967296
}

# Without --len the command streams until the reader goes away; a closed pipe is a quiet exit 0.
test_streaming_until_the_reader_closes_exits_zero() {
    local status
    "$BC_RUST" rng 2>"$TMP/err" | head -c 100000 >"$TMP/out"
    status=${PIPESTATUS[0]}
    assert_eq "$status" 0 "exit status on a closed pipe"
    assert_size "$TMP/out" 100000 "the reader got what it asked for"
}

# --seed-file instantiates the DRBG from the file (SP 800-90A Rev. 1 Section 10.1.1.2 with the
# file as the entropy input), so the same file gives the same bytes, another file different ones,
# and a file too short for the instance's strength is refused with a message.
test_seed_file_gives_a_reproducible_stream() {
    rng 32 >"$TMP/seed"
    rng 32 >"$TMP/seed2"
    "$BC_RUST" rng --len 1000 --seed-file "$TMP/seed" >"$TMP/a"
    "$BC_RUST" rng --len 1000 --seed-file "$TMP/seed" >"$TMP/b"
    assert_same "$TMP/a" "$TMP/b" "the same seed file must give the same stream"
    "$BC_RUST" rng --len 1000 --seed-file "$TMP/seed2" >"$TMP/c"
    assert_differs "$TMP/a" "$TMP/c" "another seed file must give another stream"
    assert_eq "$(hex_out "$BC_RUST" --hex-input rng --len 16 --seed-file <(hex "$TMP/seed") -x)" "$(head -c 16 "$TMP/a" | hex_out "$BC_RUST" hex-encode)" "a hex seed file with --hex-input is the same seed"
    rng 16 >"$TMP/short"
    expect_fail "16 bytes is below the 256-bit instance" "$BC_RUST" rng --len 16 --seed-file "$TMP/short"
    assert_stderr_has "Error"
    "$BC_RUST" rng --len 16 --hash sha256 --seed-file "$TMP/short" >"$TMP/d"
    assert_size "$TMP/d" 16 "16 bytes seeds the 128-bit SHA-256 instance"
}

test_hash_selects_the_drbg() {
    "$BC_RUST" rng --len 100 --hash sha256 >"$TMP/a"
    assert_size "$TMP/a" 100 "rng --hash sha256"
    "$BC_RUST" rng --len 100 --hash sha512 >"$TMP/b"
    assert_size "$TMP/b" 100 "rng --hash sha512"
    expect_fail "an unknown hash" "$BC_RUST" rng --len 1 --hash md5
}

run_all
