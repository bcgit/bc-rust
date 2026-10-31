#!/usr/bin/env bash
# The aes{128,192,256}-kw and aes{128,192,256}-kwp subcommands, end to end through the binary.
#
# What is worth testing here is the command-line contract: `-d encrypt` wraps and `-d decrypt`
# unwraps, no IV framing, whole-input reading, the input-length rules, exit codes on a rejected
# ciphertext, and key loading. The algorithms are tested in the library against the RFC and ACVP
# vectors; the RFC vectors are replayed here in both directions, which key wrap's determinism
# makes possible.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# RFC 3394 Sec 4: every example uses these KEK bytes (truncated to the key length) and this key
# data (truncated to the data length).
RFC3394_KEK=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
RFC3394_KEY_DATA=00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f
# Sec 4.1: 128 bits of key data, 128-bit KEK.
RFC3394_4_1_CT=1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5
# Sec 4.4: 192 bits of key data, 192-bit KEK.
RFC3394_4_4_CT=031d33264e15d33268f24ec260743edce1c6c7ddee725a936ba814915c6762d2
# Sec 4.6: 256 bits of key data, 256-bit KEK.
RFC3394_4_6_CT=28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21

# RFC 5649 Sec 6: both examples use a 192-bit KEK.
RFC5649_KEK=5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8
RFC5649_KEY_20=c37b7e6492584340bed12207808941155068f738
RFC5649_CT_20=138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a
RFC5649_KEY_7=466f7250617369
RFC5649_CT_7=afbeb0f07dfbf5419200f2ccb50bb24f

KEK128=${RFC3394_KEK:0:32}
KEK192=${RFC3394_KEK:0:48}

# `wrap SUB KEK` / `unwrap SUB KEK` run one direction of SUB with the hex KEK, stdin to stdout.
wrap() { "$BC_RUST" "$1" -d encrypt --key "$2"; }
unwrap() { "$BC_RUST" "$1" -d decrypt --key "$2"; }

# ---- the RFC vectors, both directions ------------------------------------------------------

test_aes128_kw_matches_rfc3394_4_1_in_both_directions() {
    local got
    got=$(unhex "${RFC3394_KEY_DATA:0:32}" | wrap aes128-kw "$KEK128" | "$BC_RUST" hex-encode)
    assert_eq "$got" "$RFC3394_4_1_CT" "4.1 wrap"
    got=$(unhex "$RFC3394_4_1_CT" | unwrap aes128-kw "$KEK128" | "$BC_RUST" hex-encode)
    assert_eq "$got" "${RFC3394_KEY_DATA:0:32}" "4.1 unwrap"
}

test_aes192_kw_matches_rfc3394_4_4_in_both_directions() {
    local got
    got=$(unhex "${RFC3394_KEY_DATA:0:48}" | wrap aes192-kw "$KEK192" | "$BC_RUST" hex-encode)
    assert_eq "$got" "$RFC3394_4_4_CT" "4.4 wrap"
    got=$(unhex "$RFC3394_4_4_CT" | unwrap aes192-kw "$KEK192" | "$BC_RUST" hex-encode)
    assert_eq "$got" "${RFC3394_KEY_DATA:0:48}" "4.4 unwrap"
}

test_aes256_kw_matches_rfc3394_4_6_in_both_directions() {
    local got
    got=$(unhex "$RFC3394_KEY_DATA" | wrap aes256-kw "$RFC3394_KEK" | "$BC_RUST" hex-encode)
    assert_eq "$got" "$RFC3394_4_6_CT" "4.6 wrap"
    got=$(unhex "$RFC3394_4_6_CT" | unwrap aes256-kw "$RFC3394_KEK" | "$BC_RUST" hex-encode)
    assert_eq "$got" "$RFC3394_KEY_DATA" "4.6 unwrap"
}

test_aes192_kwp_matches_rfc5649_in_both_directions() {
    local got
    # 20 octets: padded to 24, through the wrapping function.
    got=$(unhex "$RFC5649_KEY_20" | wrap aes192-kwp "$RFC5649_KEK" | "$BC_RUST" hex-encode)
    assert_eq "$got" "$RFC5649_CT_20" "20-octet wrap"
    got=$(unhex "$RFC5649_CT_20" | unwrap aes192-kwp "$RFC5649_KEK" | "$BC_RUST" hex-encode)
    assert_eq "$got" "$RFC5649_KEY_20" "20-octet unwrap"
    # 7 octets: a single block. The unwrapped output is exactly 7 bytes, not the padded 8.
    got=$(unhex "$RFC5649_KEY_7" | wrap aes192-kwp "$RFC5649_KEK" | "$BC_RUST" hex-encode)
    assert_eq "$got" "$RFC5649_CT_7" "7-octet wrap"
    got=$(unhex "$RFC5649_CT_7" | unwrap aes192-kwp "$RFC5649_KEK" | "$BC_RUST" hex-encode)
    assert_eq "$got" "$RFC5649_KEY_7" "7-octet unwrap"
}

# ---- the command-line contract -------------------------------------------------------------

test_hex_output_matches_binary_output() {
    local hex_out
    unhex "${RFC3394_KEY_DATA:0:32}" >"$TMP/pt"
    wrap aes128-kw "$KEK128" <"$TMP/pt" >"$TMP/ct"
    hex_out=$("$BC_RUST" aes128-kw -d encrypt --key "$KEK128" -x <"$TMP/pt")
    assert_eq "$hex_out" "$(hex "$TMP/ct")" "-x must be the hex of the binary output"
    assert_eq "$hex_out" "$RFC3394_4_1_CT" "and both are the 4.1 ciphertext"
}

test_wrapping_is_deterministic_and_adds_exactly_one_semiblock() {
    rng 32 >"$TMP/key_data"
    wrap aes128-kw "$KEK128" <"$TMP/key_data" >"$TMP/a"
    wrap aes128-kw "$KEK128" <"$TMP/key_data" >"$TMP/b"
    assert_same "$TMP/a" "$TMP/b" "no IV, so the same input always gives the same output"
    assert_size "$TMP/a" 40 "KW adds one semiblock"

    wrap aes128-kwp "$KEK128" <"$TMP/key_data" >"$TMP/a"
    assert_size "$TMP/a" 40 "aligned data costs KWP nothing extra"
    head -c 13 "$TMP/key_data" | wrap aes128-kwp "$KEK128" >"$TMP/a"
    assert_size "$TMP/a" 24 "13 bytes pad to 16, plus the header"
}

test_a_tampered_ciphertext_is_rejected_with_no_output() {
    unhex "$RFC3394_4_1_CT" >"$TMP/ct"
    flip_byte "$TMP/ct" 11
    expect_fail "a modified KW ciphertext" unwrap aes128-kw "$KEK128" <"$TMP/ct"
    assert_stderr_has "not an authentic"

    unhex "$RFC5649_CT_7" >"$TMP/ct"
    flip_byte "$TMP/ct" 0 128
    expect_fail "a modified KWP ciphertext" unwrap aes192-kwp "$RFC5649_KEK" <"$TMP/ct"
    assert_stderr_has "not an authentic"
}

test_the_wrong_kek_is_rejected() {
    unhex "$RFC3394_4_1_CT" >"$TMP/ct"
    expect_fail "the wrong KEK" unwrap aes128-kw 0f0e0d0c0b0a09080706050403020100 <"$TMP/ct"
    assert_stderr_has "not an authentic"
}

test_kw_and_kwp_are_not_interchangeable() {
    rng 16 >"$TMP/key_data"
    wrap aes128-kw "$KEK128" <"$TMP/key_data" >"$TMP/kw"
    wrap aes128-kwp "$KEK128" <"$TMP/key_data" >"$TMP/kwp"
    assert_differs "$TMP/kw" "$TMP/kwp" "the integrity check values differ"
    expect_fail "KWP must not unwrap a KW ciphertext" unwrap aes128-kwp "$KEK128" <"$TMP/kw"
    expect_fail "KW must not unwrap a KWP ciphertext" unwrap aes128-kw "$KEK128" <"$TMP/kwp"
}

test_kw_rejects_inputs_that_are_not_whole_semiblocks() {
    # wrap: 8 bytes is one semiblock (two are needed); 20 is not a whole number of them.
    rng 8 >"$TMP/short"
    expect_fail "8 bytes" wrap aes128-kw "$KEK128" <"$TMP/short"
    assert_stderr_has "8 bytes rejected"
    rng 20 >"$TMP/unaligned"
    expect_fail "20 bytes" wrap aes128-kw "$KEK128" <"$TMP/unaligned"
    assert_stderr_has "20 bytes rejected"
    # unwrap: 16 bytes is two semiblocks (three are needed).
    rng 16 >"$TMP/two"
    expect_fail "16 bytes" unwrap aes128-kw "$KEK128" <"$TMP/two"
    assert_stderr_has "16 bytes rejected"
    # KWP takes the unaligned length KW refused.
    wrap aes128-kwp "$KEK128" <"$TMP/unaligned" >"$TMP/ct"
    assert_size "$TMP/ct" 32 "20 bytes pad to 24, plus the header"
}

test_empty_input_is_rejected_by_both() {
    : >"$TMP/empty"
    expect_fail "KW wrap of nothing" wrap aes128-kw "$KEK128" <"$TMP/empty"
    assert_stderr_has "0 bytes rejected"
    expect_fail "KWP wrap of nothing" wrap aes128-kwp "$KEK128" <"$TMP/empty"
    assert_stderr_has "0 bytes rejected"
    expect_fail "KWP unwrap of nothing" unwrap aes128-kwp "$KEK128" <"$TMP/empty"
    assert_stderr_has "0 bytes rejected"
}

test_a_larger_payload_round_trips_through_kwp() {
    # An "encoded private key" sized payload that is not a multiple of 8.
    rng 3001 >"$TMP/payload"
    wrap aes256-kwp "$RFC3394_KEK" <"$TMP/payload" >"$TMP/ct"
    assert_size "$TMP/ct" $((3008 + 8)) "3001 bytes pad to 3008, plus the header"
    unwrap aes256-kwp "$RFC3394_KEK" <"$TMP/ct" >"$TMP/rec"
    assert_same "$TMP/payload" "$TMP/rec" "KWP must recover the payload"
    # ... and KW refuses it, because it is not aligned.
    expect_fail "KW on unaligned data" wrap aes256-kw "$RFC3394_KEK" <"$TMP/payload"
}

test_key_file_accepts_hex_and_binary() {
    local form
    printf '%s' "$KEK128" >"$TMP/kek.hex"
    unhex "$KEK128" >"$TMP/kek.bin"
    unhex "${RFC3394_KEY_DATA:0:32}" >"$TMP/pt"
    for form in kek.hex kek.bin; do
        "$BC_RUST" aes128-kw -d encrypt --key-file "$TMP/$form" <"$TMP/pt" >"$TMP/ct"
        assert_eq "$(hex "$TMP/ct")" "$RFC3394_4_1_CT" "--key-file $form must give the 4.1 ciphertext"
    done
}

test_a_key_of_the_wrong_length_is_rejected() {
    rng 16 >"$TMP/pt"
    expect_fail "a 24-byte key is not an AES-128 key" wrap aes128-kw "$KEK192" <"$TMP/pt"
    assert_stderr_has "16-byte key"
    expect_fail "a 16-byte key is not an AES-256 key" wrap aes256-kwp "$KEK128" <"$TMP/pt"
    assert_stderr_has "32-byte key"
}

test_a_missing_key_is_rejected() {
    rng 16 >"$TMP/pt"
    expect_fail "neither --key nor --key-file" "$BC_RUST" aes128-kw -d encrypt <"$TMP/pt"
    assert_stderr_has "\-\-key"
}

test_the_subcommands_are_listed_in_help() {
    local cmd word
    "$BC_RUST" --help >"$TMP/help"
    for cmd in aes128-kw aes192-kw aes256-kw aes128-kwp aes192-kwp aes256-kwp; do
        grep -q "$cmd" "$TMP/help" || fail "--help should list $cmd"
    done
    "$BC_RUST" aes128-kw --help >"$TMP/help"
    for word in encrypt decrypt "RFC 3394" "NO IV"; do
        grep -q "$word" "$TMP/help" || fail "aes128-kw --help should mention '$word'"
    done
}

run_all
