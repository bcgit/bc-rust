#!/usr/bin/env bash
# The hkdf-* subcommands, end to end through the binary. HKDF has no inverse to round-trip
# through, so each variant is pinned to one published known answer, and its file inputs must give
# the same output as the same values passed as hex.
#
# The known answers: HKDF-SHA256 is RFC 5869 Appendix A.1; HKDF-SHA384 and HKDF-SHA512 are
# tcId 11 of Wycheproof's testvectors_v1/hkdf_sha384_test.json and hkdf_sha512_test.json;
# HKDF-SM3, which has no published vectors, is RFC 5869 A.1's inputs through OpenSSL 3.0.13.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# ---- known answers ------------------------------------------------------------------------

# RFC 5869 Section 2.2: the salt is optional, and no --salt is the same as an empty one.
test_hkdf_sha256_salt_may_be_omitted() {
    local with_empty without
    with_empty=$(hex_out "$BC_RUST" hkdf-sha256 --salt "" --ikm 0b0b0b0b0b0b0b0b --len 32 -x)
    without=$(hex_out "$BC_RUST" hkdf-sha256 --ikm 0b0b0b0b0b0b0b0b --len 32 -x)
    assert_eq "$without" "$with_empty" "no --salt is the empty salt"
}

# `--secret-salt` changes the salt's entropy accounting, not the bytes: RFC 5869 A.1 again.
test_hkdf_sha256_secret_salt_gives_the_same_okm() {
    local got
    got=$(hex_out "$BC_RUST" hkdf-sha256 \
        --salt 000102030405060708090a0b0c --secret-salt \
        --ikm 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b \
        --additional-input f0f1f2f3f4f5f6f7f8f9 \
        --len 42 -x)
    assert_eq "$got" \
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865" \
        "RFC 5869 A.1 OKM with --secret-salt"
}

test_hkdf_sha256_matches_rfc5869_a1() {
    local got
    got=$(hex_out "$BC_RUST" hkdf-sha256 \
        --salt 000102030405060708090a0b0c \
        --ikm 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b \
        --additional-input f0f1f2f3f4f5f6f7f8f9 \
        --len 42 -x)
    assert_eq "$got" \
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865" \
        "RFC 5869 A.1 OKM"
}

# RFC 5869 A.3: zero-length salt and no info at all; `--additional-input` is optional.
test_hkdf_sha256_matches_rfc5869_a3() {
    local got
    got=$(hex_out "$BC_RUST" hkdf-sha256 \
        --salt "" \
        --ikm 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b \
        --len 42 -x)
    assert_eq "$got" \
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8" \
        "RFC 5869 A.3 OKM"
}

test_hkdf_sha384_matches_wycheproof_tc11() {
    local got
    got=$(hex_out "$BC_RUST" hkdf-sha384 \
        --salt 2614d80275b08a1cf90bae0eb607d4d5 \
        --ikm 0cbd136d66d15a4ffefde1303b430821 \
        --additional-input ee991de21aeb6baa6a5f683dbb755e6f80db1c1d \
        --len 42 -x)
    assert_eq "$got" \
        "e618b91d9f3d10c007958d025841a3347947eb41b23ec35a3d7927aad74f293c50405a56911d8158e74f" \
        "Wycheproof hkdf_sha384 tcId 11 OKM"
}

test_hkdf_sha512_matches_wycheproof_tc11() {
    local got
    got=$(hex_out "$BC_RUST" hkdf-sha512 \
        --salt 2614d80275b08a1cf90bae0eb607d4d5 \
        --ikm 0cbd136d66d15a4ffefde1303b430821 \
        --additional-input ee991de21aeb6baa6a5f683dbb755e6f80db1c1d \
        --len 42 -x)
    assert_eq "$got" \
        "e51c3bfe5f4e9b4fb0d3c3a67bb33a20c288800e03707621cf143e8581d422dfec3fe658ba8fa2e35c2c" \
        "Wycheproof hkdf_sha512 tcId 11 OKM"
}

test_hkdf_sm3_matches_openssl_on_rfc5869_a1_inputs() {
    local got
    got=$(hex_out "$BC_RUST" hkdf-sm3 \
        --salt 000102030405060708090a0b0c \
        --ikm 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b \
        --additional-input f0f1f2f3f4f5f6f7f8f9 \
        --len 42 -x)
    assert_eq "$got" \
        "c69fe91b7aaee2dd5718d72dcaee0cce93f1b8e41f792da51261b6a517e68b36ed2c595572b01dfa359b" \
        "HKDF-SM3 OKM"
}

# ---- file inputs --------------------------------------------------------------------------

# `hkdf_files_match_hex SUBCOMMAND` derives from random inputs passed once as hex and once as
# binary files, and requires the same output.
hkdf_files_match_hex() {
    local sub=$1 from_hex from_files
    rng 32 >"$TMP/salt"
    rng 32 >"$TMP/ikm"
    rng 16 >"$TMP/info"
    from_hex=$(hex_out "$BC_RUST" "$sub" --salt "$(hex "$TMP/salt")" --ikm "$(hex "$TMP/ikm")" \
        --additional-input "$(hex "$TMP/info")" --len 100 -x)
    from_files=$(hex_out "$BC_RUST" "$sub" -s "$TMP/salt" -i "$TMP/ikm" -a "$TMP/info" --len 100 -x)
    assert_eq "${#from_hex}" 200 "$sub output length"
    assert_eq "$from_files" "$from_hex" "$sub: file inputs must give the hex inputs' output"
}

test_hkdf_sha256_files_match_hex() {
    hkdf_files_match_hex hkdf-sha256
}

test_hkdf_sha384_files_match_hex() {
    hkdf_files_match_hex hkdf-sha384
}

test_hkdf_sha512_files_match_hex() {
    hkdf_files_match_hex hkdf-sha512
}

test_hkdf_sm3_files_match_hex() {
    hkdf_files_match_hex hkdf-sm3
}

# When a value is given both as hex and as a file, the file is used, as the help text says.
test_hkdf_sha256_file_wins_over_hex() {
    local from_files with_both
    rng 32 >"$TMP/salt"
    rng 32 >"$TMP/ikm"
    rng 16 >"$TMP/info"
    from_files=$(hex_out "$BC_RUST" hkdf-sha256 -s "$TMP/salt" -i "$TMP/ikm" -a "$TMP/info" --len 42 -x)
    with_both=$(hex_out "$BC_RUST" hkdf-sha256 --salt 01 -s "$TMP/salt" --ikm 02 -i "$TMP/ikm" \
        --additional-input 03 -a "$TMP/info" --len 42 -x)
    assert_eq "$with_both" "$from_files" "the file inputs must win over the hex ones"
}

# ---- output length ------------------------------------------------------------------------

# `hkdf_short_output_is_a_prefix SUBCOMMAND LEN`: RFC 5869's output is the first L octets of the
# expanded stream, so `--len LEN` must be a prefix of `--len 100`. The lengths used are one octet
# past a whole block, which the library once refused.
hkdf_short_output_is_a_prefix() {
    local sub=$1 len=$2 long short
    long=$(hex_out "$BC_RUST" "$sub" --salt 00 --ikm 0b0b0b0b --additional-input 01 --len 100 -x)
    short=$(hex_out "$BC_RUST" "$sub" --salt 00 --ikm 0b0b0b0b --additional-input 01 --len "$len" -x)
    assert_eq "$short" "${long:0:$((2 * len))}" "$sub --len $len"
}

test_hkdf_sha256_one_octet_past_a_block() {
    hkdf_short_output_is_a_prefix hkdf-sha256 33
}

test_hkdf_sha384_one_octet_past_a_block() {
    hkdf_short_output_is_a_prefix hkdf-sha384 49
}

test_hkdf_sha512_one_octet_past_a_block() {
    hkdf_short_output_is_a_prefix hkdf-sha512 65
}

test_hkdf_sm3_one_octet_past_a_block() {
    hkdf_short_output_is_a_prefix hkdf-sm3 33
}

# An empty Z derives a key from nothing (the KDF trait allows it; no command-line user means
# it): refused before any derivation, inline and from a file.
test_hkdf_refuses_an_empty_ikm() {
    expect_fail "an empty --ikm is refused" "$BC_RUST" hkdf-sha256 --salt 000102 --ikm "" --len 16
    assert_stderr_has "empty"
    : >"$TMP/empty"
    expect_fail "an empty --ikm-file is refused" "$BC_RUST" hkdf-sha256 --salt 000102 --ikm-file "$TMP/empty" --len 16
    assert_stderr_has "empty"
}

run_all
