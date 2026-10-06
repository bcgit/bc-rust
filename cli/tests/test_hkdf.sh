#!/usr/bin/env bash
# The hkdf-* subcommands, end to end through the binary. HKDF has no inverse to round-trip
# through, so each variant is pinned to one published known answer, and its file inputs must give
# the same output as the same values passed as hex.
#
# The known answers: HKDF-SHA256 is RFC 5869 Appendix A.1; HKDF-SHA384 and HKDF-SHA512 are
# tcId 11 of Wycheproof's testvectors_v1/hkdf_sha384_test.json and hkdf_sha512_test.json.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# ---- known answers ------------------------------------------------------------------------

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

run_all
