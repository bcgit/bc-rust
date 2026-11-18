#!/usr/bin/env bash
# The ripemd128, ripemd160, ripemd256, ripemd320 and hmac-ripemd160 subcommands against the
# designers' published test vectors (https://homes.esat.kuleuven.be/~bosselae/ripemd160.html)
# and RFC 2286 (test_hmac.sh covers the random HMAC round trips).
#
# Follows lib.sh's conventions: each test_* runs in its own subshell under `set -e`.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# The designers' "abc" vector for each of the four functions.
test_ripemd_matches_the_designers_abc_vectors() {
    local got
    got=$(printf 'abc' | hex_out "$BC_RUST" ripemd128 -x)
    assert_eq "$got" "c14a12199c66e4ba84636b0f69144c77" "RIPEMD-128 of abc"
    got=$(printf 'abc' | hex_out "$BC_RUST" ripemd160 -x)
    assert_eq "$got" "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc" "RIPEMD-160 of abc"
    got=$(printf 'abc' | hex_out "$BC_RUST" ripemd256 -x)
    assert_eq "$got" "afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65" "RIPEMD-256 of abc"
    got=$(printf 'abc' | hex_out "$BC_RUST" ripemd320 -x)
    assert_eq "$got" "de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d" "RIPEMD-320 of abc"
}

# The designers' "1 million times a" vector, which crosses many read-buffer boundaries.
test_ripemd160_matches_the_designers_million_a_vector() {
    local got
    got=$(head -c 1000000 /dev/zero | tr '\0' 'a' | hex_out "$BC_RUST" ripemd160 -x)
    assert_eq "$got" "52783243c1697bdbe16d37f97f68f08325dc1528" "RIPEMD-160 of a x 1000000"
}

test_ripemd_binary_output_matches_hex_output() {
    local sub len sub_len
    rng 3000 >"$TMP/msg"
    for sub_len in ripemd128:16 ripemd160:20 ripemd256:32 ripemd320:40; do
        sub=${sub_len%%:*}
        len=${sub_len##*:}
        "$BC_RUST" "$sub" <"$TMP/msg" >"$TMP/bin"
        assert_size "$TMP/bin" $((len + 1)) "$sub: $len digest bytes plus a newline"
        assert_eq "$(head -c "$len" "$TMP/bin" | "$BC_RUST" hex-encode)" "$(hex_out "$BC_RUST" "$sub" -x <"$TMP/msg")" "$sub: binary and hex agree across chunk boundaries"
    done
}

# RFC 2286 Sec 2, test_case 2: key "Jefe", data "what do ya want for nothing?".
test_hmac_ripemd160_matches_rfc2286_case_2() {
    local got
    printf 'what do ya want for nothing?' >"$TMP/data"
    got=$(hex_out "$BC_RUST" hmac-ripemd160 --key 4a656665 -x <"$TMP/data")
    assert_eq "$got" "dda6c0213a485a9e24f4742064a7f033b43c4069" "HMAC-RIPEMD160 case 2"
    expect_ok "the RFC tag must verify" "$BC_RUST" hmac-ripemd160 --key 4a656665 --verify dda6c0213a485a9e24f4742064a7f033b43c4069 <"$TMP/data"
    expect_fail "a modified tag must not verify" "$BC_RUST" hmac-ripemd160 --key 4a656665 --verify dda6c0213a485a9e24f4742064a7f033b43c4068 <"$TMP/data"
}

run_all
