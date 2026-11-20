#!/usr/bin/env bash
# The x448 subcommand, end to end through the binary: X448 key agreement (RFC 7748).
#
# The known answers are RFC 7748 Section 6.2's, copied by a script from
# crypto/ed/tests/x448_tests.rs. Hex keys are read under --hex-input; without it they are raw
# bytes.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# RFC 7748 Section 6.2.
ALICE_SK=9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b
ALICE_PK=9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0
BOB_SK=1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d
BOB_PK=3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609
SHARED_K=07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d

# ---- known answers ------------------------------------------------------------------------

test_pk_from_sk_matches_rfc7748() {
    local got
    got=$(hex_out "$BC_RUST" --hex-input x448 pk-from-sk -x < <(printf '%s' "$ALICE_SK"))
    assert_eq "$got" "$ALICE_PK" "RFC 7748 6.2 Alice's public key"
    printf '%s' "$BOB_SK" >"$TMP/bob.sk"
    got=$(hex_out "$BC_RUST" --hex-input x448 pk-from-sk --skfile "$TMP/bob.sk" -x)
    assert_eq "$got" "$BOB_PK" "RFC 7748 6.2 Bob's public key"
}

test_agree_matches_rfc7748() {
    local got
    printf '%s' "$ALICE_SK" >"$TMP/alice.sk"
    printf '%s' "$ALICE_PK" >"$TMP/alice.pk"
    printf '%s' "$BOB_SK" >"$TMP/bob.sk"
    printf '%s' "$BOB_PK" >"$TMP/bob.pk"
    got=$(hex_out "$BC_RUST" --hex-input x448 agree --skfile "$TMP/alice.sk" --pkfile "$TMP/bob.pk" -x)
    assert_eq "$got" "$SHARED_K" "RFC 7748 6.2 K, computed by Alice"
    got=$(hex_out "$BC_RUST" --hex-input x448 agree --pkfile "$TMP/alice.pk" -x <"$TMP/bob.sk")
    assert_eq "$got" "$SHARED_K" "RFC 7748 6.2 K, computed by Bob with the sk on stdin"
}

# ---- binary and hex -----------------------------------------------------------------------

test_binary_keys_match_hex_keys() {
    local from_hex from_bin
    unhex "$ALICE_SK" >"$TMP/alice.sk"
    unhex "$BOB_PK" >"$TMP/bob.pk"
    from_bin=$(hex_out "$BC_RUST" x448 agree --skfile "$TMP/alice.sk" --pkfile "$TMP/bob.pk" -x)
    assert_eq "$from_bin" "$SHARED_K" "agree with binary key files"
    "$BC_RUST" x448 agree --skfile "$TMP/alice.sk" --pkfile "$TMP/bob.pk" >"$TMP/k"
    assert_eq "$(hex "$TMP/k")" "$SHARED_K" "agree with binary output"
    from_hex=$(hex_out "$BC_RUST" x448 pk-from-sk -x <"$TMP/alice.sk")
    assert_eq "$from_hex" "$ALICE_PK" "pk-from-sk with a binary sk on stdin"
}

# ---- fresh keys ---------------------------------------------------------------------------

test_keygen_outputs_fresh_keys() {
    "$BC_RUST" x448 keygen >"$TMP/sk1"
    "$BC_RUST" x448 keygen >"$TMP/sk2"
    assert_size "$TMP/sk1" 56 "keygen binary private key"
    assert_differs "$TMP/sk1" "$TMP/sk2" "two keygens must give different keys"
    assert_eq "$(hex_out "$BC_RUST" x448 keygen -x | wc -c | tr -d ' ')" 112 "keygen -x length"
}

test_agree_with_fresh_keys() {
    "$BC_RUST" x448 keygen >"$TMP/a.sk"
    "$BC_RUST" x448 keygen >"$TMP/b.sk"
    "$BC_RUST" x448 pk-from-sk --skfile "$TMP/a.sk" >"$TMP/a.pk"
    "$BC_RUST" x448 pk-from-sk --skfile "$TMP/b.sk" >"$TMP/b.pk"
    "$BC_RUST" x448 agree --skfile "$TMP/a.sk" --pkfile "$TMP/b.pk" >"$TMP/k_a"
    "$BC_RUST" x448 agree --skfile "$TMP/b.sk" --pkfile "$TMP/a.pk" >"$TMP/k_b"
    assert_size "$TMP/a.pk" 56 "public key"
    assert_size "$TMP/k_a" 56 "shared secret"
    assert_same "$TMP/k_a" "$TMP/k_b" "both sides must agree"
}

test_check_consistency() {
    "$BC_RUST" x448 keygen >"$TMP/sk"
    "$BC_RUST" x448 pk-from-sk --skfile "$TMP/sk" >"$TMP/pk"
    expect_ok "matching pair" \
        "$BC_RUST" x448 check-consistency --skfile "$TMP/sk" --pkfile "$TMP/pk" >/dev/null
    "$BC_RUST" x448 keygen >"$TMP/other.sk"
    expect_fail "mismatched pair" \
        "$BC_RUST" x448 check-consistency --skfile "$TMP/other.sk" --pkfile "$TMP/pk"
    assert_stderr_has "FAILURE"
}

# ---- errors -------------------------------------------------------------------------------

# An all-zero public key has small order, so the shared secret would be all zeros, which the
# agreement refuses (RFC 7748 Section 6.2 allows the check).
test_low_order_public_key_is_rejected() {
    printf '%s' "$ALICE_SK" >"$TMP/sk"
    printf '%0112d' 0 >"$TMP/zero.pk"
    expect_fail "agree with an all-zero public key" \
        "$BC_RUST" --hex-input x448 agree --skfile "$TMP/sk" --pkfile "$TMP/zero.pk"
    assert_stderr_has "AgreementFailed"
}

test_wrong_length_inputs_are_rejected() {
    printf '%s' "$ALICE_SK" >"$TMP/sk"
    printf '%s' "${BOB_PK:0:110}" >"$TMP/short.pk"
    expect_fail "55-byte private key" "$BC_RUST" --hex-input x448 pk-from-sk < <(printf '%s' "${ALICE_SK:0:110}")
    assert_stderr_has "private key"
    expect_fail "55-byte public key" \
        "$BC_RUST" --hex-input x448 agree --skfile "$TMP/sk" --pkfile "$TMP/short.pk"
    assert_stderr_has "public key"
    # An X25519 key is not an X448 key.
    expect_fail "32-byte private key" "$BC_RUST" --hex-input x448 pk-from-sk < <(printf '%s' "${ALICE_SK:0:64}")
    assert_stderr_has "private key"
}

test_missing_files_are_rejected() {
    printf '%s' "$ALICE_SK" >"$TMP/sk"
    expect_fail "agree without --pkfile" "$BC_RUST" --hex-input x448 agree <"$TMP/sk"
    assert_stderr_has "pkfile"
    expect_fail "check-consistency without --pkfile" "$BC_RUST" --hex-input x448 check-consistency <"$TMP/sk"
    assert_stderr_has "pkfile"
}

run_all
