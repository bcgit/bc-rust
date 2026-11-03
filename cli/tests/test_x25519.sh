#!/usr/bin/env bash
# The x25519 subcommand, end to end through the binary: X25519 key agreement (RFC 7748) and
# DHKEM(X25519, HKDF-SHA256) encapsulation (RFC 9180).
#
# The known answers: the key agreement is RFC 7748 Section 6.1; the decapsulation is RFC 9180
# Appendix A.1.1.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# RFC 7748 Section 6.1.
ALICE_SK=77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
ALICE_PK=8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
BOB_SK=5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb
BOB_PK=de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f
SHARED_K=4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742

# RFC 9180 Appendix A.1.1.
SK_RM=4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8
PK_RM=3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d
ENC=37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431
SHARED_SECRET=fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc

# ---- known answers ------------------------------------------------------------------------

test_pk_from_sk_matches_rfc7748() {
    local got
    got=$(hex_out "$BC_RUST" x25519 pk-from-sk -x < <(printf '%s' "$ALICE_SK"))
    assert_eq "$got" "$ALICE_PK" "RFC 7748 6.1 Alice's public key"
    printf '%s' "$BOB_SK" >"$TMP/bob.sk"
    got=$(hex_out "$BC_RUST" x25519 pk-from-sk --skfile "$TMP/bob.sk" -x)
    assert_eq "$got" "$BOB_PK" "RFC 7748 6.1 Bob's public key"
}

test_agree_matches_rfc7748() {
    local got
    printf '%s' "$ALICE_SK" >"$TMP/alice.sk"
    printf '%s' "$ALICE_PK" >"$TMP/alice.pk"
    printf '%s' "$BOB_SK" >"$TMP/bob.sk"
    printf '%s' "$BOB_PK" >"$TMP/bob.pk"
    got=$(hex_out "$BC_RUST" x25519 agree --skfile "$TMP/alice.sk" --pkfile "$TMP/bob.pk" -x)
    assert_eq "$got" "$SHARED_K" "RFC 7748 6.1 K, computed by Alice"
    got=$(hex_out "$BC_RUST" x25519 agree --pkfile "$TMP/alice.pk" -x <"$TMP/bob.sk")
    assert_eq "$got" "$SHARED_K" "RFC 7748 6.1 K, computed by Bob with the sk on stdin"
}

test_decaps_matches_rfc9180_a1_1() {
    local got
    printf '%s' "$SK_RM" >"$TMP/sk"
    got=$(hex_out "$BC_RUST" x25519 pk-from-sk --skfile "$TMP/sk" -x)
    assert_eq "$got" "$PK_RM" "RFC 9180 A.1.1 pkRm"
    got=$(hex_out "$BC_RUST" x25519 decaps --skfile "$TMP/sk" -x < <(printf '%s' "$ENC"))
    assert_eq "$got" "$SHARED_SECRET" "RFC 9180 A.1.1 shared_secret, enc on stdin"
    printf '%s' "$ENC" >"$TMP/ct"
    got=$(hex_out "$BC_RUST" x25519 decaps --skfile "$TMP/sk" --ctfile "$TMP/ct" -x)
    assert_eq "$got" "$SHARED_SECRET" "RFC 9180 A.1.1 shared_secret, enc from --ctfile"
}

# ---- binary and hex -----------------------------------------------------------------------

test_binary_keys_match_hex_keys() {
    local from_hex from_bin
    unhex "$ALICE_SK" >"$TMP/alice.sk"
    unhex "$BOB_PK" >"$TMP/bob.pk"
    from_bin=$(hex_out "$BC_RUST" x25519 agree --skfile "$TMP/alice.sk" --pkfile "$TMP/bob.pk" -x)
    assert_eq "$from_bin" "$SHARED_K" "agree with binary key files"
    "$BC_RUST" x25519 agree --skfile "$TMP/alice.sk" --pkfile "$TMP/bob.pk" >"$TMP/k"
    assert_eq "$(hex "$TMP/k")" "$SHARED_K" "agree with binary output"
    from_hex=$(hex_out "$BC_RUST" x25519 pk-from-sk -x <"$TMP/alice.sk")
    assert_eq "$from_hex" "$ALICE_PK" "pk-from-sk with a binary sk on stdin"
}

# ---- fresh keys ---------------------------------------------------------------------------

test_keygen_outputs_fresh_keys() {
    "$BC_RUST" x25519 keygen >"$TMP/sk1"
    "$BC_RUST" x25519 keygen >"$TMP/sk2"
    assert_size "$TMP/sk1" 32 "keygen binary private key"
    assert_differs "$TMP/sk1" "$TMP/sk2" "two keygens must give different keys"
    assert_eq "$(hex_out "$BC_RUST" x25519 keygen -x | wc -c | tr -d ' ')" 64 "keygen -x length"
}

test_agree_with_fresh_keys() {
    "$BC_RUST" x25519 keygen >"$TMP/a.sk"
    "$BC_RUST" x25519 keygen >"$TMP/b.sk"
    "$BC_RUST" x25519 pk-from-sk --skfile "$TMP/a.sk" >"$TMP/a.pk"
    "$BC_RUST" x25519 pk-from-sk --skfile "$TMP/b.sk" >"$TMP/b.pk"
    "$BC_RUST" x25519 agree --skfile "$TMP/a.sk" --pkfile "$TMP/b.pk" >"$TMP/k_a"
    "$BC_RUST" x25519 agree --skfile "$TMP/b.sk" --pkfile "$TMP/a.pk" >"$TMP/k_b"
    assert_size "$TMP/k_a" 32 "shared secret"
    assert_same "$TMP/k_a" "$TMP/k_b" "both sides must agree"
}

test_check_consistency() {
    "$BC_RUST" x25519 keygen >"$TMP/sk"
    "$BC_RUST" x25519 pk-from-sk --skfile "$TMP/sk" >"$TMP/pk"
    expect_ok "matching pair" \
        "$BC_RUST" x25519 check-consistency --skfile "$TMP/sk" --pkfile "$TMP/pk" >/dev/null
    "$BC_RUST" x25519 keygen >"$TMP/other.sk"
    expect_fail "mismatched pair" \
        "$BC_RUST" x25519 check-consistency --skfile "$TMP/other.sk" --pkfile "$TMP/pk"
    assert_stderr_has "FAILURE"
}

# ---- encaps / decaps ----------------------------------------------------------------------

test_encaps_decaps_round_trip_with_ctfile() {
    "$BC_RUST" x25519 keygen >"$TMP/sk"
    "$BC_RUST" x25519 pk-from-sk --skfile "$TMP/sk" >"$TMP/pk"
    "$BC_RUST" x25519 encaps --pkfile "$TMP/pk" --ctfile "$TMP/ct" >"$TMP/ss1"
    "$BC_RUST" x25519 decaps --skfile "$TMP/sk" --ctfile "$TMP/ct" >"$TMP/ss2"
    assert_size "$TMP/ct" 32 "ciphertext"
    assert_size "$TMP/ss1" 32 "shared secret"
    assert_same "$TMP/ss1" "$TMP/ss2" "decaps must recover the encapsulated secret"
}

# Without --ctfile, encaps prints the ciphertext and then the shared secret, in hex, one per line.
test_encaps_to_stdout_round_trip() {
    local ct ss got
    "$BC_RUST" x25519 keygen >"$TMP/sk"
    "$BC_RUST" x25519 pk-from-sk --skfile "$TMP/sk" | "$BC_RUST" x25519 encaps >"$TMP/out"
    ct=$(sed -n 1p "$TMP/out")
    ss=$(sed -n 2p "$TMP/out")
    assert_eq "${#ct}" 64 "hex ciphertext length"
    assert_eq "${#ss}" 64 "hex shared secret length"
    got=$(hex_out "$BC_RUST" x25519 decaps --skfile "$TMP/sk" -x < <(printf '%s' "$ct"))
    assert_eq "$got" "$ss" "decaps must recover the encapsulated secret"
}

test_encaps_is_randomized() {
    printf '%s' "$PK_RM" >"$TMP/pk"
    "$BC_RUST" x25519 encaps --pkfile "$TMP/pk" --ctfile "$TMP/ct1" >"$TMP/ss1"
    "$BC_RUST" x25519 encaps --pkfile "$TMP/pk" --ctfile "$TMP/ct2" >"$TMP/ss2"
    assert_differs "$TMP/ct1" "$TMP/ct2" "two encapsulations must give different ciphertexts"
    assert_differs "$TMP/ss1" "$TMP/ss2" "two encapsulations must give different secrets"
}

# DHKEM rejects implicitly: the wrong private key gives a different secret, not an error.
test_decaps_with_wrong_key_gives_different_secret() {
    local got
    "$BC_RUST" x25519 keygen >"$TMP/sk"
    got=$(hex_out "$BC_RUST" x25519 decaps --skfile "$TMP/sk" -x < <(printf '%s' "$ENC"))
    assert_eq "${#got}" 64 "hex shared secret length"
    [ "$got" != "$SHARED_SECRET" ] || fail "the wrong private key must not give the RFC secret"
}

# ---- errors -------------------------------------------------------------------------------

# An all-zero public key has small order, so the shared secret would be all zeros, which RFC 9180
# Section 7.1.4 and RFC 8446 Section 7.4.2 require rejecting.
test_low_order_public_key_is_rejected() {
    printf '%s' "$ALICE_SK" >"$TMP/sk"
    printf '%064d' 0 >"$TMP/zero.pk"
    expect_fail "agree with an all-zero public key" \
        "$BC_RUST" x25519 agree --skfile "$TMP/sk" --pkfile "$TMP/zero.pk"
    assert_stderr_has "InvalidPublicKey"
    expect_fail "encaps to an all-zero public key" \
        "$BC_RUST" x25519 encaps --pkfile "$TMP/zero.pk" --ctfile "$TMP/ct"
    expect_fail "decaps of an all-zero enc" \
        "$BC_RUST" x25519 decaps --skfile "$TMP/sk" --ctfile "$TMP/zero.pk"
}

test_wrong_length_inputs_are_rejected() {
    printf '%s' "$ALICE_SK" >"$TMP/sk"
    printf '%s' "${BOB_PK:0:62}" >"$TMP/short.pk"
    expect_fail "31-byte private key" "$BC_RUST" x25519 pk-from-sk < <(printf '%s' "${ALICE_SK:0:62}")
    assert_stderr_has "private key"
    expect_fail "31-byte public key" \
        "$BC_RUST" x25519 agree --skfile "$TMP/sk" --pkfile "$TMP/short.pk"
    assert_stderr_has "public key"
    expect_fail "31-byte ciphertext" \
        "$BC_RUST" x25519 decaps --skfile "$TMP/sk" --ctfile "$TMP/short.pk"
    assert_stderr_has "ciphertext"
}

test_missing_files_are_rejected() {
    printf '%s' "$ALICE_SK" >"$TMP/sk"
    expect_fail "agree without --pkfile" "$BC_RUST" x25519 agree <"$TMP/sk"
    assert_stderr_has "pkfile"
    expect_fail "check-consistency without --pkfile" "$BC_RUST" x25519 check-consistency <"$TMP/sk"
    assert_stderr_has "pkfile"
    expect_fail "decaps without --skfile" "$BC_RUST" x25519 decaps < <(printf '%s' "$ENC")
    assert_stderr_has "skfile"
}

run_all
