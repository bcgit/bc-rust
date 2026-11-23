#!/usr/bin/env bash
# The encaps and decaps actions of eccdh-p256, eccdh-p384 and eccdh-p521, end to end through the
# binary: DHKEM over the NIST curves (RFC 9180 Section 4.1).
#
# The known answers for P-256 and P-521 are RFC 9180's machine-readable vectors
# (bc-test-data/crypto/hpke.txt). RFC 9180 publishes none for P-384, so that one is a BC Java
# 1.84 cross-check, not a specification's answer. Hex keys and ciphertexts are read under
# --hex-input; without it they are raw bytes.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# bc-test-data/crypto/hpke.txt, kem_id = 16, count = 67 (the first with mode = 0).
P256_SK_RM=f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2
P256_ENC=04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4
P256_SHARED_SECRET=c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8

# BC Java 1.84, the first vector of crypto/ec/tests/eccdh_dhkem_p384_bc_java_tests.rs.
P384_SK_RM=98c0889aab5610522699abe5970b7b7132022094127060b928018fb3c0e2aaae9da72e0c9cf8f909d91c1e1e58f7454a
P384_ENC=047f2b47b78f647740f77394b77592b926821fde59d0d600abdea0d03c6ff68285f9615eaab384fc97f9eb64e7bc27c36a22c75955cebbd637b4970810fbfa33e90c150c6d1f6724d2e0563e3e5622bb0c1519757e6b9cfdec607d2037c6c18abe
P384_SHARED_SECRET=81e02447bd2be2d8d7174bd37f8429cc982e5a11c22e92fd43f6bf064596063640be3396e2a69c56604bad06fc28a4c3

# bc-test-data/crypto/hpke.txt, kem_id = 18, count = 96 (the first with mode = 0).
P521_SK_RM=009227b4b91cf1eb6eecb6c0c0bae93a272d24e11c63bd4c34a581c49f9c3ca01c16bbd32a0a1fac22784f2ae985c85f183baad103b2d02aee787179dfc1a94fea11
P521_ENC=0400bec215e31718cd2eff5ba61d55d062d723527ec2029d7679a9c867d5c68219c9b217a9d7f78562dc0af3242fef35d1d6f4a28ee75f0d4b31bc918937b559b70762004c4fd6ad7373db7e31da8735fbd6171bbdcfa770211420682c760a40a482cc24f4125edbea9cb31fe71d5d796cfe788dc408857697a52fef711fb921fa7c385218
P521_SHARED_SECRET=59501bad207bf432781371e7c9c26e908958301ad138a3332c6315e18215308dc13191d9c0258b88341569ce97dfb6e54f0a4ebf70d19166256c48343de6a9ff

# name:Nenc:Nsecret, in bytes (RFC 9180 Section 7.1, Table 2).
CURVES="p256:65:32 p384:97:48 p521:133:64"

# ---- known answers ------------------------------------------------------------------------

# `decaps_known_answer CURVE SK_RM ENC SHARED_SECRET WHAT`: enc on stdin, then from --ctfile.
decaps_known_answer() {
    local curve=$1 sk=$2 enc=$3 ss=$4 what=$5 got
    printf '%s' "$sk" >"$TMP/sk"
    got=$(hex_out "$BC_RUST" --hex-input "eccdh-$curve" decaps --skfile "$TMP/sk" -x < <(printf '%s' "$enc"))
    assert_eq "$got" "$ss" "$what shared_secret, enc on stdin"
    printf '%s' "$enc" >"$TMP/ct"
    got=$(hex_out "$BC_RUST" --hex-input "eccdh-$curve" decaps --skfile "$TMP/sk" --ctfile "$TMP/ct" -x)
    assert_eq "$got" "$ss" "$what shared_secret, enc from --ctfile"
}

test_decaps_p256_matches_rfc9180() {
    decaps_known_answer p256 "$P256_SK_RM" "$P256_ENC" "$P256_SHARED_SECRET" "RFC 9180 kem_id 16"
}

test_decaps_p384_matches_bc_java() {
    decaps_known_answer p384 "$P384_SK_RM" "$P384_ENC" "$P384_SHARED_SECRET" "BC Java 1.84 P-384"
}

test_decaps_p521_matches_rfc9180() {
    decaps_known_answer p521 "$P521_SK_RM" "$P521_ENC" "$P521_SHARED_SECRET" "RFC 9180 kem_id 18"
}

# ---- round trips --------------------------------------------------------------------------

test_encaps_decaps_round_trip_with_binary_files() {
    local curve name nenc nsecret
    for curve in $CURVES; do
        IFS=: read -r name nenc nsecret <<<"$curve"
        "$BC_RUST" "eccdh-$name" keygen >"$TMP/sk"
        "$BC_RUST" "eccdh-$name" pk-from-sk --skfile "$TMP/sk" >"$TMP/pk"
        "$BC_RUST" "eccdh-$name" encaps --pkfile "$TMP/pk" --ctfile "$TMP/ct" >"$TMP/ss1"
        "$BC_RUST" "eccdh-$name" decaps --skfile "$TMP/sk" --ctfile "$TMP/ct" >"$TMP/ss2"
        assert_size "$TMP/ct" "$nenc" "$name ciphertext"
        assert_size "$TMP/ss1" "$nsecret" "$name shared secret"
        assert_same "$TMP/ss1" "$TMP/ss2" "$name: decaps must recover the encapsulated secret"
    done
}

# Hex throughout: -x on the outputs, --hex-input on the files read back.
test_encaps_decaps_round_trip_with_hex_files() {
    local curve name nenc nsecret ss1 ss2
    for curve in $CURVES; do
        IFS=: read -r name nenc nsecret <<<"$curve"
        hex_out "$BC_RUST" "eccdh-$name" keygen -x >"$TMP/sk"
        hex_out "$BC_RUST" --hex-input "eccdh-$name" pk-from-sk --skfile "$TMP/sk" -x >"$TMP/pk"
        ss1=$(hex_out "$BC_RUST" --hex-input "eccdh-$name" encaps --pkfile "$TMP/pk" --ctfile "$TMP/ct" -x)
        assert_size "$TMP/ct" $((2 * nenc)) "$name hex ciphertext"
        assert_eq "${#ss1}" $((2 * nsecret)) "$name hex shared secret length"
        ss2=$(hex_out "$BC_RUST" --hex-input "eccdh-$name" decaps --skfile "$TMP/sk" --ctfile "$TMP/ct" -x)
        assert_eq "$ss2" "$ss1" "$name: decaps must recover the encapsulated secret"
    done
}

# Without --ctfile, encaps prints the ciphertext and then the shared secret, in hex, one per line.
test_encaps_to_stdout_round_trip() {
    local curve name nenc nsecret ct ss got
    for curve in $CURVES; do
        IFS=: read -r name nenc nsecret <<<"$curve"
        "$BC_RUST" "eccdh-$name" keygen >"$TMP/sk"
        "$BC_RUST" "eccdh-$name" pk-from-sk --skfile "$TMP/sk" | "$BC_RUST" "eccdh-$name" encaps >"$TMP/out"
        ct=$(sed -n 1p "$TMP/out")
        ss=$(sed -n 2p "$TMP/out")
        assert_eq "${#ct}" $((2 * nenc)) "$name hex ciphertext length"
        assert_eq "${#ss}" $((2 * nsecret)) "$name hex shared secret length"
        got=$(hex_out "$BC_RUST" "eccdh-$name" decaps --skfile "$TMP/sk" -x < <(unhex "$ct"))
        assert_eq "$got" "$ss" "$name: decaps must recover the encapsulated secret"
    done
}

test_encaps_is_randomized() {
    local curve name nenc nsecret
    for curve in $CURVES; do
        IFS=: read -r name nenc nsecret <<<"$curve"
        "$BC_RUST" "eccdh-$name" keygen | "$BC_RUST" "eccdh-$name" pk-from-sk >"$TMP/pk"
        "$BC_RUST" "eccdh-$name" encaps --pkfile "$TMP/pk" --ctfile "$TMP/ct1" >"$TMP/ss1"
        "$BC_RUST" "eccdh-$name" encaps --pkfile "$TMP/pk" --ctfile "$TMP/ct2" >"$TMP/ss2"
        assert_differs "$TMP/ct1" "$TMP/ct2" "$name: two encapsulations must give different ciphertexts"
        assert_differs "$TMP/ss1" "$TMP/ss2" "$name: two encapsulations must give different secrets"
    done
}

# ---- errors -------------------------------------------------------------------------------

test_wrong_length_ciphertext_is_rejected() {
    local curve name nenc nsecret
    for curve in $CURVES; do
        IFS=: read -r name nenc nsecret <<<"$curve"
        "$BC_RUST" "eccdh-$name" keygen >"$TMP/sk"
        "$BC_RUST" "eccdh-$name" pk-from-sk --skfile "$TMP/sk" >"$TMP/pk"
        "$BC_RUST" "eccdh-$name" encaps --pkfile "$TMP/pk" --ctfile "$TMP/ct" >/dev/null
        slice "$TMP/ct" 0 $((nenc - 1)) >"$TMP/short.ct"
        expect_fail "$name: ciphertext one byte short" \
            "$BC_RUST" "eccdh-$name" decaps --skfile "$TMP/sk" --ctfile "$TMP/short.ct"
        assert_stderr_has "ciphertext is not the correct length"
        cat "$TMP/ct" <(printf '\0') >"$TMP/long.ct"
        expect_fail "$name: ciphertext one byte long" \
            "$BC_RUST" "eccdh-$name" decaps --skfile "$TMP/sk" --ctfile "$TMP/long.ct"
        assert_stderr_has "ciphertext is not the correct length"
        # The length is checked before the private key is read.
        expect_fail "$name: short ciphertext and no such skfile" \
            "$BC_RUST" "eccdh-$name" decaps --skfile "$TMP/absent.sk" --ctfile "$TMP/short.ct"
        assert_stderr_has "ciphertext is not the correct length"
    done
}

# The ciphertext is a curve point; with its last byte changed it is no longer on the curve.
test_modified_ciphertext_is_rejected() {
    local curve name nenc nsecret
    for curve in $CURVES; do
        IFS=: read -r name nenc nsecret <<<"$curve"
        "$BC_RUST" "eccdh-$name" keygen >"$TMP/sk"
        "$BC_RUST" "eccdh-$name" pk-from-sk --skfile "$TMP/sk" >"$TMP/pk"
        "$BC_RUST" "eccdh-$name" encaps --pkfile "$TMP/pk" --ctfile "$TMP/ct" >/dev/null
        flip_byte "$TMP/ct" $((nenc - 1))
        expect_fail "$name: ciphertext with its last byte changed" \
            "$BC_RUST" "eccdh-$name" decaps --skfile "$TMP/sk" --ctfile "$TMP/ct"
        assert_stderr_has "decapsulation failed"
    done
}

test_bad_keys_and_missing_files_are_rejected() {
    printf '%s' "$P256_SK_RM" >"$TMP/sk"
    expect_fail "decaps without --skfile" "$BC_RUST" --hex-input eccdh-p256 decaps < <(printf '%s' "$P256_ENC")
    assert_stderr_has "skfile"
    printf '%s' "${P256_SK_RM:0:62}" >"$TMP/short.sk"
    expect_fail "31-byte private key" \
        "$BC_RUST" --hex-input eccdh-p256 decaps --skfile "$TMP/short.sk" < <(printf '%s' "$P256_ENC")
    assert_stderr_has "private key"
    expect_fail "encaps to a point off the curve" \
        "$BC_RUST" --hex-input eccdh-p256 encaps < <(flip_hex "$P256_ENC" 64 1)
    assert_stderr_has "public key"
}

# RFC 9180 defines no DHKEM over the other four curves.
test_curves_without_dhkem_refuse() {
    local name
    for name in secp256k1 bp256r1 bp384r1 bp512r1; do
        "$BC_RUST" "eccdh-$name" keygen >"$TMP/sk"
        "$BC_RUST" "eccdh-$name" pk-from-sk --skfile "$TMP/sk" >"$TMP/pk"
        expect_fail "$name encaps" "$BC_RUST" "eccdh-$name" encaps --pkfile "$TMP/pk"
        assert_stderr_has "has no DHKEM"
        expect_fail "$name decaps" "$BC_RUST" "eccdh-$name" decaps --skfile "$TMP/sk" <"$TMP/pk"
        assert_stderr_has "has no DHKEM"
    done
}

run_all
