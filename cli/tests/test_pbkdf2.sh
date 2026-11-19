#!/usr/bin/env bash
# The pbkdf2 subcommand against RFC 7914 Section 11's PBKDF2-HMAC-SHA-256 vectors, Wycheproof's
# pbkdf2_hmacsha384 and pbkdf2_hmacsha512 files and the NIST ACVP "PBKDF 1.0" sample vectors
# (bc-test-data/crypto/acvp/PBKDF-1.0); every expected value is copied from its source. The
# password comes from stdin or a file and is used as the bytes it is, so the tests write it
# with printf, without a trailing newline.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# RFC 7914 Section 11, both vectors: P="passwd", S="salt", c=1 and P="Password", S="NaCl", c=80000,
# dkLen=64.
test_pbkdf2_hmac_sha256_matches_rfc_7914() {
    local got
    got=$(printf '%s' 'passwd' | hex_out "$BC_RUST" pbkdf2 --prf hmac-sha256 --salt 73616c74 -c 1 --len 64 -x)
    assert_eq "$got" "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783" "c = 1 (password on stdin)"
    printf '%s' 'Password' >"$TMP/password"
    printf '%s' 'NaCl' >"$TMP/salt"
    got=$(hex_out "$BC_RUST" pbkdf2 --prf hmac-sha256 --password-file "$TMP/password" --salt-file "$TMP/salt" --iterations 80000 --len 64 -x)
    assert_eq "$got" "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d" "c = 80000 (file inputs)"
    "$BC_RUST" pbkdf2 --prf hmac-sha256 --password-file "$TMP/password" --salt-file "$TMP/salt" -c 80000 --len 64 >"$TMP/out"
    assert_size "$TMP/out" 64 "binary output length"
    assert_eq "$(hex "$TMP/out")" "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d" "c = 80000 (binary output)"
}

# Wycheproof pbkdf2_hmacsha512_test.json tcId 3 and pbkdf2_hmacsha384_test.json tcId 1; the
# password is given in hex in the files, so it goes in through --hex-input.
test_pbkdf2_matches_wycheproof() {
    local got
    printf '%s' '7439315572766f47' >"$TMP/password.hex"
    got=$(hex_out "$BC_RUST" --hex-input pbkdf2 --prf hmac-sha512 --password-file "$TMP/password.hex" --salt 5d76db9ca0f0bae2 -c 4096 --len 65 -x)
    assert_eq "$got" "a5d7f0fe4adc54e2ac5edc54e005827a90cbd46c00b72be68f8fbd1da98c079b98622a69b1ea44c0d94cdae03c339b742d047ac63cac0d9af59786baee4a158080" "hmac-sha512"
    printf '%s' '7130577430643470' >"$TMP/password.hex"
    got=$(hex_out "$BC_RUST" --hex-input pbkdf2 --prf hmac-sha384 --password-file "$TMP/password.hex" --salt 798acc7c76739d75 -c 4096 --len 16 -x)
    assert_eq "$got" "c5a4f853b1a3960134e572c8e29a5be9" "hmac-sha384"
}

# ACVP PBKDF-1.0 tcId 20 (HMAC-SHA2-224); the password is text in the file.
test_pbkdf2_hmac_sha224_matches_acvp() {
    local got
    got=$(printf '%s' 'ggfktIvCVnTOrMgWJABpxykBlfxddOhIZHsUsbHgZlnA' | hex_out "$BC_RUST" pbkdf2 --prf hmac-sha224 --salt b9e382cb4d5486c2a8210ef70c120fa6898c11d007e0e39ba529c9dce4bb78b4159cc6f6819fad0d2f66da51be8ce9544763c1845fe19a80da046bfb62b528 -c 1 --len 179 -x)
    assert_eq "$got" "4ae376cacd42688e17d2221641ca255d109e803d5adf8a1c7f6811f2862f2429332c3235c5e6b44446b1321041dfef0e4ea40c196d32af2f60b8fd4d6c5d0e35d5ddaae4fff40f16f34328318f29a8d558a19497779dd10e9ba6d3610ac84a0ddf4af6ba0ef7a4aabc73c598bb72f41122a62f1a4fc211adba39f08b1734745c5c9e9aabd9211d477c0dbcb73e814a012bad508b2966f5506241cae08656603c279c2f982ee55243ce30874ba4d4918911be12" "derived key"
}

# The SHA-3 HMACs have no vector file here; each PRF selects its own hash, so no two agree.
test_pbkdf2_prfs_differ() {
    local prf got seen=""
    for prf in hmac-sha224 hmac-sha256 hmac-sha384 hmac-sha512 hmac-sha3-224 hmac-sha3-256 hmac-sha3-384 hmac-sha3-512; do
        got=$(printf 'password' | hex_out "$BC_RUST" pbkdf2 --prf "$prf" --salt 73616c74 -c 2 --len 20 -x)
        assert_eq "${#got}" 40 "$prf: 20 bytes of hex"
        case " $seen " in *" $got "*) fail "$prf derived the same key as another PRF" ;; esac
        seen="$seen $got"
    done
}

# The salt, the count and a trailing newline on the password each change the key.
test_pbkdf2_inputs_all_count() {
    local base other
    base=$(printf 'password' | hex_out "$BC_RUST" pbkdf2 --prf hmac-sha256 --salt 73616c74 -c 2 --len 32 -x)
    other=$(printf 'password' | hex_out "$BC_RUST" pbkdf2 --prf hmac-sha256 --salt 73616c75 -c 2 --len 32 -x)
    [ "$base" != "$other" ] || fail "the salt did not change the key"
    other=$(printf 'password' | hex_out "$BC_RUST" pbkdf2 --prf hmac-sha256 --salt 73616c74 -c 3 --len 32 -x)
    [ "$base" != "$other" ] || fail "the iteration count did not change the key"
    other=$(printf 'password\n' | hex_out "$BC_RUST" pbkdf2 --prf hmac-sha256 --salt 73616c74 -c 2 --len 32 -x)
    [ "$base" != "$other" ] || fail "a trailing newline is part of the password"
}

test_pbkdf2_refuses_bad_requests() {
    printf 'password' >"$TMP/password"
    : >"$TMP/empty"
    expect_fail "no salt" "$BC_RUST" pbkdf2 --prf hmac-sha256 --password-file "$TMP/password" -c 2 --len 16
    assert_stderr_has "salt"
    expect_fail "an empty password" "$BC_RUST" pbkdf2 --prf hmac-sha256 --password-file "$TMP/empty" --salt 00 -c 2 --len 16
    assert_stderr_has "empty"
    expect_fail "a zero iteration count" "$BC_RUST" pbkdf2 --prf hmac-sha256 --password-file "$TMP/password" --salt 00 -c 0 --len 16
    assert_stderr_has "invalid value '0'"
    expect_fail "a zero length" "$BC_RUST" pbkdf2 --prf hmac-sha256 --password-file "$TMP/password" --salt 00 -c 2 --len 0
    assert_stderr_has "zero-length"
    expect_fail "more than the cap" "$BC_RUST" pbkdf2 --prf hmac-sha256 --password-file "$TMP/password" --salt 00 -c 1 --len 16321
    assert_stderr_has "at most"
    expect_fail "an unknown PRF" "$BC_RUST" pbkdf2 --prf hmac-md5 --password-file "$TMP/password" --salt 00 -c 2 --len 16
    assert_stderr_has "invalid value 'hmac-md5'"
    expect_fail "no PRF" "$BC_RUST" pbkdf2 --password-file "$TMP/password" --salt 00 -c 2 --len 16
    assert_stderr_has "required arguments were not provided"
    assert_stderr_has "--prf <PRF>"
    expect_ok "the cap itself" "$BC_RUST" pbkdf2 --prf hmac-sha256 --password-file "$TMP/password" --salt 00 -c 1 --len 16320 -x >/dev/null
}

run_all
