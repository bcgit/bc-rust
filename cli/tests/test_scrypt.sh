#!/usr/bin/env bash
# The scrypt subcommand against RFC 7914 Section 12's second and third vectors (the first has
# an empty password, which the command refuses, and the fourth needs 1 GiB); the expected
# values are copied from the RFC. The password comes from stdin or a file and is used as the
# bytes it is, so the tests write it with printf, without a trailing newline.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# scrypt (P="password", S="NaCl", N=1024, r=8, p=16, dkLen=64)
test_scrypt_matches_rfc_7914_n_1024() {
    local got
    got=$(printf '%s' 'password' | hex_out "$BC_RUST" scrypt --log2-n 10 -r 8 -p 16 --salt 4e61436c --len 64 -x)
    assert_eq "$got" "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640" "password on stdin"
}

# scrypt (P="pleaseletmein", S="SodiumChloride", N=16384, r=8, p=1, dkLen=64); r and p are the
# defaults.
test_scrypt_matches_rfc_7914_n_16384() {
    local got
    printf '%s' 'pleaseletmein' >"$TMP/password"
    printf '%s' 'SodiumChloride' >"$TMP/salt"
    got=$(hex_out "$BC_RUST" scrypt -n 14 --password-file "$TMP/password" --salt-file "$TMP/salt" --len 64 -x)
    assert_eq "$got" "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887" "file inputs, default r and p"
    "$BC_RUST" scrypt -n 14 --password-file "$TMP/password" --salt-file "$TMP/salt" --len 64 >"$TMP/out"
    assert_size "$TMP/out" 64 "binary output length"
    assert_eq "$(hex "$TMP/out")" "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887" "binary output"
}

# The salt, each parameter and a trailing newline on the password each change the key.
test_scrypt_inputs_all_count() {
    local base other
    base=$(printf 'password' | hex_out "$BC_RUST" scrypt -n 4 -r 2 -p 2 --salt 73616c74 --len 32 -x)
    other=$(printf 'password' | hex_out "$BC_RUST" scrypt -n 4 -r 2 -p 2 --salt 73616c75 --len 32 -x)
    [ "$base" != "$other" ] || fail "the salt did not change the key"
    other=$(printf 'password' | hex_out "$BC_RUST" scrypt -n 5 -r 2 -p 2 --salt 73616c74 --len 32 -x)
    [ "$base" != "$other" ] || fail "N did not change the key"
    other=$(printf 'password' | hex_out "$BC_RUST" scrypt -n 4 -r 3 -p 2 --salt 73616c74 --len 32 -x)
    [ "$base" != "$other" ] || fail "r did not change the key"
    other=$(printf 'password' | hex_out "$BC_RUST" scrypt -n 4 -r 2 -p 3 --salt 73616c74 --len 32 -x)
    [ "$base" != "$other" ] || fail "p did not change the key"
    other=$(printf 'password\n' | hex_out "$BC_RUST" scrypt -n 4 -r 2 -p 2 --salt 73616c74 --len 32 -x)
    [ "$base" != "$other" ] || fail "a trailing newline is part of the password"
}

test_scrypt_refuses_bad_requests() {
    printf 'password' >"$TMP/password"
    : >"$TMP/empty"
    expect_fail "no salt" "$BC_RUST" scrypt -n 4 --password-file "$TMP/password" --len 16
    assert_stderr_has "salt"
    expect_fail "an empty password" "$BC_RUST" scrypt -n 4 --password-file "$TMP/empty" --salt 00 --len 16
    assert_stderr_has "empty"
    expect_fail "N = 1" "$BC_RUST" scrypt -n 0 --password-file "$TMP/password" --salt 00 --len 16
    assert_stderr_has "N must be larger than 1"
    expect_fail "N not below 2^(128 * r / 8)" "$BC_RUST" scrypt -n 16 -r 1 --password-file "$TMP/password" --salt 00 --len 16
    assert_stderr_has "N must be larger than 1"
    expect_fail "r = 0" "$BC_RUST" scrypt -n 4 -r 0 --password-file "$TMP/password" --salt 00 --len 16
    assert_stderr_has "r must be at least 1"
    expect_fail "p = 0" "$BC_RUST" scrypt -n 4 -p 0 --password-file "$TMP/password" --salt 00 --len 16
    assert_stderr_has "p must be at least 1"
    expect_fail "a zero length" "$BC_RUST" scrypt -n 4 --password-file "$TMP/password" --salt 00 --len 0
    assert_stderr_has "zero-length"
    expect_fail "more than the cap" "$BC_RUST" scrypt -n 4 --password-file "$TMP/password" --salt 00 --len 16321
    assert_stderr_has "at most"
    # N = 2^14 at r = 8 needs a little over 16 MiB.
    expect_fail "over --max-memory" "$BC_RUST" scrypt -n 14 --max-memory 16 --password-file "$TMP/password" --salt 00 --len 16
    assert_stderr_has "max-memory"
    expect_ok "within --max-memory" "$BC_RUST" scrypt -n 14 --max-memory 17 --password-file "$TMP/password" --salt 00 --len 16 -x >/dev/null
    # The default limit is 256 MiB: N = 2^18 at r = 8 needs a little over that.
    expect_fail "over the default limit" "$BC_RUST" scrypt -n 18 --password-file "$TMP/password" --salt 00 --len 16
    assert_stderr_has "max-memory"
}

run_all
