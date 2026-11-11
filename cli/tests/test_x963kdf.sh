#!/usr/bin/env bash
# The x963kdf-* subcommands against the NIST CAVP "ANS X9.63-2001" KDF component vectors
# (bc-test-data/crypto/cavp/ansx963_2001.rsp, COUNT = 0 of the named sections; every expected
# value is copied from that file), through hex and file inputs, with and without SharedInfo.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# [SHA-256] [shared secret length = 192] [SharedInfo length = 0] [key data length = 128]
test_x963kdf_sha256_no_shared_info_matches_cavp() {
    local got
    got=$(hex_out "$BC_RUST" x963kdf-sha256 --ikm 96c05619d56c328ab95fe84b18264b08725b85e33fd34f08 --len 16 -x)
    assert_eq "$got" "443024c3dae66b95e6f5670601558f71" "key_data"
}

# [SHA-256] [shared secret length = 192] [SharedInfo length = 128] [key data length = 1024]
test_x963kdf_sha256_with_shared_info_matches_cavp() {
    local got expected=c498af77161cc59f2962b9a713e2b215152d139766ce34a776df11866a69bf2e52a13d9c7c6fc878c50c5ea0bc7b00e0da2447cfd874f6cf92f30d0097111485500c90c3af8b487872d04685d14c8d1dc8d7fa08beb0ce0ababc11f0bd496269142d43525a78e5bc79a17f59676a5706dc54d54d4d1f0bd7e386128ec26afc21
    got=$(hex_out "$BC_RUST" x963kdf-sha256 --ikm 22518b10e70f2a3f243810ae3254139efbee04aa57c7af7d --additional-input 75eef81aa3041e33b80971203d2c0c52 --len 128 -x)
    assert_eq "$got" "$expected" "key_data (hex inputs)"
    unhex 22518b10e70f2a3f243810ae3254139efbee04aa57c7af7d >"$TMP/z"
    unhex 75eef81aa3041e33b80971203d2c0c52 >"$TMP/info"
    got=$(hex_out "$BC_RUST" x963kdf-sha256 --ikm-file "$TMP/z" --additional-input-file "$TMP/info" --len 128 -x)
    assert_eq "$got" "$expected" "key_data (file inputs)"
    "$BC_RUST" x963kdf-sha256 --ikm-file "$TMP/z" --additional-input-file "$TMP/info" --len 128 >"$TMP/out"
    assert_size "$TMP/out" 128 "binary output length"
    assert_eq "$(hex "$TMP/out")" "$expected" "key_data (binary output)"
}

# [SHA-384] [shared secret length = 192] [SharedInfo length = 128] [key data length = 1024]
test_x963kdf_sha384_matches_cavp() {
    local got
    got=$(hex_out "$BC_RUST" x963kdf-sha384 --ikm c051fd22539c9de791d6c43a854b8f80a6bf70190050854a --additional-input 1317504aa34759bb4c931e3b78201945 --len 128 -x)
    assert_eq "$got" "cf6a84434734ac6949e1d7976743277be789906908ad3ca3a8923da7f476abbeb574306d7243031a85566914bfd247d2519c479953d9d55b6b831e56260806c39af21b74e3ecf470e3bd8332791c8a23c13352514fdef00c2d1a408ba31b2d3f9fdcb373895484649a645d1845eec91b5bfdc5ad28c7824984482002dd4a8677" "key_data"
}

# [SHA-512] [shared secret length = 521] [SharedInfo length = 128] [key data length = 1024]
test_x963kdf_sha512_matches_cavp() {
    local got
    got=$(hex_out "$BC_RUST" x963kdf-sha512 --ikm 00aa5bb79b33e389fa58ceadc047197f14e73712f452caa9fc4c9adb369348b81507392f1a86ddfdb7c4ff8231c4bd0f44e44a1b55b1404747a9e2e753f55ef05a2d --additional-input e3b5b4c1b0d5cf1d2b3a2f9937895d31 --len 128 -x)
    assert_eq "$got" "4463f869f3cc18769b52264b0112b5858f7ad32a5a2d96d8cffabf7fa733633d6e4dd2a599acceb3ea54a6217ce0b50eef4f6b40a5c30250a5a8eeee208002267089dbf351f3f5022aa9638bf1ee419dea9c4ff745a25ac27bda33ca08bd56dd1a59b4106cf2dbbc0ab2aa8e2efa7b17902d34276951ceccab87f9661c3e8816" "key_data"
}

# The ECDH scheme of SEC 1 Section 6.1 by hand: Z from eccdh-p256 agree into x963kdf-sha256, the
# same key on both sides.
test_x963kdf_over_eccdh_z() {
    local za zb ka kb
    "$BC_RUST" eccdh-p256 keygen >"$TMP/a.sk"
    "$BC_RUST" eccdh-p256 pk-from-sk --skfile "$TMP/a.sk" >"$TMP/a.pk"
    "$BC_RUST" eccdh-p256 keygen >"$TMP/b.sk"
    "$BC_RUST" eccdh-p256 pk-from-sk --skfile "$TMP/b.sk" >"$TMP/b.pk"
    "$BC_RUST" eccdh-p256 agree --skfile "$TMP/a.sk" --pkfile "$TMP/b.pk" >"$TMP/z.a"
    "$BC_RUST" eccdh-p256 agree --skfile "$TMP/b.sk" --pkfile "$TMP/a.pk" >"$TMP/z.b"
    ka=$(hex_out "$BC_RUST" x963kdf-sha256 --ikm-file "$TMP/z.a" --additional-input 6b6579 --len 32 -x)
    kb=$(hex_out "$BC_RUST" x963kdf-sha256 --ikm-file "$TMP/z.b" --additional-input 6b6579 --len 32 -x)
    assert_eq "$kb" "$ka" "both sides derive the same key"
    [ "$ka" != "$(hex "$TMP/z.a")" ] || fail "the derived key is not Z"
}

test_x963kdf_refuses_an_oversized_len() {
    expect_fail "len above the command's bound is refused" "$BC_RUST" x963kdf-sha256 --ikm 0011 --len 16321
    assert_stderr_has "at most"
}

# An empty Z derives a key from nothing (the KDF trait allows it; no command-line user means
# it): refused before any derivation, inline and from a file.
test_x963kdf_refuses_an_empty_ikm() {
    expect_fail "an empty --ikm is refused" "$BC_RUST" x963kdf-sha256 --ikm "" --len 16
    assert_stderr_has "empty"
    : >"$TMP/empty"
    expect_fail "an empty --ikm-file is refused" "$BC_RUST" x963kdf-sha256 --ikm-file "$TMP/empty" --len 16
    assert_stderr_has "empty"
}

run_all
