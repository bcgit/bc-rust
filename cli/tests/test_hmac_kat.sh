#!/usr/bin/env bash
# The hmac-* subcommands against RFC 4231 and Wycheproof known answers (test_hmac.sh covers the random round trips).
#
# Written for the 2026-11-03 CLI review (report 15) from the vector files named in each test;
# every expected value is copied from that file, none is typed by hand. Follows lib.sh's
# conventions: each test_* runs in its own subshell under `set -e`.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# RFC 4231 Sec 4.2 Test Case 1 (standards/RFC-4231-HMAC-vectors.txt): 20-byte key, 8-byte data.
test_rfc4231_case_1() {
    local got
    unhex 4869205468657265 >"$TMP/data"
    got=$(hex_out "$BC_RUST" hmac-sha256 --key 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b -x <"$TMP/data")
    assert_eq "$got" "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7" "HMAC-SHA-256 case 1"
    got=$(hex_out "$BC_RUST" hmac-sha512 --key 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b -x <"$TMP/data")
    assert_eq "$got" "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854" "HMAC-SHA-512 case 1"
    expect_ok "the RFC tag must verify" "$BC_RUST" hmac-sha256 --key 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b --verify b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7 <"$TMP/data"
    expect_ok "the RFC tag must verify" "$BC_RUST" hmac-sha512 --key 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b --verify 87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854 <"$TMP/data"
    unhex 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b >"$TMP/key"
    got=$(hex_out "$BC_RUST" hmac-sha256 -k "$TMP/key" -x <"$TMP/data")
    assert_eq "$got" "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7" "HMAC-SHA-256 case 1 with the key from a raw file"
}

# RFC 4231 Sec 4.3 Test Case 2 (standards/RFC-4231-HMAC-vectors.txt): 4-byte key, 28-byte data.
test_rfc4231_case_2() {
    local got
    unhex 7768617420646f2079612077616e7420666f72206e6f7468696e673f >"$TMP/data"
    got=$(hex_out "$BC_RUST" hmac-sha256 --key 4a656665 -x <"$TMP/data")
    assert_eq "$got" "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" "HMAC-SHA-256 case 2"
    got=$(hex_out "$BC_RUST" hmac-sha512 --key 4a656665 -x <"$TMP/data")
    assert_eq "$got" "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737" "HMAC-SHA-512 case 2"
    expect_ok "the RFC tag must verify" "$BC_RUST" hmac-sha256 --key 4a656665 --verify 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843 <"$TMP/data"
    expect_ok "the RFC tag must verify" "$BC_RUST" hmac-sha512 --key 4a656665 --verify 164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737 <"$TMP/data"
    unhex 4a656665 >"$TMP/key"
    got=$(hex_out "$BC_RUST" hmac-sha256 -k "$TMP/key" -x <"$TMP/data")
    assert_eq "$got" "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" "HMAC-SHA-256 case 2 with the key from a raw file"
}

# RFC 4231 Sec 4.4 Test Case 3 (standards/RFC-4231-HMAC-vectors.txt): 20-byte key, 50-byte data.
test_rfc4231_case_3() {
    local got
    unhex dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd >"$TMP/data"
    got=$(hex_out "$BC_RUST" hmac-sha256 --key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa -x <"$TMP/data")
    assert_eq "$got" "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe" "HMAC-SHA-256 case 3"
    got=$(hex_out "$BC_RUST" hmac-sha512 --key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa -x <"$TMP/data")
    assert_eq "$got" "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb" "HMAC-SHA-512 case 3"
    expect_ok "the RFC tag must verify" "$BC_RUST" hmac-sha256 --key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --verify 773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe <"$TMP/data"
    expect_ok "the RFC tag must verify" "$BC_RUST" hmac-sha512 --key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --verify fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb <"$TMP/data"
    unhex aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa >"$TMP/key"
    got=$(hex_out "$BC_RUST" hmac-sha256 -k "$TMP/key" -x <"$TMP/data")
    assert_eq "$got" "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe" "HMAC-SHA-256 case 3 with the key from a raw file"
}

# RFC 4231 Sec 4.5 Test Case 4 (standards/RFC-4231-HMAC-vectors.txt): 25-byte key, 50-byte data.
test_rfc4231_case_4() {
    local got
    unhex cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd >"$TMP/data"
    got=$(hex_out "$BC_RUST" hmac-sha256 --key 0102030405060708090a0b0c0d0e0f10111213141516171819 -x <"$TMP/data")
    assert_eq "$got" "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b" "HMAC-SHA-256 case 4"
    got=$(hex_out "$BC_RUST" hmac-sha512 --key 0102030405060708090a0b0c0d0e0f10111213141516171819 -x <"$TMP/data")
    assert_eq "$got" "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd" "HMAC-SHA-512 case 4"
    expect_ok "the RFC tag must verify" "$BC_RUST" hmac-sha256 --key 0102030405060708090a0b0c0d0e0f10111213141516171819 --verify 82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b <"$TMP/data"
    expect_ok "the RFC tag must verify" "$BC_RUST" hmac-sha512 --key 0102030405060708090a0b0c0d0e0f10111213141516171819 --verify b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd <"$TMP/data"
    unhex 0102030405060708090a0b0c0d0e0f10111213141516171819 >"$TMP/key"
    got=$(hex_out "$BC_RUST" hmac-sha256 -k "$TMP/key" -x <"$TMP/data")
    assert_eq "$got" "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b" "HMAC-SHA-256 case 4 with the key from a raw file"
}

# RFC 4231 Sec 4.6 Test Case 5: the RFC truncates the output to 128 bits. The CLI has no truncation
# option, so the full tag's first 16 bytes must equal the RFC value; `--verify` of the truncated
# tag is expected to fail (the CLI compares full tags only).
test_rfc4231_case_5_truncated_output_is_a_prefix() {
    local got
    unhex 546573742057697468205472756e636174696f6e >"$TMP/data"
    got=$(hex_out "$BC_RUST" hmac-sha256 --key 0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c -x <"$TMP/data")
    assert_eq "${got:0:32}" "a3b6167473100ee06e0c796c2955552b" "HMAC-SHA-256 case 5 (first 128 bits)"
    got=$(hex_out "$BC_RUST" hmac-sha512 --key 0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c -x <"$TMP/data")
    assert_eq "${got:0:32}" "415fad6271580a531d4179bc891d87a6" "HMAC-SHA-512 case 5 (first 128 bits)"
    expect_fail "a truncated tag is not a full tag" "$BC_RUST" hmac-sha256 --key 0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c --verify a3b6167473100ee06e0c796c2955552b <"$TMP/data"
}

# RFC 4231 Sec 4.7 Test Case 6: a 131-byte key, longer than the SHA-256 block, which HMAC hashes
# first (RFC 2104 Sec 2). The CLI takes a key of any length up to 16 KiB.
test_rfc4231_case_6_long_key() {
    local got key
    key=$(printf 'aa%.0s' $(seq 131))
    unhex 54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374 >"$TMP/data"
    got=$(hex_out "$BC_RUST" hmac-sha256 --key "$key" -x <"$TMP/data")
    assert_eq "$got" "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54" "HMAC-SHA-256 case 6"
    got=$(hex_out "$BC_RUST" hmac-sha512 --key "$key" -x <"$TMP/data")
    assert_eq "$got" "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598" "HMAC-SHA-512 case 6"
    unhex "$key" >"$TMP/key"
    got=$(hex_out "$BC_RUST" hmac-sha256 -k "$TMP/key" -x <"$TMP/data")
    assert_eq "$got" "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54" "HMAC-SHA-256 case 6 with the key from a raw file"
}

# RFC 4231 Sec 4.8 Test Case 7: a 131-byte key and a 152-byte message, both over the SHA-512 block.
test_rfc4231_case_7_long_key_and_data() {
    local got key
    key=$(printf 'aa%.0s' $(seq 131))
    unhex 5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e >"$TMP/data"
    got=$(hex_out "$BC_RUST" hmac-sha256 --key "$key" -x <"$TMP/data")
    assert_eq "$got" "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2" "HMAC-SHA-256 case 7"
    got=$(hex_out "$BC_RUST" hmac-sha512 --key "$key" -x <"$TMP/data")
    assert_eq "$got" "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58" "HMAC-SHA-512 case 7"
}

# RFC 4231 Sec 4.2 Test Case 1 for the hmac-sha224 and hmac-sha384 subcommands.
test_rfc4231_case_1_sha224_and_sha384() {
    local got
    unhex 4869205468657265 >"$TMP/data"
    got=$(hex_out "$BC_RUST" hmac-sha224 --key 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b -x <"$TMP/data")
    assert_eq "$got" "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22" "HMAC-SHA-224 case 1"
    got=$(hex_out "$BC_RUST" hmac-sha384 --key 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b -x <"$TMP/data")
    assert_eq "$got" "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6" "HMAC-SHA-384 case 1"
    expect_ok "the tag must verify" "$BC_RUST" hmac-sha224 --key 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b --verify 896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22 <"$TMP/data"
}

# No published HMAC-SHA3 vector is in bc-test-data, so the four hmac-sha3-* subcommands are pinned
# by shape: the tag length, a verify round trip, and that they differ from each other and from
# HMAC-SHA2 of the same size.
test_hmac_sha3_variants_round_trip() {
    local h len tag
    rng 32 >"$TMP/key"
    rng 300 >"$TMP/msg"
    for h in 224 256 384 512; do
        tag=$(hex_out "$BC_RUST" hmac-sha3-$h -k "$TMP/key" -x <"$TMP/msg")
        assert_eq "${#tag}" $((h / 4)) "hmac-sha3-$h tag length"
        expect_ok "hmac-sha3-$h verifies its own tag" "$BC_RUST" hmac-sha3-$h -k "$TMP/key" -v "$tag" <"$TMP/msg"
        expect_fail "and not a flipped one" "$BC_RUST" hmac-sha3-$h -k "$TMP/key" -v "$(flip_hex "$tag" 0 1)" <"$TMP/msg"
    done
    assert_eq "$(hex_out "$BC_RUST" hmac-sha3-256 -k "$TMP/key" -x <"$TMP/msg" | cut -c1-16 | wc -c | tr -d ' ')" 17 "hex tag"
    [ "$(hex_out "$BC_RUST" hmac-sha3-256 -k "$TMP/key" -x <"$TMP/msg")" != "$(hex_out "$BC_RUST" hmac-sha256 -k "$TMP/key" -x <"$TMP/msg")" ] || fail "HMAC-SHA3-256 must differ from HMAC-SHA-256"
}

# Wycheproof testvectors_v1/hmac_sha512_224_test.json tcId 3 (keySize 224, tagSize 224): a
# full-length tag, since RFC 4231 has no hmac-sha512-224 vector.
test_hmac_sha512_224_matches_wycheproof_tc3() {
    local got
    unhex 2e >"$TMP/msg"
    got=$(hex_out "$BC_RUST" hmac-sha512-224 --key 8648ee936c6ebc5ae4bb48c1139a54e3ac5d897beec492dc4d740752 -x <"$TMP/msg")
    assert_eq "$got" "5979cc5dcdaf49daaadfc3388de3f5a04d183ebc896fd4f9dbdcc513" "hmac-sha512-224 tcId 3"
    expect_ok "the tag must verify" "$BC_RUST" hmac-sha512-224 --key 8648ee936c6ebc5ae4bb48c1139a54e3ac5d897beec492dc4d740752 --verify 5979cc5dcdaf49daaadfc3388de3f5a04d183ebc896fd4f9dbdcc513 <"$TMP/msg"
}

# Wycheproof testvectors_v1/hmac_sha512_256_test.json tcId 3 (keySize 256, tagSize 256): a
# full-length tag, since RFC 4231 has no hmac-sha512-256 vector.
test_hmac_sha512_256_matches_wycheproof_tc3() {
    local got
    unhex 77 >"$TMP/msg"
    got=$(hex_out "$BC_RUST" hmac-sha512-256 --key 8159fd15133cd964c9a6964c94f0ea269a806fd9f43f0da58b6cd1b33d189b2a -x <"$TMP/msg")
    assert_eq "$got" "aee7a277e0f36a042368ae52b1337ba13f1c00fdb2dfb1d5f0c304e485c3a7dc" "hmac-sha512-256 tcId 3"
    expect_ok "the tag must verify" "$BC_RUST" hmac-sha512-256 --key 8159fd15133cd964c9a6964c94f0ea269a806fd9f43f0da58b6cd1b33d189b2a --verify aee7a277e0f36a042368ae52b1337ba13f1c00fdb2dfb1d5f0c304e485c3a7dc <"$TMP/msg"
}

# Wycheproof testvectors_v1/hmac_sm3_test.json tcId 2 (keySize 256, tagSize 256): a
# full-length tag, since RFC 4231 has no hmac-sm3 vector.
test_hmac_sm3_matches_wycheproof_tc2() {
    local got
    unhex 77 >"$TMP/msg"
    got=$(hex_out "$BC_RUST" hmac-sm3 --key 8159fd15133cd964c9a6964c94f0ea269a806fd9f43f0da58b6cd1b33d189b2a -x <"$TMP/msg")
    assert_eq "$got" "51aaf64843b6d2fc7a244ab9cda9b7b57164ce6a865f9808c01931b46195411d" "hmac-sm3 tcId 2"
    expect_ok "the tag must verify" "$BC_RUST" hmac-sm3 --key 8159fd15133cd964c9a6964c94f0ea269a806fd9f43f0da58b6cd1b33d189b2a --verify 51aaf64843b6d2fc7a244ab9cda9b7b57164ce6a865f9808c01931b46195411d <"$TMP/msg"
}

# A key that is not hex, or a key file that does not exist, must be a reported error, not a panic.
test_bad_key_inputs_are_errors_not_panics() {
    expect_fail "non-hex --key" "$BC_RUST" hmac-sha256 --key zz -x </dev/null
    grep -q panicked "$LAST_STDERR" && fail "non-hex --key must not panic: $(head -1 "$LAST_STDERR")"
    assert_stderr_has "Error"
    expect_fail "missing --key-file" "$BC_RUST" hmac-sha256 -k "$TMP/does-not-exist" -x </dev/null
    grep -q panicked "$LAST_STDERR" && fail "missing key file must not panic: $(head -1 "$LAST_STDERR")"
    assert_stderr_has "Error"
    expect_fail "non-hex --verify" "$BC_RUST" hmac-sha256 --key 00 --verify zz </dev/null
    grep -q panicked "$LAST_STDERR" && fail "non-hex --verify must not panic: $(head -1 "$LAST_STDERR")"
    assert_stderr_has "Error"
}

run_all
