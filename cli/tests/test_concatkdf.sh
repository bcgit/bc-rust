#!/usr/bin/env bash
# The concatkdf-* subcommands against the NIST ACVP "KDA OneStep SP800-56Cr2" sample vectors
# (bc-test-data/crypto/acvp/KDA-OneStep-Sp800-56Cr2; every expected value is copied from
# expectedResults.json), through hex and file inputs. FixedInfo is the vector's
# t || uPartyInfo || vPartyInfo || l, l = 1024 bits as 32 big-endian bits.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# SHA2-512, tcId 126
test_concatkdf_sha512_matches_acvp() {
    local got z info expected=1e4b837e62ed9851e986b6dcebd0435fc693ffa72f630956ef6ca11d6c7e9dc1f430560f99e993864d4cc90d6dbe3aeb34a40867dbb65d8c5f093e9860f73a6babbd3ff103e655bccb744123465255a232331f5b726f2362667222572f081a6ad521f2d96b1fa5ecf1c056372795ad386c0b9129d77475538ffb3671ab2169ad
    z=bfbfc3865a3656e9e88dbfc173c00a022b3f662d22b34c6f935552f50f79a4c8343d72bbe1781352c40a08f822824165fd400c14da0efa317ba4fe6e891bf3f086e143b52607433853403c1de5c81491c3dc10036a2aaa78f298c325b067930027edc0361405420e43763e8487edc93fc9aed5
    info=1d1c1ade471858bb681687ae92c4c30aec97e754abb2efec130831927011dabd8cac0dfa1b9f2691160872c9b1b1de4c00000400
    got=$(hex_out "$BC_RUST" concatkdf-sha512 --ikm "$z" --additional-input "$info" --len 128 -x)
    assert_eq "$got" "$expected" "dkm (hex inputs)"
    unhex "$z" >"$TMP/z"
    unhex "$info" >"$TMP/info"
    got=$(hex_out "$BC_RUST" concatkdf-sha512 --ikm-file "$TMP/z" --additional-input-file "$TMP/info" --len 128 -x)
    assert_eq "$got" "$expected" "dkm (file inputs)"
    "$BC_RUST" concatkdf-sha512 --ikm-file "$TMP/z" --additional-input-file "$TMP/info" --len 128 >"$TMP/out"
    assert_size "$TMP/out" 128 "binary output length"
    assert_eq "$(hex "$TMP/out")" "$expected" "dkm (binary output)"
}

# SHA3-512, tcId 201
test_concatkdf_sha3_512_matches_acvp() {
    local got
    got=$(hex_out "$BC_RUST" concatkdf-sha3-512 \
        --ikm dd4deb6618b41a1f8effa81393b4c1bf3ee452cbed68d407f2fc227e7dd4b2949c35d41548a59e90d89415bc8a5c17e10a6fe33b1d3ed2b163340cb745f3b4a3bc336fab95cb2e211f6f09c01a373cfeb3677131776ec70be06ae077c7be00e2542ff4c75acb497ba15baae449b31b43abd37545d608d3b0fac976 \
        --additional-input df47cf7dc9545373357be8d128ad473a3e0ca6ace8826a1abf8bf20f8988a19d861c8be46d635d45b3eb89a1205489676fe01278914a3b87ff4a55d8813db214c587f52abfa2e60616e6871084d3da47d10051d4ac52b059d1b0663ad638d391daa5c6fe012b23c1b5bfca42a30d3865842c1155cf8dba8c86f755e3639cc6e0282b1ebc385f74e255206166de36512794c9d69d18fbbcf962ff5e760d79e11625a878f435cd2e5ac92a5000000400 \
        --len 128 -x)
    assert_eq "$got" "b0929368505833505374586a7912add0e85c97912e59727370ee4b4d6ff5da4a82798da67f7c35dadb47834b9442576c7faec268885f1adbb13fe3f8d9c07028a5e9d3f60cee9914e8f0012a0b42dab3ffd2eb37a66f33a89c45b494c58c52a85fe12c14991d83803801cfcc21d5ca951ab6f03111cd4775b050e655e8b0768e" "dkm"
}

# The other four variants against SP 800-56C Rev. 2 Section 4.1 computed in Python with
# hashlib (counter || Z || FixedInfo per block, counter from 1, leftmost L bytes): Z = 32 bytes
# 00112233..eeff twice, FixedInfo a1b2c3d4e5f6, L past one hash output so the counter runs.
# The ACVP sample has no group for these four hashes.
test_concatkdf_other_variants_match_hashlib() {
    local z=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff info=a1b2c3d4e5f6 got
    got=$(hex_out "$BC_RUST" concatkdf-sha256 --ikm "$z" --additional-input "$info" --len 48 -x)
    assert_eq "$got" "bc406a73a8ea56a4b6f9a5962a691e2ed2419740ac8c374ee50596cc7fc34ca32dda1ed0e381636a21e1937358ec5975" "concatkdf-sha256"
    got=$(hex_out "$BC_RUST" concatkdf-sha384 --ikm "$z" --additional-input "$info" --len 64 -x)
    assert_eq "$got" "c26778863377d1eae1881d5b2dca36490163b9fe3c86e805f48008ea50514538cf3b83e26151218850d5e983e27991f223f582bc4ce4762d69ad622e22490d21" "concatkdf-sha384"
    got=$(hex_out "$BC_RUST" concatkdf-sha3-256 --ikm "$z" --additional-input "$info" --len 48 -x)
    assert_eq "$got" "188a1406f70f3555c082c134662a5222641ad08b834daa429a672dbf986b1b13749eea21e2a0c83349a461e97c70ed62" "concatkdf-sha3-256"
    got=$(hex_out "$BC_RUST" concatkdf-sha3-384 --ikm "$z" --additional-input "$info" --len 64 -x)
    assert_eq "$got" "2b1fe0d17f85e7502f86bb80ba8ab3f12bd7bd0862531f7c3b93fb25ca1f347f140257b062c01accf6f7a18fe97ebaf4151b54929750ec0b65426f62b5a4a8d7" "concatkdf-sha3-384"
}

# The other four variants each select their own hash: no two agree on one input.
test_concatkdf_variants_differ() {
    local a b c d
    a=$(hex_out "$BC_RUST" concatkdf-sha256 --ikm 00112233445566778899aabbccddeeff --len 32 -x)
    b=$(hex_out "$BC_RUST" concatkdf-sha384 --ikm 00112233445566778899aabbccddeeff --len 32 -x)
    c=$(hex_out "$BC_RUST" concatkdf-sha3-256 --ikm 00112233445566778899aabbccddeeff --len 32 -x)
    d=$(hex_out "$BC_RUST" concatkdf-sha3-384 --ikm 00112233445566778899aabbccddeeff --len 32 -x)
    [ "$a" != "$b" ] && [ "$a" != "$c" ] && [ "$a" != "$d" ] && [ "$b" != "$c" ] && [ "$b" != "$d" ] \
        && [ "$c" != "$d" ] || fail "two variants derived the same key"
    assert_eq "${#a}" 64 "32 bytes of hex"
}

# SP 800-56A's key agreement with the one-step KDF by hand: Z from eccdh-p256 agree into
# concatkdf-sha256, the same key on both sides.
test_concatkdf_over_eccdh_z() {
    local ka kb
    "$BC_RUST" eccdh-p256 keygen >"$TMP/a.sk"
    "$BC_RUST" eccdh-p256 pk-from-sk --skfile "$TMP/a.sk" >"$TMP/a.pk"
    "$BC_RUST" eccdh-p256 keygen >"$TMP/b.sk"
    "$BC_RUST" eccdh-p256 pk-from-sk --skfile "$TMP/b.sk" >"$TMP/b.pk"
    "$BC_RUST" eccdh-p256 agree --skfile "$TMP/a.sk" --pkfile "$TMP/b.pk" >"$TMP/z.a"
    "$BC_RUST" eccdh-p256 agree --skfile "$TMP/b.sk" --pkfile "$TMP/a.pk" >"$TMP/z.b"
    ka=$(hex_out "$BC_RUST" concatkdf-sha256 --ikm-file "$TMP/z.a" --additional-input 6b6579 --len 32 -x)
    kb=$(hex_out "$BC_RUST" concatkdf-sha256 --ikm-file "$TMP/z.b" --additional-input 6b6579 --len 32 -x)
    assert_eq "$kb" "$ka" "both sides derive the same key"
    [ "$ka" != "$(hex "$TMP/z.a")" ] || fail "the derived key is not Z"
}

test_concatkdf_refuses_an_oversized_len() {
    expect_fail "len above the command's bound is refused" "$BC_RUST" concatkdf-sha256 --ikm 0011 --len 16321
    assert_stderr_has "at most"
}

run_all
