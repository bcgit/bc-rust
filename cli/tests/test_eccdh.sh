#!/usr/bin/env bash
# The eccdh-* subcommands: the NIST CAVP ECC CDH primitive known answers for P-256 and P-521
# (bc-test-data/crypto/cavp/KAS_ECC_CDH_PrimitiveTest.txt, COUNT = 0 of each section; every
# expected value is copied from that file), key-pair round trips on all seven curves, the
# consistency check, an off-curve peer key refused, and Z into hkdf-sha256. Follows lib.sh's
# conventions: each test_* runs in its own subshell under `set -e`.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# [P-256] COUNT = 0: dIUT, QIUT (04 || x || y), QCAVS and ZIUT.
test_eccdh_p256_matches_cavp() {
    local got
    unhex 7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534 >"$TMP/sk"
    unhex 04ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b23028af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141 >"$TMP/own"
    unhex 04700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac >"$TMP/peer"
    got=$(hex_out "$BC_RUST" eccdh-p256 pk-from-sk -x <"$TMP/sk")
    assert_eq "$got" "04ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b23028af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141" "QIUT from dIUT"
    expect_ok "dIUT and QIUT must be consistent" "$BC_RUST" eccdh-p256 check-consistency --skfile "$TMP/sk" --pkfile "$TMP/own" >/dev/null
    got=$(hex_out "$BC_RUST" eccdh-p256 agree --skfile "$TMP/sk" --pkfile "$TMP/peer" -x)
    assert_eq "$got" "46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b" "ZIUT (sk from --skfile)"
    got=$(hex_out "$BC_RUST" eccdh-p256 agree --pkfile "$TMP/peer" -x <"$TMP/sk")
    assert_eq "$got" "46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b" "ZIUT (sk on stdin)"
    got=$(printf '%s' 7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534 | hex_out "$BC_RUST" --hex-input eccdh-p256 agree --pkfile <(printf '%s' 04700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac) -x)
    assert_eq "$got" "46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b" "ZIUT (hex inputs with --hex-input)"
}

# [P-521] COUNT = 0, the file's 67-byte zero-led values trimmed to the curve's 66-byte fields.
test_eccdh_p521_matches_cavp() {
    local got
    unhex 017eecc07ab4b329068fba65e56a1f8890aa935e57134ae0ffcce802735151f4eac6564f6ee9974c5e6887a1fefee5743ae2241bfeb95d5ce31ddcb6f9edb4d6fc47 >"$TMP/sk"
    assert_size "$TMP/sk" 66 "sk length of P-521"
    unhex 0400602f9d0cf9e526b29e22381c203c48a886c2b0673033366314f1ffbcba240ba42f4ef38a76174635f91e6b4ed34275eb01c8467d05ca80315bf1a7bbd945f550a501b7c85f26f5d4b2d7355cf6b02117659943762b6d1db5ab4f1dbc44ce7b2946eb6c7de342962893fd387d1b73d7a8672d1f236961170b7eb3579953ee5cdc88cd2d >"$TMP/own"
    unhex 0400685a48e86c79f0f0875f7bc18d25eb5fc8c0b07e5da4f4370f3a9490340854334b1e1b87fa395464c60626124a4e70d0f785601d37c09870ebf176666877a2046d01ba52c56fc8776d9e8f5db4f0cc27636d0b741bbe05400697942e80b739884a83bde99e0f6716939e632bc8986fa18dccd443a348b6c3e522497955a4f3c302f676 >"$TMP/peer"
    assert_size "$TMP/peer" 133 "pk length of P-521"
    expect_ok "dIUT and QIUT must be consistent" "$BC_RUST" eccdh-p521 check-consistency --skfile "$TMP/sk" --pkfile "$TMP/own" >/dev/null
    got=$(hex_out "$BC_RUST" eccdh-p521 agree --skfile "$TMP/sk" --pkfile "$TMP/peer" -x)
    assert_eq "$got" "005fc70477c3e63bc3954bd0df3ea0d1f41ee21746ed95fc5e1fdf90930d5e136672d72cc770742d1711c3c3a4c334a0ad9759436a4d3c5bf6e74b9578fac148c831" "ZIUT"
}

# Every curve: keygen gives a key of the curve's length, pk-from-sk its public key of the right
# length, the pair is consistent, both sides agree on the same Z of the field's length, and a
# different pair gives a different Z.
test_eccdh_round_trips_on_every_curve() {
    local curve sk pk z za zb zc
    for curve in p256:32:65:32 p384:48:97:48 p521:66:133:66 secp256k1:32:65:32 bp256r1:32:65:32 bp384r1:48:97:48 bp512r1:64:129:64; do
        IFS=: read -r name sk pk z <<<"$curve"
        "$BC_RUST" eccdh-$name keygen >"$TMP/a.sk"
        assert_size "$TMP/a.sk" "$sk" "$name sk length"
        "$BC_RUST" eccdh-$name pk-from-sk --skfile "$TMP/a.sk" >"$TMP/a.pk"
        assert_size "$TMP/a.pk" "$pk" "$name pk length"
        expect_ok "$name pair must be consistent" "$BC_RUST" eccdh-$name check-consistency --skfile "$TMP/a.sk" --pkfile "$TMP/a.pk" >/dev/null
        "$BC_RUST" eccdh-$name keygen >"$TMP/b.sk"
        "$BC_RUST" eccdh-$name pk-from-sk --skfile "$TMP/b.sk" >"$TMP/b.pk"
        "$BC_RUST" eccdh-$name agree --skfile "$TMP/a.sk" --pkfile "$TMP/b.pk" >"$TMP/z.ab"
        assert_size "$TMP/z.ab" "$z" "$name Z length"
        za=$(hex "$TMP/z.ab")
        zb=$(hex_out "$BC_RUST" eccdh-$name agree --skfile "$TMP/b.sk" --pkfile "$TMP/a.pk" -x)
        assert_eq "$zb" "$za" "$name: both sides must agree"
        "$BC_RUST" eccdh-$name keygen >"$TMP/c.sk"
        zc=$(hex_out "$BC_RUST" eccdh-$name agree --skfile "$TMP/c.sk" --pkfile "$TMP/a.pk" -x)
        [ "$zc" != "$za" ] || fail "$name: a different pair must give a different Z"
        expect_fail "$name: a mismatched pair is refused" "$BC_RUST" eccdh-$name check-consistency --skfile "$TMP/c.sk" --pkfile "$TMP/a.pk"
        assert_stderr_has "do not match"
    done
}

# The peer key is validated when decoded: a point off the curve is refused before any
# agreement, and so is a private key of zero.
test_eccdh_refuses_invalid_keys() {
    "$BC_RUST" eccdh-p256 keygen >"$TMP/a.sk"
    "$BC_RUST" eccdh-p256 pk-from-sk --skfile "$TMP/a.sk" >"$TMP/a.pk"
    cp "$TMP/a.pk" "$TMP/off.pk"
    flip_byte "$TMP/off.pk" 64
    expect_fail "an off-curve peer key is refused" "$BC_RUST" eccdh-p256 agree --skfile "$TMP/a.sk" --pkfile "$TMP/off.pk"
    assert_stderr_has "public key"
    head -c 32 /dev/zero >"$TMP/zero.sk"
    expect_fail "d = 0 is refused" "$BC_RUST" eccdh-p256 agree --skfile "$TMP/zero.sk" --pkfile "$TMP/a.pk"
    assert_stderr_has "private key"
    expect_fail "a P-384 key is not a P-256 key" "$BC_RUST" eccdh-p384 agree --skfile "$TMP/a.sk" --pkfile "$TMP/a.pk"
}

# Z is keying material for a KDF: the raw Z written to a file and given to hkdf-sha256 as
# --ikm-file (never the inline --ikm, which would leave Z in the command history) derives a key,
# and both sides derive the same one.
test_eccdh_z_into_hkdf() {
    local ka kb
    "$BC_RUST" eccdh-p256 keygen >"$TMP/a.sk"
    "$BC_RUST" eccdh-p256 pk-from-sk --skfile "$TMP/a.sk" >"$TMP/a.pk"
    "$BC_RUST" eccdh-p256 keygen >"$TMP/b.sk"
    "$BC_RUST" eccdh-p256 pk-from-sk --skfile "$TMP/b.sk" >"$TMP/b.pk"
    "$BC_RUST" eccdh-p256 agree --skfile "$TMP/a.sk" --pkfile "$TMP/b.pk" >"$TMP/z.a"
    "$BC_RUST" eccdh-p256 agree --skfile "$TMP/b.sk" --pkfile "$TMP/a.pk" >"$TMP/z.b"
    ka=$(hex_out "$BC_RUST" hkdf-sha256 --salt 000102030405060708090a0b0c0d0e0f --ikm-file "$TMP/z.a" --additional-input 6b6579 --len 32 -x </dev/null)
    kb=$(hex_out "$BC_RUST" hkdf-sha256 --salt 000102030405060708090a0b0c0d0e0f --ikm-file "$TMP/z.b" --additional-input 6b6579 --len 32 -x </dev/null)
    assert_eq "$kb" "$ka" "both sides derive the same key"
    [ "$ka" != "$(hex "$TMP/z.a")" ] || fail "the derived key is not Z"
}

run_all
