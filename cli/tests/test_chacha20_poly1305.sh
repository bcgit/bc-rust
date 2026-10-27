#!/usr/bin/env bash
# The chacha20-poly1305 subcommand, end to end through the binary.
#
# Framing: encrypt writes a fresh 12-byte nonce, then the ciphertext (as long as the plaintext),
# then the 16-byte tag; decrypt reads the same layout back. With `--iv` / `--iv-file` the nonce is
# supplied instead and is neither written nor read, so the stream is `ciphertext || tag`. `--aad`
# (hex) or `--aad-file` (raw bytes) is authenticated but not encrypted. The fixed inputs are RFC
# 8439's Sec 2.8.2 and Appendix A.5 vectors; everything else comes from `bc-rust rng`.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

NONCE_LEN=12
TAG_LEN=16

# ---- the RFC 8439 vectors --------------------------------------------------------------------

# Sec 2.8.2. The nonce is the 32-bit fixed-common part 07000000 followed by the 64-bit IV.
S282_PLAINTEXT=4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e
S282_AAD=50515253c0c1c2c3c4c5c6c7
S282_KEY=808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
S282_NONCE=070000004041424344454647
S282_CIPHERTEXT=d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116
S282_TAG=1ae10b594f09e26a7e902ecbd0600691

# Appendix A.5, a decryption: the received tag is the one calculated there.
A5_KEY=1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0
A5_CIPHERTEXT=64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29a6ad5cb4022b02709b
A5_NONCE=000000000102030405060708
A5_AAD=f33388860000000000004e91
A5_TAG=eead9d67890cbb22392336fea1851f38
A5_PLAINTEXT=496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076616c696420666f722061206d6178696d756d206f6620736978206d6f6e74687320616e64206d617920626520757064617465642c207265706c616365642c206f72206f62736f6c65746564206279206f7468657220646f63756d656e747320617420616e792074696d652e20497420697320696e617070726f70726961746520746f2075736520496e7465726e65742d447261667473206173207265666572656e6365206d6174657269616c206f7220746f2063697465207468656d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67726573732e2fe2809d

test_a_supplied_nonce_matches_rfc8439_section_2_8_2() {
    local got
    got=$(unhex "$S282_PLAINTEXT" | hex_out "$BC_RUST" chacha20-poly1305 -d encrypt \
        --key "$S282_KEY" --iv "$S282_NONCE" --aad "$S282_AAD" -x)
    assert_eq "$got" "$S282_CIPHERTEXT$S282_TAG" "Sec 2.8.2: ciphertext || tag, with no nonce written"
    got=$(unhex "$S282_CIPHERTEXT$S282_TAG" | hex_out "$BC_RUST" chacha20-poly1305 -d decrypt \
        --key "$S282_KEY" --iv "$S282_NONCE" --aad "$S282_AAD" -x)
    assert_eq "$got" "$S282_PLAINTEXT" "Sec 2.8.2: decrypt reads ciphertext || tag alone"
}

test_a_supplied_nonce_matches_rfc8439_appendix_a5() {
    local got
    got=$(unhex "$A5_CIPHERTEXT$A5_TAG" | hex_out "$BC_RUST" chacha20-poly1305 -d decrypt \
        --key "$A5_KEY" --iv "$A5_NONCE" --aad "$A5_AAD" -x)
    assert_eq "$got" "$A5_PLAINTEXT" "A.5: the decryption"
    got=$(unhex "$A5_PLAINTEXT" | hex_out "$BC_RUST" chacha20-poly1305 -d encrypt \
        --key "$A5_KEY" --iv "$A5_NONCE" --aad "$A5_AAD" -x)
    assert_eq "$got" "$A5_CIPHERTEXT$A5_TAG" "A.5 run the other way"
}

test_decrypt_takes_the_nonce_from_the_input_by_default() {
    local got
    got=$(unhex "$S282_NONCE$S282_CIPHERTEXT$S282_TAG" | hex_out "$BC_RUST" chacha20-poly1305 \
        -d decrypt --key "$S282_KEY" --aad "$S282_AAD" -x)
    assert_eq "$got" "$S282_PLAINTEXT" "Sec 2.8.2 as nonce || ciphertext || tag"
    got=$(unhex "$A5_NONCE$A5_CIPHERTEXT$A5_TAG" | hex_out "$BC_RUST" chacha20-poly1305 \
        -d decrypt --key "$A5_KEY" --aad "$A5_AAD" -x)
    assert_eq "$got" "$A5_PLAINTEXT" "A.5 as nonce || ciphertext || tag"
}

test_iv_file_holds_the_bytes_iv_gives_in_hex() {
    unhex "$S282_NONCE" >"$TMP/nonce"
    unhex "$S282_PLAINTEXT" >"$TMP/pt"
    "$BC_RUST" chacha20-poly1305 -d encrypt --key "$S282_KEY" --iv-file "$TMP/nonce" \
        --aad "$S282_AAD" <"$TMP/pt" >"$TMP/ct"
    assert_eq "$(hex "$TMP/ct")" "$S282_CIPHERTEXT$S282_TAG" "--iv-file must be the same nonce as --iv"
}

# As for the AES commands, `--iv-file` wins when both are given: the vector's nonce in the file
# gives the vector, and the vector's nonce on the command line is ignored for the file's.
test_iv_file_wins_over_iv_when_both_are_given() {
    unhex "$S282_NONCE" >"$TMP/nonce"
    rng 12 >"$TMP/other"
    unhex "$S282_PLAINTEXT" >"$TMP/pt"
    "$BC_RUST" chacha20-poly1305 -d encrypt --key "$S282_KEY" --iv "$(hex "$TMP/other")" \
        --iv-file "$TMP/nonce" --aad "$S282_AAD" <"$TMP/pt" >"$TMP/ct"
    assert_eq "$(hex "$TMP/ct")" "$S282_CIPHERTEXT$S282_TAG" "the file's nonce must be the one used"
    "$BC_RUST" chacha20-poly1305 -d decrypt --key "$S282_KEY" --iv "$(hex "$TMP/other")" \
        --iv-file "$TMP/nonce" --aad "$S282_AAD" <"$TMP/ct" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "decrypt must take the file's nonce too"

    expect_fail "the vector's nonce in --iv must lose to the file's, and the tag then fails" \
        "$BC_RUST" chacha20-poly1305 -d decrypt --key "$S282_KEY" --iv "$S282_NONCE" \
        --iv-file "$TMP/other" --aad "$S282_AAD" <"$TMP/ct"
    assert_stderr_has "authentication failed"
}

# ---- the nonce: generated by default, or supplied --------------------------------------------

test_the_default_writes_a_generated_nonce_ahead_of_the_ciphertext_and_tag() {
    rng 32 >"$TMP/key"
    rng 69 >"$TMP/pt"
    "$BC_RUST" chacha20-poly1305 -d encrypt --key-file "$TMP/key" --aad deadbeef <"$TMP/pt" >"$TMP/ct"
    assert_size "$TMP/ct" $((NONCE_LEN + 69 + TAG_LEN)) "nonce, ciphertext and tag"
    "$BC_RUST" chacha20-poly1305 -d decrypt --key-file "$TMP/key" --aad deadbeef <"$TMP/ct" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "round trip"
}

test_each_invocation_without_iv_uses_a_fresh_nonce() {
    rng 32 >"$TMP/key"
    rng 69 >"$TMP/pt"
    local i
    : >"$TMP/nonces"
    for i in $(seq 1 8); do
        "$BC_RUST" chacha20-poly1305 -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
        head -c $NONCE_LEN "$TMP/ct" | "$BC_RUST" hex-encode >>"$TMP/nonces"
        echo >>"$TMP/nonces"
    done
    assert_eq "$(sort -u "$TMP/nonces" | wc -l)" 8 "eight encryptions must draw eight distinct nonces"
}

# A supplied nonce is used exactly as given: under the nonce a default run generated, `--iv` gives
# that run's ciphertext and tag without the nonce in front.
test_a_supplied_nonce_gives_the_default_output_without_the_nonce() {
    rng 32 >"$TMP/key"
    rng 69 >"$TMP/pt"
    "$BC_RUST" chacha20-poly1305 -d encrypt --key-file "$TMP/key" --aad deadbeef <"$TMP/pt" >"$TMP/framed"
    slice "$TMP/framed" 0 $NONCE_LEN >"$TMP/nonce"
    tail -c +$((NONCE_LEN + 1)) "$TMP/framed" >"$TMP/sealed"
    "$BC_RUST" chacha20-poly1305 -d encrypt --key-file "$TMP/key" --iv "$(hex "$TMP/nonce")" \
        --aad deadbeef <"$TMP/pt" >"$TMP/ct"
    assert_same "$TMP/sealed" "$TMP/ct" "--iv output must be the default ciphertext || tag under the same nonce"
    "$BC_RUST" chacha20-poly1305 -d decrypt --key-file "$TMP/key" --iv-file "$TMP/nonce" \
        --aad deadbeef <"$TMP/ct" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "decrypt with the nonce supplied reads only ciphertext || tag"
}

test_a_supplied_nonce_with_no_message_writes_just_the_tag() {
    rng 32 >"$TMP/key"
    rng 12 >"$TMP/nonce"
    : >"$TMP/empty"
    "$BC_RUST" chacha20-poly1305 -d encrypt --key-file "$TMP/key" --iv-file "$TMP/nonce" <"$TMP/empty" >"$TMP/ct"
    assert_size "$TMP/ct" $TAG_LEN "an empty message under a supplied nonce is the tag alone"
    "$BC_RUST" chacha20-poly1305 -d decrypt --key-file "$TMP/key" --iv-file "$TMP/nonce" <"$TMP/ct" >"$TMP/rec"
    assert_size "$TMP/rec" 0 "and decrypts back to nothing"
}

# With `--iv`, decrypt does not look for a nonce in its input: one left there is taken as
# ciphertext, and the tag no longer verifies.
test_with_iv_a_nonce_left_in_the_input_fails_authentication() {
    rng 32 >"$TMP/key"
    rng 69 >"$TMP/pt"
    "$BC_RUST" chacha20-poly1305 -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/framed"
    slice "$TMP/framed" 0 $NONCE_LEN >"$TMP/nonce"
    expect_fail "nonce || ciphertext || tag under --iv" \
        "$BC_RUST" chacha20-poly1305 -d decrypt --key-file "$TMP/key" --iv-file "$TMP/nonce" <"$TMP/framed"
    assert_stderr_has "authentication failed"
}

test_a_wrong_supplied_nonce_fails_authentication() {
    rng 32 >"$TMP/key"
    rng 12 >"$TMP/nonce"
    rng 12 >"$TMP/other"
    rng 69 >"$TMP/pt"
    "$BC_RUST" chacha20-poly1305 -d encrypt --key-file "$TMP/key" --iv-file "$TMP/nonce" <"$TMP/pt" >"$TMP/ct"
    expect_fail "another nonce must not verify" \
        "$BC_RUST" chacha20-poly1305 -d decrypt --key-file "$TMP/key" --iv-file "$TMP/other" <"$TMP/ct"
    assert_stderr_has "authentication failed"
}

# What the help warns about: one key and nonce used twice give one keystream twice, so the XOR of
# the two ciphertexts is the XOR of the two plaintexts. The repeated one-time Poly1305 key is the
# other half of the damage, which a script cannot show as directly.
test_a_repeated_supplied_nonce_reveals_the_xor_of_the_plaintexts() {
    rng 32 >"$TMP/key"
    rng 12 >"$TMP/nonce"
    rng 64 >"$TMP/p1"
    rng 64 >"$TMP/p2"
    "$BC_RUST" chacha20-poly1305 -d encrypt --key-file "$TMP/key" --iv-file "$TMP/nonce" <"$TMP/p1" >"$TMP/s1"
    "$BC_RUST" chacha20-poly1305 -d encrypt --key-file "$TMP/key" --iv-file "$TMP/nonce" <"$TMP/p2" >"$TMP/s2"
    slice "$TMP/s1" 0 64 >"$TMP/c1"
    slice "$TMP/s2" 0 64 >"$TMP/c2"
    assert_eq "$(xor_hex "$(hex "$TMP/c1")" "$(hex "$TMP/c2")")" \
        "$(xor_hex "$(hex "$TMP/p1")" "$(hex "$TMP/p2")")" "c1 xor c2 must be p1 xor p2"
}

# ---- round trips -----------------------------------------------------------------------------

test_any_input_length_round_trips_with_and_without_iv() {
    rng 32 >"$TMP/key"
    rng 12 >"$TMP/nonce"
    local len
    for len in 0 1 15 16 17 63 64 65 1023 1024 1025 4099; do
        rng "$len" >"$TMP/pt"
        "$BC_RUST" chacha20-poly1305 -d encrypt --key-file "$TMP/key" --aad deadbeef <"$TMP/pt" >"$TMP/ct"
        assert_size "$TMP/ct" $((NONCE_LEN + len + TAG_LEN)) "len $len: nonce, equal-length body, tag"
        "$BC_RUST" chacha20-poly1305 -d decrypt --key-file "$TMP/key" --aad deadbeef <"$TMP/ct" >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "len $len: round trip"

        "$BC_RUST" chacha20-poly1305 -d encrypt --key-file "$TMP/key" --iv-file "$TMP/nonce" \
            --aad deadbeef <"$TMP/pt" >"$TMP/ct"
        assert_size "$TMP/ct" $((len + TAG_LEN)) "len $len: with --iv, body and tag alone"
        "$BC_RUST" chacha20-poly1305 -d decrypt --key-file "$TMP/key" --iv-file "$TMP/nonce" \
            --aad deadbeef <"$TMP/ct" >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "len $len: round trip with --iv"
    done
}

test_round_trip_through_a_pipe_larger_than_the_pipe_buffer() {
    rng 32 >"$TMP/key"
    rng 12 >"$TMP/nonce"
    rng $((1024 * 1024 + 7)) >"$TMP/pt"
    "$BC_RUST" chacha20-poly1305 -d encrypt --key-file "$TMP/key" <"$TMP/pt" \
        | "$BC_RUST" chacha20-poly1305 -d decrypt --key-file "$TMP/key" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "1 MiB + 7 must survive encrypt | decrypt"
    "$BC_RUST" chacha20-poly1305 -d encrypt --key-file "$TMP/key" --iv-file "$TMP/nonce" <"$TMP/pt" \
        | "$BC_RUST" chacha20-poly1305 -d decrypt --key-file "$TMP/key" --iv-file "$TMP/nonce" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "and with the nonce supplied on both sides"
}

# ---- invalid input ---------------------------------------------------------------------------

test_a_nonce_of_the_wrong_length_is_rejected() {
    rng 32 >"$TMP/key"
    rng 64 >"$TMP/pt"
    local len
    for len in 0 11 13 16; do
        rng "$len" >"$TMP/nonce"
        expect_fail "a $len-byte --iv" \
            "$BC_RUST" chacha20-poly1305 -d encrypt --key-file "$TMP/key" --iv "$(hex "$TMP/nonce")" <"$TMP/pt"
        assert_stderr_has "requires exactly 12"
        expect_fail "a $len-byte --iv-file" \
            "$BC_RUST" chacha20-poly1305 -d decrypt --key-file "$TMP/key" --iv-file "$TMP/nonce" <"$TMP/pt"
        assert_stderr_has "requires exactly 12"
    done
}

test_a_nonce_that_is_not_hex_is_rejected() {
    rng 32 >"$TMP/key"
    rng 64 >"$TMP/pt"
    local iv
    for iv in zzzzzzzzzzzzzzzzzzzzzzzz 00112233445566778899aab; do
        expect_fail "--iv $iv" \
            "$BC_RUST" chacha20-poly1305 -d encrypt --key-file "$TMP/key" --iv "$iv" <"$TMP/pt"
        assert_stderr_has "not valid hex"
    done
}

test_decrypt_input_shorter_than_the_nonce_is_rejected() {
    rng 32 >"$TMP/key"
    local len
    for len in 0 1 11; do
        rng "$len" >"$TMP/short"
        expect_fail "$len bytes cannot hold a 12-byte nonce" \
            "$BC_RUST" chacha20-poly1305 -d decrypt --key-file "$TMP/key" <"$TMP/short"
        assert_stderr_has "12-byte IV"
    done
}

# With the nonce supplied there is no nonce in the stream, so the floor is the tag instead.
test_with_iv_decrypt_input_shorter_than_the_tag_is_rejected() {
    rng 32 >"$TMP/key"
    rng 12 >"$TMP/nonce"
    local len
    for len in 0 1 15; do
        rng "$len" >"$TMP/short"
        expect_fail "$len bytes cannot hold a 16-byte tag" \
            "$BC_RUST" chacha20-poly1305 -d decrypt --key-file "$TMP/key" --iv-file "$TMP/nonce" <"$TMP/short"
        assert_stderr_has "authentication failed"
    done
}

test_tampering_is_rejected_under_a_supplied_nonce() {
    rng 32 >"$TMP/key"
    rng 12 >"$TMP/nonce"
    rng 69 >"$TMP/pt"
    "$BC_RUST" chacha20-poly1305 -d encrypt --key-file "$TMP/key" --iv-file "$TMP/nonce" \
        --aad deadbeef <"$TMP/pt" >"$TMP/ct"

    cp "$TMP/ct" "$TMP/bad_ct"
    flip_byte "$TMP/bad_ct" 0
    expect_fail "a flipped ciphertext bit must not verify" \
        "$BC_RUST" chacha20-poly1305 -d decrypt --key-file "$TMP/key" --iv-file "$TMP/nonce" --aad deadbeef <"$TMP/bad_ct"
    assert_stderr_has "authentication failed"

    cp "$TMP/ct" "$TMP/bad_tag"
    flip_byte "$TMP/bad_tag" $(($(wc -c <"$TMP/ct") - 1))
    expect_fail "a flipped tag bit must not verify" \
        "$BC_RUST" chacha20-poly1305 -d decrypt --key-file "$TMP/key" --iv-file "$TMP/nonce" --aad deadbeef <"$TMP/bad_tag"
    assert_stderr_has "authentication failed"

    expect_fail "another AAD must not verify" \
        "$BC_RUST" chacha20-poly1305 -d decrypt --key-file "$TMP/key" --iv-file "$TMP/nonce" --aad 00112233 <"$TMP/ct"
    assert_stderr_has "authentication failed"
}

test_a_key_of_the_wrong_length_is_rejected() {
    rng 16 >"$TMP/key"
    rng 64 >"$TMP/pt"
    expect_fail "a 16-byte key is not a ChaCha20-Poly1305 key" \
        "$BC_RUST" chacha20-poly1305 -d encrypt --key-file "$TMP/key" <"$TMP/pt"
    assert_stderr_has "32-byte key"
}

# ---- discoverability -------------------------------------------------------------------------

test_the_subcommand_is_listed_in_help() {
    "$BC_RUST" --help >"$TMP/help"
    grep -q "chacha20-poly1305" "$TMP/help" || fail "--help should list chacha20-poly1305"
}

test_per_command_help_documents_the_nonce_and_its_reuse() {
    "$BC_RUST" chacha20-poly1305 --help >"$TMP/help"
    grep -q -- "--iv " "$TMP/help" || fail "help should list --iv"
    grep -q -- "--iv-file" "$TMP/help" || fail "help should list --iv-file"
    grep -q "If both iv and iv_file options are provided, the file will be used" "$TMP/help" \
        || fail "help should say --iv-file wins over --iv"
    grep -qi "first 12 bytes" "$TMP/help" || fail "help should say the generated nonce is written first"
    grep -q "MUST be unique" "$TMP/help" || fail "help should say a supplied nonce must not repeat"
    grep -q "Poly1305 key" "$TMP/help" || fail "help should say a repeat also reuses the Poly1305 key"
    grep -q "aad" "$TMP/help" || fail "help should mention AAD"
}

run_all
