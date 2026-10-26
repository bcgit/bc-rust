#!/usr/bin/env bash
# The chacha20 subcommand, end to end through the binary.
#
# Framing: encrypt writes a fresh 12-byte nonce as the first bytes of its output and decrypt reads
# it back from the first 12 bytes of its input, unless `--iv` / `--iv-file` supplies the nonce, in
# which case only ciphertext is written or read. Any input length is accepted, with a ciphertext
# exactly as long as the plaintext, and the block counter starts at 0. Keys and data come from
# `bc-rust rng`; the fixed inputs are RFC 8439's own vectors.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

NONCE_LEN=12
BLOCK_LEN=64

# ---- the RFC 8439 vectors --------------------------------------------------------------------

# Appendix A.2, Test Vector #1: all-zero key, nonce and plaintext, initial block counter 0.
A2_1_KEY=0000000000000000000000000000000000000000000000000000000000000000
A2_1_NONCE=000000000000000000000000
A2_1_PLAINTEXT=00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
A2_1_CIPHERTEXT=76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586

# Sec 2.4.2, the sunscreen example. Its initial counter is 1, one block past the 0 this command
# starts at, so the tests put one block ahead of the message and drop it from the output.
S242_KEY=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
S242_NONCE=000000000000004a00000000
S242_PLAINTEXT=4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e
S242_CIPHERTEXT=6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d

test_a_supplied_nonce_matches_rfc8439_appendix_a2_vector_1() {
    local got
    got=$(unhex "$A2_1_PLAINTEXT" | hex_out "$BC_RUST" chacha20 -d encrypt --key "$A2_1_KEY" --iv "$A2_1_NONCE" -x)
    assert_eq "$got" "$A2_1_CIPHERTEXT" "A.2 #1: encrypt writes the ciphertext alone"
    got=$(unhex "$A2_1_CIPHERTEXT" | hex_out "$BC_RUST" chacha20 -d decrypt --key "$A2_1_KEY" --iv "$A2_1_NONCE" -x)
    assert_eq "$got" "$A2_1_PLAINTEXT" "A.2 #1: decrypt reads the ciphertext alone"
}

test_decrypt_takes_the_nonce_from_the_input_by_default() {
    local got
    got=$(unhex "$A2_1_NONCE$A2_1_CIPHERTEXT" | hex_out "$BC_RUST" chacha20 -d decrypt --key "$A2_1_KEY" -x)
    assert_eq "$got" "$A2_1_PLAINTEXT" "A.2 #1 with its nonce ahead of the ciphertext"
}

test_a_supplied_nonce_matches_rfc8439_section_2_4_2_from_counter_1() {
    { head -c $BLOCK_LEN /dev/zero; unhex "$S242_PLAINTEXT"; } >"$TMP/pt"
    "$BC_RUST" chacha20 -d encrypt --key "$S242_KEY" --iv "$S242_NONCE" <"$TMP/pt" >"$TMP/ct"
    assert_size "$TMP/ct" $((BLOCK_LEN + 114)) "one block, then the 114-byte message"
    tail -c +$((BLOCK_LEN + 1)) "$TMP/ct" >"$TMP/body"
    assert_eq "$(hex "$TMP/body")" "$S242_CIPHERTEXT" "Sec 2.4.2: the ciphertext from counter 1"

    { head -c $BLOCK_LEN /dev/zero; unhex "$S242_CIPHERTEXT"; } >"$TMP/ct2"
    "$BC_RUST" chacha20 -d decrypt --key "$S242_KEY" --iv "$S242_NONCE" <"$TMP/ct2" >"$TMP/out"
    tail -c +$((BLOCK_LEN + 1)) "$TMP/out" >"$TMP/rec"
    assert_eq "$(hex "$TMP/rec")" "$S242_PLAINTEXT" "Sec 2.4.2: the sunscreen text back"
}

test_iv_file_holds_the_bytes_iv_gives_in_hex() {
    unhex "$S242_NONCE" >"$TMP/nonce"
    rng 100 >"$TMP/pt"
    "$BC_RUST" chacha20 -d encrypt --key "$S242_KEY" --iv "$S242_NONCE" <"$TMP/pt" >"$TMP/a"
    "$BC_RUST" chacha20 -d encrypt --key "$S242_KEY" --iv-file "$TMP/nonce" <"$TMP/pt" >"$TMP/b"
    assert_same "$TMP/a" "$TMP/b" "--iv-file must be the same nonce as --iv"
}

# As for the AES commands, `--iv-file` wins when both are given: the vector's nonce in the file
# gives the vector, and the vector's nonce on the command line is ignored for the file's.
test_iv_file_wins_over_iv_when_both_are_given() {
    unhex "$A2_1_NONCE" >"$TMP/nonce"
    rng 12 >"$TMP/other"
    unhex "$A2_1_PLAINTEXT" >"$TMP/pt"
    "$BC_RUST" chacha20 -d encrypt --key "$A2_1_KEY" --iv "$(hex "$TMP/other")" --iv-file "$TMP/nonce" <"$TMP/pt" >"$TMP/ct"
    assert_eq "$(hex "$TMP/ct")" "$A2_1_CIPHERTEXT" "the file's nonce must be the one used"
    "$BC_RUST" chacha20 -d decrypt --key "$A2_1_KEY" --iv "$(hex "$TMP/other")" --iv-file "$TMP/nonce" <"$TMP/ct" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "decrypt must take the file's nonce too"

    "$BC_RUST" chacha20 -d encrypt --key "$A2_1_KEY" --iv "$A2_1_NONCE" --iv-file "$TMP/other" <"$TMP/pt" >"$TMP/both"
    "$BC_RUST" chacha20 -d encrypt --key "$A2_1_KEY" --iv-file "$TMP/other" <"$TMP/pt" >"$TMP/file_only"
    assert_same "$TMP/file_only" "$TMP/both" "the vector's nonce in --iv must lose to the file's"
}

# ---- the nonce: generated by default, or supplied --------------------------------------------

test_the_default_writes_a_generated_nonce_ahead_of_the_ciphertext() {
    rng 32 >"$TMP/key"
    rng 69 >"$TMP/pt"
    "$BC_RUST" chacha20 -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
    assert_size "$TMP/ct" $((NONCE_LEN + 69)) "a 12-byte nonce plus a body as long as the plaintext"
    "$BC_RUST" chacha20 -d decrypt --key-file "$TMP/key" <"$TMP/ct" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "decrypt consumes exactly 12 bytes of nonce"
}

# A repeated nonce under one key repeats the keystream, so without `--iv` every run draws its own.
test_each_invocation_without_iv_uses_a_fresh_nonce() {
    rng 32 >"$TMP/key"
    rng 64 >"$TMP/pt"
    local i
    : >"$TMP/nonces"
    for i in $(seq 1 8); do
        "$BC_RUST" chacha20 -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
        head -c $NONCE_LEN "$TMP/ct" | "$BC_RUST" hex-encode >>"$TMP/nonces"
        echo >>"$TMP/nonces"
    done
    assert_eq "$(sort -u "$TMP/nonces" | wc -l)" 8 "eight encryptions must draw eight distinct nonces"
}

# A supplied nonce is used exactly as given: under the nonce a default run generated, `--iv` gives
# that run's ciphertext without the nonce in front.
test_a_supplied_nonce_gives_the_default_output_without_the_nonce() {
    rng 32 >"$TMP/key"
    rng 69 >"$TMP/pt"
    "$BC_RUST" chacha20 -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/framed"
    slice "$TMP/framed" 0 $NONCE_LEN >"$TMP/nonce"
    tail -c +$((NONCE_LEN + 1)) "$TMP/framed" >"$TMP/body"
    "$BC_RUST" chacha20 -d encrypt --key-file "$TMP/key" --iv "$(hex "$TMP/nonce")" <"$TMP/pt" >"$TMP/ct"
    assert_same "$TMP/body" "$TMP/ct" "--iv output must be the default body under the same nonce"
    "$BC_RUST" chacha20 -d decrypt --key-file "$TMP/key" --iv-file "$TMP/nonce" <"$TMP/ct" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "decrypt with the nonce supplied reads only ciphertext"
}

# With `--iv`, decrypt does not look for a nonce in its input: one left there is decrypted as
# ciphertext, which gives 12 bytes too many and not the plaintext.
test_with_iv_a_nonce_left_in_the_input_is_decrypted_as_ciphertext() {
    rng 32 >"$TMP/key"
    rng 12 >"$TMP/nonce"
    rng 69 >"$TMP/pt"
    "$BC_RUST" chacha20 -d encrypt --key-file "$TMP/key" --iv-file "$TMP/nonce" <"$TMP/pt" >"$TMP/ct"
    cat "$TMP/nonce" "$TMP/ct" >"$TMP/framed"
    "$BC_RUST" chacha20 -d decrypt --key-file "$TMP/key" --iv-file "$TMP/nonce" <"$TMP/framed" >"$TMP/rec"
    assert_size "$TMP/rec" $((NONCE_LEN + 69)) "every input byte is taken as ciphertext"
    tail -c +$((NONCE_LEN + 1)) "$TMP/rec" >"$TMP/tail"
    assert_differs "$TMP/pt" "$TMP/tail" "the plaintext must not come back from the wrong framing"
}

# What the help warns about: one key and nonce used twice give one keystream twice, so the XOR of
# the two ciphertexts is the XOR of the two plaintexts.
test_a_repeated_supplied_nonce_reveals_the_xor_of_the_plaintexts() {
    rng 32 >"$TMP/key"
    rng 12 >"$TMP/nonce"
    rng 64 >"$TMP/p1"
    rng 64 >"$TMP/p2"
    "$BC_RUST" chacha20 -d encrypt --key-file "$TMP/key" --iv-file "$TMP/nonce" <"$TMP/p1" >"$TMP/c1"
    "$BC_RUST" chacha20 -d encrypt --key-file "$TMP/key" --iv-file "$TMP/nonce" <"$TMP/p2" >"$TMP/c2"
    assert_eq "$(xor_hex "$(hex "$TMP/c1")" "$(hex "$TMP/c2")")" \
        "$(xor_hex "$(hex "$TMP/p1")" "$(hex "$TMP/p2")")" "c1 xor c2 must be p1 xor p2"
}

# ---- round trips -----------------------------------------------------------------------------

test_any_input_length_round_trips_with_and_without_iv() {
    rng 32 >"$TMP/key"
    rng 12 >"$TMP/nonce"
    local len
    for len in 0 1 63 64 65 127 128 129 1023 1024 1025 4099; do
        rng "$len" >"$TMP/pt"
        "$BC_RUST" chacha20 -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
        assert_size "$TMP/ct" $((NONCE_LEN + len)) "len $len: nonce plus an equal-length body"
        "$BC_RUST" chacha20 -d decrypt --key-file "$TMP/key" <"$TMP/ct" >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "len $len: round trip"

        "$BC_RUST" chacha20 -d encrypt --key-file "$TMP/key" --iv-file "$TMP/nonce" <"$TMP/pt" >"$TMP/ct"
        assert_size "$TMP/ct" "$len" "len $len: with --iv, the body alone"
        "$BC_RUST" chacha20 -d decrypt --key-file "$TMP/key" --iv-file "$TMP/nonce" <"$TMP/ct" >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "len $len: round trip with --iv"
    done
}

test_round_trip_through_a_pipe_larger_than_the_pipe_buffer() {
    rng 32 >"$TMP/key"
    rng 12 >"$TMP/nonce"
    rng $((1024 * 1024 + 7)) >"$TMP/pt"
    "$BC_RUST" chacha20 -d encrypt --key-file "$TMP/key" <"$TMP/pt" \
        | "$BC_RUST" chacha20 -d decrypt --key-file "$TMP/key" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "1 MiB + 7 must survive encrypt | decrypt"
    "$BC_RUST" chacha20 -d encrypt --key-file "$TMP/key" --iv-file "$TMP/nonce" <"$TMP/pt" \
        | "$BC_RUST" chacha20 -d decrypt --key-file "$TMP/key" --iv-file "$TMP/nonce" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "and with the nonce supplied on both sides"
}

test_hex_output_composes_through_hex_decode() {
    rng 32 >"$TMP/key"
    rng 4099 >"$TMP/pt"
    "$BC_RUST" chacha20 -d encrypt --key-file "$TMP/key" -x <"$TMP/pt" >"$TMP/ct.hex"
    assert_size "$TMP/ct.hex" $((2 * (NONCE_LEN + 4099) + 1)) "-x emits two hex characters per byte, then a newline"
    "$BC_RUST" hex-decode <"$TMP/ct.hex" \
        | "$BC_RUST" chacha20 -d decrypt --key-file "$TMP/key" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "-x output must decrypt after hex-decode"
}

# ---- invalid input ---------------------------------------------------------------------------

test_a_nonce_of_the_wrong_length_is_rejected() {
    rng 32 >"$TMP/key"
    rng 64 >"$TMP/pt"
    local len
    for len in 0 11 13 16; do
        rng "$len" >"$TMP/nonce"
        expect_fail "a $len-byte --iv" \
            "$BC_RUST" chacha20 -d encrypt --key-file "$TMP/key" --iv "$(hex "$TMP/nonce")" <"$TMP/pt"
        assert_stderr_has "requires exactly 12"
        expect_fail "a $len-byte --iv-file" \
            "$BC_RUST" chacha20 -d decrypt --key-file "$TMP/key" --iv-file "$TMP/nonce" <"$TMP/pt"
        assert_stderr_has "requires exactly 12"
    done
}

test_a_nonce_that_is_not_hex_is_rejected() {
    rng 32 >"$TMP/key"
    rng 64 >"$TMP/pt"
    local iv
    for iv in zzzzzzzzzzzzzzzzzzzzzzzz 00112233445566778899aab; do
        expect_fail "--iv $iv" \
            "$BC_RUST" chacha20 -d encrypt --key-file "$TMP/key" --iv "$iv" <"$TMP/pt"
        assert_stderr_has "not valid hex"
    done
}

# A nonce file written with `echo` rather than `echo -n` carries a newline, which is warned about
# and then, as the thirteenth byte, refused.
test_a_nonce_file_with_a_trailing_newline_is_warned_about() {
    rng 32 >"$TMP/key"
    rng 64 >"$TMP/pt"
    { rng 12; printf '\n'; } >"$TMP/nonce.nl"
    expect_fail "a 12-byte nonce plus a newline" \
        "$BC_RUST" chacha20 -d encrypt --key-file "$TMP/key" --iv-file "$TMP/nonce.nl" <"$TMP/pt"
    assert_stderr_has "newline"
    assert_stderr_has "requires exactly 12"
}

test_decrypt_input_shorter_than_the_nonce_is_rejected() {
    rng 32 >"$TMP/key"
    local len
    for len in 0 1 11; do
        rng "$len" >"$TMP/short"
        expect_fail "$len bytes cannot hold a 12-byte nonce" \
            "$BC_RUST" chacha20 -d decrypt --key-file "$TMP/key" <"$TMP/short"
        assert_stderr_has "12-byte IV"
    done
}

test_a_key_of_the_wrong_length_is_rejected() {
    rng 16 >"$TMP/key"
    rng 64 >"$TMP/pt"
    expect_fail "a 16-byte key is not a ChaCha20 key" \
        "$BC_RUST" chacha20 -d encrypt --key-file "$TMP/key" <"$TMP/pt"
    assert_stderr_has "32-byte key"
}

# ---- discoverability -------------------------------------------------------------------------

test_the_subcommand_is_listed_in_help() {
    "$BC_RUST" --help >"$TMP/help"
    grep -q "chacha20 " "$TMP/help" || fail "--help should list chacha20"
}

test_per_command_help_documents_the_nonce_and_its_reuse() {
    "$BC_RUST" chacha20 --help >"$TMP/help"
    grep -q -- "--iv " "$TMP/help" || fail "help should list --iv"
    grep -q -- "--iv-file" "$TMP/help" || fail "help should list --iv-file"
    grep -q "If both iv and iv_file options are provided, the file will be used" "$TMP/help" \
        || fail "help should say --iv-file wins over --iv"
    grep -qi "first 12 bytes" "$TMP/help" || fail "help should say the generated nonce is written first"
    grep -q "MUST be unique" "$TMP/help" || fail "help should say a supplied nonce must not repeat"
    grep -qiE "malleable|flipping" "$TMP/help" || fail "help should warn about malleability"
}

run_all
