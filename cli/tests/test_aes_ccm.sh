#!/usr/bin/env bash
# The aes128-ccm / aes192-ccm / aes256-ccm subcommands, end to end through the binary.
#
# Framing, and everything CCM does differently from the other modes: the nonce is a required flag
# (`--nonce` hex or `--nonce-file` raw bytes) and is NOT written to the output; the tag rides at the
# end of the ciphertext, `--tag-len` bytes of it, which must match on both sides; `--aad` /
# `--aad-file` is authenticated but not encrypted and must match; a failed tag check exits non-zero
# and writes nothing; nonce length and tag length are validated against SP 800-38C Appendix A.1,
# and the nonce length caps the payload. Keys and data come from `bc-rust rng`; the fixed inputs
# are SP 800-38C Appendix C.1 and C.4, copied from the Rust suite this file replaces.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

KEY_128=2b7e151628aed2a6abf7158809cf4f3c
KEY_192=8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
KEY_256=603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
# A 12-byte nonce, the length these tests use unless they are about nonce length.
NONCE=000102030405060708090a0b

# ---- local helpers --------------------------------------------------------------------------

# `nonce_of 13 5a` prints the hex of 13 bytes of 0x5a.
nonce_of() {
    local n=$1 byte=$2 out="" i
    for ((i = 0; i < n; i++)); do out="$out$byte"; done
    printf '%s' "$out"
}

# ---- known answers --------------------------------------------------------------------------

# SP 800-38C Appendix C.1: Klen = 128, Tlen = 32, Nlen = 56, Alen = 64, Plen = 32. The appendix's
# C is the 4-byte ciphertext followed by the 4-byte tag, exactly what this command writes. The
# appendix gives no decryption example but says one is "straightforward to construct".
test_encrypt_matches_sp800_38c_appendix_c1() {
    local got
    got=$(unhex 20212223 | "$BC_RUST" aes128-ccm -d encrypt --key 404142434445464748494a4b4c4d4e4f \
        --nonce 10111213141516 --aad 0001020304050607 --tag-len 4 | "$BC_RUST" hex-encode)
    assert_eq "$got" "7162015b4dac255d" "Appendix C.1's C string"
    got=$(unhex 7162015b4dac255d | "$BC_RUST" aes128-ccm -d decrypt --key 404142434445464748494a4b4c4d4e4f \
        --nonce 10111213141516 --aad 0001020304050607 --tag-len 4 | "$BC_RUST" hex-encode)
    assert_eq "$got" "20212223" "Appendix C.1's P"
}

# SP 800-38C Appendix C.4: the AAD is 65536 bytes -- the sixteen blocks `00 01 .. ff` repeated 256
# times -- so `--aad-file` is streamed through the MAC in many chunks, and the length is past the
# 2^16 - 2^8 boundary where A.2.2's six-octet encoding applies.
test_aad_file_matches_sp800_38c_appendix_c4() {
    local i got
    for ((i = 0; i < 256; i++)); do printf "\\x$(printf '%02x' "$i")"; done >"$TMP/block"
    for ((i = 0; i < 256; i++)); do cat "$TMP/block"; done >"$TMP/aad"
    assert_size "$TMP/aad" 65536 "Alen = 524288 bits"

    unhex 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f >"$TMP/pt"
    "$BC_RUST" aes128-ccm -d encrypt --key 404142434445464748494a4b4c4d4e4f \
        --nonce 101112131415161718191a1b1c --aad-file "$TMP/aad" --tag-len 14 <"$TMP/pt" >"$TMP/ct"
    got=$(hex "$TMP/ct")
    assert_eq "$got" "69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72b4ac6bec93e8598e7f0dadbcea5b" \
        "Appendix C.4's C string"
    "$BC_RUST" aes128-ccm -d decrypt --key 404142434445464748494a4b4c4d4e4f \
        --nonce 101112131415161718191a1b1c --aad-file "$TMP/aad" --tag-len 14 <"$TMP/ct" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "Appendix C.4's P"
}

# ---- round trips --------------------------------------------------------------------------

# Each key length, with AAD, over a payload that spans several blocks and does not end on a block
# boundary.
test_encrypt_then_decrypt_round_trips() {
    local bits key
    rng 201 >"$TMP/pt"
    for bits in 128 192 256; do
        key="KEY_$bits"
        "$BC_RUST" "aes$bits-ccm" -d encrypt --key "${!key}" --nonce "$NONCE" --aad cafebabe <"$TMP/pt" >"$TMP/ct"
        assert_size "$TMP/ct" $((201 + 16)) "$bits: the default tag length is 16, and the nonce is not written"
        "$BC_RUST" "aes$bits-ccm" -d decrypt --key "${!key}" --nonce "$NONCE" --aad cafebabe <"$TMP/ct" >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "$bits: round trip"
    done
}

# 256 KiB, past the usual 64 KiB pipe buffer: the read-all-of-stdin loop must not deadlock against
# its own output. A 12-byte nonce gives q = 3, a 16 MiB limit, so this is well inside it.
test_a_payload_larger_than_the_pipe_buffer_round_trips() {
    rng $((256 * 1024)) >"$TMP/pt"
    "$BC_RUST" aes256-ccm -d encrypt --key "$KEY_256" --nonce "$NONCE" <"$TMP/pt" >"$TMP/ct"
    assert_size "$TMP/ct" $((256 * 1024 + 16)) "payload plus tag"
    "$BC_RUST" aes256-ccm -d decrypt --key "$KEY_256" --nonce "$NONCE" <"$TMP/ct" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "256 KiB round trip"
}

# `-x` writes hex, and with a supplied nonce the output is deterministic, so it must be exactly the
# hex of what the binary form writes.
test_hex_output_matches_binary_output() {
    local as_hex
    rng 14 >"$TMP/pt"
    "$BC_RUST" aes128-ccm -d encrypt --key "$KEY_128" --nonce "$NONCE" <"$TMP/pt" >"$TMP/ct"
    as_hex=$("$BC_RUST" aes128-ccm -d encrypt --key "$KEY_128" --nonce "$NONCE" -x <"$TMP/pt")
    assert_eq "$as_hex" "$(hex "$TMP/ct")" "-x must be the hex of the binary output"
}

# A ciphertext from one key length must not decrypt under another, even with a right-length key,
# and the failure is the tag check rather than garbage.
test_the_three_variants_are_not_interchangeable() {
    rng 15 >"$TMP/pt"
    "$BC_RUST" aes128-ccm -d encrypt --key "$KEY_128" --nonce "$NONCE" <"$TMP/pt" >"$TMP/ct"
    expect_fail "aes256-ccm must reject an aes128-ccm ciphertext" \
        "$BC_RUST" aes256-ccm -d decrypt --key "$KEY_256" --nonce "$NONCE" <"$TMP/ct"
    assert_stderr_has "authentication failed"
}

# ---- the nonce ------------------------------------------------------------------------------

# The nonce is not written to the output, so `decrypt` needs the same `--nonce`: the sharpest
# difference from the other five commands, all of which prepend their generated IV.
test_the_nonce_is_not_written_to_the_output_and_is_required_to_decrypt() {
    rng 27 >"$TMP/pt"
    "$BC_RUST" aes128-ccm -d encrypt --key "$KEY_128" --nonce "$NONCE" <"$TMP/pt" >"$TMP/ct"
    assert_size "$TMP/ct" $((27 + 16)) "output is ciphertext + tag only; no nonce prefix"
    # A different nonce must fail: it changes both B0 and every counter block.
    expect_fail "a different nonce must fail the tag check" \
        "$BC_RUST" aes128-ccm -d decrypt --key "$KEY_128" --nonce 010102030405060708090a0b <"$TMP/ct"
    assert_stderr_has "authentication failed"
}

# `--nonce-file` is raw bytes, not hex-or-raw guessed like `--key-file`: 12 ASCII bytes that are
# also valid hex text must be used as those 12 bytes, not decoded down to 6 (out of 7..=13).
test_nonce_file_is_raw_bytes_not_hex_decoded() {
    printf 'aabbccddeeff' >"$TMP/nonce_raw.bin"
    rng 35 >"$TMP/pt"
    "$BC_RUST" aes128-ccm -d encrypt --key "$KEY_128" --nonce-file "$TMP/nonce_raw.bin" <"$TMP/pt" >"$TMP/ct"
    # The 12 raw bytes passed directly via --nonce must agree.
    "$BC_RUST" aes128-ccm -d decrypt --key "$KEY_128" --nonce "$(hex "$TMP/nonce_raw.bin")" <"$TMP/ct" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "--nonce-file did not hex-decode its 12 bytes"
    # The would-be hex decoding of those bytes is 6 bytes, which is a bad nonce length.
    expect_fail "the hex reading of the file is a 6-byte nonce" \
        "$BC_RUST" aes128-ccm -d decrypt --key "$KEY_128" --nonce aabbccddeeff <"$TMP/ct"
    assert_stderr_has "nonce is 6 bytes"
}

test_a_missing_nonce_is_rejected_with_an_explanation() {
    rng 4 >"$TMP/pt"
    expect_fail "no nonce" "$BC_RUST" aes128-ccm -d encrypt --key "$KEY_128" <"$TMP/pt"
    assert_stderr_has "--nonce"
    assert_stderr_has "no generated nonce"
}

# Every nonce length A.1 permits works, and nothing else does. The nonce length is not written
# anywhere, so both sides must agree on it too.
test_nonce_len_is_validated_across_a_1_s_whole_range() {
    local n nonce
    rng 13 >"$TMP/pt"
    for n in 7 8 9 10 11 12 13; do
        nonce=$(nonce_of $n 5a)
        "$BC_RUST" aes128-ccm -d encrypt --key "$KEY_128" --nonce "$nonce" <"$TMP/pt" >"$TMP/ct"
        "$BC_RUST" aes128-ccm -d decrypt --key "$KEY_128" --nonce "$nonce" <"$TMP/ct" >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "nonce length $n"
    done
    # A.1: n is an element of {7, ..., 13}.
    for n in 0 1 6 14 16; do
        nonce=$(nonce_of $n 5a)
        expect_fail "nonce length $n" \
            "$BC_RUST" aes128-ccm -d encrypt --key "$KEY_128" --nonce "$nonce" <"$TMP/pt"
        assert_stderr_has "7 to 13"
    done
}

# The nonce length caps the payload (A.1's p < 2^8q, q = 15 - n), and the error gives the numbers.
test_a_payload_past_the_q_limit_is_rejected_with_the_numbers() {
    local nonce
    nonce=$(nonce_of 13 5a) # q = 2, so the limit is 65535 bytes
    rng 65536 >"$TMP/too_big"
    expect_fail "65536 bytes is past the q = 2 limit" \
        "$BC_RUST" aes128-ccm -d encrypt --key "$KEY_128" --nonce "$nonce" <"$TMP/too_big"
    assert_stderr_has "65535"
    assert_stderr_has "65536"

    # One byte under the limit is fine, which pins the boundary rather than just the rejection.
    rng 65535 >"$TMP/ok"
    "$BC_RUST" aes128-ccm -d encrypt --key "$KEY_128" --nonce "$nonce" <"$TMP/ok" >"$TMP/ct"
    assert_size "$TMP/ct" $((65535 + 16)) "65535 bytes is accepted"

    # The decrypt side hits the same limit on the input minus its tag, explained the same way.
    rng $((65536 + 16)) >"$TMP/too_big_sealed"
    expect_fail "65536 bytes of ciphertext plus a tag is past the limit" \
        "$BC_RUST" aes128-ccm -d decrypt --key "$KEY_128" --nonce "$nonce" <"$TMP/too_big_sealed"
    assert_stderr_has "65535"
    assert_stderr_has "65536"
    assert_stderr_has "shorter nonce"
    ! grep -q "GenericError" "$LAST_STDERR" || fail "not the Debug form: $(cat "$LAST_STDERR")"
}

# A nonce file ending in a newline -- the `echo` without `-n` mistake -- is used as it is, since
# stripping it would collapse two different nonces into one, but is warned about: every length in
# 7..=13 is valid, so the only other symptom would be a failed tag check on the far side.
test_a_nonce_file_ending_in_a_newline_is_used_as_is_but_warned_about() {
    { unhex "$NONCE"; printf '\n'; } >"$TMP/nonce_nl.bin"
    unhex "$NONCE" >"$TMP/nonce_clean.bin"
    rng 47 >"$TMP/pt"

    expect_ok "a 13-byte nonce file is still valid" \
        "$BC_RUST" aes128-ccm -d encrypt --key "$KEY_128" --nonce-file "$TMP/nonce_nl.bin" <"$TMP/pt" >"$TMP/ct"
    assert_stderr_has "newline"
    assert_stderr_has "echo -n"

    # The 13 bytes, newline included, are the nonce.
    "$BC_RUST" aes128-ccm -d decrypt --key "$KEY_128" --nonce "$(hex "$TMP/nonce_nl.bin")" <"$TMP/ct" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "decrypting with the 13-byte nonce"
    expect_fail "the 12-byte nonce the file was meant to hold does not decrypt it" \
        "$BC_RUST" aes128-ccm -d decrypt --key "$KEY_128" --nonce "$NONCE" <"$TMP/ct"
    assert_stderr_has "authentication failed"

    # A file without the newline draws no warning.
    expect_ok "a clean nonce file" \
        "$BC_RUST" aes128-ccm -d encrypt --key "$KEY_128" --nonce-file "$TMP/nonce_clean.bin" <"$TMP/pt" >"$TMP/ct"
    assert_size "$LAST_STDERR" 0 "no warning for a clean file"
}

test_nonce_file_read_errors_are_reported_as_read_errors() {
    rng 4 >"$TMP/pt"
    expect_fail "a missing nonce file" \
        "$BC_RUST" aes128-ccm -d encrypt --key "$KEY_128" --nonce-file "$TMP/does-not-exist/nonce.bin" <"$TMP/pt"
    assert_stderr_has "couldn't read file"
    assert_stderr_has "nonce.bin"
}

# ---- the AAD --------------------------------------------------------------------------------

# The AAD is authenticated but not encrypted: it does not change the ciphertext length or the
# ciphertext, it does change the tag, and a mismatch on decryption is caught.
test_the_aad_is_authenticated_but_not_encrypted() {
    rng 7 >"$TMP/pt"
    "$BC_RUST" aes128-ccm -d encrypt --key "$KEY_128" --nonce "$NONCE" --aad 0011 <"$TMP/pt" >"$TMP/with"
    "$BC_RUST" aes128-ccm -d encrypt --key "$KEY_128" --nonce "$NONCE" <"$TMP/pt" >"$TMP/without"
    assert_size "$TMP/with" $(wc -c <"$TMP/without") "AAD does not change the output length"
    head -c 7 "$TMP/with" >"$TMP/with.ct"
    head -c 7 "$TMP/without" >"$TMP/without.ct"
    assert_same "$TMP/with.ct" "$TMP/without.ct" "AAD does not change the ciphertext, only the tag"
    tail -c 16 "$TMP/with" >"$TMP/with.tag"
    tail -c 16 "$TMP/without" >"$TMP/without.tag"
    assert_differs "$TMP/with.tag" "$TMP/without.tag" "AAD changes the tag"

    # Wrong AAD, missing AAD and extra AAD must all be caught.
    expect_fail "wrong AAD" \
        "$BC_RUST" aes128-ccm -d decrypt --key "$KEY_128" --nonce "$NONCE" --aad 0012 <"$TMP/with"
    assert_stderr_has "authentication failed"
    expect_fail "missing AAD" \
        "$BC_RUST" aes128-ccm -d decrypt --key "$KEY_128" --nonce "$NONCE" <"$TMP/with"
    assert_stderr_has "authentication failed"
    expect_fail "extra AAD" \
        "$BC_RUST" aes128-ccm -d decrypt --key "$KEY_128" --nonce "$NONCE" --aad 001100 <"$TMP/with"
    assert_stderr_has "authentication failed"
}

# The file is raw bytes, never hex-decoded: a file holding `ca fe ba be` is the same AAD as
# `--aad cafebabe`, while one holding the eight ASCII characters "cafebabe" is a different AAD.
# And the file wins if both flags are given, as for aes*-gcm.
test_aad_file_is_raw_bytes_and_takes_precedence() {
    unhex cafebabe >"$TMP/aad.bin"
    printf 'cafebabe' >"$TMP/aad.txt"
    rng 36 >"$TMP/pt"
    local enc=("$BC_RUST" aes128-ccm -d encrypt --key "$KEY_128" --nonce "$NONCE")

    "${enc[@]}" --aad cafebabe <"$TMP/pt" >"$TMP/with_hex"
    "${enc[@]}" --aad-file "$TMP/aad.bin" <"$TMP/pt" >"$TMP/with_file"
    assert_same "$TMP/with_hex" "$TMP/with_file" "raw bytes in a file are the same AAD as the hex flag"

    "${enc[@]}" --aad-file "$TMP/aad.txt" <"$TMP/pt" >"$TMP/with_text"
    assert_differs "$TMP/with_hex" "$TMP/with_text" "the file is not hex-decoded"

    "${enc[@]}" --aad 00 --aad-file "$TMP/aad.bin" <"$TMP/pt" >"$TMP/both"
    assert_same "$TMP/with_file" "$TMP/both" "--aad-file takes precedence over --aad"

    "$BC_RUST" aes128-ccm -d decrypt --key "$KEY_128" --nonce "$NONCE" --aad-file "$TMP/aad.bin" <"$TMP/with_file" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "decrypting with the file"
}

# A file with no size to declare -- /dev/null, a character device -- is read whole rather than
# streamed, and an empty one is the same as no AAD at all.
test_a_non_regular_aad_file_is_read_whole() {
    rng 18 >"$TMP/pt"
    "$BC_RUST" aes128-ccm -d encrypt --key "$KEY_128" --nonce "$NONCE" <"$TMP/pt" >"$TMP/without"
    "$BC_RUST" aes128-ccm -d encrypt --key "$KEY_128" --nonce "$NONCE" --aad-file /dev/null <"$TMP/pt" >"$TMP/dev_null"
    assert_same "$TMP/without" "$TMP/dev_null" "an empty AAD file is no AAD"
}

test_a_missing_aad_file_is_reported() {
    rng 4 >"$TMP/pt"
    expect_fail "a missing AAD file" \
        "$BC_RUST" aes128-ccm -d encrypt --key "$KEY_128" --nonce "$NONCE" --aad-file "$TMP/does-not-exist/aad.bin" <"$TMP/pt"
    assert_stderr_has "couldn't read file"
    assert_stderr_has "aad.bin"
}

# ---- the tag --------------------------------------------------------------------------------

# A failed tag check must exit non-zero AND write nothing: SP 800-38C Sec 6.2 requires that on
# INVALID "the payload P and the MAC T shall not be revealed".
test_a_tampered_ciphertext_produces_no_output_at_all() {
    local pos
    rng 256 >"$TMP/pt"
    "$BC_RUST" aes128-ccm -d encrypt --key "$KEY_128" --nonce "$NONCE" <"$TMP/pt" >"$TMP/ct"
    # A flipped bit in the first and last ciphertext bytes, then the first and last tag bytes.
    for pos in 0 255 256 271; do
        cp "$TMP/ct" "$TMP/bad"
        flip_byte "$TMP/bad" "$pos"
        if "$BC_RUST" aes128-ccm -d decrypt --key "$KEY_128" --nonce "$NONCE" <"$TMP/bad" >"$TMP/out" 2>"$LAST_STDERR"; then
            fail "a flipped bit at $pos must fail"
        fi
        assert_size "$TMP/out" 0 "no plaintext may be written when the tag check fails (flipped byte $pos)"
        assert_stderr_has "authentication failed"
    done
}

# `--tag-len` changes the output length and must match on both sides, and only A.1's values are
# accepted.
test_tag_len_is_validated_and_must_match() {
    local t
    rng 18 >"$TMP/pt"
    for t in 4 6 8 10 12 14 16; do
        "$BC_RUST" aes128-ccm -d encrypt --key "$KEY_128" --nonce "$NONCE" --tag-len $t <"$TMP/pt" >"$TMP/ct"
        assert_size "$TMP/ct" $((18 + t)) "tag-len $t"
        "$BC_RUST" aes128-ccm -d decrypt --key "$KEY_128" --nonce "$NONCE" --tag-len $t <"$TMP/ct" >"$TMP/rec"
        assert_same "$TMP/pt" "$TMP/rec" "tag-len $t round trip"
    done
    # A.1: t is an element of {4, 6, 8, 10, 12, 14, 16}. Odd values and out-of-range are refused.
    for t in 0 2 5 15 17 32; do
        expect_fail "tag-len $t" \
            "$BC_RUST" aes128-ccm -d encrypt --key "$KEY_128" --nonce "$NONCE" --tag-len $t <"$TMP/pt"
        assert_stderr_has "tag-len"
        assert_stderr_has "A.1"
    done
    # A tag-len mismatch between the two sides is caught rather than silently truncating.
    "$BC_RUST" aes128-ccm -d encrypt --key "$KEY_128" --nonce "$NONCE" --tag-len 16 <"$TMP/pt" >"$TMP/ct"
    expect_fail "16 on one side, 8 on the other" \
        "$BC_RUST" aes128-ccm -d decrypt --key "$KEY_128" --nonce "$NONCE" --tag-len 8 <"$TMP/ct"
    assert_stderr_has "authentication failed"
}

# An invalid tag length is a command-line error, so it must be rejected without waiting for EOF on
# the payload pipe: stdin here is held open by a sleeping writer, and `timeout` reports 124 if the
# command waited for it.
test_invalid_tag_len_is_rejected_before_stdin_is_read() {
    local status=0
    timeout 2 "$BC_RUST" aes128-ccm -d encrypt --key "$KEY_128" --nonce "$NONCE" --tag-len 5 \
        < <(sleep 5) >/dev/null 2>"$LAST_STDERR" || status=$?
    [ "$status" -ne 124 ] || fail "invalid --tag-len waited for stdin EOF"
    [ "$status" -ne 0 ] || fail "an invalid --tag-len must be rejected"
    assert_stderr_has "tag-len"
    assert_stderr_has "A.1"
}

# Sec 6.2 step 1: a C too short to contain a tag is rejected before anything else; exactly the tag
# length is an empty payload plus its tag, which is valid (Sec 5.3 footnote).
test_an_input_shorter_than_the_tag_is_rejected() {
    local len
    for len in 0 1 15; do
        rng $len >"$TMP/short"
        expect_fail "a $len-byte input cannot carry a 16-byte tag" \
            "$BC_RUST" aes128-ccm -d decrypt --key "$KEY_128" --nonce "$NONCE" <"$TMP/short"
        assert_stderr_has "shorter than"
    done
    : >"$TMP/empty"
    "$BC_RUST" aes128-ccm -d encrypt --key "$KEY_128" --nonce "$NONCE" <"$TMP/empty" >"$TMP/ct"
    assert_size "$TMP/ct" 16 "an empty payload encrypts to just the tag"
    "$BC_RUST" aes128-ccm -d decrypt --key "$KEY_128" --nonce "$NONCE" <"$TMP/ct" >"$TMP/rec"
    assert_size "$TMP/rec" 0 "and round trips to nothing"
}

# ---- keys -----------------------------------------------------------------------------------

# Key loading is shared with aes*-cbc; checked here so the CCM commands are not assumed to inherit
# it.
test_a_key_of_the_wrong_length_is_rejected() {
    rng 4 >"$TMP/pt"
    expect_fail "a 32-byte key is not an AES-128 key" \
        "$BC_RUST" aes128-ccm -d encrypt --key "$KEY_256" --nonce "$NONCE" <"$TMP/pt"
    assert_stderr_has "16-byte key"
    expect_fail "neither --key nor --key-file" \
        "$BC_RUST" aes128-ccm -d encrypt --nonce "$NONCE" <"$TMP/pt"
    assert_stderr_has "key"
}

# ---- help -----------------------------------------------------------------------------------

# The subcommands are listed in --help, and their own help documents what differs from the other
# modes: the supplied nonce, the non-streaming behaviour, and the nonce-reuse hazard.
test_the_subcommands_are_documented_in_help() {
    local cmd
    "$BC_RUST" --help >"$TMP/help"
    for cmd in aes128-ccm aes192-ccm aes256-ccm; do
        grep -q "$cmd" "$TMP/help" || fail "$cmd should be listed in --help"
    done
    "$BC_RUST" aes128-ccm --help >"$TMP/cmd_help"
    grep -q -e "NOT GENERATED" -e "SUPPLIED" "$TMP/cmd_help" || fail "the help should say the nonce is supplied"
    grep -qi "does not stream" "$TMP/cmd_help" || fail "the help should say it does not stream"
    grep -q "never reuse a nonce" "$TMP/cmd_help" || fail "the help should warn about nonce reuse"
    grep -q -- "--tag-len" "$TMP/cmd_help" && grep -q "defaults to 16" "$TMP/cmd_help" \
        || fail "the help should identify the option that has a default"
    ! grep -q "usual choice and the default" "$TMP/cmd_help" \
        || fail "the help must not claim the required nonce has a default"
}

run_all
