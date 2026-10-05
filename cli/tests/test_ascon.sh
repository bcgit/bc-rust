#!/usr/bin/env bash
# The ascon-hash256 / ascon-xof128 / ascon-cxof128 / ascon-aead-128 subcommands, end to end
# through the binary.
#
# Framing for the AEAD: encrypt writes a fresh 16-byte nonce as the first bytes of its output,
# the 16-byte tag rides at the end of the ciphertext, and `--ad` is authenticated but not
# encrypted. There is no way to supply a nonce, so the AEAD has no known-answer test here; its
# vectors are pinned in `crypto/ascon/tests/*.rs`. Keys and data come from `bc-rust rng`; the
# fixed hash/XOF inputs are the NIST LWC known-answer values from the same Rust suites.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

NONCE_LEN=16
TAG_LEN=16

# ---- ascon-hash256 ------------------------------------------------------------------------

# LWC_HASH_KAT_256.txt Count 1: the digest of the empty message.
test_hash256_matches_the_kat_for_the_empty_message() {
    local got
    got=$(hex_out "$BC_RUST" ascon-hash256 -x </dev/null)
    assert_eq "$got" "0b3be5850f2f6b98caf29f8fdea89b64a1fa70aa249b8f839bd53baa304d92b2" "empty-message digest"
}

# LWC_HASH_KAT_256.txt Count 9.
test_hash256_matches_the_kat_for_a_multi_byte_message() {
    local got
    unhex 0001020304050607 >"$TMP/msg"
    got=$(hex_out "$BC_RUST" ascon-hash256 -x <"$TMP/msg")
    assert_eq "$got" "b88e497ae8e6fb641b87ef622eb8f2fca0ed95383f7ffebe167acf1099ba764f" "8-byte message digest"
}

# ---- ascon-xof128 --------------------------------------------------------------------------

# LWC_XOF_KAT_128_512.txt Count 1: 64 bytes squeezed after absorbing the empty message.
test_xof128_matches_the_kat_for_the_empty_message() {
    local got
    got=$(hex_out "$BC_RUST" ascon-xof128 64 -x </dev/null)
    assert_eq "$got" \
        "473d5e6164f58b39dfd84aacdb8ae42ec2d91fed33388ee0d960d9b3993295c6ad77855a5d3b13fe6ad9e6098988373af7d0956d05a8f1665d2c67d1a3ad10ff" \
        "64-byte squeeze of the empty message"
}

# The output length is the caller's choice, and shorter output is a prefix of longer output --
# every XOF's defining property, pinned here because the CLI turns the length into a positional
# argument.
test_xof128_output_length_is_a_prefix_of_a_longer_squeeze() {
    local full short
    full=$(hex_out "$BC_RUST" ascon-xof128 64 -x </dev/null)
    short=$(hex_out "$BC_RUST" ascon-xof128 16 -x </dev/null)
    assert_eq "${#short}" 32 "16 bytes is 32 hex characters"
    assert_eq "${full:0:32}" "$short" "the 16-byte squeeze must be a prefix of the 64-byte one"
}

# ---- ascon-cxof128 -------------------------------------------------------------------------

# LWC_CXOF_KAT_128_512.txt Count 4: message `00`, customization `10`.
test_cxof128_matches_the_kat() {
    local got
    unhex 00 >"$TMP/msg"
    got=$(hex_out "$BC_RUST" ascon-cxof128 64 --customization 10 -x <"$TMP/msg")
    assert_eq "$got" \
        "63fa8ba86382f2d544580f51322d080424b42c556eb74503cd73cf052bb993bd6f5210984c71c9c445f43ccc5b158226e509bd339cd634414377f79411aa8d5c" \
        "customized squeeze"
}

# No `--customization` at all must give the same output as an empty one: the CLI's optional
# argument must treat "absent" and "empty" identically.
test_cxof128_with_no_customization_matches_an_empty_one() {
    local without with_empty
    without=$(hex_out "$BC_RUST" ascon-cxof128 64 -x </dev/null)
    with_empty=$(hex_out "$BC_RUST" ascon-cxof128 64 --customization "" -x </dev/null)
    assert_eq "$without" "$with_empty" "absent and empty customization must agree"
    # LWC_CXOF_KAT_128_512.txt Count 1: message and customization both empty.
    assert_eq "$without" \
        "4f50159ef70bb3dad8807e034eaebd44c4fa2cbbc8cf1f05511ab66cdcc529905ca12083fc186ad899b270b1473dc5f7ec88d1052082dcdfe69fb75d269e7b74" \
        "empty-message, empty-customization squeeze"
}

# ---- ascon-aead-128: round trips --------------------------------------------------------------

test_aead128_encrypt_then_decrypt_round_trips() {
    rng 16 >"$TMP/key"
    rng 4096 >"$TMP/pt"
    "$BC_RUST" ascon-aead-128 -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
    assert_size "$TMP/ct" $((4096 + NONCE_LEN + TAG_LEN)) "ciphertext is nonce plus plaintext plus tag"
    "$BC_RUST" ascon-aead-128 -d decrypt --key-file "$TMP/key" <"$TMP/ct" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "decrypt must recover the plaintext"
}

test_aead128_associated_data_round_trips() {
    rng 16 >"$TMP/key"
    rng 256 >"$TMP/pt"
    "$BC_RUST" ascon-aead-128 -d encrypt --key-file "$TMP/key" --ad deadbeef <"$TMP/pt" >"$TMP/ct"
    "$BC_RUST" ascon-aead-128 -d decrypt --key-file "$TMP/key" --ad deadbeef <"$TMP/ct" >"$TMP/rec"
    assert_same "$TMP/pt" "$TMP/rec" "the same AD on both sides must round-trip"
}

test_aead128_each_invocation_uses_a_fresh_nonce() {
    rng 16 >"$TMP/key"
    rng 32 >"$TMP/pt"
    "$BC_RUST" ascon-aead-128 -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct1"
    "$BC_RUST" ascon-aead-128 -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct2"
    assert_size "$TMP/ct1" $((32 + NONCE_LEN + TAG_LEN)) "first ciphertext length"
    assert_size "$TMP/ct2" $((32 + NONCE_LEN + TAG_LEN)) "second ciphertext length"
    head -c $NONCE_LEN "$TMP/ct1" >"$TMP/n1"
    head -c $NONCE_LEN "$TMP/ct2" >"$TMP/n2"
    assert_differs "$TMP/n1" "$TMP/n2" "two encryptions must draw different nonces"
}

# ---- ascon-aead-128: rejected inputs --------------------------------------------------------

test_aead128_wrong_associated_data_is_rejected() {
    rng 16 >"$TMP/key"
    rng 64 >"$TMP/pt"
    "$BC_RUST" ascon-aead-128 -d encrypt --key-file "$TMP/key" --ad deadbeef <"$TMP/pt" >"$TMP/ct"
    expect_fail "different AD must fail the tag check" \
        "$BC_RUST" ascon-aead-128 -d decrypt --key-file "$TMP/key" --ad cafebabe <"$TMP/ct"
    assert_stderr_has "authentication failed"
}

test_aead128_a_flipped_ciphertext_byte_is_rejected() {
    rng 16 >"$TMP/key"
    rng 64 >"$TMP/pt"
    "$BC_RUST" ascon-aead-128 -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
    flip_byte "$TMP/ct" $NONCE_LEN
    expect_fail "a flipped ciphertext byte must fail the tag check" \
        "$BC_RUST" ascon-aead-128 -d decrypt --key-file "$TMP/key" <"$TMP/ct"
    assert_stderr_has "authentication failed"
}

test_aead128_a_flipped_tag_byte_is_rejected() {
    rng 16 >"$TMP/key"
    rng 64 >"$TMP/pt"
    "$BC_RUST" ascon-aead-128 -d encrypt --key-file "$TMP/key" <"$TMP/pt" >"$TMP/ct"
    flip_byte "$TMP/ct" $(($(wc -c <"$TMP/ct") - 1))
    expect_fail "a flipped tag byte must fail the tag check" \
        "$BC_RUST" ascon-aead-128 -d decrypt --key-file "$TMP/key" <"$TMP/ct"
    assert_stderr_has "authentication failed"
}

# Decrypt input shorter than the generated 16-byte nonce is rejected before any tag check is
# attempted, including the empty-input case.
test_aead128_decrypt_input_shorter_than_the_nonce_is_rejected() {
    local len
    rng 16 >"$TMP/key"
    for len in 0 1 15; do
        rng "$len" >"$TMP/short"
        expect_fail "$len bytes cannot hold a 16-byte nonce" \
            "$BC_RUST" ascon-aead-128 -d decrypt --key-file "$TMP/key" <"$TMP/short"
        assert_stderr_has "shorter than the 16-byte nonce"
    done
}

# ---- help -----------------------------------------------------------------------------------

test_the_subcommands_are_listed_in_help() {
    local name
    "$BC_RUST" --help >"$TMP/help"
    for name in ascon-hash256 ascon-xof128 ascon-cxof128 ascon-aead-128; do
        grep -q -- "$name" "$TMP/help" || fail "--help should list $name"
    done
}

run_all
