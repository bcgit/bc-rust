#!/usr/bin/env bash
# The blake2b-512 / blake2s-256 / blake2b-512-mac / blake2s-256-mac / blake3 / blake3-keyed-hash
# / blake3-derive-key subcommands, end to end through the binary: known answers in hex and binary,
# --length, --key / --key-file loading, key-length rejection and the --verify exit codes.
#
# The known-answer values were copied by script, never retyped, from the vectors embedded in the
# algorithm crates' tests: for BLAKE2, `RFC_ABC` (RFC 7693 Appendix A / B) and the `KAT` table
# (from the official BLAKE2 KAT, github.com/BLAKE2/BLAKE2 testvectors/blake2-kat.json; message
# bytes 0, 1, ..., len - 1, key bytes 0, 1, ..., kk - 1) in crypto/blake2/tests/blake2{b,s}_tests.rs;
# for BLAKE3, crypto/blake3/tests/vectors/mod.rs (from the official
# github.com/BLAKE3-team/BLAKE3 test_vectors/test_vectors.json; input bytes i % 251).

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# RFC 7693 Appendix A / B: BLAKE2b-512("abc") / BLAKE2s-256("abc").
BLAKE2B_ABC=ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923
BLAKE2S_ABC=508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982
# blake2-kat.json, message 0, 1, ..., 254: unkeyed, and keyed with the bytes 0, 1, ..., kk - 1.
BLAKE2B_255=5b21c5fd8868367612474fa2e70e9cfa2201ffeee8fafab5797ad58fefa17c9b5b107da4a3db6320baaf2c8617d5a51df914ae88da3867c2d41f0cc14fa67928
BLAKE2B_255_KEYED=142709d62e28fcccd0af97fad0f8465b971e82201dc51070faa0372aa43e92484be1c1e73ba10906d5d1853db6a4106e0a7bf9800d373d6dee2d46d62ef2a461
BLAKE2S_255=f03f5789d3336b80d002d59fdf918bdb775b00956ed5528e86aa994acb38fe2d
BLAKE2S_255_KEYED=3fb735061abc519dfe979e54c1ee5bfad0a9d858b3315bad34bde999efd724dd
# blake2-kat.json, empty message, keyed.
BLAKE2B_0_KEYED=10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568
BLAKE2S_0_KEYED=48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49
# test_vectors.json `key` and `context_string` fields.
BLAKE3_KEY="whats the Elvish word for friend"
BLAKE3_CONTEXT="BLAKE3 2019-12-27 16:29:52 test vectors context"
# test_vectors.json, input_len 0: the 131-byte hash, keyed_hash and derive_key outputs.
BLAKE3_0_HASH=af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a26f5487789e8f660afe6c99ef9e0c52b92e7393024a80459cf91f476f9ffdbda7001c22e159b402631f277ca96f2defdf1078282314e763699a31c5363165421cce14d
BLAKE3_0_KEYED=92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26b18171a2f22a4b94822c701f107153dba24918c4bae4d2945c20ece13387627d3b73cbf97b797d5e59948c7ef788f54372df45e45e4293c7dc18c1d41144a9758be58960856be1eabbe22c2653190de560ca3b2ac4aa692a9210694254c371e851bc8f
BLAKE3_0_DERIVE=2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d905630c8be290dfcf3e6842f13bddd573c098c3f17361f1f206b8cad9d088aa4a3f746752c6b0ce6a83b0da81d59649257cdf8eb3e9f7d4998e41021fac119deefb896224ac99f860011f73609e6e0e4540f93b273e56547dfd3aa1a035ba6689d89a0
# test_vectors.json, input_len 1025: the 131-byte hash, keyed_hash and derive_key outputs.
BLAKE3_1025_HASH=d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444f4c4a22b4b399155358a994e52bf255de60035742ec71bd08ac275a1b51cc6bfe332b0ef84b409108cda080e6269ed4b3e2c3f7d722aa4cdc98d16deb554e5627be8f955c98e1d5f9565a9194cad0c4285f93700062d9595adb992ae68ff12800ab67a
BLAKE3_1025_KEYED=357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea69362396b77fdc0d2634a552970843722066c3c15902ae5097e00ff53f1e116f1cd5352720113a837ab2452cafbde4d54085d9cf5d21ca613071551b25d52e69d6c81123872b6f19cd3bc1333edf0c52b94de23ba772cf82636cff4542540a7738d5b930
BLAKE3_1025_DERIVE=effaa245f065fbf82ac186839a249707c3bddf6d3fdda22d1b95a3c970379bcb5d31013a167509e9066273ab6e2123bc835b408b067d88f96addb550d96b6852dad38e320b9d940f86db74d398c770f462118b35d2724efa13da97194491d96dd37c3c09cbef665953f2ee85ec83d88b88d11547a6f911c8217cca46defa2751e7f3ad
# test_vectors.json, input_len 102400 (100 x the 1 KiB read buffer): the hash output.
BLAKE3_102400_HASH=bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085e01c59dab908c04c3342b816941a26d69c2605ebee5ec5291cc55e15b76146e6745f0601156c3596cb75065a9c57f35585a52e1ac70f69131c23d611ce11ee4ab1ec2c009012d236648e77be9295dd0426f29b764d65de58eb7d01dd42248204f45f8e


# ---- inputs ---------------------------------------------------------------------------------

# `counting N` writes the bytes 0, 1, ..., N - 1 (mod 256): the BLAKE2 KAT message and key.
counting() {
    local i out=''
    for ((i = 0; i < $1; i++)); do out+=$(printf '%02x' $((i % 256))); done
    unhex "$out"
}

# `counting_hex N`: the same bytes, as hex.
counting_hex() {
    counting "$1" | "$BC_RUST" hex-encode
}

# `blake3_input N` writes the BLAKE3 test-vector input: "a repeating sequence of 251 bytes: 0, 1,
# 2, ..., 249, 250, 0, 1, ..." (test_vectors.json `_comment`).
blake3_input() {
    local i block=''
    for ((i = 0; i < 251; i++)); do block+=$(printf '%02x' "$i"); done
    local reps=$(($1 / 251 + 1)) all=''
    for ((i = 0; i < reps; i++)); do all+=$block; done
    unhex "${all:0:$((2 * $1))}"
}

# `bin_hex CMD...` runs CMD, whose binary output ends in the newline every digest command
# writes, and prints that output without the newline, as hex.
bin_hex() {
    "$@" >"$TMP/.bin"
    assert_eq "$(tail -c 1 "$TMP/.bin" | "$BC_RUST" hex-encode)" 0a "binary output ends in a newline"
    head -c -1 "$TMP/.bin" | "$BC_RUST" hex-encode
}

# ---- blake2b-512 / blake2s-256 --------------------------------------------------------------

test_blake2_hashes_match_rfc7693_appendices() {
    printf abc >"$TMP/msg"
    assert_eq "$(hex_out "$BC_RUST" blake2b-512 -x <"$TMP/msg")" "$BLAKE2B_ABC" "BLAKE2b-512(abc)"
    assert_eq "$(hex_out "$BC_RUST" blake2s-256 -x <"$TMP/msg")" "$BLAKE2S_ABC" "BLAKE2s-256(abc)"
}

# A two-block (BLAKE2b) / four-block (BLAKE2s) message from the official KAT, in hex and binary.
test_blake2_hashes_match_the_official_kat_in_hex_and_binary() {
    counting 255 >"$TMP/msg"
    assert_eq "$(hex_out "$BC_RUST" blake2b-512 -x <"$TMP/msg")" "$BLAKE2B_255" "blake2b hex"
    assert_eq "$(bin_hex "$BC_RUST" blake2b-512 <"$TMP/msg")" "$BLAKE2B_255" "blake2b binary"
    assert_eq "$(hex_out "$BC_RUST" blake2s-256 -x <"$TMP/msg")" "$BLAKE2S_255" "blake2s hex"
    assert_eq "$(bin_hex "$BC_RUST" blake2s-256 <"$TMP/msg")" "$BLAKE2S_255" "blake2s binary"
}

# ---- blake2b-512-mac / blake2s-256-mac ------------------------------------------------------

test_blake2_macs_match_the_official_keyed_kat_in_hex_and_binary() {
    local kb ks
    counting 255 >"$TMP/msg"
    kb=$(counting_hex 64)
    ks=$(counting_hex 32)
    assert_eq "$(hex_out "$BC_RUST" blake2b-512-mac --key "$kb" -x <"$TMP/msg")" \
        "$BLAKE2B_255_KEYED" "blake2b-512-mac hex"
    assert_eq "$(bin_hex "$BC_RUST" blake2b-512-mac --key "$kb" <"$TMP/msg")" \
        "$BLAKE2B_255_KEYED" "blake2b-512-mac binary"
    assert_eq "$(hex_out "$BC_RUST" blake2b-512-mac --key "$kb" -x </dev/null)" \
        "$BLAKE2B_0_KEYED" "blake2b-512-mac, empty message"
    assert_eq "$(hex_out "$BC_RUST" blake2s-256-mac --key "$ks" -x <"$TMP/msg")" \
        "$BLAKE2S_255_KEYED" "blake2s-256-mac hex"
    assert_eq "$(bin_hex "$BC_RUST" blake2s-256-mac --key "$ks" <"$TMP/msg")" \
        "$BLAKE2S_255_KEYED" "blake2s-256-mac binary"
    assert_eq "$(hex_out "$BC_RUST" blake2s-256-mac --key "$ks" -x </dev/null)" \
        "$BLAKE2S_0_KEYED" "blake2s-256-mac, empty message"
}

# `blake2_verify SUBCOMMAND KEY_LEN TAG` checks the --verify exit codes for one variant. The tag
# must match in full, including length (MAC::do_verify_final).
blake2_verify() {
    local sub=$1 key tag=$3
    key=$(counting_hex "$2")
    counting 255 >"$TMP/msg"
    expect_ok "the right tag verifies" "$BC_RUST" "$sub" --key "$key" -v "$tag" <"$TMP/msg"
    assert_eq "$("$BC_RUST" "$sub" --key "$key" -v "$tag" <"$TMP/msg")" "" "verify writes nothing"
    expect_fail "a wrong tag fails" \
        "$BC_RUST" "$sub" --key "$key" -v "$(flip_hex "$tag" 0 1)" <"$TMP/msg"
    expect_fail "a truncated tag fails" \
        "$BC_RUST" "$sub" --key "$key" -v "${tag:0:$((${#tag} - 2))}" <"$TMP/msg"
}

test_blake2b_512_mac_verify_exit_codes() {
    blake2_verify blake2b-512-mac 64 "$BLAKE2B_255_KEYED"
}

test_blake2s_256_mac_verify_exit_codes() {
    blake2_verify blake2s-256-mac 32 "$BLAKE2S_255_KEYED"
}

# The key file holds raw bytes, like the HMAC commands' --key-file; it wins over --key.
test_blake2_mac_key_file_is_loaded_as_raw_bytes() {
    counting 255 >"$TMP/msg"
    counting 64 >"$TMP/key64"
    counting 32 >"$TMP/key32"
    assert_eq "$(hex_out "$BC_RUST" blake2b-512-mac --key-file "$TMP/key64" -x <"$TMP/msg")" \
        "$BLAKE2B_255_KEYED" "blake2b-512-mac --key-file"
    assert_eq "$(hex_out "$BC_RUST" blake2s-256-mac -k "$TMP/key32" -x <"$TMP/msg")" \
        "$BLAKE2S_255_KEYED" "blake2s-256-mac -k"
    assert_eq "$(hex_out "$BC_RUST" blake2s-256-mac -k "$TMP/key32" --key 00 -x <"$TMP/msg")" \
        "$BLAKE2S_255_KEYED" "the key file wins over --key"
}

# RFC 7693 s. 2.1 table, "Key bytes": "0 <= kk <= 64" (BLAKE2b) / "0 <= kk <= 32" (BLAKE2s);
# kk = 0 is the unkeyed hash, which is the other command.
test_blake2_mac_rejects_bad_keys() {
    local sub
    printf abc >"$TMP/msg"
    expect_fail "a 33-byte key" "$BC_RUST" blake2s-256-mac --key "$(counting_hex 33)" <"$TMP/msg"
    assert_stderr_has "1 to 32 bytes"
    expect_fail "a 65-byte key" "$BC_RUST" blake2b-512-mac --key "$(counting_hex 65)" <"$TMP/msg"
    assert_stderr_has "1 to 64 bytes"
    for sub in blake2b-512-mac blake2s-256-mac; do
        expect_fail "$sub: an empty key" "$BC_RUST" "$sub" --key "" <"$TMP/msg"
        assert_stderr_has "got 0 bytes"
        expect_fail "$sub: no key" "$BC_RUST" "$sub" <"$TMP/msg"
        assert_stderr_has "must be supplied"
        expect_fail "$sub: bad hex" "$BC_RUST" "$sub" --key "not hex" <"$TMP/msg"
        assert_stderr_has "not valid hex"
    done
}

# ---- blake3 ---------------------------------------------------------------------------------

test_blake3_default_length_is_the_first_32_bytes_of_the_vector() {
    blake3_input 1025 >"$TMP/msg"
    assert_eq "$(hex_out "$BC_RUST" blake3 -x </dev/null)" "${BLAKE3_0_HASH:0:64}" "empty input"
    assert_eq "$(hex_out "$BC_RUST" blake3 -x <"$TMP/msg")" "${BLAKE3_1025_HASH:0:64}" "hex"
    assert_eq "$(bin_hex "$BC_RUST" blake3 <"$TMP/msg")" "${BLAKE3_1025_HASH:0:64}" "binary"
}

# The full 131-byte extended output, and BLAKE3 spec s. 2.6, "Shorter outputs are prefixes of
# longer ones", at lengths on both sides of the 64-byte output block.
test_blake3_length_selects_a_prefix_of_the_xof_stream() {
    local len
    blake3_input 1025 >"$TMP/msg"
    assert_eq "$(hex_out "$BC_RUST" blake3 --length 131 -x <"$TMP/msg")" "$BLAKE3_1025_HASH" \
        "131 bytes"
    assert_eq "$(bin_hex "$BC_RUST" blake3 -l 131 <"$TMP/msg")" "$BLAKE3_1025_HASH" \
        "131 bytes, binary"
    for len in 0 1 31 33 63 64 65 100; do
        assert_eq "$(hex_out "$BC_RUST" blake3 -l "$len" -x <"$TMP/msg")" \
            "${BLAKE3_1025_HASH:0:$((2 * len))}" "length $len"
    done
}

# 100 KiB is many 1 KiB reads and many 1 KiB chunks: the streaming loop and the CV stack together.
test_blake3_streams_a_long_input() {
    blake3_input 102400 >"$TMP/msg"
    assert_eq "$(hex_out "$BC_RUST" blake3 -x <"$TMP/msg")" "${BLAKE3_102400_HASH:0:64}" "100 KiB"
}

# ---- blake3-keyed-hash ----------------------------------------------------------------------

test_blake3_keyed_hash_matches_the_vector_in_hex_and_binary() {
    local key
    key=$(printf '%s' "$BLAKE3_KEY" | "$BC_RUST" hex-encode)
    blake3_input 1025 >"$TMP/msg"
    assert_eq "$(hex_out "$BC_RUST" blake3-keyed-hash --key "$key" -x <"$TMP/msg")" \
        "${BLAKE3_1025_KEYED:0:64}" "hex"
    assert_eq "$(bin_hex "$BC_RUST" blake3-keyed-hash --key "$key" <"$TMP/msg")" \
        "${BLAKE3_1025_KEYED:0:64}" "binary"
    assert_eq "$(hex_out "$BC_RUST" blake3-keyed-hash --key "$key" --length 131 -x <"$TMP/msg")" \
        "$BLAKE3_1025_KEYED" "131 bytes"
    assert_eq "$(hex_out "$BC_RUST" blake3-keyed-hash --key "$key" -x </dev/null)" \
        "${BLAKE3_0_KEYED:0:64}" "empty input"
}

test_blake3_keyed_hash_verify_exit_codes() {
    local key tag=${BLAKE3_1025_KEYED:0:64}
    key=$(printf '%s' "$BLAKE3_KEY" | "$BC_RUST" hex-encode)
    blake3_input 1025 >"$TMP/msg"
    expect_ok "the right tag verifies" "$BC_RUST" blake3-keyed-hash --key "$key" -v "$tag" <"$TMP/msg"
    assert_eq "$("$BC_RUST" blake3-keyed-hash --key "$key" -v "$tag" <"$TMP/msg")" "" \
        "verify writes nothing"
    expect_fail "a wrong tag fails" \
        "$BC_RUST" blake3-keyed-hash --key "$key" -v "$(flip_hex "$tag" 31 128)" <"$TMP/msg"
    # The tag is the 32-byte default output; neither a prefix nor the extended output verifies.
    expect_fail "a truncated tag fails" \
        "$BC_RUST" blake3-keyed-hash --key "$key" -v "${tag:0:62}" <"$TMP/msg"
    expect_fail "a 33-byte tag fails" \
        "$BC_RUST" blake3-keyed-hash --key "$key" -v "${BLAKE3_1025_KEYED:0:66}" <"$TMP/msg"
    # --verify checks the 32-byte tag, so a different --length is refused, not ignored.
    expect_fail "--verify with --length" \
        "$BC_RUST" blake3-keyed-hash --key "$key" -v "$tag" -l 64 <"$TMP/msg"
    assert_stderr_has "cannot be combined with --length"
}

test_blake3_keyed_hash_key_file_is_loaded_as_raw_bytes() {
    printf '%s' "$BLAKE3_KEY" >"$TMP/key"
    blake3_input 1025 >"$TMP/msg"
    assert_eq "$(hex_out "$BC_RUST" blake3-keyed-hash -k "$TMP/key" -x <"$TMP/msg")" \
        "${BLAKE3_1025_KEYED:0:64}" "key file"
}

# BLAKE3 spec s. 2.3: keyed_hash takes "a 256-bit key"; any other length is refused with a
# message and a non-zero exit, whether it comes from --key or --key-file.
test_blake3_keyed_hash_rejects_a_key_that_is_not_32_bytes() {
    local len hex
    hex=$(printf '%s%s' "$BLAKE3_KEY" "$BLAKE3_KEY" | "$BC_RUST" hex-encode)
    printf abc >"$TMP/msg"
    for len in 0 1 16 31 33 64; do
        expect_fail "a $len-byte key" \
            "$BC_RUST" blake3-keyed-hash --key "${hex:0:$((2 * len))}" <"$TMP/msg"
        assert_stderr_has "requires a 32-byte key"
    done
    printf '%s' "${BLAKE3_KEY:0:31}" >"$TMP/key31"
    expect_fail "a 31-byte key file" "$BC_RUST" blake3-keyed-hash -k "$TMP/key31" <"$TMP/msg"
    assert_stderr_has "got 31 bytes"
}

# ---- blake3-derive-key ----------------------------------------------------------------------

test_blake3_derive_key_matches_the_vector() {
    blake3_input 1025 >"$TMP/msg"
    assert_eq "$(hex_out "$BC_RUST" blake3-derive-key --context "$BLAKE3_CONTEXT" -x <"$TMP/msg")" \
        "${BLAKE3_1025_DERIVE:0:64}" "hex"
    assert_eq "$(bin_hex "$BC_RUST" blake3-derive-key --context "$BLAKE3_CONTEXT" <"$TMP/msg")" \
        "${BLAKE3_1025_DERIVE:0:64}" "binary"
    assert_eq "$(hex_out "$BC_RUST" blake3-derive-key -c "$BLAKE3_CONTEXT" -l 131 -x <"$TMP/msg")" \
        "$BLAKE3_1025_DERIVE" "131 bytes"
    assert_eq "$(hex_out "$BC_RUST" blake3-derive-key -c "$BLAKE3_CONTEXT" -x </dev/null)" \
        "${BLAKE3_0_DERIVE:0:64}" "empty key material"
}

# The context is part of the function: a different context gives an unrelated key, and the
# command will not run without one.
test_blake3_derive_key_requires_and_binds_the_context() {
    local other
    blake3_input 1025 >"$TMP/msg"
    other=$(hex_out "$BC_RUST" blake3-derive-key -c "another context" -x <"$TMP/msg")
    [ "$other" != "${BLAKE3_1025_DERIVE:0:64}" ] || fail "the context must change the key"
    [ "$other" != "${BLAKE3_1025_HASH:0:64}" ] || fail "derive_key is not the plain hash"
    expect_fail "no context" "$BC_RUST" blake3-derive-key -x <"$TMP/msg"
}

run_all
