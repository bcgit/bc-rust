#!/usr/bin/env bash
# The ed25519 and ed25519ph subcommands, end to end through the binary: Ed25519 and Ed25519ph
# signatures (RFC 8032 Section 5.1) on one key pair.
#
# The known answers are RFC 8032 Section 7.1 (Ed25519) and Section 7.3 (Ed25519ph), lifted by
# script from crypto/ed/tests/ed25519_rfc8032_tests.rs. Hex keys and signatures are read under
# --hex-input; without it they are raw bytes. The message on stdin is always raw.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# RFC 8032 Section 7.1, TEST 1.
T1_SK=9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
T1_PK=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
T1_MSG=
T1_SIG=e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b

# RFC 8032 Section 7.1, TEST 2.
T2_SK=4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb
T2_PK=3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
T2_MSG=72
T2_SIG=92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00

# RFC 8032 Section 7.1, TEST 3.
T3_SK=c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7
T3_PK=fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025
T3_MSG=af82
T3_SIG=6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a

# RFC 8032 Section 7.1, TEST 1024.
T1024_SK=f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5
T1024_PK=278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e
T1024_MSG=08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0
T1024_SIG=0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03

# RFC 8032 Section 7.3, TEST abc.
PH_SK=833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42
PH_PK=ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf
PH_MSG=616263
PH_SIG=98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406
# ---- known answers ------------------------------------------------------------------------

# `kat CMD NAME SK PK MSG SIG`: the public key, the signature and its verification.
kat() {
    local cmd=$1 name=$2 sk=$3 pk=$4 msg=$5 sig=$6 got
    printf '%s' "$sk" >"$TMP/sk"
    printf '%s' "$pk" >"$TMP/pk"
    printf '%s' "$sig" >"$TMP/sig"
    unhex "$msg" >"$TMP/msg"
    got=$(hex_out "$BC_RUST" --hex-input "$cmd" pk-from-sk --skfile "$TMP/sk" -x)
    assert_eq "$got" "$pk" "$name: public key"
    got=$(hex_out "$BC_RUST" --hex-input "$cmd" sign --skfile "$TMP/sk" -x <"$TMP/msg")
    assert_eq "$got" "$sig" "$name: signature"
    expect_ok "$name: the signature verifies" \
        "$BC_RUST" --hex-input "$cmd" verify --pkfile "$TMP/pk" --sigfile "$TMP/sig" <"$TMP/msg" >/dev/null
}

test_ed25519_matches_rfc8032_7_1() {
    kat ed25519 "TEST 1" "$T1_SK" "$T1_PK" "$T1_MSG" "$T1_SIG"
    kat ed25519 "TEST 2" "$T2_SK" "$T2_PK" "$T2_MSG" "$T2_SIG"
    kat ed25519 "TEST 3" "$T3_SK" "$T3_PK" "$T3_MSG" "$T3_SIG"
    kat ed25519 "TEST 1024" "$T1024_SK" "$T1024_PK" "$T1024_MSG" "$T1024_SIG"
}

test_ed25519ph_matches_rfc8032_7_3() {
    kat ed25519ph "TEST abc" "$PH_SK" "$PH_PK" "$PH_MSG" "$PH_SIG"
}

# One key pair serves both, and a signature of one is not a signature of the other.
test_the_two_algorithms_do_not_verify_each_other() {
    printf '%s' "$PH_PK" >"$TMP/pk"
    printf '%s' "$PH_SIG" >"$TMP/ph.sig"
    printf '%s' "$PH_SK" >"$TMP/sk"
    unhex "$PH_MSG" >"$TMP/msg"
    expect_fail "an Ed25519ph signature under ed25519" \
        "$BC_RUST" --hex-input ed25519 verify --pkfile "$TMP/pk" --sigfile "$TMP/ph.sig" <"$TMP/msg"
    assert_stderr_has "invalid"
    "$BC_RUST" --hex-input ed25519 sign --skfile "$TMP/sk" -x <"$TMP/msg" >"$TMP/pure.sig"
    expect_ok "the Ed25519 signature under ed25519" \
        "$BC_RUST" --hex-input ed25519 verify --pkfile "$TMP/pk" --sigfile "$TMP/pure.sig" <"$TMP/msg" >/dev/null
    expect_fail "an Ed25519 signature under ed25519ph" \
        "$BC_RUST" --hex-input ed25519ph verify --pkfile "$TMP/pk" --sigfile "$TMP/pure.sig" <"$TMP/msg"
    assert_stderr_has "invalid"
}

# ---- binary and hex -----------------------------------------------------------------------

test_binary_keys_match_hex_keys() {
    local got
    unhex "$T2_SK" >"$TMP/sk"
    unhex "$T2_PK" >"$TMP/pk"
    unhex "$T2_MSG" >"$TMP/msg"
    got=$(hex_out "$BC_RUST" ed25519 pk-from-sk -x <"$TMP/sk")
    assert_eq "$got" "$T2_PK" "pk-from-sk with a binary sk on stdin"
    "$BC_RUST" ed25519 sign --skfile "$TMP/sk" <"$TMP/msg" >"$TMP/sig"
    assert_size "$TMP/sig" 64 "binary signature"
    assert_eq "$(hex "$TMP/sig")" "$T2_SIG" "sign with a binary key file and binary output"
    expect_ok "verify with binary files" \
        "$BC_RUST" ed25519 verify --pkfile "$TMP/pk" --sigfile "$TMP/sig" <"$TMP/msg" >/dev/null
}

# ---- fresh keys ---------------------------------------------------------------------------

test_keygen_outputs_fresh_keys() {
    "$BC_RUST" ed25519 keygen >"$TMP/sk1"
    "$BC_RUST" ed25519ph keygen >"$TMP/sk2"
    assert_size "$TMP/sk1" 32 "keygen binary private key"
    assert_differs "$TMP/sk1" "$TMP/sk2" "two keygens must give different keys"
    assert_eq "$(hex_out "$BC_RUST" ed25519 keygen -x | wc -c | tr -d ' ')" 64 "keygen -x length"
    "$BC_RUST" ed25519 pk-from-sk --skfile "$TMP/sk1" >"$TMP/pk1"
    assert_size "$TMP/pk1" 32 "public key"
}

# The message is several of the CLI's 1 KB chunks, so ed25519ph streams it and ed25519 gathers it.
test_sign_verify_round_trip_and_tampering() {
    local cmd
    "$BC_RUST" ed25519 keygen >"$TMP/sk"
    "$BC_RUST" ed25519 pk-from-sk --skfile "$TMP/sk" >"$TMP/pk"
    rng 5000 >"$TMP/msg"
    for cmd in ed25519 ed25519ph; do
        "$BC_RUST" $cmd sign --skfile "$TMP/sk" <"$TMP/msg" >"$TMP/sig"
        "$BC_RUST" $cmd sign --skfile "$TMP/sk" <"$TMP/msg" >"$TMP/sig2"
        assert_size "$TMP/sig" 64 "$cmd: signature"
        assert_same "$TMP/sig" "$TMP/sig2" "$cmd: signing is deterministic"
        expect_ok "$cmd: round trip" \
            "$BC_RUST" $cmd verify --pkfile "$TMP/pk" --sigfile "$TMP/sig" <"$TMP/msg" >/dev/null

        cp "$TMP/msg" "$TMP/bad.msg"
        flip_byte "$TMP/bad.msg" 4999
        expect_fail "$cmd: a message changed in its last byte" \
            "$BC_RUST" $cmd verify --pkfile "$TMP/pk" --sigfile "$TMP/sig" <"$TMP/bad.msg"
        assert_stderr_has "invalid"

        cp "$TMP/sig" "$TMP/bad.sig"
        flip_byte "$TMP/bad.sig" 0
        expect_fail "$cmd: a signature changed in R" \
            "$BC_RUST" $cmd verify --pkfile "$TMP/pk" --sigfile "$TMP/bad.sig" <"$TMP/msg"
        assert_stderr_has "invalid"
        cp "$TMP/sig" "$TMP/bad.sig"
        flip_byte "$TMP/bad.sig" 32
        expect_fail "$cmd: a signature changed in S" \
            "$BC_RUST" $cmd verify --pkfile "$TMP/pk" --sigfile "$TMP/bad.sig" <"$TMP/msg"
        assert_stderr_has "invalid"

        "$BC_RUST" ed25519 keygen | "$BC_RUST" ed25519 pk-from-sk >"$TMP/other.pk"
        expect_fail "$cmd: another key" \
            "$BC_RUST" $cmd verify --pkfile "$TMP/other.pk" --sigfile "$TMP/sig" <"$TMP/msg"
        assert_stderr_has "invalid"
    done
}

test_check_consistency() {
    "$BC_RUST" ed25519 keygen >"$TMP/sk"
    "$BC_RUST" ed25519 pk-from-sk --skfile "$TMP/sk" >"$TMP/pk"
    expect_ok "matching pair" \
        "$BC_RUST" ed25519 check-consistency --skfile "$TMP/sk" --pkfile "$TMP/pk" >/dev/null
    expect_ok "matching pair, sk on stdin" \
        "$BC_RUST" ed25519ph check-consistency --pkfile "$TMP/pk" <"$TMP/sk" >/dev/null
    "$BC_RUST" ed25519 keygen >"$TMP/other.sk"
    expect_fail "mismatched pair" \
        "$BC_RUST" ed25519 check-consistency --skfile "$TMP/other.sk" --pkfile "$TMP/pk"
    assert_stderr_has "FAILURE"
}

# ---- the Ed25519ph context ----------------------------------------------------------------

test_ed25519ph_context_is_bound() {
    "$BC_RUST" ed25519 keygen >"$TMP/sk"
    "$BC_RUST" ed25519 pk-from-sk --skfile "$TMP/sk" >"$TMP/pk"
    printf 'msg' >"$TMP/msg"
    printf 'ctx' >"$TMP/ctx"
    : >"$TMP/empty"
    "$BC_RUST" ed25519ph sign --skfile "$TMP/sk" <"$TMP/msg" >"$TMP/sig"
    "$BC_RUST" ed25519ph sign --skfile "$TMP/sk" --ctxfile "$TMP/empty" <"$TMP/msg" >"$TMP/sig-empty"
    "$BC_RUST" ed25519ph sign --skfile "$TMP/sk" --ctxfile "$TMP/ctx" <"$TMP/msg" >"$TMP/sig-ctx"
    assert_same "$TMP/sig" "$TMP/sig-empty" "no context is the empty context"
    assert_differs "$TMP/sig" "$TMP/sig-ctx" "the context changes the signature"
    expect_fail "a context the signer did not use must not verify" \
        "$BC_RUST" ed25519ph verify --pkfile "$TMP/pk" --sigfile "$TMP/sig" --ctxfile "$TMP/ctx" <"$TMP/msg"
    assert_stderr_has "invalid"
    expect_ok "signature with context verifies with it" \
        "$BC_RUST" ed25519ph verify --pkfile "$TMP/pk" --sigfile "$TMP/sig-ctx" --ctxfile "$TMP/ctx" <"$TMP/msg" >/dev/null
    expect_fail "and not without it" \
        "$BC_RUST" ed25519ph verify --pkfile "$TMP/pk" --sigfile "$TMP/sig-ctx" <"$TMP/msg"
    assert_stderr_has "invalid"
}

test_ed25519ph_context_length_limit() {
    "$BC_RUST" ed25519 keygen >"$TMP/sk"
    "$BC_RUST" ed25519 pk-from-sk --skfile "$TMP/sk" >"$TMP/pk"
    head -c 255 /dev/zero >"$TMP/ctx255"
    head -c 256 /dev/zero >"$TMP/ctx256"
    "$BC_RUST" ed25519ph sign --skfile "$TMP/sk" --ctxfile "$TMP/ctx255" </dev/null >"$TMP/sig"
    expect_ok "a 255-byte context is allowed" \
        "$BC_RUST" ed25519ph verify --pkfile "$TMP/pk" --sigfile "$TMP/sig" --ctxfile "$TMP/ctx255" </dev/null >/dev/null
    expect_fail "a 256-byte context, signing" \
        "$BC_RUST" ed25519ph sign --skfile "$TMP/sk" --ctxfile "$TMP/ctx256" </dev/null
    assert_stderr_has "Error"
    grep -q panicked "$LAST_STDERR" && fail "a long context must not panic: $(head -1 "$LAST_STDERR")"
    expect_fail "a 256-byte context, verifying" \
        "$BC_RUST" ed25519ph verify --pkfile "$TMP/pk" --sigfile "$TMP/sig" --ctxfile "$TMP/ctx256" </dev/null
    assert_stderr_has "Error"
    grep -q panicked "$LAST_STDERR" && fail "a long context must not panic: $(head -1 "$LAST_STDERR")"
    return 0
}

# Ed25519 has no context, so the subcommand has no flag for one.
test_ed25519_takes_no_context() {
    "$BC_RUST" ed25519 keygen >"$TMP/sk"
    "$BC_RUST" ed25519 pk-from-sk --skfile "$TMP/sk" >"$TMP/pk"
    printf 'ctx' >"$TMP/ctx"
    expect_fail "ed25519 with --ctxfile" \
        "$BC_RUST" ed25519 sign --skfile "$TMP/sk" --ctxfile "$TMP/ctx" </dev/null
    assert_stderr_has "ctxfile"

    # Ed25519ph takes one for signing and verification only.
    local action
    for action in keygen pk-from-sk check-consistency; do
        expect_fail "ed25519ph $action with --ctxfile" \
            "$BC_RUST" ed25519ph $action --skfile "$TMP/sk" --pkfile "$TMP/pk" --ctxfile "$TMP/ctx" </dev/null >"$TMP/out"
        assert_stderr_has "ctxfile"
        assert_size "$TMP/out" 0 "ed25519ph $action with --ctxfile writes nothing"
    done
}

# ---- errors -------------------------------------------------------------------------------

# The neutral element (y = 1) is a point of the curve of small order; a decoded public key is
# validated in full, so it is refused as a key.
test_small_order_public_key_is_rejected() {
    printf '01%062d' 0 >"$TMP/neutral.pk"
    printf '%s' "$T1_SIG" >"$TMP/sig"
    expect_fail "verify under the neutral element" \
        "$BC_RUST" --hex-input ed25519 verify --pkfile "$TMP/neutral.pk" --sigfile "$TMP/sig" </dev/null
    assert_stderr_has "public key"
    printf '%s' "$T1_SK" >"$TMP/sk"
    expect_fail "check-consistency against the neutral element" \
        "$BC_RUST" --hex-input ed25519 check-consistency --skfile "$TMP/sk" --pkfile "$TMP/neutral.pk"
    assert_stderr_has "public key"
}

test_wrong_length_inputs_are_rejected() {
    printf '%s' "$T1_SK" >"$TMP/sk"
    printf '%s' "$T1_PK" >"$TMP/pk"
    printf '%s' "${T1_PK:0:62}" >"$TMP/short.pk"
    printf '%s' "${T1_SIG:0:126}" >"$TMP/short.sig"
    printf '%s' "$T1_SIG" >"$TMP/sig"
    expect_fail "31-byte private key" "$BC_RUST" --hex-input ed25519 pk-from-sk < <(printf '%s' "${T1_SK:0:62}")
    assert_stderr_has "private key"
    expect_fail "33-byte private key" "$BC_RUST" --hex-input ed25519 pk-from-sk < <(printf '%s00' "$T1_SK")
    assert_stderr_has "private key"
    expect_fail "31-byte public key" \
        "$BC_RUST" --hex-input ed25519 verify --pkfile "$TMP/short.pk" --sigfile "$TMP/sig" </dev/null
    assert_stderr_has "public key"
    expect_fail "63-byte signature" \
        "$BC_RUST" --hex-input ed25519 verify --pkfile "$TMP/pk" --sigfile "$TMP/short.sig" </dev/null
    assert_stderr_has "invalid"
    expect_fail "63-byte signature, ed25519ph" \
        "$BC_RUST" --hex-input ed25519ph verify --pkfile "$TMP/pk" --sigfile "$TMP/short.sig" </dev/null
    assert_stderr_has "invalid"
}

test_missing_files_are_rejected() {
    printf '%s' "$T1_SK" >"$TMP/sk"
    printf '%s' "$T1_PK" >"$TMP/pk"
    printf '%s' "$T1_SIG" >"$TMP/sig"
    expect_fail "sign without --skfile" "$BC_RUST" --hex-input ed25519 sign </dev/null
    assert_stderr_has "skfile"
    expect_fail "verify without --pkfile" "$BC_RUST" --hex-input ed25519 verify --sigfile "$TMP/sig" </dev/null
    assert_stderr_has "pkfile"
    expect_fail "verify without --sigfile" "$BC_RUST" --hex-input ed25519ph verify --pkfile "$TMP/pk" </dev/null
    assert_stderr_has "sigfile"
    expect_fail "check-consistency without --pkfile" "$BC_RUST" --hex-input ed25519 check-consistency <"$TMP/sk"
    assert_stderr_has "pkfile"

    # What signing reads besides the key is read before the key is loaded; a failure there
    # gives no signature.
    expect_fail "ed25519ph sign with a --ctxfile that is not there" \
        "$BC_RUST" --hex-input ed25519ph sign --skfile "$TMP/sk" --ctxfile "$TMP/no-such-file" </dev/null >"$TMP/out"
    assert_size "$TMP/out" 0 "no signature without the context"
    printf 'not hex' >"$TMP/bad.ctx"
    expect_fail "ed25519ph sign with a --ctxfile that is not hex" \
        "$BC_RUST" --hex-input ed25519ph sign --skfile "$TMP/sk" --ctxfile "$TMP/bad.ctx" </dev/null >"$TMP/out"
    assert_size "$TMP/out" 0 "no signature without the context"
}

run_all
