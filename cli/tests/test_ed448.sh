#!/usr/bin/env bash
# The ed448 and ed448ph subcommands, end to end through the binary: Ed448 and Ed448ph
# signatures (RFC 8032 Section 5.2) on one key pair, each under an optional context.
#
# The known answers are RFC 8032 Section 7.4 (Ed448) and Section 7.5 (Ed448ph), lifted by
# script from crypto/ed/tests/ed448_rfc8032_tests.rs. Hex keys, contexts and signatures are
# read under --hex-input; without it they are raw bytes. The message on stdin is always raw.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# RFC 8032 Section 7.4, Blank.
T0_SK=6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b
T0_PK=5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180
T0_MSG=
T0_CTX=
T0_SIG=533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600

# RFC 8032 Section 7.4, 1 octet.
T1_SK=c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e
T1_PK=43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480
T1_MSG=03
T1_CTX=
T1_SIG=26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00

# RFC 8032 Section 7.4, 1 octet (with context).
T1C_SK=c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e
T1C_PK=43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480
T1C_MSG=03
T1C_CTX=666f6f
T1C_SIG=d4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea000c85741de5c8da1144a6a1aba7f96de42505d7a7298524fda538fccbbb754f578c1cad10d54d0d5428407e85dcbc98a49155c13764e66c3c00

# RFC 8032 Section 7.4, 1023 octets.
T1023_SK=872d093780f5d3730df7c212664b37b8a0f24f56810daa8382cd4fa3f77634ec44dc54f1c2ed9bea86fafb7632d8be199ea165f5ad55dd9ce8
T1023_PK=a81b2e8a70a5ac94ffdbcc9badfc3feb0801f258578bb114ad44ece1ec0e799da08effb81c5d685c0c56f64eecaef8cdf11cc38737838cf400
T1023_MSG=6ddf802e1aae4986935f7f981ba3f0351d6273c0a0c22c9c0e8339168e675412a3debfaf435ed651558007db4384b650fcc07e3b586a27a4f7a00ac8a6fec2cd86ae4bf1570c41e6a40c931db27b2faa15a8cedd52cff7362c4e6e23daec0fbc3a79b6806e316efcc7b68119bf46bc76a26067a53f296dafdbdc11c77f7777e972660cf4b6a9b369a6665f02e0cc9b6edfad136b4fabe723d2813db3136cfde9b6d044322fee2947952e031b73ab5c603349b307bdc27bc6cb8b8bbd7bd323219b8033a581b59eadebb09b3c4f3d2277d4f0343624acc817804728b25ab797172b4c5c21a22f9c7839d64300232eb66e53f31c723fa37fe387c7d3e50bdf9813a30e5bb12cf4cd930c40cfb4e1fc622592a49588794494d56d24ea4b40c89fc0596cc9ebb961c8cb10adde976a5d602b1c3f85b9b9a001ed3c6a4d3b1437f52096cd1956d042a597d561a596ecd3d1735a8d570ea0ec27225a2c4aaff26306d1526c1af3ca6d9cf5a2c98f47e1c46db9a33234cfd4d81f2c98538a09ebe76998d0d8fd25997c7d255c6d66ece6fa56f11144950f027795e653008f4bd7ca2dee85d8e90f3dc315130ce2a00375a318c7c3d97be2c8ce5b6db41a6254ff264fa6155baee3b0773c0f497c573f19bb4f4240281f0b1f4f7be857a4e59d416c06b4c50fa09e1810ddc6b1467baeac5a3668d11b6ecaa901440016f389f80acc4db977025e7f5924388c7e340a732e554440e76570f8dd71b7d640b3450d1fd5f0410a18f9a3494f707c717b79b4bf75c98400b096b21653b5d217cf3565c9597456f70703497a078763829bc01bb1cbc8fa04eadc9a6e3f6699587a9e75c94e5bab0036e0b2e711392cff0047d0d6b05bd2a588bc109718954259f1d86678a579a3120f19cfb2963f177aeb70f2d4844826262e51b80271272068ef5b3856fa8535aa2a88b2d41f2a0e2fda7624c2850272ac4a2f561f8f2f7a318bfd5caf9696149e4ac824ad3460538fdc25421beec2cc6818162d06bbed0c40a387192349db67a118bada6cd5ab0140ee273204f628aad1c135f770279a651e24d8c14d75a6059d76b96a6fd857def5e0b354b27ab937a5815d16b5fae407ff18222c6d1ed263be68c95f32d908bd895cd76207ae726487567f9a67dad79abec316f683b17f2d02bf07e0ac8b5bc6162cf94697b3c27cd1fea49b27f23ba2901871962506520c392da8b6ad0d99f7013fbc06c2c17a569500c8a7696481c1cd33e9b14e40b82e79a5f5db82571ba97bae3ad3e0479515bb0e2b0f3bfcd1fd33034efc6245eddd7ee2086ddae2600d8ca73e214e8c2b0bdb2b047c6a464a562ed77b73d2d841c4b34973551257713b753632efba348169abc90a68f42611a40126d7cb21b58695568186f7e569d2ff0f9e745d0487dd2eb997cafc5abf9dd102e62ff66cba87
T1023_CTX=
T1023_SIG=e301345a41a39a4d72fff8df69c98075a0cc082b802fc9b2b6bc503f926b65bddf7f4c8f1cb49f6396afc8a70abe6d8aef0db478d4c6b2970076c6a0484fe76d76b3a97625d79f1ce240e7c576750d295528286f719b413de9ada3e8eb78ed573603ce30d8bb761785dc30dbc320869e1a00

# RFC 8032 Section 7.5, TEST abc.
PH_SK=833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49
PH_PK=259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880
PH_MSG=616263
PH_CTX=
PH_SIG=822f6901f7480f3d5f562c592994d9693602875614483256505600bbc281ae381f54d6bce2ea911574932f52a4e6cadd78769375ec3ffd1b801a0d9b3f4030cd433964b6457ea39476511214f97469b57dd32dbc560a9a94d00bff07620464a3ad203df7dc7ce360c3cd3696d9d9fab90f00

# RFC 8032 Section 7.5, TEST abc (with context).
PHC_SK=833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49
PHC_PK=259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880
PHC_MSG=616263
PHC_CTX=666f6f
PHC_SIG=c32299d46ec8ff02b54540982814dce9a05812f81962b649d528095916a2aa481065b1580423ef927ecf0af5888f90da0f6a9a85ad5dc3f280d91224ba9911a3653d00e484e2ce232521481c8658df304bb7745a73514cdb9bf3e15784ab71284f8d0704a608c54a6b62d97beb511d132100
# `fails_silently MSG CMD...`: CMD must fail and write nothing to stdout. Not `expect_fail`,
# which sends stdout to /dev/null and so cannot show that nothing was written.
fails_silently() {
    local msg=$1
    shift
    if "$@" >"$TMP/out" 2>"$LAST_STDERR"; then
        fail "$msg (command succeeded: $*)"
    fi
    assert_size "$TMP/out" 0 "$msg: nothing on stdout"
}

# ---- known answers ------------------------------------------------------------------------

# `kat CMD NAME SK PK MSG CTX SIG`: the public key, the signature and its verification, under
# the context CTX when it is not empty.
kat() {
    local cmd=$1 name=$2 sk=$3 pk=$4 msg=$5 ctx=$6 sig=$7 got
    local -a with_ctx=()
    printf '%s' "$sk" >"$TMP/sk"
    printf '%s' "$pk" >"$TMP/pk"
    printf '%s' "$sig" >"$TMP/sig"
    unhex "$msg" >"$TMP/msg"
    if [ -n "$ctx" ]; then
        printf '%s' "$ctx" >"$TMP/ctx"
        with_ctx=(--ctxfile "$TMP/ctx")
    fi
    got=$(hex_out "$BC_RUST" --hex-input "$cmd" pk-from-sk --skfile "$TMP/sk" -x)
    assert_eq "$got" "$pk" "$name: public key"
    got=$(hex_out "$BC_RUST" --hex-input "$cmd" sign --skfile "$TMP/sk" "${with_ctx[@]}" -x <"$TMP/msg")
    assert_eq "$got" "$sig" "$name: signature"
    expect_ok "$name: the signature verifies" \
        "$BC_RUST" --hex-input "$cmd" verify --pkfile "$TMP/pk" --sigfile "$TMP/sig" "${with_ctx[@]}" <"$TMP/msg" >/dev/null
    if [ -n "$ctx" ]; then
        expect_fail "$name: and not without its context" \
            "$BC_RUST" --hex-input "$cmd" verify --pkfile "$TMP/pk" --sigfile "$TMP/sig" <"$TMP/msg"
        assert_stderr_has "invalid"
    fi
}

test_ed448_matches_rfc8032_7_4() {
    kat ed448 "Blank" "$T0_SK" "$T0_PK" "$T0_MSG" "$T0_CTX" "$T0_SIG"
    kat ed448 "1 octet" "$T1_SK" "$T1_PK" "$T1_MSG" "$T1_CTX" "$T1_SIG"
    kat ed448 "1 octet (with context)" "$T1C_SK" "$T1C_PK" "$T1C_MSG" "$T1C_CTX" "$T1C_SIG"
    kat ed448 "1023 octets" "$T1023_SK" "$T1023_PK" "$T1023_MSG" "$T1023_CTX" "$T1023_SIG"
    assert_eq "$T1C_CTX" 666f6f "the vector with a context has one"
}

test_ed448ph_matches_rfc8032_7_5() {
    kat ed448ph "TEST abc" "$PH_SK" "$PH_PK" "$PH_MSG" "$PH_CTX" "$PH_SIG"
    kat ed448ph "TEST abc (with context)" "$PHC_SK" "$PHC_PK" "$PHC_MSG" "$PHC_CTX" "$PHC_SIG"
    assert_eq "$PHC_CTX" 666f6f "the vector with a context has one"
}

# One key pair serves both, and a signature of one is not a signature of the other.
test_the_two_algorithms_do_not_verify_each_other() {
    printf '%s' "$PH_PK" >"$TMP/pk"
    printf '%s' "$PH_SIG" >"$TMP/ph.sig"
    printf '%s' "$PH_SK" >"$TMP/sk"
    unhex "$PH_MSG" >"$TMP/msg"
    expect_fail "an Ed448ph signature under ed448" \
        "$BC_RUST" --hex-input ed448 verify --pkfile "$TMP/pk" --sigfile "$TMP/ph.sig" <"$TMP/msg"
    assert_stderr_has "invalid"
    "$BC_RUST" --hex-input ed448 sign --skfile "$TMP/sk" -x <"$TMP/msg" >"$TMP/pure.sig"
    expect_ok "the Ed448 signature under ed448" \
        "$BC_RUST" --hex-input ed448 verify --pkfile "$TMP/pk" --sigfile "$TMP/pure.sig" <"$TMP/msg" >/dev/null
    expect_fail "an Ed448 signature under ed448ph" \
        "$BC_RUST" --hex-input ed448ph verify --pkfile "$TMP/pk" --sigfile "$TMP/pure.sig" <"$TMP/msg"
    assert_stderr_has "invalid"
}

# ---- binary and hex -----------------------------------------------------------------------

test_binary_keys_match_hex_keys() {
    local got
    unhex "$T1C_SK" >"$TMP/sk"
    unhex "$T1C_PK" >"$TMP/pk"
    unhex "$T1C_MSG" >"$TMP/msg"
    unhex "$T1C_CTX" >"$TMP/ctx"
    got=$(hex_out "$BC_RUST" ed448 pk-from-sk -x <"$TMP/sk")
    assert_eq "$got" "$T1C_PK" "pk-from-sk with a binary sk on stdin"
    "$BC_RUST" ed448 sign --skfile "$TMP/sk" --ctxfile "$TMP/ctx" <"$TMP/msg" >"$TMP/sig"
    assert_size "$TMP/sig" 114 "binary signature"
    assert_eq "$(hex "$TMP/sig")" "$T1C_SIG" "sign with binary key and context files and binary output"
    expect_ok "verify with binary files" \
        "$BC_RUST" ed448 verify --pkfile "$TMP/pk" --sigfile "$TMP/sig" --ctxfile "$TMP/ctx" <"$TMP/msg" >/dev/null
}

# ---- fresh keys ---------------------------------------------------------------------------

test_keygen_outputs_fresh_keys() {
    "$BC_RUST" ed448 keygen >"$TMP/sk1"
    "$BC_RUST" ed448ph keygen >"$TMP/sk2"
    assert_size "$TMP/sk1" 57 "keygen binary private key"
    assert_differs "$TMP/sk1" "$TMP/sk2" "two keygens must give different keys"
    assert_eq "$(hex_out "$BC_RUST" ed448 keygen -x | wc -c | tr -d ' ')" 114 "keygen -x length"
    "$BC_RUST" ed448 pk-from-sk --skfile "$TMP/sk1" >"$TMP/pk1"
    assert_size "$TMP/pk1" 57 "public key"
}

# The message is several of the CLI's 1 KB chunks, so ed448ph streams it and ed448 gathers it.
test_sign_verify_round_trip_and_tampering() {
    local cmd
    "$BC_RUST" ed448 keygen >"$TMP/sk"
    "$BC_RUST" ed448 pk-from-sk --skfile "$TMP/sk" >"$TMP/pk"
    rng 5000 >"$TMP/msg"
    for cmd in ed448 ed448ph; do
        "$BC_RUST" $cmd sign --skfile "$TMP/sk" <"$TMP/msg" >"$TMP/sig"
        "$BC_RUST" $cmd sign --skfile "$TMP/sk" <"$TMP/msg" >"$TMP/sig2"
        assert_size "$TMP/sig" 114 "$cmd: signature"
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
        flip_byte "$TMP/bad.sig" 57
        expect_fail "$cmd: a signature changed in S" \
            "$BC_RUST" $cmd verify --pkfile "$TMP/pk" --sigfile "$TMP/bad.sig" <"$TMP/msg"
        assert_stderr_has "invalid"

        "$BC_RUST" ed448 keygen | "$BC_RUST" ed448 pk-from-sk >"$TMP/other.pk"
        expect_fail "$cmd: another key" \
            "$BC_RUST" $cmd verify --pkfile "$TMP/other.pk" --sigfile "$TMP/sig" <"$TMP/msg"
        assert_stderr_has "invalid"
    done
}

test_check_consistency() {
    "$BC_RUST" ed448 keygen >"$TMP/sk"
    "$BC_RUST" ed448 pk-from-sk --skfile "$TMP/sk" >"$TMP/pk"
    expect_ok "matching pair" \
        "$BC_RUST" ed448 check-consistency --skfile "$TMP/sk" --pkfile "$TMP/pk" >/dev/null
    expect_ok "matching pair, sk on stdin" \
        "$BC_RUST" ed448ph check-consistency --pkfile "$TMP/pk" <"$TMP/sk" >/dev/null
    "$BC_RUST" ed448 keygen >"$TMP/other.sk"
    expect_fail "mismatched pair" \
        "$BC_RUST" ed448 check-consistency --skfile "$TMP/other.sk" --pkfile "$TMP/pk"
    assert_stderr_has "FAILURE"
}

# ---- the context, which both algorithms take ----------------------------------------------

test_context_is_bound() {
    local cmd
    "$BC_RUST" ed448 keygen >"$TMP/sk"
    "$BC_RUST" ed448 pk-from-sk --skfile "$TMP/sk" >"$TMP/pk"
    printf 'msg' >"$TMP/msg"
    printf 'ctx' >"$TMP/ctx"
    : >"$TMP/empty"
    for cmd in ed448 ed448ph; do
        "$BC_RUST" $cmd sign --skfile "$TMP/sk" <"$TMP/msg" >"$TMP/sig"
        "$BC_RUST" $cmd sign --skfile "$TMP/sk" --ctxfile "$TMP/empty" <"$TMP/msg" >"$TMP/sig-empty"
        "$BC_RUST" $cmd sign --skfile "$TMP/sk" --ctxfile "$TMP/ctx" <"$TMP/msg" >"$TMP/sig-ctx"
        assert_same "$TMP/sig" "$TMP/sig-empty" "$cmd: no context is the empty context"
        assert_differs "$TMP/sig" "$TMP/sig-ctx" "$cmd: the context changes the signature"
        expect_fail "$cmd: a context the signer did not use must not verify" \
            "$BC_RUST" $cmd verify --pkfile "$TMP/pk" --sigfile "$TMP/sig" --ctxfile "$TMP/ctx" <"$TMP/msg"
        assert_stderr_has "invalid"
        expect_ok "$cmd: signature with context verifies with it" \
            "$BC_RUST" $cmd verify --pkfile "$TMP/pk" --sigfile "$TMP/sig-ctx" --ctxfile "$TMP/ctx" <"$TMP/msg" >/dev/null
        expect_fail "$cmd: and not without it" \
            "$BC_RUST" $cmd verify --pkfile "$TMP/pk" --sigfile "$TMP/sig-ctx" <"$TMP/msg"
        assert_stderr_has "invalid"
    done
}

test_context_length_limit() {
    local cmd
    "$BC_RUST" ed448 keygen >"$TMP/sk"
    "$BC_RUST" ed448 pk-from-sk --skfile "$TMP/sk" >"$TMP/pk"
    head -c 255 /dev/zero >"$TMP/ctx255"
    head -c 256 /dev/zero >"$TMP/ctx256"
    for cmd in ed448 ed448ph; do
        "$BC_RUST" $cmd sign --skfile "$TMP/sk" --ctxfile "$TMP/ctx255" </dev/null >"$TMP/sig"
        expect_ok "$cmd: a 255-byte context is allowed" \
            "$BC_RUST" $cmd verify --pkfile "$TMP/pk" --sigfile "$TMP/sig" --ctxfile "$TMP/ctx255" </dev/null >/dev/null
        fails_silently "$cmd: a 256-byte context, signing" \
            "$BC_RUST" $cmd sign --skfile "$TMP/sk" --ctxfile "$TMP/ctx256" </dev/null
        assert_stderr_has "Error"
        grep -q panicked "$LAST_STDERR" && fail "a long context must not panic: $(head -1 "$LAST_STDERR")"
        expect_fail "$cmd: a 256-byte context, verifying" \
            "$BC_RUST" $cmd verify --pkfile "$TMP/pk" --sigfile "$TMP/sig" --ctxfile "$TMP/ctx256" </dev/null
        assert_stderr_has "Error"
        grep -q panicked "$LAST_STDERR" && fail "a long context must not panic: $(head -1 "$LAST_STDERR")"
    done
    return 0
}

# Both subcommands take a context for signing and verification only.
test_context_is_refused_where_it_is_not_used() {
    local cmd action
    "$BC_RUST" ed448 keygen >"$TMP/sk"
    "$BC_RUST" ed448 pk-from-sk --skfile "$TMP/sk" >"$TMP/pk"
    printf 'ctx' >"$TMP/ctx"
    for cmd in ed448 ed448ph; do
        for action in keygen pk-from-sk check-consistency; do
            fails_silently "$cmd $action with --ctxfile" \
                "$BC_RUST" $cmd $action --skfile "$TMP/sk" --pkfile "$TMP/pk" --ctxfile "$TMP/ctx" </dev/null
            assert_stderr_has "ctxfile"
        done
    done
}

# ---- errors -------------------------------------------------------------------------------

# The neutral element (y = 1) is a point of the curve of small order; a decoded public key is
# validated in full, so it is refused as a key.
test_small_order_public_key_is_rejected() {
    printf '01%0112d' 0 >"$TMP/neutral.pk"
    printf '%s' "$T0_SIG" >"$TMP/sig"
    expect_fail "verify under the neutral element" \
        "$BC_RUST" --hex-input ed448 verify --pkfile "$TMP/neutral.pk" --sigfile "$TMP/sig" </dev/null
    assert_stderr_has "public key"
    printf '%s' "$T0_SK" >"$TMP/sk"
    expect_fail "check-consistency against the neutral element" \
        "$BC_RUST" --hex-input ed448 check-consistency --skfile "$TMP/sk" --pkfile "$TMP/neutral.pk"
    assert_stderr_has "public key"
}

test_wrong_length_inputs_are_rejected() {
    printf '%s' "$T0_SK" >"$TMP/sk"
    printf '%s' "$T0_PK" >"$TMP/pk"
    printf '%s' "${T0_PK:0:112}" >"$TMP/short.pk"
    printf '%s' "${T0_SIG:0:226}" >"$TMP/short.sig"
    printf '%s' "$T0_SIG" >"$TMP/sig"
    expect_fail "56-byte private key" "$BC_RUST" --hex-input ed448 pk-from-sk < <(printf '%s' "${T0_SK:0:112}")
    assert_stderr_has "private key"
    expect_fail "58-byte private key" "$BC_RUST" --hex-input ed448 pk-from-sk < <(printf '%s00' "$T0_SK")
    assert_stderr_has "private key"
    expect_fail "56-byte public key" \
        "$BC_RUST" --hex-input ed448 verify --pkfile "$TMP/short.pk" --sigfile "$TMP/sig" </dev/null
    assert_stderr_has "public key"
    expect_fail "113-byte signature" \
        "$BC_RUST" --hex-input ed448 verify --pkfile "$TMP/pk" --sigfile "$TMP/short.sig" </dev/null
    assert_stderr_has "invalid"
    expect_fail "113-byte signature, ed448ph" \
        "$BC_RUST" --hex-input ed448ph verify --pkfile "$TMP/pk" --sigfile "$TMP/short.sig" </dev/null
    assert_stderr_has "invalid"
}

test_missing_files_are_rejected() {
    local cmd
    printf '%s' "$T0_SK" >"$TMP/sk"
    printf '%s' "$T0_PK" >"$TMP/pk"
    printf '%s' "$T0_SIG" >"$TMP/sig"
    expect_fail "sign without --skfile" "$BC_RUST" --hex-input ed448 sign </dev/null
    assert_stderr_has "skfile"
    expect_fail "verify without --pkfile" "$BC_RUST" --hex-input ed448 verify --sigfile "$TMP/sig" </dev/null
    assert_stderr_has "pkfile"
    expect_fail "verify without --sigfile" "$BC_RUST" --hex-input ed448ph verify --pkfile "$TMP/pk" </dev/null
    assert_stderr_has "sigfile"
    expect_fail "check-consistency without --pkfile" "$BC_RUST" --hex-input ed448 check-consistency <"$TMP/sk"
    assert_stderr_has "pkfile"

    # What signing reads besides the key is read before the key is loaded; a failure there
    # gives no signature.
    printf 'not hex' >"$TMP/bad.ctx"
    for cmd in ed448 ed448ph; do
        fails_silently "$cmd sign with a --ctxfile that is not there" \
            "$BC_RUST" --hex-input $cmd sign --skfile "$TMP/sk" --ctxfile "$TMP/no-such-file" </dev/null
        fails_silently "$cmd sign with a --ctxfile that is not hex" \
            "$BC_RUST" --hex-input $cmd sign --skfile "$TMP/sk" --ctxfile "$TMP/bad.ctx" </dev/null
    done
}

run_all
