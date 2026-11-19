#!/usr/bin/env bash
# The kbkdf-* subcommands (SP 800-108r1) against the NIST CAVP KBKDF response files
# (bc-test-data/crypto/cavp/KDF*_gen.rsp; every KO is copied from the file) and the NIST ACVP
# "KDF KMAC SP800-108r1" sample vectors (bc-test-data/crypto/acvp/KDF-KMAC-Sp800-108r1; every
# derivedKey is copied from expectedResults.json). L is in bits in both.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# ---- counter mode: KDFCTR_gen.rsp ---------------------------------------------------------

# [PRF=HMAC_SHA256] [CTRLOCATION=BEFORE_FIXED] [RLEN=32_BITS] COUNT=0: the command's defaults.
test_kbkdf_counter_hmac_sha256_before_fixed_32() {
    local got ki fixed expected=10621342bfb0fd40046c0e29f2cfdbf0
    ki=dd1d91b7d90b2bd3138533ce92b272fbf8a369316aefe242e659cc0ae238afe0
    fixed=01322b96b30acd197979444e468e1c5c6859bf1b1cf951b7e725303e237e46b864a145fab25e517b08f8683d0315bb2911d80a0e8aba17f3b413faac
    got=$(hex_out "$BC_RUST" kbkdf-counter --prf hmac-sha256 --ikm "$ki" --additional-input "$fixed" --len 16 -x)
    assert_eq "$got" "$expected" "KO (hex inputs, defaults)"
    got=$(hex_out "$BC_RUST" kbkdf-counter --prf hmac-sha256 --counter-bits 32 --counter-position before-fixed \
        --ikm "$ki" --additional-input "$fixed" --len 16 -x)
    assert_eq "$got" "$expected" "KO (counter flags spelled out)"
    unhex "$ki" >"$TMP/ki"
    unhex "$fixed" >"$TMP/fixed"
    got=$(hex_out "$BC_RUST" kbkdf-counter --prf hmac-sha256 --ikm-file "$TMP/ki" --additional-input-file "$TMP/fixed" --len 16 -x)
    assert_eq "$got" "$expected" "KO (file inputs)"
    "$BC_RUST" kbkdf-counter --prf hmac-sha256 --ikm-file "$TMP/ki" --additional-input-file "$TMP/fixed" --len 16 >"$TMP/out"
    assert_size "$TMP/out" 16 "binary output length"
    assert_eq "$(hex "$TMP/out")" "$expected" "KO (binary output)"
}

# [PRF=HMAC_SHA512] [CTRLOCATION=AFTER_FIXED] [RLEN=8_BITS] COUNT=0
test_kbkdf_counter_hmac_sha512_after_fixed_8() {
    local got
    got=$(hex_out "$BC_RUST" kbkdf-counter --prf hmac-sha512 --counter-bits 8 --counter-position after-fixed \
        --ikm ab052ef2e9137415060435b9a73a67623e07f3467981fe8093c440973658851028c86e44a1fd9100b413792f14e257683aa74b83ecd96d24c862c2263a496cfb \
        --additional-input 668831e2701803581eb9083a0928cc00d83a3c19ca4df061d155a880a66ba24857ad6f4bd7a67382215b5b9d81b37737d74f7a5ef78486aeea2f9ac1 \
        --len 16 -x)
    assert_eq "$got" "6ec2b089107021463bae15f8f5c771ab" "KO"
}

# [PRF=CMAC_AES256] [CTRLOCATION=MIDDLE_FIXED] [RLEN=16_BITS] COUNT=0: the fixed input data is
# DataBeforeCtrData (50 bytes) || DataAfterCtrData, with the counter at offset 50.
test_kbkdf_counter_cmac_aes256_in_fixed_16() {
    local got before after
    before=14e20e83dbe001af8ab304d0cf14dba30caa751271b976a927b3c8544e24ad0a98e6604eddd9fda2bf2a9ba81ec507f942f5
    after=43a412a8be794adb0f2e
    got=$(hex_out "$BC_RUST" kbkdf-counter --prf cmac-aes256 --counter-bits 16 --counter-position in-fixed --counter-offset 50 \
        --ikm ce7ec625c6dcd1ff21ec48ed35ff70fc0f69946107e6583849f711a725ba1684 \
        --additional-input "$before$after" --len 16 -x)
    assert_eq "$got" "e2c310966e6cf312eff7ab44deddb9dc" "KO"
}

# ---- feedback mode ------------------------------------------------------------------------

# KDFFeedbackCounter_gen.rsp [PRF=HMAC_SHA384] [CTRLOCATION=BEFORE_ITER] [RLEN=24_BITS] COUNT=0:
# a non-empty IV and a counter.
test_kbkdf_feedback_hmac_sha384_iv_and_counter() {
    local got
    got=$(hex_out "$BC_RUST" kbkdf-feedback --prf hmac-sha384 --counter-bits 24 --counter-position before-iteration \
        --iv d07e38a303542bc85cdb1902cbf19afe7578e79cdba5e4fb244eef7004218599e48b9d14e1d7708ecef20c80d7452009 \
        --ikm bbfb5cede9f2c18f96e998da4f8b28c327356cca31493af483eb9cbc3fe3d28661c97ef641ec92a66cdbd42f4314e8e0 \
        --additional-input cb6724f8727ee95ee792b7bbb0333c9a2b669c63dc0d94ebea557f7009c6c893158f12fe4429155224b4eee3b450ab0973b5ed \
        --len 64 -x)
    assert_eq "$got" "46d7a02b702da5674d784aa938f232eca83390a44712902192eb037f23ccf56732de3243dcb82c0106db66e9a2babd34d94b67d273ac55a8d29c23a6c58b3a56" "KO"
}

# The same vector with the IV from a file, which wins over --iv when both are given.
test_kbkdf_feedback_iv_file() {
    local got expected=46d7a02b702da5674d784aa938f232eca83390a44712902192eb037f23ccf56732de3243dcb82c0106db66e9a2babd34d94b67d273ac55a8d29c23a6c58b3a56
    unhex d07e38a303542bc85cdb1902cbf19afe7578e79cdba5e4fb244eef7004218599e48b9d14e1d7708ecef20c80d7452009 >"$TMP/iv"
    for inline in "" "--iv 00ff"; do
        # shellcheck disable=SC2086
        got=$(hex_out "$BC_RUST" kbkdf-feedback --prf hmac-sha384 --counter-bits 24 --counter-position before-iteration \
            --iv-file "$TMP/iv" $inline \
            --ikm bbfb5cede9f2c18f96e998da4f8b28c327356cca31493af483eb9cbc3fe3d28661c97ef641ec92a66cdbd42f4314e8e0 \
            --additional-input cb6724f8727ee95ee792b7bbb0333c9a2b669c63dc0d94ebea557f7009c6c893158f12fe4429155224b4eee3b450ab0973b5ed \
            --len 64 -x)
        assert_eq "$got" "$expected" "KO (--iv-file ${inline:+and --iv})"
    done
    expect_fail "the guard with an IV file" "$BC_RUST" kbkdf-feedback --prf hmac-sha256 --counter-bits 32 --key-control-guard --iv-file "$TMP/iv" --ikm 0011 --len 16
    assert_stderr_has "cannot be used with"
}

# KDFFeedbackCounter_gen.rsp [PRF=CMAC_AES128] [CTRLOCATION=BEFORE_ITER] [RLEN=8_BITS] COUNT=5:
# IVlen = 0, so no --iv and an empty one are the same.
test_kbkdf_feedback_cmac_aes128_empty_iv() {
    local got ki fixed expected
    ki=36db18b4d4b6ebbebd49b942f25de3e4
    fixed=3d15a36e4837e3aae2d043353a112ee8521d36f9be36caccde0b94d8f3e484173d49f7cfdc55225299bb938693dfc57825ab83
    expected=fd354ad083a39d981facc7293c504399b0d233196e7149ad1f3b626dadc1df2cc6bda8e9f75dda2f147503ebc332e2cea0daeef1163500ff6cb4d2cd714de73d
    got=$(hex_out "$BC_RUST" kbkdf-feedback --prf cmac-aes128 --counter-bits 8 --counter-position before-iteration \
        --ikm "$ki" --additional-input "$fixed" --len 64 -x)
    assert_eq "$got" "$expected" "KO (no --iv)"
    got=$(hex_out "$BC_RUST" kbkdf-feedback --prf cmac-aes128 --counter-bits 8 --counter-position before-iteration --iv "" \
        --ikm "$ki" --additional-input "$fixed" --len 64 -x)
    assert_eq "$got" "$expected" "KO (empty --iv)"
}

# KDFFeedbackNoCounter_gen.rsp [PRF=HMAC_SHA256] COUNT=0: no counter.
test_kbkdf_feedback_hmac_sha256_no_counter() {
    local got
    got=$(hex_out "$BC_RUST" kbkdf-feedback --prf hmac-sha256 \
        --iv 5c2a2262d14994904c9c2de36d66c7ebdaed32b5cc441c222258857f5af29bea \
        --ikm 4b02ffb1cb9987496e19872597b026f7409d92433f9135068c29307985598586 \
        --additional-input a38f30844136c33e00d4254a8bc5f51e8473ac20e5628e77e4d91a704d58bf0d4d0fefb5f92d897f1958b0af188180b2e2d2f7 \
        --len 64 -x)
    assert_eq "$got" "ef46a7cc3f2fd3aac2d55c7386b99279098ad8af07e113c683e43601d3e0c9a48165a580d60b9c2df75cdfc066855607c0dd51ad8fc0296c3f72e83d3d5742e2" "KO"
}

# ---- double-pipeline mode -----------------------------------------------------------------

# KDFDblPipelineCounter_gen.rsp [PRF=HMAC_SHA512] [CTRLOCATION=AFTER_FIXED] [RLEN=16_BITS] COUNT=0
test_kbkdf_double_pipeline_hmac_sha512_counter() {
    local got
    got=$(hex_out "$BC_RUST" kbkdf-double-pipeline --prf hmac-sha512 --counter-bits 16 --counter-position after-fixed \
        --ikm 16b69d00a86d279640650c38e3320eeab45fab0cab8472e509d7a95544cc8d68c0db962ad4024ff6c6f19c8f990911af2f5b3194dfa51b9fa4107a8b2612e360 \
        --additional-input f79e0701726fd404131b49e396bc721bc41f750b9667f531e09fea32010305f23a98e1b33d193b8ab42ed1b6c7cdc40f51f047 \
        --len 64 -x)
    assert_eq "$got" "7334958745537da20e8292b05aa23f8f639faf665234cf9b27cfb0927124d491d0619ffe3b2f0f6ae420cbbcea8b6cdcf42efdcbd75d8b52396da74622ccd538" "KO"
}

# KDFDblPipelineNoCounter_gen.rsp [PRF=CMAC_AES192] COUNT=0
test_kbkdf_double_pipeline_cmac_aes192_no_counter() {
    local got
    got=$(hex_out "$BC_RUST" kbkdf-double-pipeline --prf cmac-aes192 \
        --ikm d17dc30b2ae32686e5acd5612d0a5abe88feb3c8704df7ac \
        --additional-input ccc0d0e85a83506fab3b2ca66a6b11605fb895d144b90adb4aa8e5ad8a86cfa58828cbf26539dceea168f4d675ff8810c63fb3 \
        --len 64 -x)
    assert_eq "$got" "b36bdf061b50c62fc3d17bbdabed230417b24e7c48ed9e4846d2675813d838fd7d85538bd71bf3610121b905371acc6eb68f9626594dee4bccc09e318e91d923" "KO"
}

# ---- KMAC ---------------------------------------------------------------------------------

# macMode KMAC-128 (tgId 1), tcId 45: derivedKeyLength 544 bits.
test_kbkdf_kmac128_matches_acvp() {
    local got
    got=$(hex_out "$BC_RUST" kbkdf-kmac128 --label-hex 12aecdf51085ac0775 \
        --ikm a7f30e01356fb758cf27c698ed2d42d5c69b4bbc06279e662cab3995bd65ce02fc19a7181ac3c1808f0b66eddab45fe586f6f7597b09604f0b28c4f6ef46633514a04c4d12c8cbbef4c6c66676aa8ff0a229dc209be3a24966bae1e682b6475572dd9869a5020e6217933d1d52c609ec0e46ad369cd513ad09f150212be25232e4182d80979d374f5f78f6ae90ab3ab6db \
        --additional-input e27365c7da112c4f49b38078fe1252d49ad125e766e00881f0160eea5130f7f89a8b63d039655f4881404819fd8d29bdb747417ca5a10046449f2c395aad8f92cc7d0627d0091bdb4eca8967264c201d506897e0c2c476a0b234da5541ad130ba76e661eab7a254f2704401b42b37a1ef46ee76db83701339bb2a1f55943e08fe6cc1aa06b158b38d65018c3f7125354293399213df9d7c20fd23337b2fba040c8382e9507a4528e8f256790f91005cfe954f1f983a8c715622244bea31a5d3de111d4fce23ca81b2d1dc9050f3ae45490d752103981529c3411d2b0bf7fab582a76cade6496a73c642b7ad544fc2634d2043e4f7388b4abf039928a780c47 \
        --len 68 -x)
    assert_eq "$got" "2f351c6251e093f12a507d91c6c3e905c944844ec00a138ba9f92d5a138ffe0c2c56f7687255507fce396e9f678251ca7e64dc5e0a94d9c095c921f80696e25ad910c2c5" "derivedKey"
}

# macMode KMAC-256 (tgId 2), tcId 71: derivedKeyLength 1432 bits.
test_kbkdf_kmac256_matches_acvp() {
    local got
    got=$(hex_out "$BC_RUST" kbkdf-kmac256 \
        --label-hex 040aa3d6e601bf02b9daf534573afbde49aeb18a48aee56603d8218c57d057ba6d28bde8d6dcc232e3690ae520c7124979782666878531c1f37ab2a834 \
        --ikm 81552fc39417d16a91415d2d4bd76bf3e47abe017d939fa93bbb7e58efc30350a7fe7f9f96503e7e1779fc231e922b9291ff3e732988b301f5c513d296e9e38e657cbf776afcf222eee7893094946f4f8d1442d35268cd6775e99b88722c66a0aa91b78de2b8a7d3d290dcf6ef28eb904e86fffd8a8e201d09a22f11cfc4b2cbde78597f25bdd58d12cc617385d609a5fb6b4d25f745190411dc4bb746ba9f340462cdf9cee6fc9babf743a49232f9545a76cc6ff9b62dab7228662159818456 \
        --additional-input a36cc3c016fc698475576f14380f7a70d8e0b5 \
        --len 179 -x)
    assert_eq "$got" "730524531ecb8be1df2ba9e3a7d2322cd2d203c07daac1ae9c3d14cc15ebe49414ebea97a3e8bd6893e4798521bd7606991cb4aefe46bc5a6952d43e57db331d5ca34b6aa2e8adb2557fb751d08704361eb8eb0aa1b26620cbc8daa3c7b5630ab31a1b0170f9de32244d10635ee8b0fd88ba57194ece6698b55018741c9ce1ab9edd2a18050e36bbd652b2852298ebdccb1f4fcf7044dc098b365807212576befb423d501b6701538559fc39c36a3bc3554b03" "derivedKey"
}

# --label is the text of --label-hex, and the Label is part of what is derived.
test_kbkdf_kmac_label_text_is_its_bytes() {
    local text hex_label none
    text=$(hex_out "$BC_RUST" kbkdf-kmac256 --label KDF --ikm 000102030405060708090a0b0c0d0e0f --len 32 -x)
    hex_label=$(hex_out "$BC_RUST" kbkdf-kmac256 --label-hex 4b4446 --ikm 000102030405060708090a0b0c0d0e0f --len 32 -x)
    none=$(hex_out "$BC_RUST" kbkdf-kmac256 --ikm 000102030405060708090a0b0c0d0e0f --len 32 -x)
    assert_eq "$text" "$hex_label" "--label KDF is --label-hex 4b4446"
    [ "$text" != "$none" ] || fail "the Label did not change the output"
    assert_eq "${#none}" 64 "32 bytes of hex"
}

# ---- the guards against key control -------------------------------------------------------

test_kbkdf_key_control_guard_changes_the_output() {
    local ki=dff1e50ac0b69dc40f1051d46c2b069c fixed=000102030405060708090a0b0c0d0e0f plain guarded
    plain=$(hex_out "$BC_RUST" kbkdf-counter --prf cmac-aes128 --ikm "$ki" --additional-input "$fixed" --len 32 -x)
    guarded=$(hex_out "$BC_RUST" kbkdf-counter --prf cmac-aes128 --key-control-guard --ikm "$ki" --additional-input "$fixed" --len 32 -x)
    assert_eq "${#guarded}" 64 "counter: 32 bytes of hex"
    [ "$plain" != "$guarded" ] || fail "counter: the guard did not change the output"
    plain=$(hex_out "$BC_RUST" kbkdf-feedback --prf cmac-aes128 --counter-bits 32 --ikm "$ki" --additional-input "$fixed" --len 32 -x)
    guarded=$(hex_out "$BC_RUST" kbkdf-feedback --prf cmac-aes128 --counter-bits 32 --key-control-guard --ikm "$ki" --additional-input "$fixed" --len 32 -x)
    assert_eq "${#guarded}" 64 "feedback: 32 bytes of hex"
    [ "$plain" != "$guarded" ] || fail "feedback: the guard did not change the output"
}

# ---- refusals -----------------------------------------------------------------------------

test_kbkdf_counter_refuses_inconsistent_position_flags() {
    expect_fail "an offset without in-fixed" "$BC_RUST" kbkdf-counter --prf hmac-sha256 --counter-offset 2 --ikm 0011 --additional-input 00010203 --len 16
    assert_stderr_has "in-fixed"
    expect_fail "an offset with after-fixed" "$BC_RUST" kbkdf-counter --prf hmac-sha256 --counter-position after-fixed --counter-offset 2 --ikm 0011 --additional-input 00010203 --len 16
    assert_stderr_has "in-fixed"
    expect_fail "in-fixed without an offset" "$BC_RUST" kbkdf-counter --prf hmac-sha256 --counter-position in-fixed --ikm 0011 --additional-input 00010203 --len 16
    assert_stderr_has "counter-offset"
    expect_fail "an offset past the fixed input data" "$BC_RUST" kbkdf-counter --prf hmac-sha256 --counter-position in-fixed --counter-offset 5 --ikm 0011 --additional-input 00010203 --len 16
    assert_stderr_has "key derivation failed"
    expect_fail "a counter of 12 bits" "$BC_RUST" kbkdf-counter --prf hmac-sha256 --counter-bits 12 --ikm 0011 --len 16
    assert_stderr_has "counter-bits"
    expect_fail "an unknown PRF" "$BC_RUST" kbkdf-counter --prf hmac-md5 --ikm 0011 --len 16
    assert_stderr_has "invalid value 'hmac-md5'"
    expect_fail "no PRF" "$BC_RUST" kbkdf-counter --ikm 0011 --len 16
    assert_stderr_has "<PRF>"
}

test_kbkdf_feedback_refuses_inconsistent_flags() {
    expect_fail "a position without a counter" "$BC_RUST" kbkdf-feedback --prf hmac-sha256 --counter-position after-fixed --ikm 0011 --len 16
    assert_stderr_has "counter-bits"
    expect_fail "the guard without a counter" "$BC_RUST" kbkdf-feedback --prf hmac-sha256 --key-control-guard --ikm 0011 --len 16
    assert_stderr_has "counter-bits"
    expect_fail "the guard with an IV" "$BC_RUST" kbkdf-feedback --prf hmac-sha256 --counter-bits 32 --key-control-guard --iv 0011 --ikm 0011 --len 16
    assert_stderr_has "cannot be used with"
    expect_fail "the counter mode's position name" "$BC_RUST" kbkdf-feedback --prf hmac-sha256 --counter-bits 32 --counter-position before-fixed --ikm 0011 --len 16
    assert_stderr_has "invalid value 'before-fixed'"
    expect_fail "an offset" "$BC_RUST" kbkdf-feedback --prf hmac-sha256 --counter-bits 32 --counter-offset 2 --ikm 0011 --len 16
    assert_stderr_has "unexpected argument '--counter-offset'"
}

test_kbkdf_double_pipeline_refuses_inconsistent_flags() {
    expect_fail "a position without a counter" "$BC_RUST" kbkdf-double-pipeline --prf hmac-sha256 --counter-position before-iteration --ikm 0011 --len 16
    assert_stderr_has "counter-bits"
    expect_fail "an offset" "$BC_RUST" kbkdf-double-pipeline --prf hmac-sha256 --counter-bits 32 --counter-offset 2 --ikm 0011 --len 16
    assert_stderr_has "unexpected argument '--counter-offset'"
    expect_fail "the guard flag, which this mode has not" "$BC_RUST" kbkdf-double-pipeline --prf hmac-sha256 --counter-bits 32 --key-control-guard --ikm 0011 --len 16
    assert_stderr_has "unexpected argument '--key-control-guard'"
}

test_kbkdf_kmac_refuses_both_labels() {
    expect_fail "--label with --label-hex" "$BC_RUST" kbkdf-kmac128 --label KDF --label-hex 4b4446 --ikm 0011 --len 16
    assert_stderr_has "label"
}

# SP 800-108r1 Section 6.2: CMAC takes a key of the cipher's length only.
test_kbkdf_refuses_a_cmac_key_of_the_wrong_length() {
    local ki24=d17dc30b2ae32686e5acd5612d0a5abe88feb3c8704df7ac
    expect_fail "counter: a 24-byte key for AES-128" "$BC_RUST" kbkdf-counter --prf cmac-aes128 --ikm "$ki24" --len 16
    assert_stderr_has "key derivation failed"
    expect_fail "feedback: a 24-byte key for AES-256" "$BC_RUST" kbkdf-feedback --prf cmac-aes256 --ikm "$ki24" --len 16
    assert_stderr_has "key derivation failed"
    expect_fail "double-pipeline: a 24-byte key for AES-128" "$BC_RUST" kbkdf-double-pipeline --prf cmac-aes128 --ikm "$ki24" --len 16
    assert_stderr_has "key derivation failed"
    expect_ok "counter: a 24-byte key for AES-192" "$BC_RUST" kbkdf-counter --prf cmac-aes192 --ikm "$ki24" --len 16 >/dev/null
}

# The KMAC KDF takes a key-derivation key of at most 512 bytes.
test_kbkdf_kmac_refuses_a_key_over_512_bytes() {
    rng 512 >"$TMP/k512"
    rng 513 >"$TMP/k513"
    expect_ok "a 512-byte key" "$BC_RUST" kbkdf-kmac256 --ikm-file "$TMP/k512" --len 16 >/dev/null
    expect_fail "a 513-byte key" "$BC_RUST" kbkdf-kmac256 --ikm-file "$TMP/k513" --len 16
    assert_stderr_has "key derivation failed"
}

test_kbkdf_refuses_bad_lengths_and_an_empty_key() {
    expect_fail "len above the command's bound" "$BC_RUST" kbkdf-kmac128 --ikm 0011 --len 16321
    assert_stderr_has "at most"
    # An 8-bit counter over CMAC gives at most 255 blocks of 16 bytes.
    expect_fail "len above 2^r - 1 PRF outputs" "$BC_RUST" kbkdf-counter --prf cmac-aes128 --counter-bits 8 --ikm dff1e50ac0b69dc40f1051d46c2b069c --len 4081
    assert_stderr_has "key derivation failed"
    expect_fail "a zero len" "$BC_RUST" kbkdf-counter --prf hmac-sha256 --ikm 0011 --len 0
    assert_stderr_has "zero-length"
    expect_fail "an empty --ikm" "$BC_RUST" kbkdf-counter --prf hmac-sha256 --ikm "" --len 16
    assert_stderr_has "empty"
}

run_all
