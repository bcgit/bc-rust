#!/usr/bin/env bash
# The aes*-cmac and aes*-gmac subcommands against the ACVP known answers, and their round trips.
#
# Written for the 2026-11-03 CLI review (report 15) from the vector files named in each test;
# every expected value is copied from that file, none is typed by hand. Follows lib.sh's
# conventions: each test_* runs in its own subshell under `set -e`.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# ACVP CMAC-AES (bc-test-data/crypto/aes_tdes_vectors/CMAC/CMAC-AES.4014544.{req,rsp}.json),
# tgId 6 tcId 41: AES-128, a 416-byte message, a 16-byte tag.
test_aes128_cmac_matches_acvp() {
    local got
    unhex 93D255B8DD1D4FEF87188DE84B0D011887DC20BB688B5C26C263D449CD2E34D0A155715EC8F22090C5EB3D1E9DE35A201BA964F571D28605301EABFEAE15DBC4372ACCA52E1CC2EBD1918EEE918D446D61825EA8F36CFA6EFA9F7B8ADDF22253DACEABE151BBA37A5257616C4181A5ABA888F0D068B593E30C1E60D197144233FECF6F3639EDF65152C75D864F068D5B71129E1F2520224A04E5CF480CF542AFDEB173CEDC16BE47A815F08BFF98C8DB676DC6D9C420E4719D4C4CF7349E6642535D1E18E2F4C837EB63400991C09651DC03E77338950DFCC955C2A44DAAAAE81E814C96E9A5DF4EE0FE6ED11DAEC75FF19AA1DF8785C49FF308BDC242A8365A345DB7581F87EB7EE36FF8FC3500048617044D8404DF46D6DA6B1DD523C2BDD9FBA4D12235DF643F1EA6BECE5B9E0B11DDE085008231FF0680EC3784C60A24A13E549A4111E1679D05CFB603E5C7C311F0E4DF4864FC2D96E5E3049C7C690ED5A9A3961EB0FBF5BC28E9FCAFC7E4E98489B3EED5DFCE45D4734B3D079E9086027F7EE8CF4B4CC5DEBABF16AAD0A1E123EBA22D036C8E539273E16B75DAB07C3F >"$TMP/msg"
    assert_size "$TMP/msg" 416 "message length"
    got=$(hex_out "$BC_RUST" aes128-cmac --key 94cd50a907d427b6b75a643361b8b5de -x <"$TMP/msg")
    assert_eq "$got" "2c930aaccc775c99e421a0989621947c" "CMAC-AES128 tcId 41"
    expect_ok "the tag verifies" "$BC_RUST" aes128-cmac --key 94cd50a907d427b6b75a643361b8b5de -v 2c930aaccc775c99e421a0989621947c <"$TMP/msg"
    expect_fail "a flipped tag does not" "$BC_RUST" aes128-cmac --key 94cd50a907d427b6b75a643361b8b5de -v 3c930aaccc775c99e421a0989621947c <"$TMP/msg"
    assert_stderr_has "MAC verification failed"
}

# The same file, tgId 24 tcId 185: AES-256, a 416-byte message, a 16-byte tag.
test_aes256_cmac_matches_acvp() {
    local got
    unhex 9DB5CEAEC709883E16E4474BE66842D184026CDC0BCE6CCDB41187E9F59FD665F473B29B3B47E33695D21DF9E34E09517BE2E14760897C505109F5AB3F1E1034DD2A99EFBABEB4664ACC66881EBED6AABDC70806D3B4908E626D59EFAD2D02FC5A3BB7BAF8C61984E8B5FBF118DFBDABF9A3D9421B6B6F95E592B6D4429C1B45BD7E68DC69D04D960A24724349762019419C8CC873C07BC318218B465D23A85BF8446738F9FF47866B4C02972E87B670D814F7EAF8148A24B761DBB157B9E30CBBA1CB00E6F92D398685DCFEE43324F3D2E2FF413063FCC4454D322638CE0B484BE7CA537B8953D755284EF4D8CF72E988137F63012EF485F4468939D18361D479B5CD561CAC065245016F24E8F00BCE8703AA9AA385FE183EE6FF82DB99D9C54D36E5E39EFAEC32AD22E80047326CF4C865D2AA48AF0B5E996C5109DEB4752E01B75754E5D4345AADF249AEE497858FF0DE3651C7DA7CA48BCAB8D2549A24F7D1CC97CDC15CD2FFB69A84C5539629513FA6A403AC46FA988418B1B7D4EBF432B79D450DE8C53594E2E398C17301BD3C828CBD49CCDC9417DA8092F7F1B4E34E >"$TMP/msg"
    got=$(hex_out "$BC_RUST" aes256-cmac --key 5cf7c611d3abddfdf070e0405ed5191610a26cb73951297eae18b9c6c22505c2 -x <"$TMP/msg")
    assert_eq "$got" "c23b79870186e3294e7d9a2e2ef0993e" "CMAC-AES256 tcId 185"
}

# CMAC round trips for the three key lengths: the tag is 16 bytes, verifies, and rejects another
# message, another key and a truncated tag; the key file form agrees with the inline form.
test_cmac_round_trips() {
    local bits tag
    rng 100 >"$TMP/msg"
    rng 100 >"$TMP/other"
    for bits in 128 192 256; do
        rng $((bits / 8)) >"$TMP/key"
        rng $((bits / 8)) >"$TMP/other_key"
        tag=$(hex_out "$BC_RUST" "aes$bits-cmac" -k "$TMP/key" -x <"$TMP/msg")
        assert_eq "${#tag}" 32 "aes$bits-cmac tag length"
        assert_eq "$(hex_out "$BC_RUST" "aes$bits-cmac" --key "$(hex "$TMP/key")" -x <"$TMP/msg")" "$tag" "inline key agrees"
        expect_ok "verifies" "$BC_RUST" "aes$bits-cmac" -k "$TMP/key" -v "$tag" <"$TMP/msg"
        expect_fail "not another message" "$BC_RUST" "aes$bits-cmac" -k "$TMP/key" -v "$tag" <"$TMP/other"
        expect_fail "not another key" "$BC_RUST" "aes$bits-cmac" -k "$TMP/other_key" -v "$tag" <"$TMP/msg"
        expect_fail "not a truncated tag" "$BC_RUST" "aes$bits-cmac" -k "$TMP/key" -v "${tag:0:16}" <"$TMP/msg"
    done
    expect_fail "a wrong-length key" "$BC_RUST" aes128-cmac --key 0011 </dev/null
    assert_stderr_has "16-byte key"
}

# ACVP AES-GMAC (bc-test-data/crypto/aes_tdes_vectors/GCM/ACVP-AES-GMAC.4014543.{req,rsp}.json),
# tgId 2 tcId 16: AES-128, a 96-bit IV, 16 bytes of AAD, a 128-bit tag. The data is the AAD.
test_aes128_gmac_matches_acvp() {
    local got
    unhex A936747E0088B908FBDB8AC596C09376 >"$TMP/aad"
    got=$(hex_out "$BC_RUST" aes128-gmac --key 209730e4737a56343a8bd50013e7cf9a --iv 2920dcb53254a95eaba3dd4e -x <"$TMP/aad")
    assert_eq "$got" "349c7f0b588598c575bf10b29330a9fb" "GMAC-AES128 tcId 16"
    expect_ok "the tag verifies with --iv" "$BC_RUST" aes128-gmac --key 209730e4737a56343a8bd50013e7cf9a --iv 2920dcb53254a95eaba3dd4e -v 349c7f0b588598c575bf10b29330a9fb <"$TMP/aad"
    expect_ok "and as nonce || tag" "$BC_RUST" aes128-gmac --key 209730e4737a56343a8bd50013e7cf9a -v 2920dcb53254a95eaba3dd4e349c7f0b588598c575bf10b29330a9fb <"$TMP/aad"
    expect_fail "not under another nonce" "$BC_RUST" aes128-gmac --key 209730e4737a56343a8bd50013e7cf9a --iv 2920dcb53254a95eaba3dd4f -v 349c7f0b588598c575bf10b29330a9fb <"$TMP/aad"
    unhex 2920dcb53254a95eaba3dd4e >"$TMP/iv"
    got=$(hex_out "$BC_RUST" aes128-gmac --key 209730e4737a56343a8bd50013e7cf9a --iv-file "$TMP/iv" -x <"$TMP/aad")
    assert_eq "$got" "349c7f0b588598c575bf10b29330a9fb" "the nonce from a raw file"
}

# The same file, tgId 9 tcId 121: AES-256, 32 bytes of AAD.
test_aes256_gmac_matches_acvp() {
    local got
    unhex 8AF7DADB6A185623BDDAB8637D6C9D3BAD39FAE4B6833AB41EC5DFB1BEE5A0DD >"$TMP/aad"
    got=$(hex_out "$BC_RUST" aes256-gmac --key dc4185d2af1d50b6272e5e2b498200c8c351a16bde94a4033f4d58fdf0211215 --iv fdbba151a8245eaafa7ead03 -x <"$TMP/aad")
    assert_eq "$got" "2f762326f3b2bf7e4971eac077958eb8" "GMAC-AES256 tcId 121"
}

# Without --iv a fresh nonce is drawn and written ahead of the tag, so the output is 28 bytes,
# verifies as nonce || tag, and two runs draw two nonces; the tag is bound to the data.
test_gmac_generates_a_nonce_per_tag() {
    local bits out
    rng 100 >"$TMP/msg"
    for bits in 128 192 256; do
        rng $((bits / 8)) >"$TMP/key"
        "$BC_RUST" "aes$bits-gmac" -k "$TMP/key" <"$TMP/msg" >"$TMP/out1"
        assert_size "$TMP/out1" 29 "nonce || tag and a newline"
        out=$(hex_out "$BC_RUST" "aes$bits-gmac" -k "$TMP/key" -x <"$TMP/msg")
        assert_eq "${#out}" 56 "hex nonce || tag"
        expect_ok "verifies as nonce || tag" "$BC_RUST" "aes$bits-gmac" -k "$TMP/key" -v "$out" <"$TMP/msg"
        expect_ok "and as --iv plus the tag" "$BC_RUST" "aes$bits-gmac" -k "$TMP/key" --iv "${out:0:24}" -v "${out:24}" <"$TMP/msg"
        expect_fail "not over other data" "$BC_RUST" "aes$bits-gmac" -k "$TMP/key" -v "$out" < <(rng 100)
        [ "$out" != "$(hex_out "$BC_RUST" "aes$bits-gmac" -k "$TMP/key" -x <"$TMP/msg")" ] || fail "two runs must draw two nonces"
    done
    rng 16 >"$TMP/key"
    expect_fail "a verify value of the wrong shape" "$BC_RUST" aes128-gmac -k "$TMP/key" -v 00 <"$TMP/msg"
    assert_stderr_has "nonce"
    expect_fail "an IV of the wrong length" "$BC_RUST" aes128-gmac -k "$TMP/key" --iv 0011 <"$TMP/msg"
    assert_stderr_has "12"
}

run_all
