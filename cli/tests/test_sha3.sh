#!/usr/bin/env bash
# The sha3-*, shake*, cshake*, kmac*, kmacxof*, tuplehash*, tuplehashxof*, parallelhash* and
# parallelhashxof* subcommands against the CAVP and SP 800-185 known answers.
#
# Written for the 2026-11-03 CLI review (report 15) from the vector files named in each test;
# every expected value is copied from that file, none is typed by hand. Follows lib.sh's
# conventions: each test_* runs in its own subshell under `set -e`.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# CAVP SHA3_224ShortMsg.rsp (bc-test-data/crypto/sha3/byte-oriented), Len = 0 and Len = 64.
test_sha3_224_matches_cavp_short_msg() {
    local got
    got=$(hex_out "$BC_RUST" sha3-224 -x </dev/null)
    assert_eq "$got" "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7" "sha3-224 of the empty message"
    unhex e4ea2c16366b80d6 >"$TMP/msg"
    got=$(hex_out "$BC_RUST" sha3-224 -x <"$TMP/msg")
    assert_eq "$got" "7dd1a8e3ffe8c99cc547a69af14bd63b15ac26bd3d36b8a99513e89e" "sha3-224 of an 8-byte message"
}

# CAVP SHA3_256ShortMsg.rsp (bc-test-data/crypto/sha3/byte-oriented), Len = 0 and Len = 64.
test_sha3_256_matches_cavp_short_msg() {
    local got
    got=$(hex_out "$BC_RUST" sha3-256 -x </dev/null)
    assert_eq "$got" "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a" "sha3-256 of the empty message"
    unhex 8bca931c8a132d2f >"$TMP/msg"
    got=$(hex_out "$BC_RUST" sha3-256 -x <"$TMP/msg")
    assert_eq "$got" "dbb8be5dec1d715bd117b24566dc3f24f2cc0c799795d0638d9537481ef1e03e" "sha3-256 of an 8-byte message"
}

# CAVP SHA3_384ShortMsg.rsp (bc-test-data/crypto/sha3/byte-oriented), Len = 0 and Len = 64.
test_sha3_384_matches_cavp_short_msg() {
    local got
    got=$(hex_out "$BC_RUST" sha3-384 -x </dev/null)
    assert_eq "$got" "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004" "sha3-384 of the empty message"
    unhex c44a2c58c84c393a >"$TMP/msg"
    got=$(hex_out "$BC_RUST" sha3-384 -x <"$TMP/msg")
    assert_eq "$got" "60ad40f964d0edcf19281e415f7389968275ff613199a069c916a0ff7ef65503b740683162a622b913d43a46559e913c" "sha3-384 of an 8-byte message"
}

# CAVP SHA3_512ShortMsg.rsp (bc-test-data/crypto/sha3/byte-oriented), Len = 0 and Len = 64.
test_sha3_512_matches_cavp_short_msg() {
    local got
    got=$(hex_out "$BC_RUST" sha3-512 -x </dev/null)
    assert_eq "$got" "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26" "sha3-512 of the empty message"
    unhex af53fa3ff8a3cfb2 >"$TMP/msg"
    got=$(hex_out "$BC_RUST" sha3-512 -x <"$TMP/msg")
    assert_eq "$got" "03c2ac02de1765497a0a6af466fb64758e3283ed83d02c0edb3904fd3cf296442e790018d4bf4ce55bc869cebb4aa1a799afc9d987e776fef5dfe6628e24de97" "sha3-512 of an 8-byte message"
}

# CAVP SHA3_256LongMsg.rsp, the first message of at least 3 KiB (Len = 25200 bits), crossing the 1 KiB
# chunking of `helpers::stream_hash` and the 136-byte rate many times.
test_sha3_256_matches_cavp_long_msg() {
    local got
    unhex d9c7762f278a6ecb070bca56c4f7d7fea31590df217906d47dfb058c76e7f4e056f6fd632f7d6e3b65e55f306c5b9603d3c8a70182045fd7404763a878e0155d3c29b73d8abad3bdceddda99a9420b23f1f496dbf98c024112a5cce7518f51ca9348ede2bfa765f84bdb82b80214ff070480a6970e79b5b8fbfd86718b5e6fcf643ae87d56aeeb95e3c7a1b6ff393a5714541c5a493341e40437da6dadb43913b6e9ed34d8362f3b9f897dba281a84ba2a58434f33226e6f343b100340f8753f913c472fcca6f79385095eed061da5d84c74629b53af03fe94f1705dcb94ecfafd1b3c97ba680c45a0308e7720ab645a8590c0693140ca3c2a4142a0d6ef66ed036e16942ae336f8f5e4547ffe2d8ae8da94a6df563f89ce0014cdf7ea71abc0aa1d1b4da57f3c548e0ef72d2909df2955685c254912095f1e505a888e82821afb1194ebb2a4e8037297c0aa28a92bc6fdf42a64922312958adf317b4a8ab4a3fc30c895daba00aaa965f71e83733666da2158c4bad86c184ea79af9a6f10a04b7630174a4294df43c62e4b1c3d1c8b2f5d52d6c489bde917292dd2a2b1f49e5349385b0985a97863274ce896f2aa85255f9f285c4d331a8fc874135607d3ced7aa69e703eb3a60b9385ffd10fe59fed0276f036b7e72d04f66d0f42cd71aac5918691dc1f9d4129677cbdaf2c6c752b05326ca8a8419a4e672e907bfb645a158119a91ec2813288b741514b4d26f2b66517b1021f48402d58b1090671bf158452492d5bafc53fd18abc03cefa7bdd332a0c066da464e74ad0dec50bb7e8a3ba0dfc64be6fd331ace9d51a60bbd3004d5df8b211c0fd564cd79d0bb35649cc60ba1c976c8911cfc0db74e028199621aa05c5fe15fa7b56dc75d62225d548581e5f900f9085e9e3b668819b4f9b2c09f22a5a32a2db47afa2b371538abc4f0e9b06401150ecc2333598e494fccafe80ced49f96dfeac729459856e60a94c5b780b614e8d4450389e6748513582c724ee60c7c71f5af648b6e2d6e23cce4121b7478f4db451816ab71034c5f8b4bf13ae1d9d90d0bb2869fc4799f51f9349d022053c831cbee62617d4e22c2bcafe40d67449eb04a7c962bf084d2bab80dd0342b4f78338d4d4f75b25bed8214deb18f2254b3a3da94faf89956f0a432f512783e74ec29b4c045adba3497e8ba62c288b711002ee2821cce68f8df588f76cc9801cb0d5b67ccacd33ae1063cd6c37dc0d1836e988acf63750571891ef618645a1b5bc110cffbecaddd6824c692874cff16b3e32bfc0236b417c9d43d8f624387352cf19114d46d0448d3d7cd1438960c2ea8482d5da3ff544608aaff83dcd1e7f64786275ddf989f262a099b845dc2b0c26a86e7d83a251e3c37f2aafa0e764107b36618d2a5d3481d73a1760b7f3ab37a0283a1925010d79e5e94871b819b5e0f787bac9dad87c5d5b887a7d12565ddfd7729a3b66c274a178377de0fbca607b79fab2de37f1ddff800a376fdd7abf5f4d15f346a17d43e4db085f7fe470102a72fe0e1cfa4fb5e2b54dd2ab71e74c506190c9dd6d87f7ae8eca5190fab12178630011286a38b0a18bb1d0d29802813dc561a2724378ec79140bf8e6a6f4310fdabf606330434ab673d4b6578872fa81d90701779bc6aedf0b2bc9c381bfbb4b3a6a705fc505d08c0e24f7bcfbbf24c72cff6b800f07bb4ac4d828ca138a1ca512cfc59090e70eac9b3119754a3d7c6831c9451de5a29e46d16faa6cc4d9f1b7e42dd4983c6d4192db779012fc747e0f77e32293e83dd44dd170c31e2e25c6fe3f2321c9201f15d92f6700089afab6077feb88946f1fd9da257a1770a7f408d2743e31b5d452f7ea179dcdd8ae4690faaa30eb91e2ef3b764de9fbe6dadb33ff33ed88e0d1df6430147a7e159edebb539751d01efc2255accb5f04f32f31d4befe9f9bdc90eae755a68b7511f52971acb7ccba9e133fd4e81e37a7282dae67ac24e2fefbaa2bfdc56e5f678039cd70509c101f81b0be15a2c70276e85e976941575606d086091409bc54a9d2e5212409a4ba837c6d13b487565dd8d62a836618f647580dad08c69d1109d07c7fcaf912822a6af090e72de03c98615429f8ca9d925576e587b191fa1cfd6fff72218c1584fe5a50d49eee57fa4094f4c57e1339ac0ec7face89e29b309ddcde64db498d4d94b64f90a172490fe4e83a9579ec87b3b1efdfb9f8550aec69ab9bb04ebdd44c8c233f6da5565dfe03df98027293024a0d42e7029345c3a0ef50b9fd0255a4f2531592c3f106e1451bef8fa50ec333cf7f65c300d151500ead60ab938cad59ef77f1fc2c3b008d65ab9c93f594d986c466bcd66d38e42a86125ff32c44217d94696cde1ee9dfbcd0216b576cab6295b971dc9380409adda7cca3231fcf6e8a71a5dabb0473f0fa251bd02c82c8eacb1f1f39ace27ed1c3d42adebdf694c0fb07cbc005856ff0cfd4f96f85c053dea185dd58751c4a25879bbb6726392ad569d739b1600a343b985058ae15be02bab36e1abd7e964902937efce0ee6ff82831608e233d1b774dfe37a7f03ec42c0b7b3885dd3bd8e1f561fe7db099039315fc24279a0f319fb46bfb65ea838b564d53857d4c3f6cab7a9d8aac6a988c724b24a2949a58d513eb6bfc2101666c07fcf6d58f6efbba0c0e80b407837f731c14455c53889c7e8a7f78ea57c959fec796bf992ac9e3599a2dc5fb2d8fa040072dc8c1f2f96ca659dd0d267896f0bbfba72850ddf198c3cc54d7d07cd3cd8bb9e44973e1712be50870b341121ead1c3aaabb8d275a9e71191030c4741439aeaac421d2ad646cb32cf6e5baa2b501a80b1e03be858946ea16fc5b57a1b597316069fc6ec567a1791dcc2f03a8ee70d7d38d7b5576e224b73c55c20a943c48bc613223c8b7df6cdf816ce9aca34f8d342a559cf28a19da310fc91f4dca0cc09823b95240f350113ece55c026004ca9357622e3162d74ba1fe7d2ad9191cbb16d2e6be298165e411f7b132cf07e6a77645d51e820dfa766ac7afef796a9ed7d93f7c67f1e8f5e8f1a0e219aac4c2d5a49368f16a32f16429f2f9aa79d60f6a7b506556244ccc52d86fe0d93ba1809d44c9826e93d7a45d0408c521846555ba238e0a546bb5d46df0ed143a29a509477e6f8a5fa207fbab23907a1d40205910fa7fd1286e2cf48061a1e4041dd8431b7c0eea8a42c7de95af127f66550e03b328ad239cd4b814d25314b9febe431761632d09b719213562d0173ec46c383cedd4a0697645621cacedccfcf2b5ed6d605e554fb0cf1ce85bad261eff2da4ea0426de097f6b31f556575313a6a9df2e61920d243c0dc0dfc86fc787de3f5cf64147f16d7feb2d8518ba3168e2431f40ac2addf0227b1603f13d82e12b4b6849ec5f61fb3e705eb53a3eec61702bb78d894c4d1b2bc0253a1d40e095acf8ceca4d95b41d83a0cd6e030a0e681708aefc4021e60d1f84f66d95a068092aef9860ab12743a17238196bd471fe49e820d7418d02f2fc6718f85a284a3a66cd7cef550fe28b9c3a28216ae1ca53dce42dbdf5a81b1e7e72dfa688a1417d43c597670828059044dc5d9d71eb22ada6ff020244f5ef29e4c603f00957a4efc601d9ab88ac08e827d338dc0573035254934e52b3c8c7cbdbbb364330ddbd084a1ca41b7b0e74f9b1d95a6b8a0bf4f8523b431dc6c36d7aafdcd73eb386223d6c70874543b1d25b7f3922da94087fe62c61b0c1f268289cfda58730f6034d1589a813a777589963ec9d3297a80afcd25fb0f7edcb1981c9319f96d87cb7c6274e2da9b08a4542c9865ffa213a8604134883890fb56a1185d845a683bc1605c9166be9ff011a56f2e8fbfa05c00c1e4f8354049645dc50397e1236c138c084916efd34f1504a5e66611bb2c3dcffb3dd9ccccb2ff0e2b67a8f9fc82f7739db06d45c1b260c47c19a9b29a4d9e5f35d4401387d1b5b0fccbf8948bb0cfbd471afd3031d0b99b51906039050c67f6983293d416b06c8d5fb8ef7a7b0083b32d0e2e78cbb209cf4cd4f16fa36f80dd4cde3bd524570deb7db5f572727afb9d781468e4365f36a9976cc61c1d81d15c7860a1df57cc81137e4a724518251fc34fb4133d1bdf2a7157e045081a4742ba44412cb95719ae4d89ffcebb1709d86cdb77974b213bcb6fb7b9d8fa43cbbc41d908432dcd467ee1c65d719c142e0ce144e45dd6f17a03ebdd7ee6bb401425375f3d50016159d8165eebc3b0ba9da46bb184cba632a4b92cf1b7d714b82a67e5fd69bafeba5ca33579312dbfae5d89504add4a828dc2d57b1cec12ca53166893dc13e9ec8156c9863eb815909b76a1d839794334aadb3e2085a601a8badf128924c345935d503151d607e4ec27f1d64da3e01c8230f7de63566c0b75958d4b0efc0136baf751c3de69a7039bfad50ff5b3983f35c81e9c8bb4c798 >"$TMP/msg"
    got=$(hex_out "$BC_RUST" sha3-256 -x <"$TMP/msg")
    assert_eq "$got" "20e819aa8988e4a3c491673504b59ca44db6703f01094e0d87a85ce9c4d9ac4f" "long message"
}

# CAVP SHAKE128ShortMsg.rsp ([Outputlen = 128]), Len = 0 and Len = 64, and SHAKE128VariableOut.rsp's
# longest output (COUNT = 1116, Outputlen = 1120 bits = 140 bytes): the
# positional length argument selects the squeeze length.
test_shake128_matches_cavp() {
    local got
    got=$(hex_out "$BC_RUST" shake128 16 -x </dev/null)
    assert_eq "$got" "7f9c2ba4e88f827d616045507605853e" "shake128 of the empty message"
    unhex 7bf2fef375bcaff3 >"$TMP/msg"
    got=$(hex_out "$BC_RUST" shake128 16 -x <"$TMP/msg")
    assert_eq "$got" "5ef5578b89c50532131b7843de7329a3" "shake128 of an 8-byte message"
    unhex a8ded9816defca8327c194a48a88ae4e >"$TMP/msg"
    got=$(hex_out "$BC_RUST" shake128 140 -x <"$TMP/msg")
    assert_eq "$got" "ed7397b2215c6c412bf444b1b96fc55c531aef025c6dd13fb4ab53fcc20c91917d82c8d6710a8d7b4c24d18b54150490e98ee01b4a4b9790d1878810a8392d3fa203b066327c0c67cace3a08c57d0d30b62ba43121d8d715637884f055c55ad6689692249885dce01c96979f1a2b309943e14abb0ba8e227bceb381667579e10694bd442b99064aa88501431" "shake128 variable-length output"
}

# CAVP SHAKE256ShortMsg.rsp ([Outputlen = 256]), Len = 0 and Len = 64, and SHAKE256VariableOut.rsp's
# longest output (COUNT = 1240, Outputlen = 2000 bits = 250 bytes): the
# positional length argument selects the squeeze length.
test_shake256_matches_cavp() {
    local got
    got=$(hex_out "$BC_RUST" shake256 32 -x </dev/null)
    assert_eq "$got" "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f" "shake256 of the empty message"
    unhex 587cb398fe82ffda >"$TMP/msg"
    got=$(hex_out "$BC_RUST" shake256 32 -x <"$TMP/msg")
    assert_eq "$got" "54f5dddb85f62dba7dc4727d502bdee959fb665bd482bd0ce31cbdd1a042e4b5" "shake256 of an 8-byte message"
    unhex dc886df3f69c49513de3627e9481db5871e8ee88eb9f99611541930a8bc885e0 >"$TMP/msg"
    got=$(hex_out "$BC_RUST" shake256 250 -x <"$TMP/msg")
    assert_eq "$got" "00648afbc5e651649db1fd82936b00dbbc122fb4c877860d385c4950d56de7e096d613d7a3f27ed8f26334b0ccc1407b41dccb23dfaa529818d1125cd5348092524366b85fabb97c6cd1e6066f459bcc566da87ec9b7ba36792d118ac39a4ccef6192bbf3a54af18e57b0c146101f6aeaa822bc4b4c9708b09f0b3bab41bcce964d999d1107bd7c27af989ebe1e104a35478df362ec4c9628f5ea29cc1164b92960d42068a59b1ddcb8875722ed59df36ea654d97b6bf39e5075121ec93f8a8ea6ee5d923997ae8a9d4c315a3d074e3ff83dfa26490f0f5b00a3cc3f110f0f761eaac885a3d1eee302014191733bf77b4d58cca49258897d6460" "shake256 variable-length output"
}

# SP 800-185 KMAC sample, bc-test-data/crypto/sp800-185/KMAC.rsp COUNT = 0 (kmac128, S = "",
# 32-byte tag). The key is the sample's 32-byte key, passed as hex; the customization string is
# passed as the characters themselves (`-s`), since the CLI takes it as a string.
test_kmac128_sample_count_0() {
    local got
    unhex 00010203 >"$TMP/msg"
    got=$(hex_out "$BC_RUST" kmac128 32 --key 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f -x <"$TMP/msg")
    assert_eq "$got" "e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e" "KMAC128 COUNT 0"
    expect_ok "the sample tag must verify" "$BC_RUST" kmac128 32 --key 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f --verify "e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e" <"$TMP/msg"
    expect_fail "a different length must not verify the same tag" "$BC_RUST" kmac128 33 --key 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f --verify "e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e" <"$TMP/msg"
}

# SP 800-185 KMAC sample, bc-test-data/crypto/sp800-185/KMAC.rsp COUNT = 1 (kmac128, S = 'My Tagged Application',
# 32-byte tag). The key is the sample's 32-byte key, passed as hex; the customization string is
# passed as the characters themselves (`-s`), since the CLI takes it as a string.
test_kmac128_sample_count_1() {
    local got
    unhex 00010203 >"$TMP/msg"
    got=$(hex_out "$BC_RUST" kmac128 32 -s 'My Tagged Application' --key 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f -x <"$TMP/msg")
    assert_eq "$got" "3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5" "KMAC128 COUNT 1"
    expect_ok "the sample tag must verify" "$BC_RUST" kmac128 32 -s 'My Tagged Application' --key 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f --verify "3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5" <"$TMP/msg"
    expect_fail "a different length must not verify the same tag" "$BC_RUST" kmac128 33 -s 'My Tagged Application' --key 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f --verify "3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5" <"$TMP/msg"
}

# SP 800-185 KMAC sample, bc-test-data/crypto/sp800-185/KMAC.rsp COUNT = 3 (kmac256, S = 'My Tagged Application',
# 64-byte tag). The key is the sample's 32-byte key, passed as hex; the customization string is
# passed as the characters themselves (`-s`), since the CLI takes it as a string.
test_kmac256_sample_count_3() {
    local got
    unhex 00010203 >"$TMP/msg"
    got=$(hex_out "$BC_RUST" kmac256 64 -s 'My Tagged Application' --key 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f -x <"$TMP/msg")
    assert_eq "$got" "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd" "KMAC256 COUNT 3"
    expect_ok "the sample tag must verify" "$BC_RUST" kmac256 64 -s 'My Tagged Application' --key 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f --verify "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd" <"$TMP/msg"
    expect_fail "a different length must not verify the same tag" "$BC_RUST" kmac256 65 -s 'My Tagged Application' --key 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f --verify "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd" <"$TMP/msg"
}

# SP 800-185 TupleHash sample, TupleHash.rsp COUNT = 0 (tuplehash128, S = "", 32 bytes).
test_tuplehash128_sample_count_0() {
    local got
    got=$(hex_out "$BC_RUST" tuplehash128 32 -e 000102 -e 101112131415 -x </dev/null)
    assert_eq "$got" "c5d8786c1afb9b82111ab34b65b2c0048fa64e6d48e263264ce1707d3ffc8ed1" "TupleHash128 COUNT 0"
}

# SP 800-185 TupleHash sample, TupleHash.rsp COUNT = 1 (tuplehash128, S = 'My Tuple App', 32 bytes).
test_tuplehash128_sample_count_1() {
    local got
    got=$(hex_out "$BC_RUST" tuplehash128 32 -s 'My Tuple App' -e 000102 -e 101112131415 -x </dev/null)
    assert_eq "$got" "75cdb20ff4db1154e841d758e24160c54bae86eb8c13e7f5f40eb35588e96dfb" "TupleHash128 COUNT 1"
}

# SP 800-185 TupleHash sample, TupleHash.rsp COUNT = 3 (tuplehash256, S = "", 64 bytes).
test_tuplehash256_sample_count_3() {
    local got
    got=$(hex_out "$BC_RUST" tuplehash256 64 -e 000102 -e 101112131415 -x </dev/null)
    assert_eq "$got" "cfb7058caca5e668f81a12a20a2195ce97a925f1dba3e7449a56f82201ec607311ac2696b1ab5ea2352df1423bde7bd4bb78c9aed1a853c78672f9eb23bbe194" "TupleHash256 COUNT 3"
}

# SP 800-185 ParallelHash sample, ParallelHash.rsp COUNT = 0 (parallelhash128, B = 8, S = "", 32 bytes).
test_parallelhash128_sample_count_0() {
    local got
    unhex 000102030405060710111213141516172021222324252627 >"$TMP/msg"
    got=$(hex_out "$BC_RUST" parallelhash128 32 -b 8 -x <"$TMP/msg")
    assert_eq "$got" "ba8dc1d1d979331d3f813603c67f72609ab5e44b94a0b8f9af46514454a2b4f5" "ParallelHash128 COUNT 0"
}

# SP 800-185 ParallelHash sample, ParallelHash.rsp COUNT = 1 (parallelhash128, B = 8, S = 'Parallel Data', 32 bytes).
test_parallelhash128_sample_count_1() {
    local got
    unhex 000102030405060710111213141516172021222324252627 >"$TMP/msg"
    got=$(hex_out "$BC_RUST" parallelhash128 32 -b 8 -s 'Parallel Data' -x <"$TMP/msg")
    assert_eq "$got" "fc484dcb3f84dceedc353438151bee58157d6efed0445a81f165e495795b7206" "ParallelHash128 COUNT 1"
}

# SP 800-185 ParallelHash sample, ParallelHash.rsp COUNT = 3 (parallelhash256, B = 8, S = "", 64 bytes).
test_parallelhash256_sample_count_3() {
    local got
    unhex 000102030405060710111213141516172021222324252627 >"$TMP/msg"
    got=$(hex_out "$BC_RUST" parallelhash256 64 -b 8 -x <"$TMP/msg")
    assert_eq "$got" "bc1ef124da34495e948ead207dd9842235da432d2bbc54b4c110e64c451105531b7f2a3e0ce055c02805e7c2de1fb746af97a1dd01f43b824e31b87612410429" "ParallelHash256 COUNT 3"
}

# Shorter XOF output is a prefix of longer output (FIPS 202 Sec 6.2 defines SHAKE as a function of
# the output length d: the first d bits).
test_shake128_output_is_a_prefix_of_a_longer_squeeze() {
    local full short
    full=$(hex_out "$BC_RUST" shake128 200 -x </dev/null)
    short=$(hex_out "$BC_RUST" shake128 32 -x </dev/null)
    assert_eq "${full:0:64}" "$short" "the 32-byte squeeze must be a prefix of the 200-byte one"
}

# SP 800-185 Sec 6.2: B must be greater than zero; the CLI refuses it before reading stdin.
test_parallelhash_block_size_zero_is_rejected() {
    expect_fail "B = 0" "$BC_RUST" parallelhash128 32 -b 0 </dev/null
    assert_stderr_has "block-size"
}

# SP 800-185 Sec 8.4.2 / the library's own floor: a KMAC tag shorter than 4 bytes (32 bits) is
# refused. The refusal must be a reported error (exit 255 and an `Error:` line), not a panic.
test_kmac_tag_shorter_than_4_bytes_is_an_error_not_a_panic() {
    local len
    for len in 0 1 3; do
        expect_fail "KMAC length $len" "$BC_RUST" kmac128 "$len" --key 00 -x </dev/null
        grep -q panicked "$LAST_STDERR" && fail "length $len must not panic: $(head -1 "$LAST_STDERR")"
        assert_stderr_has "Error"
    done
}

# SP 800-185 cSHAKE samples, bc-test-data/crypto/sp800-185/cSHAKE.rsp COUNT = 0 (cSHAKE128, N = "",
# S = "Email Signature", 256 bits) and COUNT = 2 (cSHAKE256, the same N and S, 512 bits); and
# Sec 3.3: with N and S both empty, cSHAKE is SHAKE.
test_cshake_samples_and_the_shake_case() {
    local got
    unhex 00010203 >"$TMP/msg"
    got=$(hex_out "$BC_RUST" cshake128 32 -s 'Email Signature' -x <"$TMP/msg")
    assert_eq "$got" "c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5" "cSHAKE128 COUNT 0"
    got=$(hex_out "$BC_RUST" cshake256 64 -s 'Email Signature' -x <"$TMP/msg")
    assert_eq "$got" "d008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd164020e2be0560858d9c00c037e34a96937c561a74c412bb4c746469527281c8c" "cSHAKE256 COUNT 2"
    got=$(hex_out "$BC_RUST" cshake128 32 --customization-hex 456d61696c205369676e6174757265 -x <"$TMP/msg")
    assert_eq "$got" "c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5" "the customization given in hex"
    assert_eq "$(hex_out "$BC_RUST" cshake128 32 -x <"$TMP/msg")" "$(hex_out "$BC_RUST" shake128 32 -x <"$TMP/msg")" "cSHAKE128 with empty N and S is SHAKE128"
    assert_eq "$(hex_out "$BC_RUST" cshake256 32 -x <"$TMP/msg")" "$(hex_out "$BC_RUST" shake256 32 -x <"$TMP/msg")" "cSHAKE256 with empty N and S is SHAKE256"
    expect_fail "both customization forms at once" "$BC_RUST" cshake128 32 -s a --customization-hex 61 <"$TMP/msg"
}

# SP 800-185 KMACXOF sample, KMACXOF.rsp COUNT = 0 (kmacxof128, S = "", 256 bits), and that the XOF
# form is not the fixed-length KMAC of the same length (Sec 4.3.1 encodes L = 0).
test_kmacxof128_sample_count_0() {
    local got
    unhex 00010203 >"$TMP/msg"
    got=$(hex_out "$BC_RUST" kmacxof128 32 --key 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f -x <"$TMP/msg")
    assert_eq "$got" "cd83740bbd92ccc8cf032b1481a0f4460e7ca9dd12b08a0c4031178bacd6ec35" "KMACXOF128 COUNT 0"
    [ "$got" != "$(hex_out "$BC_RUST" kmac128 32 --key 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f -x <"$TMP/msg")" ] || fail "KMACXOF128 must differ from KMAC128"
    assert_eq "${got:0:32}" "$(hex_out "$BC_RUST" kmacxof128 16 --key 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f -x <"$TMP/msg")" "a shorter KMACXOF output is a prefix"
}

# SP 800-185 TupleHashXOF sample, TupleHashXOF.rsp COUNT = 0 (tuplehashxof128, S = "", 256 bits).
test_tuplehashxof128_sample_count_0() {
    local got
    got=$(hex_out "$BC_RUST" tuplehashxof128 32 -e 000102 -e 101112131415 -x </dev/null)
    assert_eq "$got" "2f103cd7c32320353495c68de1a8129245c6325f6f2a3d608d92179c96e68488" "TupleHashXOF128 COUNT 0"
}

# SP 800-185 ParallelHashXOF sample, ParallelHashXOF.rsp COUNT = 0 (parallelhashxof128, B = 8,
# S = "", 256 bits).
test_parallelhashxof128_sample_count_0() {
    local got
    unhex 000102030405060710111213141516172021222324252627 >"$TMP/msg"
    got=$(hex_out "$BC_RUST" parallelhashxof128 32 -b 8 -x <"$TMP/msg")
    assert_eq "$got" "fe47d661e49ffe5b7d999922c062356750caf552985b8e8ce6667f2727c3c8d3" "ParallelHashXOF128 COUNT 0"
}

# A XOF squeezes to stdout in pieces, so a long output is a long run rather than an allocation:
# 3 MB from shake128 arrives as exactly that many bytes, and the fixed-length SP 800-185 forms,
# which are computed whole, refuse a request over the command's cap with a pointer to the XOF form.
test_long_xof_output_streams_and_fixed_output_is_capped() {
    "$BC_RUST" shake128 3000000 </dev/null >"$TMP/out"
    assert_size "$TMP/out" 3000001 "3 MB and a newline"
    "$BC_RUST" kmacxof256 2000000 --key 00 </dev/null >"$TMP/out"
    assert_size "$TMP/out" 2000001 "2 MB and a newline"
    expect_fail "kmac over the cap" "$BC_RUST" kmac128 268435457 --key 00 </dev/null
    assert_stderr_has "kmacxof"
    expect_fail "tuplehash over the cap" "$BC_RUST" tuplehash128 268435457 -e 00 </dev/null
    assert_stderr_has "tuplehashxof"
    expect_fail "parallelhash over the cap" "$BC_RUST" parallelhash128 268435457 -b 8 </dev/null
    assert_stderr_has "parallelhashxof"
}

run_all
