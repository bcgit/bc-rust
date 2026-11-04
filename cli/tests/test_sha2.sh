#!/usr/bin/env bash
# The sha224 / sha256 / sha384 / sha512 / sha512-224 / sha512-256 subcommands against the CAVP SHS known answers.
#
# Generated for the 2026-11-03 CLI review (plan 15) from the vector files named in each test;
# every expected value is copied from that file, none is typed by hand. Follows lib.sh's
# conventions: each test_* runs in its own subshell under `set -e`.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# CAVP SHS byte-oriented SHA224ShortMsg.rsp (bc-test-data/crypto/sha2/byte-oriented), Len = 0 and Len = 64.
test_sha224_matches_cavp_short_msg() {
    local got
    got=$(hex_out "$BC_RUST" sha224 -x </dev/null)
    assert_eq "$got" "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f" "sha224 of the empty message"
    assert_eq "${#got}" 56 "sha224 digest length"
    unhex 5f77b3664823c33e >"$TMP/msg"
    got=$(hex_out "$BC_RUST" sha224 -x <"$TMP/msg")
    assert_eq "$got" "bdf21ff325f754157ccf417f4855360a72e8fd117d28c8fe7da3ea38" "sha224 of an 8-byte message"
}

# CAVP SHS byte-oriented SHA256ShortMsg.rsp (bc-test-data/crypto/sha2/byte-oriented), Len = 0 and Len = 64.
test_sha256_matches_cavp_short_msg() {
    local got
    got=$(hex_out "$BC_RUST" sha256 -x </dev/null)
    assert_eq "$got" "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" "sha256 of the empty message"
    assert_eq "${#got}" 64 "sha256 digest length"
    unhex 5738c929c4f4ccb6 >"$TMP/msg"
    got=$(hex_out "$BC_RUST" sha256 -x <"$TMP/msg")
    assert_eq "$got" "963bb88f27f512777aab6c8b1a02c70ec0ad651d428f870036e1917120fb48bf" "sha256 of an 8-byte message"
}

# CAVP SHS byte-oriented SHA384ShortMsg.rsp (bc-test-data/crypto/sha2/byte-oriented), Len = 0 and Len = 64.
test_sha384_matches_cavp_short_msg() {
    local got
    got=$(hex_out "$BC_RUST" sha384 -x </dev/null)
    assert_eq "$got" "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b" "sha384 of the empty message"
    assert_eq "${#got}" 96 "sha384 digest length"
    unhex de60275bdafce4b1 >"$TMP/msg"
    got=$(hex_out "$BC_RUST" sha384 -x <"$TMP/msg")
    assert_eq "$got" "a3d861d866c1362423eb21c6bec8e44b74ce993c55baa2b6640567560ebecdaeda07183dbbbd95e0f522caee5ddbdaf0" "sha384 of an 8-byte message"
}

# CAVP SHS byte-oriented SHA512ShortMsg.rsp (bc-test-data/crypto/sha2/byte-oriented), Len = 0 and Len = 64.
test_sha512_matches_cavp_short_msg() {
    local got
    got=$(hex_out "$BC_RUST" sha512 -x </dev/null)
    assert_eq "$got" "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" "sha512 of the empty message"
    assert_eq "${#got}" 128 "sha512 digest length"
    unhex 6f8d58b7cab1888c >"$TMP/msg"
    got=$(hex_out "$BC_RUST" sha512 -x <"$TMP/msg")
    assert_eq "$got" "a3941def2803c8dfc08f20c06ba7e9a332ae0c67e47ae57365c243ef40059b11be22c91da6a80c2cff0742a8f4bcd941bdee0b861ec872b215433ce8dcf3c031" "sha512 of an 8-byte message"
}

# CAVP SHS byte-oriented SHA512_224ShortMsg.rsp (bc-test-data/crypto/sha2/byte-oriented), Len = 0 and Len = 64.
test_sha512_224_matches_cavp_short_msg() {
    local got
    got=$(hex_out "$BC_RUST" sha512-224 -x </dev/null)
    assert_eq "$got" "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4" "sha512-224 of the empty message"
    assert_eq "${#got}" 56 "sha512-224 digest length"
    unhex 6963446913771410 >"$TMP/msg"
    got=$(hex_out "$BC_RUST" sha512-224 -x <"$TMP/msg")
    assert_eq "$got" "21f6c373637e6a5e89d6e88811110c5c3fa12e497144912914c546e1" "sha512-224 of an 8-byte message"
}

# CAVP SHS byte-oriented SHA512_256ShortMsg.rsp (bc-test-data/crypto/sha2/byte-oriented), Len = 0 and Len = 64.
test_sha512_256_matches_cavp_short_msg() {
    local got
    got=$(hex_out "$BC_RUST" sha512-256 -x </dev/null)
    assert_eq "$got" "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a" "sha512-256 of the empty message"
    assert_eq "${#got}" 64 "sha512-256 digest length"
    unhex b4e2e8501f54be91 >"$TMP/msg"
    got=$(hex_out "$BC_RUST" sha512-256 -x <"$TMP/msg")
    assert_eq "$got" "d25265bf9cbc0dd2f108a2f5e8f69db7d15e5b8fe9100fe887dae20b6e054fe8" "sha512-256 of an 8-byte message"
}

# CAVP SHA256LongMsg.rsp, the first message of at least 3 KiB (Len = 25064 bits = 3133 bytes), so the
# 1 KiB stdin chunking (`cli/src/sha2_cmd.rs:29`) is crossed several times; fed both from a file and
# through a pipe.
test_sha256_matches_cavp_long_msg_across_chunk_boundaries() {
    local got
    unhex df753c3c6eb6f4e34dde6ee5388b5b818196c4e7a951439e2d0d7223a2e0a4d304a5d30a4c43da8d4033e4258f3c258d1d81c88e9cbe28695ccf427564726b09c14d3e9c1e33d92b95a349dcc59142e02569139d9752da0d41b0f46198ecb8ebbd77653a0d0c5887f436835001131a4240578f5cc493c15283b8712f67d7f53fa12a302c4158c16703f57bc96c48157b16522313490b45ffcaef9f27f8b989ce146f87b9e19e7b946de719912eba9c525062b7094e42cfdec05e6791741ddc60bf4d522b1567eed6d81446ef6ef11590968f3487fcbfc5b50b0cb1b4028856bd4acc79c8073a82f4ed85e82a5474eafd8fe280d57a0a914d530166d9cb845fac5cf4e4d9dc9f9fb85341e88b0acb8161e462843bf1ab996e41466c48f6985ff69dce7ca5bf1eade8b2502f5ab57e44843d182801892a47df7ce2ad49ac4dbe63b7612776d640144db4bba4df8015992e400a556e6910026aaddd10241529e4bb4fb5ce92498c3cafff892e619119ea269842f1cbbae531d57c407c2058b639c610d35a42418b8ed63bc2b72a10129e35ebc8e560a32f3ee99012db869e7c264c9fc2b1cee6c37089116f268026861d23e2a21a754d78906e925b149e0e021114a78abd7e5fbe4b92289763acfbffcfb824da7752e0478f2c29230fb0d1d063e7ce34649ad50488b72a4255f5b6041cbb5a78e33f8325a3ebfe73b4040e6e858dbcc790696f1b8dc1bc78e6a57f1e6cf62b8248835e993472b952ebe2ee65ddce1a4b2834568dc4778842fd0380d3272f40028d679a2baa8a01c99c91993bd57290c91443b1e293a336a78256deaeb52f40ff9a335f636dfb7edfaf5a367bd440c5473cdea9a0640b6eb05ee7c4347ebed482572fd4cae58dd99c0c85edaa410162d0884d66519e78d76477fe58efeba3a492aca222e77b07ba089b5ae852867d0e69e0d70f7ca9b319cbb6e2c26662a8573781d670429533c82c45204cfa0a7c721c2cc6ccaaed81dded03dd2b214c939579be11e7649dd7ac0ff021442b35c636f05460c762d2adcbd34735bba9122d08614b9cafd4f9bc0eb985a3f56c6f2201ee40ee252cc0fd8a84683399851a3e56f610bfef1a13aa9433edef8a45205a7b1cd8b711901f3bc308501fee3dce8e2741f5c1d0bf5169e9840e4d293eb0344d840505b117572d1d68e541e15a95e42448e3ec794a1dc0b3b4d204fbe088791f2ead1e2d48d09c41ab11e09b63d60af415c0861243de789bcc205e27b20ef19820b94baeacf24fd6d9bb4643e0fbc640b076d8c533fb5948d3dfa1d53dab63616412d45cc9261085fbcbb902596be1b01feb2ab8a1de2b63d1f9162f07c79822029e015e2ad2a5f617288200578e23eb6c09c41315eeb693cf55055a9acb598200471add5460d7d038bce96461cc539a9fb6edff1793c281d3dbb6817e1d6c2968f46600d1366ebb636e3557008d3b64bedceea4303516d4e87370ca392799c0428d2ef027be3261a226b000bb39a1f2d3620f29e73c7b3513057d5d5550aaef94f9bad4e15eeb67fccca0881a384eebe53098b6c511b94c5e7923635aff655d682252d5848060787a494e16a5f20af8fd2ed175511a98c0d0b7ab04ce9e94b3c5ef3e1b9a8b5a3a228302d3e5d09cc12244028c13c0e03a71a85d673b94fd98b448c5cdabe7a155fe6304e66138ceed5c5a7223936b58614a3280b5284969b53b1531133dfbfd7216d19b78a1936625b3586a635a84c9de623e5e151e259fb2653ec816da31363970b610b12e4a2d1030263273ef71fb58c2b53db0a490693637acd3fe09f0135116f8abb88fc3eb57daac127cda9cb678707d66ae42f28de9bb4599f353a15d631081b4b64c6868a1bad352a6a46bc2e67680213680b3d474f8f2641c3eaadc16643773d2eea06b97d6813918d448e649dca4b570e73b067ff69c7aa1547458131c043035fcd2bee1389f10fbf29aeb49a8d36c85fef2ebb1be2924ab1d67990140cf3206fe682726e8161f7686c99a8fe4f48c9d4d414ab35783aa6220eb6689d680c26e7dc96f0eecccaeb2193db9c397ef5edf5d8eed2cc99054ede5698953e8fe2895005d5e434eab05d7325d108dcaac2a74b5429ac51d3a6a74f447c8067d33aca20f8cbb6a169a6c0c5a93699384123884dec61a265a673321d6efec4a9e0696be32be502e4a802a7918478a80cd0bcf365e8135f68801f81a12c7bdc9525f2d10f25be334f4478847f4df3cfaad7f38b2bfdab2deb0ef018730390228a126bac1d6cb3d271bd6ce9e76c447a92d54bc21883b5b85d8199691b8ac8512934385f8677626adc81544a5275e73375473a1ab420bf6940b67ff6033880c2d319fd6de2bc5656e02ec31858e1588492bc42f7774b14cb24ec1831b293460218220f59bac1ec414d143df6534524d8ab82fb0aea6972588ab0f6cea201a49978eaf295672ea09443d02946e9f7b8b9f059d6a77612449bd293900f6a2a18e375e35bc370392fda84f1199c859fa0a331af4a6fb2bc07ffad02788673631f9a8f998f467e97c68e80e58369aea3592ecfd1eac618fd390e7a9c24b656532509367c21a0eac1212ac83c0b20cd896eb72b801c4d212c5452bbbf09317b50c5c9fb1997553d2bbc29bb42f5748ad83dc6e538736763eff646f0f9aa6a5b028e575de074f5fe5de425dab8e6b73f0662f88d49749749ae7b55aaba9cd38deecb3bcf6f3ee5a6de5589b70c637b82aa6aa67451847f5aee60295990350f8c6c18d1d02449b6bf037cdfd09bd033de2ab16b4adf47620036511c7e192770cf0103c4009e49ebaf83c682a805d172aa0dd3a1615121f1e20caab99893c8a9ce43f89cc13ba3f700c5cf3cbdd8dbaa8eda4e036845a89168d7e98b39bebd0d22bb8396a29aec6b5b5ff3487263435df4f68cebb02b4fe31d3eaa0bc1e8692d44ce117c151a87ab0798df507653cd0f65091cd4e9808c49779758b5d1bf518cacf24ea7a9590a58ae36efcf2a18cd3157887a5974c3e246f0786203d9920aadd3de8793cfd4e8d6a780a11f1e30c86664eb21e3d283e66e106872805a0ef90341c948db090cb7a79c2cafeac32a4310e5a7b00e934f0d217fddf6c5c394a11f9f792ee7d56edb6df48148aca963c1b3824481242773db03674f6b1eb6a1977515349644c579d88c392517cf417bc8d0a35821df1f90b4769f334c2593d440866ba21b7c59cc4374d29ea9dd1be0ccfac1492e99dc244e0d60301664fbab30d60b382ae8f2c480ca79445b50a9215294749de3eefdbcec3a52bc56475e84ecd67c7d413530f134ff65bcc8c469bbde3035dd0e48f4b9338fff4e88572cffe92a17c7facb84e0b486507e6e92ee2ed4407d7cfa2241a79870ce5d291ef77a9a2395deb4267f01a3e191ffa95696e8e957c3f424256506af7f386eb5093e9384655ef819c07fd277b3d2b7259a048861f891e938acff64dd1dd5f9c89072c94c61ebca784417e1945f7b3b5fb7b76bf2757fa29433414095ef1f94b06f248a36abb4bc6c0bd7adae56f402b43a1021ff80e5e6c3530b088e358db628dfd464f7a5424471922f951a3cf593cfbbbf390d9d5cfc42769d4b1ab398d47e7d02d7f3d13d09057190366c63c8750e97052f911d4d799e287876cfdbd9864dc12051bfc1ed60b4249a10198e051cfd7692641e934fd532f33d2a1200b831f336bd60aff9dbe1fa15bda0a5fe33f218b4e7752a91dc95ad415bb385d4dd6e2b685a9368eb911333ef6b769646dd9aecdc64e1399b6c41799d44d1afca81a142b058586f19955b1dfc33e07efa4a8df6779b26c002875f048188d2d4546d61c5b9673e26f6715004d6979ca47b3331a1f10ab45289a654ea78b855a7f4f92640ede7a325248d6885091709bb6c002c8bf33418657351a9a80d33c8af4ebd6530b85a25ee06622b1afe32a6382f49e520d897d18d6211e3a9998baa3ea402b511c34f34f62e980e33406af08f4768e1ed2bb66e1ed85f998ba83088eaa7918c6079376eb1ff97986a5a30774546f5a96d57004cae389311aad3b2d347cbc261a9549321b61bc9402cb613b8dea068b21e05160bb0257502a3969317ca731dbb68eff2fc86e5d59bf6ee9513dfd64a826b906819d9014de2f25b51d4d7502c200ba5c76d89002502656e2546ad7b0390f29367056d6eb61913ac6f8912c546061e1090e350cd4029d4af549febe13c743f88933d01c0263b74045ca2f15523f42caadffc52dfaf68d14ca3ae0fbb5d92aeea9d4f1aa816b0bffd99b0f7821e6093ef152723a9cb45f7a082ef8d6bdf72cd33b5aa3c79102f43e2b74199decdd20057d0e227ae4c57945582e2e9653a9b16eeacecdbc5aaedac7e35c35cbd9adede7f83bbf36f8b0453d61416a85a17821885b3757d203fa2560a85c4b4c10 >"$TMP/msg"
    assert_size "$TMP/msg" 3133 "message length"
    got=$(hex_out "$BC_RUST" sha256 -x <"$TMP/msg")
    assert_eq "$got" "176b0c71e213031a29f56009aac7ebec591ba24a8b162d80506b2df8f59e11a2" "from a file"
    got=$(cat "$TMP/msg" | hex_out "$BC_RUST" sha256 -x)
    assert_eq "$got" "176b0c71e213031a29f56009aac7ebec591ba24a8b162d80506b2df8f59e11a2" "through a pipe"
}

# Binary output is the same digest without the hex rendering; both end in one newline.
test_sha256_binary_output_matches_hex_output() {
    rng 100 >"$TMP/msg"
    "$BC_RUST" sha256 <"$TMP/msg" >"$TMP/bin"
    assert_size "$TMP/bin" 33 "32 digest bytes plus a newline"
    assert_eq "$(head -c 32 "$TMP/bin" | "$BC_RUST" hex-encode)" "$(hex_out "$BC_RUST" sha256 -x <"$TMP/msg")" "binary and hex agree"
}

test_the_subcommands_are_listed_in_help() {
    "$BC_RUST" --help >"$TMP/help"
    local cmd
    for cmd in sha224 sha256 sha384 sha512 sha512-224 sha512-256; do
        grep -q "$cmd" "$TMP/help" || fail "--help should list $cmd"
    done
}

run_all
