# 0.1.4 Features / Changelog

## Major features

* New algorithms added to crypto/ :
    * Block ciphers -- ARIA (RFC 5794), Camellia (RFC 3713) and SM4 (GB/T 32907-2016), constant-time and
      table-free (bit-sliced S-boxes, four blocks at a time), and three-key TDEA (SP 800-67 Rev 2) with two-key
      TDEA for decryption only; each with CBC, CFB, CFB8, OFB, CTR, GCM, CCM, CMAC, GMAC and key wrap.
    * AES modes -- OFB (all block ciphers), AES-XTS (SP 800-38E) and AES-GCM-SIV (RFC 8452); AES KW / KWP
      (SP 800-38F) and TDEA TKW over the new `KeyWrapper` / `KeyUnwrapper` traits.
    * ChaCha20, Poly1305 and ChaCha20-Poly1305 (RFC 8439).
    * Hashes -- SHA-1 (interoperation only, no security strength), RIPEMD-128/160/256/320, BLAKE2b-512,
      BLAKE2s-256 and BLAKE3.
    * KDFs -- PBKDF2 (RFC 8018), scrypt (RFC 7914), SP 800-108 (Counter, Feedback, Double-Pipeline and KMAC),
      the ANSI X9.63 KDF and the SP 800-56C one-step (concatenation) KDF.
    * ECDSA (FIPS 186-5, with RFC 6979) and ECC CDH (SP 800-56A) over P-256, P-384, P-521, secp256k1 and the
      three brainpool curves, written once over a `Curve` marker; SM2 signatures and SM2 public key encryption.
    * Ed25519 / Ed25519ph and Ed448 / Ed448ph (RFC 8032), X25519 and X448 (RFC 7748).
    * DHKEM (RFC 9180) over X25519, X448, P-256, P-384 and P-521, and HPKE in all four modes (no CLI yet).
    * RSA -- RSASSA-PKCS1-v1_5, RSASSA-PSS, RSASVE and RSAES-OAEP, with FIPS 186-5 key generation, at 2048 to
      8192 bits.
    * ML-KEM with its shared secret derived through HKDF.
* Fewer, larger crates: the library is the umbrella `bouncycastle` over nine crates -- `core`, `digest`, `rng`,
  `symmetric`, `ec`, `pqc`, `modexp`, `hybrid` and `utils` -- each primitive a module under its old name
  (`bouncycastle::digest::sha2`, `bouncycastle::pqc::mlkem`), one path per algorithm. `bouncycastle-factory`
  is removed: algorithms are named by type. Every library crate is `#![no_std]`, with `std` and `alloc`
  features; a build with `default-features = false` links neither `std` nor an allocator.
* Keys own their operations, finished: KEM encapsulation and decapsulation (`EncapsulatingKey` /
  `DecapsulatingKey`), key agreement (`AgreementKey`), key transport and MACs (split into `MACGenerator` /
  `MACVerifier`, the tag a fixed-length array) move onto key objects, as ciphers and signatures did in 0.1.3;
  one pair of key encoding traits (`PrivateKey<N>` / `PublicKey<N>`) replaces six. A KEM or agreement that
  derives its key takes a KDF *description* (`KdfParams`), which a key held in an HSM or token can read.
* Secrets no longer left behind: a systematic pass found and removed copies of keys, nonces, pad states and
  intermediates on the dead stack and in moved-from values, across every algorithm family. Compressions,
  key schedules, signing, key generation and decoding run in their own frame and wipe it, with one shared
  stack wipe (`bouncycastle_utils::stack_wipe`) that is checked to cover its own frame on x86-64, aarch64,
  thumbv6m and riscv32i. Workers finish in place (`finish_*`, `_boxed` finals), so one-shots and boxed workers
  no longer move state. Four in-tree checks run in CI on x86-64 and arm64 (`check_{rsa,sm2,ecdsa,symmetric}_stack.sh`),
  each searching what an operation leaves on the stack and comparing two runs over different secrets.
* Performance and footprint:
    * SHA-256 about 20% and SHA-384/512 about 20% faster on x86-64 (HMAC, HKDF and PBKDF2 likewise), with
      smaller compression frames on every target.
    * ML-DSA / ML-KEM memory lower again, e.g. ML-DSA-87 KeyGen 133 kB to 99 kB, ML-KEM-1024 Encaps 42 kB to 32 kB.

## Minor features / bug fixes

Trait system:

* Cipher and MAC workers no longer suspend or clone (#173): a copy repeats a nonce, counter or keystream
  position. Hashes, XOFs and KMAC keep `Suspendable`; HMAC and HKDF no longer suspend.
* Every encrypting key takes a caller-supplied IV or nonce (`create_encryptor_nonce`, `encrypt_nonce_out`).
* One-shot signing, verification and in-place AEAD have roles of their own (`OneShotSigningKey`,
  `AeadInPlaceEncryptionKey`, ...), for schemes that cannot stream.
* HashML-DSA, Ed25519ph and Ed448ph are views reached by `as_prehash()`; every signature key names one
  algorithm. Signing requires a `CollisionResistantHash` (`hazmat::WithoutCollisionResistance<H>` opts back in).
* A short RNG draw is an error everywhere (key generation, nonces, IVs, `rnd`, ML-KEM's `m`), through
  `RNGExt::next_bytes_exact_out`; `RNG::next_bytes` (returning a `Vec`) is gone.
* `KeyType::SharedSecret`, and a reviewed KDF entropy accounting (`core::hazmat::KdfCredit`).
* SHA-3 and SHAKE no longer implement `KDF` (the construction was non-standard).

Fixes:

* ECDSA refuses a non-empty context instead of dropping it; HMAC keeps its key's strength; SM2 decryption accepts
  hybrid-form `C1`; `X25519PrivateKey::pk` / `X448PrivateKey::pk` and ML-KEM `pk()` refuse an unfilled key
  where they returned an all-zero public key; `Sp80090ADrbg` raises a requested strength below 112 bits and no
  longer panics on prediction resistance; `hex` and `base64` zeroize their outputs and decoders on error.

Command line:

* A `bc-rust` subcommand for every new primitive: the new ciphers and modes, key wrap, XTS, GCM-SIV, the new
  hashes and KDFs, ECDSA, ECC CDH, SM2 (signatures and encryption), Ed25519/Ed448, X25519/X448, RSA and
  ML-KEM-HKDF. Commands exiting on an error wipe the secrets they hold first.

Docs, build and CI:

* Stack-usage ("Memory Usage") tables re-measured throughout, each naming its method and toolchain.
* CI adds a bare-metal `no_std` build (thumbv6m), constant-time assembly and memcheck checks for AES and
  RSA-OAEP, and the four stack checks on x86-64 and arm64; the gitea origin runs copies of every pull-request
  check.
* Wycheproof is pinned to a commit; CAVP, ACVP, RFC and Wycheproof vectors cover every new algorithm.
* Thanks to Francis Mendoza (ChaCha20-Poly1305, XTS), royb (key wrap, BLAKE2/BLAKE3), Mike Ounsworth
  (ML-DSA stack work, X25519), Peter Dettman (EdDSA and the Curve448 family) and Megan (Gitea Actions).

* Github issues and PRs resolved: #123, #139, #140, #141, #142, #143, #157, #160, #173, #177, #180, #184, #186,
  #192, #193, #194, #195.

## Full changelog

Every change in this release, in the order it landed.

### Major features

* ARIA -- `bouncycastle-aria`, the RFC 5794 block cipher at 128, 192 and 256 bits, constant-time and table-free (the
  S-boxes as bit-sliced Boolean circuits, four blocks at a time), on the key objects as `ARIA128Key<M>` and friends
  with CBC, CFB, CFB8, OFB, CTR, GCM, CCM, CMAC, GMAC, KW and KWP; the
  `aria*-{cbc,cfb,cfb8,ofb,ctr,gcm,ccm,kw,kwp}` CLI commands.
* Camellia -- `bouncycastle-camellia`, the RFC 3713 block cipher at 128, 192 and 256 bits, constant-time and table-free
  (the S-box as a bit-sliced Boolean circuit, four blocks at a time), on the key objects as `Camellia128Key<M>` and
  friends with CBC, CFB, CFB8, OFB, CTR, GCM, CCM, CMAC, GMAC and KW; the
  `camellia*-{cbc,cfb,cfb8,ofb,ctr,gcm,ccm,kw}` CLI commands.
* SM4 -- `bouncycastle-sm4`, the GB/T 32907-2016 block cipher (draft-ribose-cfrg-sm4-10), constant-time and
  table-free (the S-box as a bit-sliced Boolean circuit, four blocks at a time), on the key object `SM4Key<M>` with
  CBC, CFB, CFB8, OFB, CTR, GCM and CCM (RFC 8998's AEAD_SM4_GCM and AEAD_SM4_CCM), KW and KWP; the
  `sm4-{cbc,cfb,cfb8,ofb,ctr,gcm,ccm,kw,kwp}` CLI commands.
* CHACHA20 -- ChaCha20, Poly1305 and ChaCha20-Poly1305 (RFC 8439).
* RIPEMD -- `bouncycastle-ripemd`, the RIPEMD-128, RIPEMD-160, RIPEMD-256 and RIPEMD-320 hash functions of Dobbertin,
  Bosselaers and Preneel, with bit-oriented messages and `Suspendable`; `HMAC_RIPEMD160` (RFC 2104);
  `HashFactory` and `MACFactory` entries; the `ripemd*` and `hmac-ripemd160` CLI commands. Legacy functions,
  below the library's smallest modelled strength, so all report `SecurityStrength::None`.
* TDES -- three-key TDEA (NIST SP 800-67 Rev 2) as a constant-time, table-free bit-sliced engine under `hazmat`,
  with ECB, CBC, CFB64, CFB8, OFB and CTR (SP 800-38A Appendix E) and TDEA Key Wrap (SP 800-38F TKW) through the key
  role traits; two-key TDEA decrypts, unwraps and verifies CMAC tags only, which `BlockPermutation::DECRYPT_ONLY`
  makes a compile error for every encrypting, wrapping and tag-generating route (CMAC over TDEA is reached through
  the generic `BlockCipherKey`, not `TDESKey`); the `tdes-*` and `tdes2-*` CLI commands, whose `encrypt` refuses input past
  SP 800-67 Rev 2 Sec 3.4's 2^20 blocks counted as the blocks TDEA processes (8 MiB; 1 MiB for CFB8, 699,048
  bytes for TKW).
* AES Key Wrap -- AES_KW and AES_KWP (NIST SP 800-38F; RFC 3394 / RFC 5649) over any 128-bit block permutation,
  with the `KeyWrapper` / `KeyUnwrapper` core traits and the `aes*-kw` / `aes*-kwp` CLI commands.
* AES-XTS -- XTS-AES-128 and XTS-AES-256 (NIST SP 800-38E; IEEE Std 1619-2007) for storage, as `XTS_AES_128` /
  `XTS_AES_256` over `bouncycastle_cipher::modes::XTSKey`, taking one data unit of 16 bytes to 2^20 blocks per call;
  the `aes128-xts` / `aes256-xts` CLI commands.
* CBC ciphertext stealing -- CBC-CS1, CBC-CS2 and CBC-CS3 (Addendum to NIST SP 800-38A) over any 128-bit block
  permutation, as the `CBC_CS1` / `CBC_CS2` / `CBC_CS3` mode types, `CTS` being CBC-CS3 (RFC 2040); the
  `AES_CBC_CS{1,2,3}_*` and `AES_CTS_*` aliases; the `aes*-cbc-cs{1,2,3}` CLI commands, with `aes*-cts` for CS3.
* ECDSA -- FIPS 186-5 signatures over P-256, P-384, P-521, secp256k1, brainpoolP256r1, brainpoolP384r1 and
  brainpoolP512r1, with the RFC 6979 deterministic variant, through the `SigningKey` / `DeterministicSigningKey` /
  `VerifyingKey` core roles; the `ecdsa-*` CLI commands.
* SM2 -- the GB/T 32918.2-2016 signature algorithm with SM3, on the same roles; the `sm2` CLI command.
* `bouncycastle-ec` -- the constant-time, fixed-width curve arithmetic under both: per-curve field, scalar and
  Jacobian-point arithmetic, SEC 1 codec and comb, wNAF and variable-base multipliers, all under `hazmat`, with the
  generic limb arithmetic (`barrett`, `inverse_vartime`) at the crate root.
* X25519 -- `bouncycastle-ed`, the Diffie-Hellman function of RFC 7748 over Curve25519, on the key agreement
  roles: `X25519PrivateKey` implements `AgreementKey` over `()` for the raw shared secret and over
  `KdfParams<HkdfDescription<SHA256>, LEN>` for a derived key (`X25519_HKDF_SHA256`), and with `X25519PublicKey` the KEM roles
  as DHKEM(X25519, HKDF-SHA256) of RFC 9180 Section 4.1 (`DHKEM_X25519_HKDF_SHA256`), through the new
  `bouncycastle-dhkem` crate's generic DHKEM;
  `keygen` draws the key from the caller's RNG; checked against RFC 7748's vectors, RFC 9180 Appendix A.1.1, A.1.2, A.2.1, A.2.2, A.7.1 and A.7.2, and
  Wycheproof's X25519 set; the `x25519` CLI subcommand covers keygen, pk-from-sk, check-consistency, agree, encaps
  and decaps.
* X448 -- `bouncycastle-ed::x448`, the Diffie-Hellman function of RFC 7748 over Curve448, in the shape of X25519:
  `X448PrivateKey` implements `AgreementKey` over `()` for the raw shared secret and over
  `KdfParams<HkdfDescription<SHA512>, LEN>` for a derived key (`X448_HKDF_SHA512`), and with `X448PublicKey` the KEM
  roles as DHKEM(X448, HKDF-SHA512) of RFC 9180 Section 4.1 (`DHKEM_X448_HKDF_SHA512`, `kem_id` 0x0021), which makes
  the keys HPKE keys; `keygen`, `keygen_out` and the seed forms. It is classed at 192 bits, `SecurityStrength` having
  no 224-bit level. The DHKEM refuses the private key 4 x order, a clamped scalar that is 0 mod the group order.
  Checked against RFC 7748's X448 vectors, Wycheproof's X448 set and the `kem_id` 33 entries of RFC 9180's vector
  file, at the KEM and through HPKE; the `x448` CLI subcommand covers keygen, pk-from-sk, check-consistency, agree,
  encaps and decaps; with criterion benches and a stack harness in `mem_usage_benches`.
* Ed25519 and Ed25519ph -- `bouncycastle-ed::ed25519`, the EdDSA signatures of RFC 8032 Section 5.1 (FIPS 186-5
  Section 7) on the signature roles: `Ed25519PrivateKey` and `Ed25519PublicKey` are keys of `Ed25519` (one-shot
  roles only, no context), and `as_prehash()` on either gives the `Ed25519ph` key (streaming and one-shot, with a
  context).
  Verification is cofactored, and a decoded public key is validated in full, so one outside the prime-order subgroup
  is refused. `keygen` and `keygen_out` draw the key from the caller's RNG; checked against RFC 8032 Sections 7.1
  and 7.3, Wycheproof's Ed25519 set and the vectors of "Taming the many EdDSAs"; the `ed25519` and `ed25519ph` CLI
  subcommands cover keygen, pk-from-sk, check-consistency, sign and verify, `ed25519ph` streaming the message under
  an optional `--ctxfile`; with criterion benches and a stack harness in `mem_usage_benches`. The markers `Ed25519`
  and `Ed448` carry `id-Ed25519` and `id-Ed448` (RFC 8410); the pre-hash forms have no identifier. `core` gains
  `SignatureError::ComputationFault`, for a computed point that fails its own check.
* Ed448 and Ed448ph -- `bouncycastle-ed::ed448`, the EdDSA signatures of RFC 8032 Section 5.2 (FIPS 186-5 Section 7)
  on the signature roles, in the shape of Ed25519's: `Ed448PrivateKey` and `Ed448PublicKey` are keys of `Ed448`
  (one-shot roles only), and `as_prehash()` on either gives the `Ed448ph` key (streaming and one-shot). Both take a
  context of up to 255 octets, which is where Ed448 differs from Ed25519. Verification is cofactored, a decoded
  public key is validated in full, and the one private key whose public key would be the neutral element is
  refused. Classed at 192 bits, `SecurityStrength` having no 224-bit level. Checked against RFC 8032 Sections 7.4
  and 7.5 and Wycheproof's Ed448 set; the `ed448` and `ed448ph` CLI subcommands cover keygen, pk-from-sk, check-consistency,
  sign and verify, each under an optional `--ctxfile`, `ed448ph` streaming the message; with criterion benches and
  a stack harness in `mem_usage_benches`.
* DHKEM over P-256, P-384 and P-521 -- RFC 9180 Section 4.1's DHKEM(P-256, HKDF-SHA256), DHKEM(P-384, HKDF-SHA384)
  and DHKEM(P-521, HKDF-SHA512) (`kem_id` 0x0010 to 0x0012) on the ECC CDH keys: `ECCDHPublicKey<C>` and
  `ECCDHPrivateKey<C>` over `P256`, `P384` and `P521` carry the KEM roles with `()` as the parameters, under the
  markers `DHKEM_P256_HKDF_SHA256`, `DHKEM_P384_HKDF_SHA384` and `DHKEM_P521_HKDF_SHA512` (`ECDHKEM<C>`), with
  `dhkem::derive_key_pair` for Section 7.1.3's `DeriveKeyPair`. `bouncycastle-dhkem` gains the rejection-sampling
  form of `DeriveKeyPair` beside the expand form: `DHKEMParams::DERIVE_KEY_PAIR_BY_EXPAND` is replaced by
  `DERIVE_KEY_PAIR`, a `DeriveKeyPairForm`, and `DHKEMParams::private_key_from_bytes` returns an `Option`, a change
  for implementors of a DHKEM group. Checked against the RFC's machine-readable vectors for P-256 and P-521 (32
  sets each; P-521's key derivation is the first two-block `LabeledExpand`), and, for P-384, which the RFC defines
  but publishes no vectors for, against BC Java 1.84 in both directions.
* PBKDF2 -- RFC 8018 Section 5.2 over HMAC (SHA-2, SHA-3), as `bouncycastle-pbkdf2`, on the `KDF` trait with the salt
  and the iteration count on the instance; a key derived from a password is typed `Unknown`. The `pbkdf2` CLI command
  reads the password from `--password-file` or stdin; the option has no short form, `-p` being scrypt's parameter p.
* scrypt -- RFC 7914, as `bouncycastle-scrypt`: `SCrypt` over working memory the caller supplies
  (`derive_with_memory_out`, `ScryptParams::work_len`), and on the `KDF` trait with the `std` feature, allocating up to
  a limit. The `scrypt` CLI command takes `--log2-n`, `-r`, `-p` and `--max-memory`.
* HPKE -- RFC 9180 Sections 5 and 6 in all four modes, as `bouncycastle-hybrid::hpke`, on the X25519, X448, P-256,
  P-384 and P-521 keys: `setup_sender` / `setup_recipient` (Base, PSK) and `setup_auth_sender` / `setup_auth_recipient`
  (Auth, AuthPSK) give contexts with `seal_out` / `open_out` and `export_out`; HKDF over SHA-256, SHA-384 or
  SHA-512 with AES-128-GCM, AES-256-GCM, ChaCha20Poly1305 or export-only. No CLI command yet.
* AES-GCM-SIV -- the nonce misuse-resistant AEAD of RFC 8452, as `AES128Key<GCM_SIV>` and `AES256Key<GCM_SIV>`
  (aliased `AES_GCM_SIV_128` and `AES_GCM_SIV_256`): whole-message in-place encryption and decryption with a
  detached tag, a failed decryption leaving the buffer zeroized; the `aes128-gcm-siv` and `aes256-gcm-siv` CLI
  commands, a `modes::gcm_siv` bench group and the `bench_gcm_siv_mem_usage` stack harness.
* SP 800-108 -- key derivation using pseudorandom functions (NIST SP 800-108r1), as `bouncycastle-kbkdf`: the KDFs in
  Counter, Feedback and Double-Pipeline Mode over HMAC (SHA-2, SHA-3) or CMAC (AES), and the KDF Using KMAC, on the
  `KDF` trait; six parameterless instantiations in `KDFFactory`; the `kbkdf-counter`, `kbkdf-feedback`,
  `kbkdf-double-pipeline`, `kbkdf-kmac128` and `kbkdf-kmac256` CLI commands.
* `bouncycastle-dhkem` -- the generic DHKEM is a crate of its own, apart from HPKE, and gains `AuthEncap` and
  `AuthDecap`. Its `_out` functions return the number of bytes written.
* SHA-1 -- `bouncycastle_digest::sha1`, FIPS 180-4's SHA-1 on the `Hash` traits, for interoperation with what already
  uses it (an older peer's RSA-OAEP hash or MGF1, a fingerprint): not collision resistant, so it is credited with
  no security strength (`SecurityStrength::None`). Checked against NIST's CAVP SHAVS vectors and RFC 3174's; the
  `sha1` CLI command. It does not carry `CollisionResistantHash`, so the RSA signature schemes verify over it and
  do not sign, short of `hazmat::WithoutCollisionResistance<SHA1>`.
* RSA -- `bouncycastle-rsa`: RSASSA-PKCS1-v1_5 and RSASSA-PSS (RFC 8017 Section 8) on the signature roles, RSASVE
  (NIST SP 800-56B Rev. 2 Section 7.2.1) on the KEM roles, its secret value raw or through HKDF, and key generation
  by FIPS 186-5 Appendix A.1.3 with 25 Miller-Rabin rounds (FIPS 140-3 IG C.F), at RSA-2048, 3072, 4096 and 8192;
  RSA-1024 and RSA-1536 verify signatures and nothing else. A public key encodes as `n || e` and a private key as
  `p || q || dP || dQ || qInv || e`, with `e` in 8 big-endian bytes, and a modulus must have exactly its size's bit
  length. A private key's constructor and decoder refuse components that do not belong together with `e` (RFC 8017
  Section 3.2), in constant time; `RsaPrivateComponents::validate` is SP 800-56B Rev. 2 Section 6.4.1.4.3's
  validation of a key pair, primality included, for a key from elsewhere. The result of every private-key
  operation is checked against `e` before it is released (`SignatureError::ComputationFault`, or the operation's
  one decryption error). A non-empty `ctx` is refused with `SignatureError::LengthError`, RSA having no context
  input. Private-key operations wipe the stack they used, sized for an optimised x86-64 build; a key the caller
  moves out of the `Result` it was returned in is the caller's to wipe. The `rsa-<size>` and `rsasve-<size>` CLI
  commands. Two checks, run by CI and by hand: `dev_scripts/check_rsa_ct.sh` puts the CRT and the constructor's
  congruences under memcheck with the key undefined, and `dev_scripts/check_rsa_stack.sh` searches the stack each
  private-key operation used for the key.
* RSAES-OAEP -- RFC 8017 Section 7.1 key transport on the RSA key-establishment keys, under `OaepParams<H, M, LEN>`
  (label hash, MGF1 hash, label): as a KEM that draws the key (KTS-OAEP-basic, SP 800-56B Rev. 2) and, through
  the new `core::key_transport_key` roles, for a key the caller holds; the `rsa-oaep-<size>` CLI commands. The hashes
  are RFC 8017's seven (SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256), a sealed trait
  `OaepHash`. `dev_scripts/check_oaep_ct.sh`, run on pull requests, puts the decoding under memcheck with the encoded
  message undefined and reads its Cortex-M0 and RISC-V 32I assembly.

### Minor features / bug fixes

* OFB (NIST SP 800-38A Sec 6.4) over any block permutation, as `bouncycastle_cipher::modes::OFB` / `Ofb`, a keystream
  under `StreamCipher`; the `AES_OFB_*`, `ARIA_OFB_*`, `Camellia_OFB_*`, `SM4_OFB`, `TDES_OFB` and `TDES2_OFB` aliases,
  `ModeNames::OFB_ALG_NAME`, and the `aes*-ofb`, `aria*-ofb`, `camellia*-ofb`, `sm4-ofb`, `tdes-ofb` and `tdes2-ofb`
  CLI commands.
* The key-wrap workers `Kw`, `Kwp` and `Tkw` carry their direction in the type, as the cipher modes do:
  `KeyWrapper` is implemented for the encrypting worker only, so an unwrapper has no wrapping method and a
  permutation that decrypts only is refused a wrapper at compile time by every route. The `AES_KW_*`, `AES_KWP_*`,
  `ARIA_KW_*`, `ARIA_KWP_*`, `Camellia_KW_*`, `SM4_KW`, `SM4_KWP` and `TDES_TKW` aliases gain the `Dir` parameter;
  `TDES2_TKW` is the decrypting one.
* `bouncycastle_utils::bitslice` holds what the bit-sliced ciphers share: the `PlaneWord` trait, the byte-lane
  transpose `ortho`, and the non-linear section of the Boyar-Peralta AES S-box circuit as `gf256_inverse_nonlinear`,
  which the AES, ARIA, Camellia and SM4 S-boxes all call instead of carrying their own copies.
* `BlockCipherKey<P, M>` in `bouncycastle-cipher` is the one block cipher key object: the role impls, the key-material
  constructor and GMAC's nonce-bound pair are written once over the permutation, and `AES128Key<M>`, `ARIA256Key<M>`,
  `Camellia192Key<M>`, `SM4Key<M>` and the rest are aliases of it; `KeyExpansion<KEY_LEN>` carries a permutation's
  constructor, with `ElectronicCodeBook` the tie of key length to block length. The CLI's block cipher commands, the
  block cipher test suites (`bouncycastle-cipher-test-framework`), the CLI test harness and the stack-usage harness
  are likewise one copy over the permutation.
* Cipher and MAC workers no longer implement `SuspendableKeyed` (#173): a resumed worker is a second copy of a
  nonce, counter or keystream position. The AES modes, CMAC and Ascon-AEAD128 lose their suspended-state
  constants and `hazmat::ModeKey` goes with them; hashes, XOFs and KMAC keep `Suspendable`. `SuspendableKeyed` itself
  then went: HMAC and HKDF no longer suspend (a worker cannot be rebuilt without its key, and the key object makes a
  new one), which also drops the `SUSPENDED_HMAC_*` and `SUSPENDED_HKDF_*` constants and HKDF's two const parameters,
  so an instantiation is `HKDF<SHA256>`. The SHA-3 family's suspended states are 10 bytes shorter than before
  (SHA-3 and SHAKE 405, cSHAKE 406, KMAC and TupleHash 414, ParallelHashXOF 832, ParallelHash 840), the KDF
  bookkeeping having left the sponge; a state suspended by an earlier build does not resume.
* Cipher workers are no longer `Clone` (#173), for the same reason: two copies of an encryptor go on from one nonce,
  counter or keystream position. The CBC, CFB, CFB8, CTR, OFB, ECB, GCM and CCM packet workers, the padded encryptor
  and decryptor and `Ascon_AEAD128` lose it, both directions; a second worker is made from the key. The declared-length
  CCM workers, the MAC workers other than KMAC's, the key-wrap workers and the ChaCha20 family were already not
  `Clone`. Nothing else changes: the keys, key states, hashes, XOFs and KMAC workers that were `Clone` still are.
* The AEAD keys' one-shots that work in the caller's buffer are spelled `_inplace`, as QUALITY_AND_STYLE.md's suffix
  rule and every other in-place method already were: `encrypt_detached_inplace`, `encrypt_detached_inplace_nonce`
  and `decrypt_detached_inplace` on the AEAD key and mode traits (formerly `_in_place`).
* The in-place AEAD one-shots move to a role pair of their own, `AeadInPlaceEncryptionKey` /
  `AeadInPlaceDecryptionKey` (mode traits `AeadInPlaceEncryptMode` / `AeadInPlaceDecryptMode`), which names no worker
  type and which every AEAD key implements; `AeadEncryptionKey`, `AeadDeclaredEncryptionKey` and their decrypting
  halves no longer carry them. Callers import the new traits; behaviour is unchanged. The bodies over a streaming
  worker are public as `core::symmetric_key::encrypt_detached_inplace` / `decrypt_detached_inplace`, for an AEAD key
  outside `core` to implement the role with.
* A block cipher key reports its algorithm: `Mode<P>` carries the mode's `ALG_NAME` over the permutation and
  `BlockCipherKey<P, M>` implements `Algorithm` from it, so `AES128Key<GCM>` is `AES_GCM_128` and
  `AES256Key<GCM_SIV>`, which has no worker to ask, is `AES_GCM_SIV_256`. `ALG_NAME` is a required item of the
  hazmat trait `Mode<P>`, so a mode implemented outside the workspace must add one.
* The signature one-shots over a whole message move to roles of their own, `OneShotSigningKey`,
  `DeterministicOneShotSigningKey` and `OneShotVerifyingKey`, which name no worker type, so a scheme that cannot take
  its message in pieces can implement them alone. Each is a supertrait of its streaming role (`SigningKey`,
  `DeterministicSigningKey`, `VerifyingKey`), which keeps only its `create_*` constructor; every key implements the
  one-shot role over its own worker with `core::signature_key::sign_out_with_signer` / `verify_with_verifier`, which
  are public for a key outside `core` to do the same. Callers of `sign`, `sign_out`, `sign_deterministic`,
  `sign_deterministic_out` and `verify` import the new traits; behaviour is unchanged.
* Workers are finished where they sit, and a worker held as `Box<dyn ..>` can finish its message (#173). Each worker
  trait (`Hash`, the symmetric and AEAD encryptors and decryptors, `MACGenerator` / `MACVerifier`, `SignatureSigner` /
  `SignatureVerifier`) now has one required finishing method on `&mut self` (`finish_into`,
  `finish_partial_bits_into`, `finish_encrypt`, `finish_decrypt_into`,
  `finish_encrypt_detached_into`, `finish_decrypt_detached_into`, `finish_mac_into`, `finish_mac_verify`,
  `finish_signature_into`, `finish_signature_verify`), and the consuming finals are provided over it, each with a
  `_boxed` twin taking `self: Box<Self>` (`do_final_out_boxed`, `do_final_partial_bits_out_boxed`,
  `do_encrypt_final_boxed`, `do_decrypt_final_boxed`, `do_decrypt_final_out_boxed`,
  `do_encrypt_final_detached_out_boxed`, `do_decrypt_final_detached_out_boxed`, `do_verify_final_boxed`). A boxed
  worker's `Secret` state is wiped inside its box, which the final never moves it out of. The finishing methods take a
  `&core::traits::FinishToken`, whose constructor is private to `core`, so that they are called by the provided
  consuming finals and not a second time by accident; a worker type that deliberately hands its token to a worker it only borrows can still defeat this. Callers
  are unaffected; an implementor of a worker trait outside this workspace writes the in-place method instead of the
  consuming final. Code that owns a worker without implementing a worker trait takes a token from
  `core::hazmat::finish_token()` and with it the duty to finish the worker once and not use it again: the X9.63 and
  concatenation KDFs' block loops, `MuBuilder::do_final`, `MACFactoryWorker`'s finals, CCM's in-place one-shots, and
  HMAC's hazmat half `finish_out`, which now borrows the inner hash (`finish_out(&key, &mut inner, out)`) for HKDF and
  RFC 6979. Not covered: a by-value final is still handed the worker by a move, which may leave a copy unwiped, as may
  any move the caller makes, and `XOF::into_squeezer` still consumes.
* KEM encapsulation and decapsulation move onto the keys, as signing did: the `EncapsulatingKey` /
  `DecapsulatingKey` roles in `core::kem_key` hand out `KEMEncapsulator` / `KEMDecapsulator` workers that
  borrow the key, implemented per algorithm over the parameters a worker is made from (`()` for ML-KEM, a
  configured KDF for a KEM that derives its secret), which select the algorithm at the call. `encaps_out` writes the
  shared secret into the caller's `KeyMaterial<SS_LEN>` beside the ciphertext and `decaps_out` is the decapsulating
  primitive, each zeroizing its buffers first and leaving them so on error, with `encaps` and `decaps` provided over
  them: the caller decides where a derived key lives. The static `encaps(pk)` with its
  OS DRBG, the run-time ciphertext length check with `KEMError::LengthError`, and the expanded-key statics are
  gone; the ML-KEM key types carry only their parameter set, and `MLKEMPublicKeyTrait` / `MLKEMPrivateKeyTrait`
  no longer extend `KEMPublicKey` / `KEMPrivateKey`. `KeyType::SharedSecret` is added for the raw `Z` of a key
  agreement; a KDF credits it, labelling its output with no more than `Z`'s strength.
* ML-KEM with its shared secret derived through HKDF: `MLKEM512_HKDF_SHA256`, `MLKEM768_HKDF_SHA512` and
  `MLKEM1024_HKDF_SHA512` are roles the plain ML-KEM keys carry over `core::kdf_params::KdfParams<K, LEN>`, a borrowed KDF
  instance (an HKDF keyed with RFC 5869's salt through `new_with_salt`), the info and the derived key's length, the KDF
  type selecting the algorithm and `KeyLen::<N>` the length (one byte to 255 hash outputs, checked at compile time;
  the `*_SS_LEN` constants are the one-hash-output lengths the CLI derives), in both ML-KEM crates
  and as the `mlkem512-hkdf-sha256`, `mlkem768-hkdf-sha512` and `mlkem1024-hkdf-sha512` CLI subcommands; the
  derived key is labelled at no more than the lesser of the KEM's and the KDF's strengths, and no more than its
  length holds. HKDF credits its output as
  full-entropy once half a hash output of typed key material has gone in, where it needed a full one, so a
  32-byte secret seeds HKDF-SHA512 as it does HKDF-SHA256. The `hkdf-*` CLI subcommands type their salt as
  RFC 5869's non-secret random value, as the `mlkem*-hkdf-*` ones do; `--secret-salt` marks it as the secret salt
  of SP 800-56C Rev. 2 Section 5.1, which HKDF credits.
* The KDF of a KEM or key-agreement pairing is described, not instantiated: `core::kdf_params::KdfParams<D, LEN>`
  borrows a `KdfDescription`, what the KDF is made from as readable fields and the `Engine` it builds, so that a
  key held where the shared secret must not leave (a token, an HSM) can read the KDF's identity and parameters and
  hand the device the same derivation, where a software key builds the engine for each derivation. HKDF's is
  `bouncycastle_hkdf::HkdfDescription<'s, H>`, the hash and RFC 5869's salt (`with_salt`, `new` for the absent one,
  `salt()` to read it back; a salt typed `Unknown` is refused where the description is made); the X9.63 and
  concatenation KDFs, made from nothing but their hash, describe themselves, so `X963KDF<H>` and `ConcatKDF<H>`
  serve as before. The ML-KEM pairings are over `KdfParams<'p, HkdfDescription<'s, SHA256>, LEN>` and siblings,
  the ECC CDH HKDF pairing likewise; an HKDF instance that absorbed input through the streaming API, which the
  pairings refused at the derivation, can no longer reach one. `bouncycastle-eccdh`'s `token_key_tests` is the
  shape: a key that holds no material, agreeing through the same parameters as the software key by reading them.
  `KDFFactory` has no description form yet, so a derivation chosen at run time is still built by hand. Mutants on
  apollo: core `kdf_params.rs` 5 (3 caught, 2 unviable), hkdf 133 (89 caught, 43 unviable, 1 missed, the
  description's `Clone`, closed by a test), mlkem-common `kdf.rs` 12 (4 caught, 7 unviable, 1 missed, `derive`'s
  defensive length check), eccdh `kdf.rs` and `eccdh.rs` 39 (10 caught, 21 unviable, 8 missed: `x963_max_len`'s
  const-only arithmetic and `derive`'s defensive check, as before).
* The MAC worker trait splits in two, as the signature and cipher workers are: `MACGenerator<MAC_LEN>`
  (`do_update`, `do_final_out` into a `[u8; MAC_LEN]`, `do_final`) and `MACVerifier<MAC_LEN>` (`do_update`,
  `do_verify_final(&[u8; MAC_LEN]) -> Result<(), MACError>`) replace `MAC`, whose finals and key-era one-shots
  were on one trait, so a verify-only key no longer hands out a worker that can produce a tag. The tag is the
  construction's full output as a const-generic array: no run-time length, no `InvalidLength` on the streaming
  path, no truncation method (a protocol that truncates does so on the array it gets back), and verification
  is a `Result` with `MACError::VerificationFailed` rather than a `bool`. The worker types carry their direction,
  `HMAC<'k, H, Dir>`, `KMAC128<Dir, MAC_LEN>`, `Cmac<'k, P, Dir, BLOCK_LEN>`, `Poly1305<Dir>`, with the
  `Encrypting` / `Decrypting` markers now in `bouncycastle_core::direction` (re-exported by `bouncycastle-cipher`).
  `MacGenerationKey<MAC_LEN>` / `MacVerificationKey<MAC_LEN>` bound their workers on the split traits; GMAC gets
  the nonce-bound role pair `NonceMacGenerationKey` / `NonceMacVerificationKey` in place of the inherent pair on
  the key; `MacMode<P, MAC_LEN>` has `generate_init` / `verify_init` for `mac_init`. KMAC's output length is the
  key type's const parameter, `KMAC128Key<MAC_LEN = 32>` / `KMAC256Key<MAC_LEN = 64>`, and `with_params` takes
  only the customization string; `HMAC::keygen_from_rng` is `HmacKey::keygen_from_rng`, `Poly1305Key::into_mac`
  is `into_generator` / `into_verifier`, and `MIN_FIPS_DIGEST_LEN`, `CMAC_MIN_TAG_LEN` and `hmac::hazmat::finish_out`'s
  `Result` go with the truncation floors. `MACFactory` keeps run-time lengths as the run-time form: its `mac`,
  `mac_out`, `verify` and `MACFactoryWorker<Dir>`'s finals are inherent over slices and `Vec`s; `MACFactory` no
  longer implements the `MacGenerationKey` / `MacVerificationKey` roles and `MACFactoryWorker` no core worker trait,
  so code generic over the roles takes a concrete key. A truncated tag cannot be verified through the role or
  factory APIs (SP 800-38B Sec 6.3's truncated verification is not implemented). The `kmac*` CLI
  commands compute their tag through KMACXOF's length-binding final read, and refuse a wrong-length `--verify`
  before reading input as the other MAC commands do.
* Every encrypting key takes a caller-supplied IV or nonce as the AEAD keys already did:
  `SymmetricEncryptionKey` and `BlockEncryptionKey` gain `create_encryptor_nonce` and the `encrypt_nonce_out` /
  `encrypt_nonce` / `encrypt_inplace_nonce` one-shots, `SymmetricEncryptMode` and `BlockEncryptMode` the
  `encrypt_init_nonce` constructor, implemented by CBC, CFB, CFB8, OFB, CTR, padded ECB and `ChaCha20Key`. The drawing
  forms remain the default; the caller of a `_nonce` form takes on the obligation they discharge (SP 800-38A
  Appendix C's unpredictable IV for CBC and CFB, Appendix B's unique counter blocks for CTR, RFC 8439 Sec 2.4's
  never-repeated nonce for ChaCha20). The known-answer suites pin their IVs through the new forms instead of a
  seeded RNG, and the CLI's `--iv` flags run through them; `--iv` / `--iv-file` and `--nonce` / `--nonce-file` are
  two spellings of one flag on every command that has either.
* The KDF entropy accounting after review: a full-entropy key with no strength (a `SharedSecret` whose producer
  stated none, which is now the default for one built from bytes, or a key too short to carry 112 bits) credits
  nothing, so a `CryptographicRandom` output of 14 bytes or more carries a strength; a KDF instance that has absorbed input
  through the streaming API is refused; and a zero-length derivation is refused.
  A derivation from no keys is refused; HKDF's `extract_out`, `extract_and_expand_out` and
  `do_extract_final_out` zeroize the output before any check, as the `_out` rule asks; and the ML-KEM pairings
  cap the derived key's label at the pairing's strength, so a secret salt does not lift it.
* SHA-3 and SHAKE no longer implement `KDF`, and `KDFFactory` loses the `SHA3-224` to `SHA3-512`, `SHAKE128` and
  `SHAKE256` names. The construction was this library's own, a single hash of the keys and the info, which no
  standard describes: SP 800-56C Rev. 2 Section 4.1's one-step KDF puts a counter before `Z || FixedInfo` and
  admits the SHA-3 hashes and KMAC as its function, and SHAKE not at all. HKDF over SHA-3 remains as
  `HKDF<SHA3_256>` and its siblings, written out; there is no alias or factory entry for it.
* Two-party key agreement gets the same shape ahead of the ECC CDH crate: the `AgreementKey` role in
  `core::agreement_key`, `AgreementKey<Params, SS_LEN>` with `()` the raw primitive's parameters and a KDF's
  `KdfParams` a KDF-bearing variant's, hands out a
  `KeyAgreement` worker whose `agree_out(&peer_pk, &mut z)` writes `Z` into the caller's buffer as
  `KeyType::SharedSecret`, zeroized first, with `agree(&peer_pk)` provided over it on the worker and the key; `KeyAgreementError` and
  the encodable `KeyAgreementPrivateKey` / `KeyAgreementPublicKey` traits go with it.
* `bouncycastle-eccdh`: ECC CDH (SP 800-56A Rev. 3 Section 5.7.1.2) over P-256, P-384, P-521, secp256k1,
  brainpoolP256r1, brainpoolP384r1 and brainpoolP512r1, with its own key types per curve (full public-key
  validation at decode, key generation by extra random bits), the markers `ECCDHP256` and friends on the
  `AgreementKey` role over `()`, and `ECCDHP256_HKDF_SHA256` over `KdfParams<HkdfDescription<SHA256>, LEN>` on the P-256 keys;
  tested against the CAVP ECC CDH primitive vectors, RFC 7027 Appendix A and the Wycheproof ECDH sets.
* `bouncycastle-x963kdf`: the ANSI X9.63 KDF of SEC 1 v2 Section 3.6.1 over SHA-224, SHA-256, SHA-384 and
  SHA-512, on the `KDF` trait and in `KDFFactory` (`X963KDF-SHA256` and so on) and as the `x963kdf-sha*` CLI
  subcommands, checked against the CAVP ANS X9.63-2001 component vectors; `KdfParams<X963KDF_SHA256, LEN>` and its
  siblings, the KDF instance, `SharedInfo` and `keydatalen`, are the parameters of the ECC CDH keys' second agreement role, SEC 1 Section 6.1's ECDH scheme
  (`ECCDHP256_X963KDF_SHA256`, `ECCDHP384_X963KDF_SHA384`, `ECCDHP521_X963KDF_SHA512` and the rest).
* `bouncycastle-concatkdf`: the NIST concatenation KDF, SP 800-56C Rev. 2 Section 4.1's one-step KDF with
  `H(x) = hash(x)`, over SHA-2 and SHA-3 (`ConcatKDF_SHA256` and so on) on the `KDF` trait and in `KDFFactory`
  (`ConcatKDF-SHA256` and so on) and as the `concatkdf-sha*` CLI subcommands, checked against the ACVP KDA OneStep
  SP800-56Cr2 vectors; `KdfParams<ConcatKDF_SHA256, LEN>` and its siblings are a third KDF role on the ECC CDH keys,
  SP 800-56A Rev. 3 Section 5.8's one-step derivation (`ECCDHP256_ConcatKDF_SHA256` and the rest).
* `bouncycastle-ec` gains one marker type per curve at its root (`P256`, `P384`, `P521`, `Secp256K1`, `Bp256r1`,
  `Bp384r1`, `Bp512r1`) and `curve::Curve`, implemented by the markers, which names a curve's arithmetic types
  and routes to its `hazmat` functions, so a role crate is written once over `C: Curve`; the signature and
  key-agreement crates hang their key pairs on the markers (`P256::generate_signature_key_pair::<SHA256>(&mut rng)`,
  `P256::generate_agreement_key_pair(&mut rng)`). `bouncycastle-utils` gains `const_str::ConstStr`, a string
  concatenated at compile time, for algorithm names built from type parameters.
* `bouncycastle-eccdh` is one implementation over `Curve`: the algorithm is `ECCDH<C>` and the keys
  `ECCDHPublicKey<C>` / `ECCDHPrivateKey<C>` for a marker `C`, `keys::keygen::<C>`, and the KDF pairings are
  `ECCDH_X963KDF<C, H>` and `ECCDH_ConcatKDF<C, H>` over the hash matched to the curve (`eccdh::MatchedHash`)
  and `ECCDH_HKDF_SHA256<C>` on P-256. The per-curve modules and markers (`ECCDHP256`, `keys_p256` and the
  rest) go; the algorithm names, encodings, strengths and test vectors are unchanged.
* `bouncycastle-ecdsa` is one implementation over `Curve` and the hash: the algorithm is `ECDSA<C, H>` for a
  marker `C` and any `ecdsa::EcdsaHash` hash `H` (SHA-2, SHA-3, SM3), named `ECDSA-P256-SHA256` and so on, at the lesser
  of the curve's and the hash's strength; the keys `ECDSAPublicKey<C, H>` / `ECDSAPrivateKey<C, H>` carry the
  pairing in full, with no default hash, and re-pair with `with_hash`; the conventional pairings keep their names as aliases (`ECDSAP256 = ECDSA<P256, SHA256>`). The
  per-curve modules (`ecdsa_p256`, `keys_p256`, `rfc6979_p256` and the rest) go; RFC 6979 is implemented once in
  its general form. The algorithm names change from `ECDSA-P256` to `ECDSA-P256-SHA256` (and `ECDetDSA-` likewise);
  encodings and the default pairings' outputs are unchanged. The tests now cover the CAVP SigGen and SigVer matrix
  for P-256, P-384 and P-521 under SHA-224 to SHA-512, RFC 6979's appendix under the same hashes, and every
  Wycheproof ECDSA file for these curves, SHA-3 included. A non-empty `ctx` is refused with
  `SignatureError::LengthError`, as Ed25519 does, ECDSA having no context input; it was accepted and dropped.
* The six per-role key encoding traits are one pair, `PrivateKey<N>` / `PublicKey<N>`, with `from_bytes` returning
  `KeyDecodingError`, which converts into each role's error as its `DecodingError`. A key that serves two roles, such
  as X25519 in key agreement and as a KEM, implements it once, so `encode` and `from_bytes` are no longer ambiguous
  on it.

* Hidden stack copies removed from the `mldsa` and `mldsa-lowmemory` crates; `mldsa-lowmemory`'s memory table is re-measured.
* `keygen_out` / `keygen_from_seed_out` on `MLDSATrait` and `MLKEMTrait` generate into keys made with `zeroized()` (ML-KEM into the private key alone, whose `pk()` is the public key), leaving no copy of the private key behind; an unfilled key does not sign, verify or decapsulate (`ActingOnZeroizedKey`).
* ML-DSA and ML-KEM stack usage is lower (ML-DSA-87 KeyGen 133,320 to 99,128 bytes, expanded-key Verify 189,240 to 139,192; ML-KEM-1024 Encaps 41,816 to 32,040); both memory tables are re-measured.
* `SampleNTT` and `RejBoundedPoly` squeeze whole SHAKE blocks (504 and 272 bytes); the ML-KEM memory tables are re-measured.
* The ML-KEM stack harness measures encapsulation and decapsulation alone, on a key made beforehand; its Decaps rows had included a key generation. Both ML-KEM memory tables are re-measured (ML-KEM-1024 Decaps with an expanded key 50,648 to 37,624 bytes), and `mlkem`'s key generation has one assembly, which lowers its peak (ML-KEM-1024 KeyGen 24,376 to 22,248).
* `bouncycastle-utils`: `ct_eq_bytes_mask` is renamed `ct_eq_bytes_condition`.
* `core::hazmat::label_kdf_output` is the `KDF` trait's rule for typing derived keying material as one function; KBKDF, the Concat KDF, the X9.63 KDF and PBKDF2 call it where each had its own copy. No change in behaviour.
* HashML-DSA can use a pre-hash weaker than the parameter set when the caller names it as `hazmat::AnyStrength<H>` (in `mldsa` and `mldsa-lowmemory`; `--allow-weak-hash` in the CLI), which lowers the signature's strength to the hash's; the default still refuses it. The ACVP pre-hash vectors, which pair every hash with every parameter set, now run. `HashAlgParams` gains `PRE_HASH_STRENGTH_RULE`, which a hash function leaves at its default.
* HashML-DSA is a key of its own (`mldsa` and `mldsa-lowmemory`). An ML-DSA key, plain or expanded, keeps the roles over `MLDSA<P>` alone; `sk.as_prehash::<H>()` and `pk.as_prehash::<H>()` give `HashMLDSAPrivateKey` and `HashMLDSAPublicKey`, views that borrow the key and copy nothing, with the ordinary signing and verifying roles over the marker `HashMLDSA<P, H>` and the digest-supplied `sign_ph` / `verify_ph`. For a 0.1.3 caller, `sk.create_ph_signer::<H>(rng, ctx)` becomes `sk.as_prehash::<H>().create_signer(rng, ctx)` and `sk.sign_ph::<H>(..)` becomes `sk.as_prehash::<H>().sign_ph(..)`, likewise when verifying; `core`'s `PreHashSigningKey`, `DeterministicPreHashSigningKey` and `PreHashVerifyingKey` keep only the digest-supplied methods, over an algorithm marker that names its hash (`PreHashAlgorithm::Hash`), which the two signing traits require to be a `CollisionResistantHash`; the HashML-DSA workers report the pairing's name (`HashML-DSA-44_with_SHA512`) where they reported the parameter set's. The parameter-set types `MLDSA44Params`, `MLDSA65Params` and `MLDSA87Params` are exported from both crates, to name the marker and the views with.
* `bouncycastle-sha3`: `finish_squeezer` on SHAKE, cSHAKE and KMACXOF ends the input where the sponge sits and lends out its squeezer, for a sponge that has absorbed a secret: `XOF::into_squeezer` moves the sponge, and a release build was seen to leave copies of it on the stack (Ed448's private key, KMAC's keyed state in the KMAC KDF, the state of ML-KEM's implicit-rejection hash). ML-DSA, ML-KEM, the KMAC KDF and Ed448 finish their secret hashes that way.
* `bouncycastle-sha3` overwrites the stack frame of each Keccak-f permutation after it: the permutation spills lanes of the state there (14 of the 25 output lanes on x86-64), which a scan found on the dead stack after the KMAC KDF, ML-DSA and Ed448. The overwrite is sized for an optimised build (checked on x86-64 and aarch64), and an unoptimised build's larger frame is not covered. It costs 3 to 4% of SHA-3 time and 336 bytes of stack; the ML-DSA, ML-KEM, KBKDF, PBKDF2 and Ed448 memory tables are re-measured.
* A signature is generated only over a hash that carries the new marker `core::traits::CollisionResistantHash`, required by ECDSA's signing roles and key-pair generation and by a HashML-DSA key's signing roles, and not by verification. The SHA-2, SHA-3, SHAKE, SM3, BLAKE2, BLAKE3 and Ascon-Hash256 hashes carry it; the RIPEMD functions do not, so `ECDSA<C, RIPEMD160>` now verifies and no longer signs, and `AnyStrength<RIPEMD160>` no longer signs. `core::hazmat::WithoutCollisionResistance<H>` opts back in: the same algorithm and the same signature bytes.
* `FixedSeedRNG` moved from `bouncycastle-rng` to `bouncycastle_core::hazmat`, with no re-export left behind, and `cipher`, `ascon`, `ecdsa`, `sm2`, `mldsa`, `mldsa-lowmemory`, `mlkem` and `mlkem-lowmemory` no longer depend on `bouncycastle-rng` at build time (it is a dev-dependency, for their docs and tests).
* `RNG::next_bytes`, which returned a `Vec`, is removed from the trait; draw into a buffer with `next_bytes_out`. The `Vec`- and `Box`-returning one-shots of `Hash`, `HashOneShot`, `KDF`, `XOFSqueezer` and `XOF` are behind `bouncycastle-core`'s default `std` feature, as the symmetric ones were; nothing changes with default features.
* `bouncycastle-sha2`, `bouncycastle-sm3`, `bouncycastle-ripemd`, `bouncycastle-blake2`, `bouncycastle-hmac` and `bouncycastle-hkdf` are `#![no_std]`: the crates themselves use nothing from `std`. `bouncycastle-core`, which they depend on, is not yet, so this is not by itself a build for a target without `std`.
* `XOFSqueezer::do_output` and `do_output_final`, which return a `Vec`, are provided methods behind `bouncycastle-core`'s `std` feature, over `do_output_out` and `do_output_final_out`; an XOF implements only the `_out` forms, and one that binds its output length on the last read overrides `do_output_final_out` alone. `bouncycastle-sha3`, `bouncycastle-blake3` and `bouncycastle-ascon` are `#![no_std]`, with a default `std` feature over their `Vec`-returning one-shots (the parameterised `hash` methods, `TupleHash::hash_tuple`, `XOF::xof`). As for the crates above, `bouncycastle-core` is not yet `no_std`, so a build of them without `std` still links it.
* `bouncycastle-factory` is removed, and with it `bouncycastle::factory`: selection of a hash, XOF, KDF, MAC or RNG by name at run time (`HashFactory::new("SHA256")` and the like), the `default_128_bit` / `default_256_bit` defaults of `AlgorithmFactory`, and `MACFactory`, which was the library's home for a MAC with a tag length chosen at run time. Nothing in the library or the CLI used it; algorithms are named by type. Entries elsewhere in these notes that mention a `*Factory` entry describe the tree before the removal. `bouncycastle-rng` loses `HASH_DRBG_SHA256_NAME` and `HASH_DRBG_SHA512_NAME`, which only the factory used.
* `bouncycastle-mldsa-common`, `bouncycastle-mldsa`, `bouncycastle-mldsa-lowmemory`, `bouncycastle-mlkem-common`, `bouncycastle-mlkem` and `bouncycastle-mlkem-lowmemory` are one crate, `bouncycastle-pqc`, each a module of it under its old name (`bouncycastle_pqc::mldsa`, `::mldsa_lowmemory`, `::mlkem`, `::mlkem_lowmemory`, and the shared `::mldsa_common` and `::mlkem_common`), with every item at the path it had and no change in behaviour. A 0.1.3 user of one of those crates depends on `bouncycastle-pqc` instead and writes `bouncycastle_pqc::mldsa::` for `bouncycastle_mldsa::`, and likewise for the others; a user of the umbrella changes nothing, since `bouncycastle::mldsa`, `::mldsa_lowmemory`, `::mlkem` and `::mlkem_lowmemory` are as they were, and `bouncycastle::pqc` is added. Entries elsewhere in these notes that name those crates describe the tree before the merge.
* `bouncycastle-blake2`, `bouncycastle-blake3`, `bouncycastle-ripemd`, `bouncycastle-sm3`, `bouncycastle-pbkdf2`, `bouncycastle-scrypt`, `bouncycastle-concatkdf` and `bouncycastle-x963kdf` are one crate, `bouncycastle-digest`, each a module of it under its old name (`bouncycastle_digest::blake2`, `::blake3`, `::ripemd`, `::sm3`, `::pbkdf2`, `::scrypt`, `::concatkdf`, `::x963kdf`), with every item at the path it had and no change in behaviour. scrypt's and BLAKE3's `std` features are now the crate's. A 0.1.3 user of one of those crates depends on `bouncycastle-digest` instead and writes `bouncycastle_digest::sm3::` for `bouncycastle_sm3::`, and likewise for the others; a user of the umbrella changes nothing, since `bouncycastle::blake2` and the rest are as they were, and `bouncycastle::digest` is added. Entries elsewhere in these notes that name those crates describe the tree before the merge.
* `bouncycastle-aria`, `bouncycastle-ascon`, `bouncycastle-camellia`, `bouncycastle-chacha20`, `bouncycastle-poly1305`, `bouncycastle-chacha20-poly1305-aead`, `bouncycastle-kbkdf`, `bouncycastle-sm4` and `bouncycastle-tdes` are one crate, `bouncycastle-symmetric`, each a module of it under its old name (`bouncycastle_symmetric::aria`, `::ascon`, `::camellia`, `::chacha20`, `::poly1305`, `::chacha20_poly1305_aead`, `::kbkdf`, `::sm4`, `::tdes`), with every item at the path it had and no change in behaviour. Ascon's `std` feature is now the crate's. A 0.1.3 user of one of those crates depends on `bouncycastle-symmetric` instead and writes `bouncycastle_symmetric::ascon::` for `bouncycastle_ascon::`, and likewise for the others; a user of the umbrella changes nothing, since `bouncycastle::ascon` and the rest are as they were, and `bouncycastle::symmetric` is added. Entries elsewhere in these notes that name those crates describe the tree before the merge.
* `bouncycastle-base64` is the `base64` module of `bouncycastle-core` (`bouncycastle_core::base64`), with every item at the path it had below it and no change in behaviour. A 0.1.3 user writes `bouncycastle_core::base64::` for `bouncycastle_base64::`; `bouncycastle::base64` is as it was. `encode`, `decode`, `do_update` and `do_final` each have an `_out` form that writes into the caller's buffer and returns the number of bytes written (`encode_out`, `decode_out`, `do_update_out`, `do_final_out`), with `_out_len` functions for the buffer size and a new `Base64Error::InsufficientOutputBufferSize`; those need no allocator, and the forms returning a `String` or a `Vec` are behind core's default `std` feature.
* `bouncycastle-hex` is the `hex` module of `bouncycastle-core` (`bouncycastle_core::hex`), with every item at the path it had below it; a 0.1.3 user writes `bouncycastle_core::hex::` for `bouncycastle_hex::`, and `bouncycastle::hex` is as it was. `encode_out` and `decode_out` zeroize the output buffer before checking its length, and `decode_out` leaves it zeroized on an error, where before a short buffer was returned as it was and a decoding error left the bytes decoded so far in it; `encode_out_len` and `decode_out_len` give the buffer sizes. `encode` and `decode`, which return a `String` and a `Vec`, are behind core's default `std` feature.
* `bouncycastle-sha2`, `bouncycastle-sha3`, `bouncycastle-hmac` and `bouncycastle-hkdf` are modules of `bouncycastle-digest` under their old names (`bouncycastle_digest::sha2`, `::sha3`, `::hmac`, `::hkdf`), with every item at the path it had and no change in behaviour. SHA-3's `std` feature is now the crate's. A 0.1.3 user of one of those crates depends on `bouncycastle-digest` instead and writes `bouncycastle_digest::sha2::` for `bouncycastle_sha2::`, and likewise for the others; a user of the umbrella changes nothing, since `bouncycastle::sha2`, `::sha3`, `::hmac` and `::hkdf` are as they were. Entries elsewhere in these notes that name those crates describe the tree before the merge.
* `bouncycastle-aes` is the `aes` module of `bouncycastle-symmetric` (`bouncycastle_symmetric::aes`), with every item at the path it had below it, and `bouncycastle-cipher` is that crate's root: `bouncycastle_symmetric::modes`, `::padding`, `::stream`, `::BlockCipherKey` and the `Encrypting` / `Decrypting` / `Direction` re-export, with no change in behaviour. A 0.1.3 user of either crate depends on `bouncycastle-symmetric` instead and writes `bouncycastle_symmetric::aes::` for `bouncycastle_aes::` and `bouncycastle_symmetric::` for `bouncycastle_cipher::`. `bouncycastle::aes` is as it was; `bouncycastle::cipher` is gone and has no alias, so a user of the umbrella writes `bouncycastle::symmetric::modes::GCM` for `bouncycastle::cipher::modes::GCM`. Entries elsewhere in these notes that name those crates describe the tree before the merge.
* The fixed-width limb arithmetic `nat` and the generic Montgomery multiplication `montgomery` are modules of `bouncycastle-utils` (`bouncycastle_utils::nat`, `::montgomery`), not of `bouncycastle-ec`, with every item as it was and no change in behaviour; both forbid `unsafe`. `bouncycastle-rsa` no longer depends on `bouncycastle-ec`.
* `bouncycastle-ecdsa`, `bouncycastle-eccdh`, `bouncycastle-sm2`, `bouncycastle-ed` and `bouncycastle-dhkem` are modules of `bouncycastle-ec` under their old names (`bouncycastle_ec::ecdsa`, `::eccdh`, `::sm2`, `::ed`, `::dhkem`), beside the curve arithmetic, which stays at the crate root; every item is at the path it had and there is no change in behaviour. A user of one of those crates depends on `bouncycastle-ec` instead and writes `bouncycastle_ec::ecdsa::` for `bouncycastle_ecdsa::`, and likewise for the others; a user of the umbrella changes nothing, since `bouncycastle::ecdsa`, `::eccdh`, `::sm2`, `::ed` and `::dhkem` are as they were. Entries elsewhere in these notes that name those crates describe the tree before the merge.
* `bouncycastle-rsa` is the `rsa` module of `bouncycastle-modexp` (`bouncycastle_modexp::rsa`), the crate for the public-key algorithms built on modular exponentiation, of which RSA is the one member today; every item is at the path it had below the module and there is no change in behaviour. A user of that crate depends on `bouncycastle-modexp` instead and writes `bouncycastle_modexp::rsa::` for `bouncycastle_rsa::`; a user of the umbrella changes nothing, since `bouncycastle::rsa` is as it was, beside the new `bouncycastle::modexp`. Entries elsewhere in these notes that name that crate describe the tree before the move.
* The umbrella `bouncycastle` re-exports each library crate once (`bouncycastle::core`, `::digest`, `::rng`, `::symmetric`, `::ec`, `::pqc`, `::modexp`, `::hybrid`) and nothing else: the flat paths the entries above say were kept (`bouncycastle::sha2`, `::aes`, `::ecdsa`, `::mlkem`, `::hpke`, `::rsa`, `::hex` and the rest, 35 in all) are gone, so each algorithm has one path and the umbrella's documentation lists it once. A user of the umbrella writes the family in front of the old name: `bouncycastle::digest::` before `blake2`, `blake3`, `concatkdf`, `hkdf`, `hmac`, `pbkdf2`, `ripemd`, `scrypt`, `sha2`, `sha3`, `sm3` and `x963kdf`; `bouncycastle::symmetric::` before `aes`, `aria`, `ascon`, `camellia`, `chacha20`, `chacha20_poly1305_aead`, `kbkdf`, `poly1305`, `sm4` and `tdes`; `bouncycastle::ec::` before `dhkem`, `eccdh`, `ecdsa`, `ed` and `sm2`; `bouncycastle::pqc::` before `mldsa`, `mldsa_lowmemory`, `mlkem` and `mlkem_lowmemory`; `bouncycastle::hybrid::hpke`; `bouncycastle::modexp::rsa`; and `bouncycastle::core::` before `hex` and `base64`. Nothing else changes.
* The block cipher modes, the padding, the stream helpers and `BlockCipherKey` of `bouncycastle-symmetric` are in one private module, `framework`, and re-exported at the crate root, so every public path is as it was (`bouncycastle_symmetric::modes`, `::padding`, `::stream`, `::BlockCipherKey`) and there is no change in behaviour. Its internals are private to it again: the two `StreamCipher` items and the padded workers' `from_inner` that the move into the family had left reachable from the cipher modules, and the sealed supertrait of `stream::KeyStreamPolicy`, which a cipher module can no longer implement for a keystream of its own.
* `bouncycastle-core` is `#![no_std]`, and with it a build of `bouncycastle-utils`, `-core`, `-digest`, `-symmetric`, `-ec`, `-pqc`, `-modexp`, `-hybrid` or the umbrella `bouncycastle` with `default-features = false` links neither `std` nor an allocator. Nothing changes with default features: each of those crates but `-utils` has `default = ["std"]`, and a crate's `std` turns on the `std` of the crates it depends on. Everything that needs a heap is behind a new `alloc` feature of the same crates, which `std` implies: the `Vec`-, `String`- and `Box`-returning one-shots (including `hex` and `base64`), the `_boxed` finals of the worker traits (`do_final_out_boxed` and the like), scrypt's `KDF` impl, and the BLAKE3, SHA-3 and Ascon `Vec` one-shots, all of which were behind `std` or ungated. A `no_std` build with a heap asks for `default-features = false, features = ["alloc"]`; one without asks for `default-features = false` and uses the `_out` forms. `bouncycastle-rng` seeds from the operating system and still needs `std`, so in the umbrella it is an optional dependency that `std` turns on: `bouncycastle::rng` is not there in a build without `std`. The entries above that say `bouncycastle-core` is not yet `no_std`, or that put a one-shot behind `std`, describe the tree before this.
* SM2 public key encryption (GB/T 32918.4-2016, with SM3) in `bouncycastle_ec::sm2::encryption`, with a key pair of its own: `encrypt_detached_inplace` / `decrypt_detached_inplace` work on the message in the caller's buffer and take or return `C1` and `C3`, and the `_out` forms write and read `C1 || C3 || C2` or, named `c1c2c3`, `C1 || C2 || C3`. A ciphertext that does not decrypt is one error and leaves no plaintext. `bouncycastle-core` gains `PublicKeyEncryptionError`. The `sm2-encryption` CLI command (`keygen`, `pk-from-sk`, `encrypt`, `decrypt`) reads the whole input and writes `C1 || C3 || C2`, or `C1 || C2 || C3` under `--c1c2c3`.
* `HmacKey::from_key_material` holds a key to `HMACParams::HMAC_MAX_SECURITY_STRENGTH`, as `keygen_from_rng` holds the RNG, where it read the hash's `MAX_SECURITY_STRENGTH`. Every hash in the library states one value for both, so no key it accepted or refused changes; a foreign `HMACParams` hash that states two is now checked against the HMAC's.
* The HKDF name of a hash is `hkdf::HKDFParams::HKDF_ALG_NAME`, a trait of the `hkdf` module over `HMACParams`, where it was a constant of `HMACParams`; `HKDF<H>`, `HkdfDescription<H>` and `RSASVE_HKDF<K, H>` are bound on it. Every name string is unchanged. A hash of your own implements `HKDFParams` beside `HMACParams`; code generic over `H: HMACParams` that names `HKDF<H>` writes `H: HKDFParams`.
* `core::hazmat::KdfCredit` is `label_kdf_output`'s rule as a running account (`credit` each key, then `label_output`), for a KDF that takes its keys one at a time; `label_kdf_output` is written over it and gives what it gave.
* HKDF types what it derives through `core::hazmat::KdfCredit` / `label_kdf_output`, the `KDF` trait's rule, where it had its own copy; what it credits (the IKMs given as keys and a salt typed `MACKey`), the seeding bar of half a hash output and the cap are as they were, and every label over SHA-2, SHA-3 and SM3 is unchanged. One label changes: over RIPEMD-160, whose strength is none, `extract_and_expand_out` and the `KDF` derivations type a seeded output `CryptographicRandom` with no strength, as `extract` types the PRK, where they gave `Unknown`.
* An HKDF instance no longer clones itself for each `KDF` derivation: the extract runs over the salt key where it sits, so no second copy of the key's two pad states is made. Results are unchanged.
* HKDF over RIPEMD-160 (`HKDF<RIPEMD160>`, "HKDF-RIPEMD160"; no alias, no CLI command) has tests: known answers for RFC 5869 Appendix A.1 to A.3's inputs on which Python's `hmac`/`hashlib` and OpenSSL 3.0.13 agree, there being no published HKDF-RIPEMD160 vector, and the `KDF` framework suite, which now expects a seeded output to carry a strength only from a function that claims one.
* `X25519PrivateKey` has `from_bytes_out`, which decodes into a key the caller holds, and a `clone_from` that copies field by field into one, as the X448, Ed25519 and Ed448 private keys have.
* `X25519` and `X448` implement `AlgorithmOID` with `id-X25519` and `id-X448` of RFC 8410 Section 3.
* `X25519PrivateKey::pk` and `X448PrivateKey::pk` return a `Result`: a private key that was never filled (`zeroized()`, or one an `_out` generator failed on) has no public key and gives `ActingOnZeroizedKey`, as the Ed25519 and Ed448 keys do, where it gave the all-zero public key.
* `keypair_consistency_check(&pk, &sk)` in `bouncycastle_ec::ed::x25519` and `::x448`, as the Ed25519 and Ed448 modules have: `KeyAgreementError::ConsistencyCheckFailed`, a new variant, when the public key is not the private key's, and `ActingOnZeroizedKey` for a private key that was never filled. The `x25519` and `x448` CLI `check-consistency` actions call it.
* An `X25519PrivateKey` or `X448PrivateKey` that was never filled is equal only to another such key, as the Ed keys are; it compared equal to the key decoded from zero bytes.
* Ed25519 signing with a key that was never filled and a non-empty context reports the key (`ActingOnZeroizedKey`), as Ed25519ph, Ed448 and Ed448ph do, where it reported the context.
* `bouncycastle-rng` is `#![no_std]`, the last library crate to be, with `default = ["std"]`: `std` gates the constructors that seed from the operating system (`new`, `new_from_os`, `Default`) and the `getrandom` dependency, and implies `alloc`, which gates `Sp80090ADrbg::generate`. With `default-features = false` the crate is the DRBG seeded by the caller (`hazmat::NewUninitialized`, then `instantiate`, `reseed`, `generate_out` and the `RNG` methods), with no allocator and no fallback seed, and `bouncycastle::rng` is now there in a build of the umbrella without `std`, where the entry above says it is not. `generate` is a provided method over `generate_out`, which now zeroizes its buffer before any check, so an error leaves it zeroized. Nothing else changes with default features.
* `bouncycastle-core` gains `traits::RNGExt`, implemented for every `RNG` including `dyn RNG`, with `next_array::<N>()`: `N` bytes from one `next_bytes_out` draw, returned by value, and an error rather than a partly filled array when the RNG fails or reports a short draw. It needs neither `std` nor `alloc`. The array is not wiped, so it is for public values (nonces, salts, IVs, test data); secrets are drawn into a `KeyMaterial` or `Secret` through the `_out` methods, among them `RNGExt::next_bytes_exact_out`, which fills a caller's buffer and refuses a short draw, wiping the buffer. `RNG` itself is unchanged and stays dyn-compatible.
* `Sp80090ADrbg::instantiate` raises a requested strength below 112 bits, `SecurityStrength::None` included, to 112 (SP 800-90A Rev. 1 Section 9.1 step 4), so the 112-bit seed and nonce minimums apply where a 1-byte seed was accepted before; `prediction_resistance = true` returns `RNGError::GenericError` where it panicked.
* `pqc`: the ML-KEM KDF workers `MLKEMKdfEncapsulator` and `MLKEMKdfDecapsulator` are defined once, in `mlkem_common::kdf`, over the key they borrow, and reached at the paths they had in `mlkem` and `mlkem_lowmemory` (the low-memory encapsulator as an alias with the parameters it had), so `mlkem::MLKEMKdfDecapsulator` and `mlkem_lowmemory::MLKEMKdfDecapsulator` are now one generic type, as are the two encapsulators. No change in behaviour.
* `keygen_out` / `keygen_from_seed_out` on Ed25519, Ed448, X25519 and X448 return `Result<(), _>`: they fill the private key, and the public key is read from it with `sk.pk()`, which cannot fail once the call has returned `Ok`, as ML-KEM's is and as ML-DSA's is read from the `pk` its `keygen_out` fills.
* `kbkdf`: the KMAC, HMAC and CMAC PRFs build their MAC key from `K_IN` in place, and a CMAC or GMAC key re-tags its material for the permutation in place, so the HMAC and CMAC PRFs and CMAC and GMAC keys leave no copy of the key on the stack (the KMAC PRF still leaves the copies its keyed cSHAKE sponge makes in `bouncycastle-digest`); the KBKDF stack figures drop by up to 592 bytes (the KMAC KDF) and the module's table is re-measured.
* The in-place AEAD one-shots no longer leave plaintext in a stack buffer of their own: ChaCha20-Poly1305's and Ascon-AEAD128's `encrypt_detached_inplace` / `decrypt_detached_inplace` work in the caller's buffer with no copy, and `core::symmetric_key::encrypt_detached_inplace` / `decrypt_detached_inplace`, which the GCM and CCM keys use, wipe the chunk and last-block buffers they copy plaintext through. Outputs are unchanged.
* `core::base64`: `Base64Encoder` and `Base64Decoder` keep the incomplete block they hold in a `Secret`, wiped on drop, and a `Base64Decoder` whose `do_update_out` fails for any reason other than padding or a short buffer is wiped and refuses every later call with the new `Base64Error::DecoderFailed` (it kept the symbols of the failed block and went on decoding). `core::hex` wipes the half-decoded byte its decoder holds on every return, the errors included.
* The `KDF` one-shots `derive_key` and `derive_key_from_multiple` derive straight into the boxed key they return, leaving no copy of it on the stack (and the call's peak stack is that much lower, about 1.1 KB for KBKDF).
* `SymmetricCipherDecryptor`'s required finishing method is `finish_decrypt_into(&mut self, token, out: &mut [u8; FINAL_LEN]) -> Result<usize, _>`, which writes the last plaintext into the caller's buffer, zeroized past the count and on every error, where `finish_decrypt` returned it by value; an implementor outside the workspace writes the new method. `do_decrypt_final_out` now writes straight into the caller's buffer, and the key one-shots (`decrypt_out`, `decrypt_with_aad_out` and their declared-length forms) finish into a `Secret`, so a CBC/PKCS7 decrypt no longer leaves its last plaintext block on the stack. `do_decrypt_final` and `do_decrypt_final_boxed` still return the block by value, with the bytes after the data now 0 where a padded final returned the padding; the new `do_decrypt_final_out_boxed` is the boxed form that leaves no copy. The provided `_out` finals, detached ones included, zeroize the caller's buffer on an error themselves as well, whatever the implementor left there. Outputs are otherwise unchanged.
* `bouncycastle-digest`: the Keccak sponge clears its input queue once the block it holds is absorbed, so a KMAC or KMACXOF key, and the clones and suspended states of its workers, no longer carry bytes of the key that went through the queue. Outputs and the suspended-state format are unchanged.
* `bouncycastle-digest`: SHA-1, the SHA-2 hashes and SM3 clear their block buffer once the block in it is compressed, so a clone or a suspended state carries only the bytes still buffered, as RIPEMD does; and `do_final_partial_bits_out` zeroizes the output buffer before refusing more than 7 bits. Outputs are unchanged.
* `bouncycastle-digest`: SHA-1, SHA-2 and SM3 compress in a frame of their own and overwrite the stack it used afterwards, so the message schedule and the working variables (the message and chaining value of what was hashed: an HMAC key, a private key) are not left on the dead stack. Sized for an optimised build on x86-64; an unoptimised build is not covered. It costs about 3% of the time of a one-block SHA-256 hash and about 6% of a one-block SHA-512 hash (under 3% from 1 KiB up), and each compression reaches 150 to 550 bytes deeper into the stack.
* `bouncycastle-digest`: an `HmacKey` is made in a frame of its own whose stack is overwritten before the key is returned, the key written straight to the caller rather than held above the overwrite, and a key longer than the block is hashed the same way, so the copies of the two pad states that construction made, and the schedule of the padded key, are not left on the dead stack. Making an HMAC-SHA256 key takes about 9% longer and a tag about 4% longer (with the compression wipe), and making a key reaches 1 to 2 KiB deeper into the stack (HMAC-SM3: 992 to 2976 bytes by the frame-chain measure of the module's table), which matters on a small target.
* `bouncycastle-digest`: each HKDF operation (`extract_out`, `expand_out`, `extract_and_expand_out`, `do_extract_init`, `do_extract_final_out` and the `KDF` derivations) runs in a frame of its own whose stack is overwritten before it returns, so the PRK, its pad states, the salt key's states and the IKM are not left on the dead stack. The overwrite is 4.5 KiB over SHA-2, SM3 and RIPEMD-160 and 9 KiB over SHA-3; an HKDF-SHA256 derivation takes about 8 to 9% longer (HKDF-SHA3-256 about 4%), and an operation reaches up to about 2.3 KiB deeper into the stack (HKDF-SM3 `extract_and_expand_out`: 2368 to 4688 bytes by the frame-chain measure), which matters on a small target.
* `bouncycastle-symmetric`: AES-GCM-SIV encryption and decryption run in a frame of their own whose stack is overwritten before they return, so the per-nonce keys, the second key schedule, POLYVAL's state and the key stream are not left on the dead stack. It costs about 1% of the instructions of a 16-byte encryption and 0.2% at 1 KiB (cachegrind, AES-128; less for AES-256); a call's peak stack rises from 880 / 1,104 bytes (AES-128 / AES-256) to about 1.9 KiB, and the module's table is re-measured. `dev_scripts/check_symmetric_stack.sh` checks HMAC, HKDF, BLAKE3 and AES-GCM-SIV for what they leave on the stack.
* `bouncycastle-digest`: `finish_squeezer` on TupleHashXOF and ParallelHashXOF, as SHAKE, cSHAKE and KMACXOF have it: the input ends where the value sits and the squeezer is lent out, so a value that absorbed a secret is not moved; it is finished from the call (more input, another final or `suspend` panics).
* `bouncycastle-digest`: `finish_squeezer` on `BLAKE3`, `BLAKE3DeriveKey` and the `BLAKE3KeyedHash` generator ends the input where the value sits and returns its squeezer, without moving the hasher (whose chaining values are keyed, or derived from the key material); the `blake3-keyed-hash` and `blake3-derive-key` CLI commands use it. A BLAKE3 value finished where it sits (by `finish_squeezer`, `finish_into` or a MAC final) is finished: more input, another final or `suspend` panics.
* `bouncycastle-digest`: a KMAC key and a KMACXOF are keyed in a frame of their own whose stack is overwritten before the value is returned, so the copies of the keyed sponge (which inverts to the key) that building it made are not left on the dead stack. Making a KMAC128 key takes about 3% longer.
* `HKDF` is not `Clone`: mid-extract it holds the salt key's pad states and an inner hash that has absorbed the IKM, and keyed workers do not clone. A second derivation is made from the salt (`HKDF::new_with_salt`, or a `KDF` instance, which serves any number of derivations).
* `bouncycastle-digest`: `ripemd::hkdf::HKDF_RIPEMD160`, the alias for HKDF over RIPEMD-160 (and `HKDF_RIPEMD160_NAME`), with an `hkdf-ripemd160` CLI command, a criterion bench and a stack-usage row; the HKDF itself is unchanged.
* `HmacKey::keygen_from_rng` accepts an RNG that types its output as something other than a MAC key (`FixedSeedRNG` types it `Seed`), and returns a `MACKey` as it does from a DRBG, where it failed with `HazardousOperationNotPermitted`.
* SM2 decryption accepts `C1` in the hybrid form of GB/T 32918.1-2016 (`06` or `07`, then `x1` and `y1`), the tag to match the parity of `y1`, beside the uncompressed form, as Bouncy Castle Java does; a hybrid `C1` with the wrong tag is one more `DecryptionFailed`. Encryption still writes `C1` uncompressed, and the compressed form is still refused. `hazmat::sm2_sec1` gains `decode_uncompressed_or_hybrid` and `decode_point_uncompressed_or_hybrid`.
* `bouncycastle-digest`: a cSHAKE that has been finished where it sits (`finish_squeezer`, `finish_into`) panics on `suspend`, as KMACXOF, TupleHashXOF and ParallelHashXOF already do; it wrote a state that no type could resume.
* `MLKEMPrivateKeyTrait::pk` in `pqc::mlkem` returns `Result<&MLKEMPublicKey<P>, KEMError>`: a private key that was never filled (`zeroized()`, or one `keygen_out` failed on) has no public key and gives `ActingOnZeroizedKey`, as the X25519, X448 and Ed keys do, where it gave the all-zero public key, which hides nothing encapsulated to it.
* ML-DSA `sign_mu_out`, in `pqc::mldsa` and `pqc::mldsa_lowmemory`, zeroizes its output before it draws `rnd`, so an RNG failure leaves the output zeroed.
* `keygen_out` / `keygen_from_seed_out` and `zeroized()` keys in `pqc::mlkem_lowmemory` and `pqc::mldsa_lowmemory`, in the shape of the full modules: ML-KEM fills the private key and its `pk()`, now a `Result`, gives `ActingOnZeroizedKey` for a key that was never filled; ML-DSA fills the caller's public and private keys. An unfilled key does not sign, verify or decapsulate, and encodes as zeros.
* The ML-DSA and HashML-DSA one-shot `sign_out` / `sign_deterministic_out`, in both ML-DSA modules, draw `rnd` into their own frame and sign without building a signer, so no moved signer leaves `rnd` on the stack; signatures are unchanged. A streaming signer (`create_signer`) holds `rnd` until it is finished.
* `pqc::mldsa` signing keeps 𝐲, NTT(𝐲), 𝐰, 𝐳, c𝐬1, c𝐬2 and c𝐭0 in `Secret`s scoped to each rejection round, so no c𝐬1 is left on the stack after `sign_out` or a streaming final, and its Sign stack rows fall by 5 to 8 kB; ExpandMask's squeezed bytes and the low-memory 𝐰 rows are wiped. The ML-KEM public key types' fields are private. The KeyGen stack rows of all four PQC modules are now measured with the keys left in storage the caller holds, so the by-value rows include moving the result there (ML-DSA-44 by-value KeyGen reads 71,432 bytes where the earlier method gave 40,792); signatures and outputs are unchanged.
* The SM2 signing key (`sm2::keys`) is loaded and generated, `k` is drawn, and signatures are made in frames of their own whose stack is overwritten afterwards (5,120 bytes after `from_bytes` and `keygen`, 4,096 after `create_signer`, `sign_out` and the signer's final), so the key, `(1 + dA)^-1`, `k` and the arithmetic's intermediates are not left on the dead stack, and `from_bytes` keeps no unwiped copy of the bytes or limbs it reads; `dev_scripts/check_sm2_stack.sh` covers these operations. The five operations reach 1.7 to 3.1 kB deeper into the stack; signatures are unchanged.
* SM2 signing key generation (`sm2::keys::keygen`) and `create_signer`, and so `sign` and `sign_out`, refuse an RNG that writes fewer bytes than it was asked for, with `SignatureError::RNGError(RNGError::GenericError(..))`, as SM2 encryption does; they reduced the partly written draw to a key or `k`.
* `bouncycastle-digest`: RIPEMD-128, RIPEMD-160, RIPEMD-256 and RIPEMD-320 compress in a frame of their own and overwrite the stack it used afterwards, as SHA-1, SHA-2 and SM3 do, so the message words and line variables (the message and chaining value of what was hashed, an HMAC key among them) are not left on the dead stack. Sized for an optimised build on x86-64; an unoptimised build is not covered. It costs 2 to 4% of the time of a one-block hash (RIPEMD-160 +2.0%, RIPEMD-128 +3.8%), under 1% from 1 KiB up, and 2.8% of an HMAC-RIPEMD160 tag; each entry point reaches 336 to 384 bytes deeper into the stack. Outputs are unchanged.
* The one-shots `bouncycastle-core` provides over a worker (hash, XOF, MAC generate and verify, the symmetric and AEAD key one-shots, sign and verify), and the inherent `hash` / `hash_out` of cSHAKE, KMACXOF, TupleHash, ParallelHash, BLAKE3DeriveKey and Ascon-CXOF128, finish the worker where it sits instead of moving it into a consuming final, which left a copy of its state and buffered message on the stack. `XOF` gains the required method `finish_xof_into`. Outputs are unchanged; the one-shots use less stack (about 120 bytes for a hash, up to 2 KiB for an XOF), which only the RIPEMD table has been re-measured for.
* ECDSA and ECCDH key generation (and so DHKEM over the NIST curves) on all seven curves, Ed25519, Ed448, X25519 and X448 key generation, and the random ECDSA signer's `k`, refuse an RNG that writes fewer bytes than it was asked for, as SM2 does, with `RNGError::GenericError` inside the operation's error, where they reduced the partly written draw. `bouncycastle-core-test-framework` gains `ShortRNG` for testing it.
* `bouncycastle-digest`: BLAKE3 runs every update that compresses, every final, every squeezer read and `BLAKE3Squeezer::from_suspended` in a frame of its own and overwrites the stack it used afterwards (1 KiB after a final or an update that completes a chunk, 512 bytes after one within a chunk, a squeezer read or `from_suspended`), so the compression's working state and message words and the chaining values (the message, a `keyed_hash` key, `derive_key` key material) are not left on the dead stack; the squeezers from `finish_squeezer`, `into_squeezer` and `from_suspended`, and a `BLAKE3KeyedHashKey` made from key material, are returned without leaving a moved-from copy, and a `keyed_hash` worker no longer copies the key into its chunk state. Sized for an optimised build on x86-64; an unoptimised build is not covered. With the compression's round now inlined, a one-block hash takes about 2% more instructions, 1 KiB and longer inputs about 6% fewer, and 64-byte streaming updates (a wipe per block) about 1% fewer; the stack rows move by -1.6 to +0.4 KiB. Outputs are unchanged.
* `bouncycastle-digest`: an HMAC worker takes the key's inner pad state at its first update or final, where it sits, rather than as it is made, and that copy and the tag's finishing (the outer pad state, the inner digest) run in frames of their own whose stack is overwritten afterwards, so `mac`, `mac_out`, `verify` and a moved, unused worker leave no key-equivalent pad state on the stack. Sized for an optimised build on x86-64. An HMAC tag over 32 bytes takes 2.3 to 3% more instructions, under 1% from 1 KiB up, and PBKDF2 2% more; HKDF, whose own wipe shrinks from 576 to 448 words, takes 1.4 to 2.8% fewer over SHA-2 and 0.4% more over SHA-3. The worker grows by 8 bytes. Outputs are unchanged.
* The stack and size tables re-measured after the in-place one-shots and the HMAC, BLAKE3 and RIPEMD wipes: the SHA-1, SM3, PBKDF2 and scrypt stack figures and the SHA-3 object sizes in `bouncycastle-digest`, the SP 800-108 KDF table in `bouncycastle-symmetric` and the HPKE table in `bouncycastle-hybrid`. The KDF rows that run HMAC rise by 2 to 3 kB (scrypt from 2,312 to 5,288 bytes) with the HMAC wipe frame; the hash one-shots fall by about 120 bytes and the SHA-3 objects by 16 to 32 bytes.
* The SM2 stack table in `bouncycastle-ec` re-measured: the stack the computation itself writes (the "Unwiped" columns) is 300 to 470 bytes lower for encryption and decryption, and with rustc 1.88 for the signing key and for signing other than `create_signer`; the stack written with the wipes moves by under 2%.
* The RSA stack table in `bouncycastle-modexp` re-measured with rustc 1.97 nightly (the earlier figures did not reproduce, and named no toolchain): 12 to 36% lower, e.g. RSA-2048 sign 14,344 bytes (was 16,456).
* `ECDSAPrivateKey::with_hash` takes `&self` and returns a copy, so `d` is no longer left in the caller's frame by a move; `key.with_hash::<H2>()` is unchanged, and the path form `ECDSAPrivateKey::with_hash::<H2>(&key)` now takes a reference.
* ECDSA and ECC CDH private keys (and so DHKEM's ephemeral key) are decoded and generated in a frame whose stack is then overwritten, so `d` and the RNG's output are not left on the dead stack; `dev_scripts/check_ecdsa_stack.sh` covers it. About 320 more instructions per decode, under 0.5% per key generation.
* ECDSA signing (`create_signer`, `sign_out`, both signers' finals and the one-shots over them) runs in a frame whose stack is then overwritten, so `d`, `k` and the RNG's output are not left on the dead stack, on all seven curves. Costs 1.9% of a random and 0.7% of a deterministic P-256 signature (under 0.5% on the larger curves); signatures are unchanged.
* `KeyMaterial::from_rng` and `from_rng_as_type`, and so the `generate` of every symmetric cipher key and of the BLAKE2, BLAKE3 and KMAC keys, refuse an RNG that writes fewer bytes than it was asked for with `KeyMaterialError::GenericError`, where they returned the key with its unwritten bytes zero. `RNGExt::next_array`'s short-draw error carries the library's one message for it.
* `HmacKey::keygen_from_rng` refuses an RNG whose `fill_keymaterial_out` fills less than the whole key with `RNGError::GenericError`, where it returned the shorter key, which HMAC accepts. `ShortRNG` fills key material one byte short as well.
* `bouncycastle-symmetric`: every drawn IV and nonce (CBC, CFB, CFB8, CTR, OFB, GCM, GCM-SIV, CCM, GMAC, ChaCha20, ChaCha20-Poly1305, Ascon-AEAD128) refuses an RNG that writes fewer bytes than it was asked for with `SymmetricCipherError::RNGError` (`MACError::RNGError` for GMAC), where it used the partly written draw.
* `bouncycastle-pqc`: ML-DSA and HashML-DSA hedged signing (`rnd`) and ML-KEM encapsulation (`m`), in both forms of each, refuse an RNG that writes fewer bytes than it was asked for with `RNGError::GenericError` inside the operation's error, where they used the partly written draw. The signature and KEM framework suites check this for every implementation.
* `bouncycastle-digest`: SHA-224/SHA-256 compression keeps a 16-word rolling message schedule, zeroized on return, in place of the 64-word array, and needs fewer operations per round: about 15% fewer instructions and 18 to 22% faster on x86-64, with a compression frame of 72 rather than 248 bytes and a 256-byte rather than 512-byte wipe after it. Outputs are unchanged.
* ECDSA and ECC CDH private keys' `encode`, `encode_out` and `derive_pk` run in a frame whose stack is then overwritten, on all seven curves: the encodings left the bytes of `d` on P-521 and brainpoolP512r1, and `derive_pk` left `d`-dependent intermediates of the fixed-base multiplication (up to 5 kB) on every curve. About 150 more instructions per encoding and 0.1 to 0.5% per `derive_pk`; outputs are unchanged.
* ECC CDH agreement and DHKEM over P-256, P-384 and P-521 (each DH product, `pk(skR)`, the private-key test of `DeriveKeyPair`) run their scalar multiplications in a frame whose stack is then overwritten, so a limb of `d`, limbs of `Z` and the multiplier's intermediates are not left on the dead stack, and an encapsulation no longer moves its ephemeral key out of key generation's `Result`, which left a limb of it and of the RNG's draw on P-521. `agree` takes 0.1 to 0.4% more instructions and an encapsulation or decapsulation 0.04 to 0.4%; their stack rows rise by 1.4 to 3.3 kB. Outputs are unchanged.
* `dhkem::hazmat`'s `salt_key`, `labeled_extract_out` and `labeled_expand` (every DHKEM's KDF, X25519's and X448's included, and HPKE's key schedule, whose salt key is keyed by the KEM's shared secret) and `DHKEM::derive_key_pair` run in a frame whose stack is then overwritten, so copies of the HMAC pad states keyed by a salt or a PRK, and the moved copies of a derived private key, are not left on the dead stack; `dev_scripts/check_ecdsa_stack.sh` now covers the encodings, `derive_pk`, ECC CDH agreement and the DHKEMs (X25519's reported, not failed). Measured against 65625f5e built the same way, the X25519 and X448 KEM rows rise by 144 bytes, HPKE's `export_out` by 112 and its other rows move by -672 to +32 bytes (the table now reads what that build gives); outputs are unchanged.
* Ed25519 and Ed448 run each fixed-base multiplication (key expansion's `[s]B`, signing's `[r]B`) in a frame whose stack is then overwritten (3 KiB and 4 KiB), so limbs of the point and of its normalising inversion are not left on the dead stack after key generation, decoding or signing; and `keygen`, `keygen_from_seed`, the trait's `from_bytes` and `clone` of the Ed25519, Ed448, X25519 and X448 private keys build the key in a wiped frame, so the move out of it leaves no copy of the key, its digest, `s` or the prefix. `dev_scripts/check_ecdsa_stack.sh` covers these keys and every form of EdDSA signing and XDH agreement (X25519's documented inversion residue is reported, not failed). Sized on x86-64; the check passes on arm64 as well. Outputs are unchanged; about 0.3% more instructions over a mix of decoding, signing and agreement. Key generation, private-key decoding and signing reach 1.1 to 1.7 kB (Ed25519) and 1.4 to 2.3 kB (Ed448) deeper into the stack, the by-value XDH key rows up to 416 bytes; the four memory tables are re-measured.
* ECDSA, ECC CDH and DHKEM private-key decoding (`from_bytes`, `DHKEMParams::private_key_from_bytes`) reduces the key into a scalar that is wiped when dropped, and keeps a copy of it, through the new `SecretScalar::from_borrowed_limbs_into`: the scalar it moved out instead left a limb of `d` at the top of the decoding's frame, which on arm64 the stack wipe after it does not reach (P-256, P-384, secp256k1 and the brainpool curves). Outputs are unchanged.
* `bouncycastle-digest`: SHA-384/SHA-512/SHA-512/t compression keeps a 16-word rolling message schedule, zeroized on return, in place of the 80-word array, and needs fewer operations per round: about 11% fewer instructions and 19 to 21% faster on x86-64, with the compression using 320 rather than 800 bytes of stack (368 rather than 852 on thumbv6m) and a 640-byte rather than 1280-byte wipe after it. Outputs are unchanged.
* The Ascon stack table in `bouncycastle-symmetric`, the BLAKE2 one in `bouncycastle-digest` and both ML-KEM memory tables in `bouncycastle-pqc` re-measured, each by the method its prose now states in full (the earlier figures did not reproduce): Ascon rows move by -184 to +112 bytes, the BLAKE2 hash one-shot reads 696 bytes where one-shot and streaming shared 1,120, and ML-KEM Encaps is up to 15% lower (ML-KEM-1024 26,776 to 22,872 bytes) and expanded-key Encaps up to 20% higher.
* The stack wipes after secret-bearing computations (`bouncycastle_utils::stack_wipe`, now shared by `bouncycastle-digest`, `-symmetric`, `-ec` and `-modexp`) overwrite every byte down from the caller's stack pointer, where the wipe's own frame left 4 to 16 bytes at its top unwritten (checked on x86-64, aarch64, thumbv6m and riscv32i at every wipe size in use; it relies on the second, 128-byte wipe saving no register and the first keeping under 128 bytes above its array). A wipe reaches up to 16 bytes less deep, so HKDF's grows from 448 to 504 words. Instruction counts are unchanged or lower (P-256 signing -2%, HKDF-SHA256 -11%).
