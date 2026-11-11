# 0.1.4 Features / Changelog

## Major features

* ARIA -- `bouncycastle-aria`, the RFC 5794 block cipher at 128, 192 and 256 bits, constant-time and table-free (the
  S-boxes as bit-sliced Boolean circuits, four blocks at a time), on the key objects as `ARIA128Key<M>` and friends
  with CBC, CFB, CFB8, CTR, GCM, CCM, CMAC, GMAC, KW and KWP; the `aria*-{cbc,cfb,cfb8,ctr,gcm,ccm,kw,kwp}` CLI
  commands.
* Camellia -- `bouncycastle-camellia`, the RFC 3713 block cipher at 128, 192 and 256 bits, constant-time and table-free
  (the S-box as a bit-sliced Boolean circuit, four blocks at a time), on the key objects as `Camellia128Key<M>` and
  friends with CBC, CFB, CFB8, CTR, GCM, CCM, CMAC, GMAC and KW; the `camellia*-{cbc,cfb,cfb8,ctr,gcm,ccm,kw}` CLI
  commands.
* SM4 -- `bouncycastle-sm4`, the GB/T 32907-2016 block cipher (draft-ribose-cfrg-sm4-10), constant-time and
  table-free (the S-box as a bit-sliced Boolean circuit, four blocks at a time), on the key object `SM4Key<M>` with
  CBC, CFB, CFB8, CTR, GCM and CCM (RFC 8998's AEAD_SM4_GCM and AEAD_SM4_CCM), KW and KWP; the
  `sm4-{cbc,cfb,cfb8,ctr,gcm,ccm,kw,kwp}` CLI commands.
* CHACHA20 -- ChaCha20, Poly1305 and ChaCha20-Poly1305 (RFC 8439).
* AES Key Wrap -- AES_KW and AES_KWP (NIST SP 800-38F; RFC 3394 / RFC 5649) over any 128-bit block permutation,
  with the `KeyWrapper` / `KeyUnwrapper` core traits and the `aes*-kw` / `aes*-kwp` CLI commands.
* ECDSA -- FIPS 186-5 signatures over P-256, P-384, P-521, secp256k1, brainpoolP256r1, brainpoolP384r1 and
  brainpoolP512r1, with the RFC 6979 deterministic variant, through the `SigningKey` / `DeterministicSigningKey` /
  `VerifyingKey` core roles; the `ecdsa-*` CLI commands.
* SM2 -- the GB/T 32918.2-2016 signature algorithm with SM3, on the same roles; the `sm2` CLI command.
* `bouncycastle-ec` -- the constant-time, fixed-width curve arithmetic under both: per-curve field, scalar and
  Jacobian-point arithmetic, SEC 1 codec and comb, wNAF and variable-base multipliers, all under `hazmat`, with the
  generic limb arithmetic (`nat`, `montgomery`, `barrett`, `inverse_vartime`) at the crate root.

## Minor features / bug fixes

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
  `encrypt_init_nonce` constructor, implemented by CBC, CFB, CFB8, CTR, padded ECB and `ChaCha20Key`. The drawing
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
  `AgreementKey` role over `()`, and `ECCDHP256_HKDF_SHA256` over `KdfParams<HKDF_SHA256, LEN>` on the P-256 keys;
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

