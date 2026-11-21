# 0.1.4 Features / Changelog

## Major features

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
* ECDSA -- FIPS 186-5 signatures over P-256, P-384, P-521, secp256k1, brainpoolP256r1, brainpoolP384r1 and
  brainpoolP512r1, with the RFC 6979 deterministic variant, through the `SigningKey` / `DeterministicSigningKey` /
  `VerifyingKey` core roles; the `ecdsa-*` CLI commands.
* SM2 -- the GB/T 32918.2-2016 signature algorithm with SM3, on the same roles; the `sm2` CLI command.
* `bouncycastle-ec` -- the constant-time, fixed-width curve arithmetic under both: per-curve field, scalar and
  Jacobian-point arithmetic, SEC 1 codec and comb, wNAF and variable-base multipliers, all under `hazmat`, with the
  generic limb arithmetic (`nat`, `montgomery`, `barrett`, `inverse_vartime`) at the crate root.
* X25519 -- `bouncycastle-ed`, the Diffie-Hellman function of RFC 7748 over Curve25519, on the key agreement
  roles: `X25519PrivateKey` implements `AgreementKey` over `()` for the raw shared secret and over
  `KdfParams<HkdfDescription<SHA256>, LEN>` for a derived key (`X25519_HKDF_SHA256`), and with `X25519PublicKey` the KEM roles
  as DHKEM(X25519, HKDF-SHA256) of RFC 9180 Section 4.1 (`DHKEM_X25519_HKDF_SHA256`), through the new
  `bouncycastle-hpke` crate's generic DHKEM;
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
  Section 7) on the signature roles: `Ed25519PrivateKey` and `Ed25519PublicKey` serve both algorithms, under the
  markers `Ed25519` (one-shot roles only, no context) and `Ed25519ph` (streaming and one-shot, with a context).
  Verification is cofactored, and a decoded public key is validated in full, so one outside the prime-order subgroup
  is refused. `keygen` and `keygen_out` draw the key from the caller's RNG; checked against RFC 8032 Sections 7.1
  and 7.3, Wycheproof's Ed25519 set and the vectors of "Taming the many EdDSAs"; the `ed25519` and `ed25519ph` CLI
  subcommands cover keygen, pk-from-sk, check-consistency, sign and verify, `ed25519ph` streaming the message under
  an optional `--ctxfile`; with criterion benches and a stack harness in `mem_usage_benches`. The markers `Ed25519`
  and `Ed448` carry `id-Ed25519` and `id-Ed448` (RFC 8410); the pre-hash forms have no identifier. `core` gains
  `SignatureError::ComputationFault`, for a computed point that fails its own check.
* Ed448 and Ed448ph -- `bouncycastle-ed::ed448`, the EdDSA signatures of RFC 8032 Section 5.2 (FIPS 186-5 Section 7)
  on the signature roles, in the shape of Ed25519's: `Ed448PrivateKey` and `Ed448PublicKey` serve both algorithms,
  under the markers `Ed448` (one-shot roles only) and `Ed448ph` (streaming and one-shot). Both take a context of up
  to 255 octets, which is where Ed448 differs from Ed25519. Verification is cofactored, a decoded public key is
  validated in full, and the one private key whose public key would be the neutral element is refused. Classed at
  192 bits, `SecurityStrength` having no 224-bit level. Checked against RFC 8032 Sections 7.4 and 7.5 and
  Wycheproof's Ed448 set; the `ed448` and `ed448ph` CLI subcommands cover keygen, pk-from-sk, check-consistency,
  sign and verify, each under an optional `--ctxfile`, `ed448ph` streaming the message; with criterion benches and
  a stack harness in `mem_usage_benches`.
* DHKEM over P-256, P-384 and P-521 -- RFC 9180 Section 4.1's DHKEM(P-256, HKDF-SHA256), DHKEM(P-384, HKDF-SHA384)
  and DHKEM(P-521, HKDF-SHA512) (`kem_id` 0x0010 to 0x0012) on the ECC CDH keys: `ECCDHPublicKey<C>` and
  `ECCDHPrivateKey<C>` over `P256`, `P384` and `P521` carry the KEM roles with `()` as the parameters, under the
  markers `DHKEM_P256_HKDF_SHA256`, `DHKEM_P384_HKDF_SHA384` and `DHKEM_P521_HKDF_SHA512` (`ECDHKEM<C>`), with
  `dhkem::derive_key_pair` for Section 7.1.3's `DeriveKeyPair`. `bouncycastle-hpke` gains the rejection-sampling
  form of `DeriveKeyPair` beside the expand form: `DHKEMParams::DERIVE_KEY_PAIR_BY_EXPAND` is replaced by
  `DERIVE_KEY_PAIR`, a `DeriveKeyPairForm`, and `DHKEMParams::private_key_from_bytes` returns an `Option`, a change
  for implementors of a DHKEM group. Checked against the RFC's machine-readable vectors for P-256 and P-521 (32
  sets each; P-521's key derivation is the first two-block `LabeledExpand`), and, for P-384, which the RFC defines
  but publishes no vectors for, against BC Java 1.84 in both directions.
* PBKDF2 -- RFC 8018 Section 5.2 over HMAC (SHA-2, SHA-3), as `bouncycastle-pbkdf2`, on the `KDF` trait with the salt
  and the iteration count on the instance; a key derived from a password is typed `Unknown`. The `pbkdf2` CLI command
  reads the password from a file or stdin.
* scrypt -- RFC 7914, as `bouncycastle-scrypt`: `SCrypt` over working memory the caller supplies
  (`derive_with_memory_out`, `ScryptParams::work_len`), and on the `KDF` trait with the `std` feature, allocating up to
  a limit. The `scrypt` CLI command takes `--log2-n`, `-r`, `-p` and `--max-memory`.
* HPKE -- RFC 9180 Sections 5 and 6 in all four modes, as `bouncycastle-hpke`, on the X25519, X448, P-256, P-384
  and P-521 keys: `setup_sender` / `setup_recipient` (Base, PSK) and `setup_auth_sender` / `setup_auth_recipient`
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
* `bouncycastle-dhkem` -- the generic DHKEM leaves `bouncycastle-hpke` for a crate of its own
  (`bouncycastle_hpke::dhkem::*` is now `bouncycastle_dhkem::*`), and gains `AuthEncap` and `AuthDecap`. Its
  `_out` functions return the number of bytes written.

## Minor features / bug fixes

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
  `finish_partial_bits_into`, `finish_encrypt`, `finish_decrypt`,
  `finish_encrypt_detached_into`, `finish_decrypt_detached_into`, `finish_mac_into`, `finish_mac_verify`,
  `finish_signature_into`, `finish_signature_verify`), and the consuming finals are provided over it, each with a
  `_boxed` twin taking `self: Box<Self>` (`do_final_out_boxed`, `do_final_partial_bits_out_boxed`,
  `do_encrypt_final_boxed`, `do_decrypt_final_boxed`, `do_encrypt_final_detached_out_boxed`,
  `do_decrypt_final_detached_out_boxed`, `do_verify_final_boxed`). A boxed worker's `Secret` state is wiped inside its
  box, which the final never moves it out of. The finishing methods take a `&core::traits::FinishToken`, whose
  constructor is private to `core`, so that they are called by the provided consuming finals and not a second time by
  accident; a worker type that deliberately hands its token to a worker it only borrows can still defeat this. Callers
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
  Wycheproof ECDSA file for these curves, SHA-3 included.
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
* `bouncycastle-sha3`: `finish_squeezer` on SHAKE, cSHAKE and KMACXOF ends the input where the sponge sits and lends out its squeezer, for a sponge that has absorbed a secret: `XOF::into_squeezer` moves the sponge, and a release build was seen to leave copies of it on the stack (Ed448's private key, KMAC's keyed state in the KMAC KDF, the state of ML-KEM's implicit-rejection hash). ML-DSA, ML-KEM, the KMAC KDF and Ed448 finish their secret hashes that way.
* `bouncycastle-sha3` overwrites the stack frame of each Keccak-f permutation after it: the permutation spills lanes of the state there (14 of the 25 output lanes on x86-64), which a scan found on the dead stack after the KMAC KDF, ML-DSA and Ed448. The overwrite is sized for an optimised build (checked on x86-64 and aarch64), and an unoptimised build's larger frame is not covered. It costs 3 to 4% of SHA-3 time and 336 bytes of stack; the ML-DSA, ML-KEM, KBKDF, PBKDF2 and Ed448 memory tables are re-measured.
* A signature is generated only over a hash that carries the new marker `core::traits::CollisionResistantHash`, required by ECDSA's signing roles and key-pair generation and by the pre-hash signing roles (HashML-DSA), and not by verification. The SHA-2, SHA-3, SHAKE, SM3, BLAKE2, BLAKE3 and Ascon-Hash256 hashes carry it; the RIPEMD functions do not, so `ECDSA<C, RIPEMD160>` now verifies and no longer signs, and `AnyStrength<RIPEMD160>` no longer signs. `core::hazmat::WithoutCollisionResistance<H>` opts back in: the same algorithm and the same signature bytes.
* `FixedSeedRNG` moved from `bouncycastle-rng` to `bouncycastle_core::hazmat`, with no re-export left behind, and `cipher`, `ascon`, `ecdsa`, `sm2`, `mldsa`, `mldsa-lowmemory`, `mlkem` and `mlkem-lowmemory` no longer depend on `bouncycastle-rng` at build time (it is a dev-dependency, for their docs and tests).
* `RNG::next_bytes`, which returned a `Vec`, is removed from the trait; draw into a buffer with `next_bytes_out`. The `Vec`- and `Box`-returning one-shots of `Hash`, `HashOneShot`, `KDF`, `XOFSqueezer` and `XOF` are behind `bouncycastle-core`'s default `std` feature, as the symmetric ones were; nothing changes with default features.
