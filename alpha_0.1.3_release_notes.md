# 0.1.3 Features / Changelog

## Major features

* New algorithms added to crypto/ :
    * SM3 -- the SM3 hash (GB/T 32905-2016 / ISO/IEC 10118-3:2018), ported from bc-java, with HMAC-SM3.
    * AES -- AES-128/192/256 in ECB, CBC (PKCS#7 or whole blocks), CFB, CFB8, CTR, CCM and GCM, plus CMAC and GMAC;
      the modes and padding are a new `cipher` crate, generic over the block cipher.
    * ASCON -- Ascon-AEAD128, Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128 (NIST SP 800-232).
    * SP 800-185 -- cSHAKE, KMAC, TupleHash and ParallelHash, in the sha3 crate.
    * HMAC and HKDF are generic over the hash, with aliases in each hash crate: HMAC over SHA-3, HMAC-SM3,
      HMAC-SHA512/224, HMAC-SHA512/256 and HKDF-SHA384 are new (#122).
* Key objects (PRs #170, #172): anything keyed is a key built once from `KeyMaterial` -- `AES128Key<GCM>`,
  `AES128Key<CBC<PKCS7>>`, `HmacKey<H>`, `KMAC128Key`, `AsconAEAD128Key` -- which validates and expands the key once,
  hands out workers that borrow it (`create_encryptor(rng)`, `create_decryptor(init_data)`, `create_generator()`),
  and provides the one-shots (`encrypt`, `mac`, `verify`). The worker traits keep only the streaming methods:
  `do_*_init` and the key-taking one-shots are gone, and resume takes the key object.
* Signature keys likewise: `SigningKey` (`create_signer(rng, ctx)`, `sign`), `DeterministicSigningKey`,
  `VerifyingKey` (`create_verifier`, `verify`) and the pre-hash forms with the hash as a type parameter
  (`create_ph_signer::<SHA512>`); `Signer` is now `SignatureSigner`, and `do_sign_init` / `do_verify_init` are gone.
  ML-DSA and HashML-DSA are on these traits.
* Further memory usage improvements on ML-DSA / ML-KEM, with a slight throughput gain (the work was mostly removing
  unnecessary memcpy's). New figures for the largest size:
    * ML-DSA-87/Sign 118 kb, ML-DSA-87/Verify 212 kb
    * ML-DSA-87_lowmemory/Sign 25 kb, ML-DSA-87_lowmemory/Verify 21 kb
    * ML-KEM-1024/Encaps 44 kb, ML-KEM-1024/Decaps 58 kb
    * ML-KEM-1024_lowmemory/Encaps 11 kb, ML-KEM-1024_lowmemory/Decaps 21 kb

## Minor features / bug fixes

Trait system:

* Anything that draws randomness takes the caller's `&mut dyn RNG` (`keygen`, `create_signer`, `create_encryptor`,
  `encaps_rng`); the `keygen()` that built its own DRBG is gone. `FixedSeedRNG` moved to `bouncycastle-rng`.
* `AlgorithmInfo` (`alg_name()`, `max_security_strength()`) is the run-time form of `Algorithm`; `Hash`, `KDF`,
  `MAC` and the signature workers take it as a supertrait, and the factories report the algorithm selected.
* `HashOneShot` holds the one-shot `hash(data)` / `hash_out(data, out)`, called as `SHA256::hash(msg)`.
* `Hash` no longer requires `Clone`, and the hash, XOF, cipher and MAC worker traits are usable as `dyn`.
* XOF: absorb-after-squeeze is forbidden; the API is the one-shot `XOF::xof()`, or `into_squeezer()` then
  `XOFSqueezer::do_output()` / `do_output_final()`.
* Error enums are `#[non_exhaustive]` (#81); `Condition` covers the unsigned types (PR #63); the constant-time
  barrier in bouncycastle-utils is `read_volatile` / `write_volatile` rather than the best-effort `black_box`.
* `hazmat` modules hold what is only safe when composed correctly (`bouncycastle_core::hazmat` defines the term):
  `do_hazardous_operations`, ML-KEM `encaps_with_randomness` and `HashDRBG80090A::new_uninitialized` (both now
  extension traits), the raw block permutation, ECB and the CTR keystream.

ML-DSA / ML-KEM:

* Fixed an `i32` overflow in ML-DSA-87 verification from a missing reduction, found with Wycheproof (PR #137).
* Parameter sets are sealed traits (`MLDSAParams`, `HashMLDSAParams`, `MLKEMParams`) instead of const-generic
  turbofish; key types carry only `P` (`MLDSAPublicKey<P>`), with the encoded lengths inferred (#117).
* The ML-DSA external-mu interface is on the keys (`compute_mu`, `sign_mu`, `verify_mu`, `create_mu_builder`); the
  FIPS 204 deterministic variant is `DeterministicSigningKey` and the hedged one draws `rnd` from the caller's RNG;
  `sign_with_expanded_key`, `set_signer_rnd` and `sign_init_from_seed` are gone. Expanded keys borrow the key they
  expand.
* HashML-DSA drops `HashMLDSA65_with_SHA256` and `HashMLDSA87_with_SHA256` (SHA-256 is below those sets' strength),
  leaving ML-DSA-44 with SHA-256 or SHA-512 and ML-DSA-65/87 with SHA-512; the SHA-512 pairings carry OIDs.
* ML-KEM gains expanded public and private keys; `mldsa-common` and `mlkem-common` hold the arithmetic shared with
  the low-memory crates.

SHA-2 / SHA-3:

* SHA-2: SHA512/224, SHA512/256, and `do_final_partial_bits()` / `do_final_partial_bits_out()` (FIPS 180-4 s. 5.1).
* SHA-3: `squeeze_partial_byte_final()` on a first squeeze skipped the SHAKE domain suffix and returned the wrong
  bits, fixed; the final partial byte's bit order now matches DER BIT STRING (#91). Keccak absorbs whole blocks
  straight from the caller's slice.

Command line:

* A `bc-rust` subcommand for every new primitive: the AES modes and MACs, Ascon, SM3, SP 800-185, HMAC over every
  hash.

Docs, build and CI:

* QUALITY_AND_STYLE.md covers key objects, `hazmat`, `dyn`-compatibility and the `_out` / `_inplace` / `_nonce`
  suffixes; CONTRIBUTING.md and the new ISSUES_STYLE_GUIDE.md (PR #72, thanks to @jjkurczak) state the submission
  bar and the AI policy.
* Github Actions build, test, doc and format-check every pull request (#45, thanks to @officialfrancismendoza; #59).
* Crate versions inherit from the workspace (thanks to Tamish Dahiya); factory docs link the core traits (thanks to
  Polly Labs); build instructions clarified (thanks to Michael Richardson).
* A `mutants` cargo profile makes `cargo mutants` on ML-DSA / ML-KEM take seconds per mutant rather than minutes.

* Github issues and PRs resolved: #45, #59, #62, #63, #72, #81, #91, #117, #122, #133, #137, #170, #172.
