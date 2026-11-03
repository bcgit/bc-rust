# 0.1.3 Features / Changelog

## Major features

* New algorithms added to crypto/ :
    * SM3 -- the SM3 hash (GB/T 32905-2016 / ISO/IEC 10118-3:2018), ported from bc-java.
    * AES -- AES-128/192/256, along with its modes AES_ECB, AES_CBC, AES_CCM, AES_CFB, AES_CFB8, AES_CTR, and AES_GCM.
    * ASCON -- Ascon-AEAD128, Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128 (NIST SP 800-232).
* Further memory usage improvements on ML-DSA / ML-KEM. New figures for the largest size are:
    * ML-DSA-87/Sign 118 kb, ML-DSA-87/Verify 212 kb
    * ML-DSA-87_lowmemory/Sign 25 kb, ML-DSA-87_lowmemory/Verify 21 kb
    * ML-KEM-1024/Encaps 44 kb, ML-KEM-1024/Decaps 58 kb
    * ML-KEM-1024_lowmemory/Encaps 11 kb, ML-KEM-1024/Decaps 21 kb
    * Performance (throughput) actually saw a slight performance increase as this cleanup was largely about finding and
      removing unnecessary memcpy's.

## Minor features / bug fixes

* Signature keys build their own workers, as cipher and MAC keys do. `core::signature_key` adds `SigningKey`
  (`create_signer(&self, rng, ctx)`, `sign`), `DeterministicSigningKey` (`create_signer_deterministic`), `VerifyingKey`
  (`create_verifier`, `verify`) and the pre-hash forms with the hash as a type parameter (`create_ph_signer::<SHA512>`,
  `sign_ph`, `verify_ph`). `Signer` is `SignatureSigner` and, with `SignatureVerifier`, keeps only the streaming methods
  (`do_update`, `do_final`, `do_verify_final`); `do_sign_init` / `do_verify_init`, `PHSigner` / `PHSignatureVerifier`
  and the ML-DSA side doors (`sign_with_expanded_key`, `set_signer_rnd`, `sign_init_from_seed`, the fixed-hash
  `HashMLDSA*_with_*` signers) are gone. Randomness comes from the caller's `&mut dyn RNG`: ML-DSA's `rnd` is drawn
  from it (the hedged variant) and no method takes it directly; FIPS 204's deterministic variant (`rnd` all zeros) is
  `DeterministicSigningKey` / `DeterministicPreHashSigningKey` on the ML-DSA keys (`sign_deterministic`,
  `create_signer_deterministic`, `sign_ph_deterministic`) and `sign_mu_deterministic` at the mu level. A known-answer
  test with any other `rnd` reproduces it with `bouncycastle_rng::FixedSeedRNG`, which moved there from the test
  framework and is now generic over what holds its bytes. The `HashMLDSA*_with_*` types remain as the FIPS 204 pairing names and OIDs. ML-DSA's
  external-mu interface is on the keys too: `pk.compute_mu`, `pk.verify_mu`, `sk.compute_mu`, `sk.sign_mu` (an
  expanded key uses its cached matrix), with `create_mu_builder(ctx)` on both keys as the streaming form of
  `compute_mu` (`MuBuilder::from_tr` remains for a party holding only the key hash; the static `MuBuilder::do_init`
  and `MuBuilder::compute_mu` are gone); they replace
  `MLDSATrait`'s static `compute_mu_from_*`, `sign_mu*`, `verify_mu` and the `sign_mu_deterministic_from_seed` forms,
  and the key types carry only their parameter set: `MLDSAPublicKey<P>`, `MLDSAPrivateKey<P>`, the expanded keys
  (which now borrow the key they expand, `MLDSAPrivateKeyExpanded<'k, P>`, so a private key's secret exists once;
  `key()` reaches the borrowed key, which holds the encoding; `A_hat`, `pk_decode` and `sk_decode` leave the key
  traits, `from_bytes` decodes),
  `MLDSASeedPrivateKey<P>` and the marker `MLDSA<P>`, with the encoded lengths inferred through the sealed
  `PublicKeyLen` / `PrivateKeyLen` / `SignatureLen` (/ `FullPrivateKeyLen`) traits.
* `AlgorithmInfo` (`alg_name()`, `max_security_strength()`) is the run-time form of `Algorithm`'s constants, with a
  blanket impl; `Hash`, `KDF`, `MAC` and the new signature workers take it as a supertrait and lose their own
  `max_security_strength`, and the factories report the algorithm they selected instead of `"TODO"`.
* `HashOneShot: Hash + Default` holds the one-shot `hash(data)` / `hash_out(data, out)`, called as `SHA256::hash(msg)`;
  parameterised hashes keep an instance method.
* Design discussions about whether core::traits::XOF (in the abstract) should allow interleaving absorb -> squeeze ->
  absorb (ie "absorb-after-squeeze). Outcome: absorb-after-squeeze forbidden. Could be changed in the future. Refactored
  to an `XOF::xof()`, `XOF.into_squeezer()`, 'XOFSqueezer.output ()' shape.
* SHA2:
    * Implemented SHA512/224 and SHA512/256.
    * `Hash::do_final_partial_bits()` / `do_final_partial_bits_out()` are now implemented for SHA-2 (FIPS 180-4 s. 5.1).
* SHA3:
    * Fixed a bug in `XOF::squeeze_partial_byte_final()`: when it was the first squeeze it bypassed the SHAKE `1111`
      domain suffix and returned raw Keccak output, and it returned the wrong `num_bits` bits of the output byte.
    * Changed the order of bits when absorbing a final partial byte to match ASN.1 DER BIT_STRING bit ordering.
* The constant-time helpers in bouncycastle-utils now use a more robust optimization barrier based on unsafe
  `read_volatile` / `write_volatile` instead of `core::hint::black_box`, which is documented as best-effort only.
* Added the `hazmat` module convention for primitives whose safe use is the caller's job; `bouncycastle_core::hazmat`
  defines it.
    * The `do_hazardous_operations` handler for `KeyMaterial` is now `hazmat`.
    * ML-KEM `encaps_internal` is now `hazmat::EncapsWithRandomness::encaps_with_randomness`, and
      `HashDRBG80090A::new_unititialized` is `hazmat::NewUninitialized::new_uninitialized` (typo fixed); both are
      extension traits, so the call needs the `hazmat` import.
    * New cipher-related features `ElectronicCodeBook`, `KeyStream`, the `AES*Internal` types, `Ecb` and `AES_ECB_*`,
      and `CtrKeyStream` under their crates' `hazmat` modules.
