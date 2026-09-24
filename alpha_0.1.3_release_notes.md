# 0.1.3 Features / Changelog

## Major features

* New algorithms added to crypto/ :
    * SM3 -- the SM3 hash (GB/T 32905-2016 / ISO/IEC 10118-3:2018), ported from bc-java.
    * AES -- AES-128/192/256, along with its modes AES_ECB, AES_CBC, AES_GCM.
    * ASCON -- Ascon-AEAD128, Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128 (NIST SP 800-232).
      `AsconAead128Encryptor` / `AsconAead128Decryptor` implement the generated-nonce
      `AEADCipherEncryptor` / `AEADCipherDecryptor` pair; the inherent `AsconAead128` API keeps the
      explicit-nonce, in-place streaming form (`new_encrypting` / `new_decrypting`).
      `Ascon_AEAD128<Dir>` names the pair by direction (`Ascon_AEAD128<Encrypting>` /
      `Ascon_AEAD128<Decrypting>`).
    * `bouncycastle-ascon` is re-exported as `bouncycastle::ascon`; `Ascon-Hash256` and
      `Ascon-XOF128` are registered in the factories, and the CLI adds `ascon-hash256`,
      `ascon-xof128`, `ascon-cxof128` and `ascon-aead128`. The AEAD command generates and prefixes
      the nonce by default, with `--nonce`/`--nonce-file` retained for deterministic vectors.
      Streaming decrypt releases plaintext before the final tag check, so callers must discard any
      output if finalization or the CLI exit status reports authentication failure.
* `core` gains the streaming AEAD split: `AEADCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN,
  FINAL_LEN>` and `AEADCipherDecryptor<...>`, which extend `SymmetricCipherEncryptor<KEY_LEN,
  NONCE_LEN, FINAL_LEN>` / `SymmetricCipherDecryptor<...>`. The inherited methods are the AEAD
  with no associated data and the tag inline (`ciphertext || tag`), so an AEAD can be held and
  used as a plain symmetric cipher; `FINAL_LEN` is the tag plus anything the cipher holds back,
  and every decryptor holds back the last `TAG_LEN` bytes it has seen, since it cannot know which
  layout its final call will ask for. The AEAD traits add `do_update_aad`; the detached-tag
  methods, each named for the base method it mirrors plus `_detached` (`do_final_detached` /
  `do_final_out_detached`, `encrypt_out_detached`, `encrypt_out_rng_detached`, `encrypt_detached`,
  `decrypt_out_detached`, `decrypt_detached` and the `*_len_detached` sizing helpers); and the
  inline-tag one-shots with AAD, named for their base method plus `_with_aad`
  (`encrypt_out_with_aad`, `encrypt_out_rng_with_aad`, `encrypt_with_aad`, `decrypt_out_with_aad`,
  `decrypt_with_aad`).
  `SymmetricCipherDecryptor::decrypt_out` now zeroizes what it wrote when `do_final` fails, as the
  AEAD one-shots always have.
  The older single-type `core::traits::AEADCipher`, which this splits and which had no
  implementors, is removed, along with its `core-test-framework` suites
  (`TestFrameworkAEADCipher::test` / `::test_plain_one_shots`).
  Mutation testing of the pair's defaults (`traits.rs`, scoped to `AEADCipher{En,De}cryptor` and
  `SymmetricCipherDecryptor::decrypt_out`, tested through `bouncycastle-core` +
  `bouncycastle-ascon`) reports 134 mutants, 107 caught, 27 unviable and none missed; the
  `AsconAead128Encryptor` / `AsconAead128Decryptor` adapters report 76 mutants, 49 caught, 27
  unviable and none missed.
* ASCON testing covers the NIST LWC KAT sweeps from `bc-test-data` (1089 AEAD128, 1025 Hash256,
  1025 XOF128 and 1089 CXOF128 cases when the data repository is present), plus embedded always-on
  vectors. Mutation testing for `bouncycastle-ascon` reports 661 mutants, 558 caught, 97 unviable
  and 6 missed; the six survivors are the sponge boundary and `set_state_byte` OR/XOR equivalences
  documented at their sites.

## Minor features / bug fixes

* Design discussions about whether core::traits::XOF (in the abstract) should allow interleaving absorb -> squeeze ->
  absorb (ie "absorb-after-squeeze). Outcome: absorb-after-squeeze forbidden. Could be changed in the future.
* SHA2:
    * Implemented SHA512/224 and SHA512/256.
    * `Hash::do_final_partial_bits()` / `do_final_partial_bits_out()` are now implemented for SHA-2 (FIPS 180-4 s. 5.1).
* SHA3:
    * Fixed a bug in `XOF::squeeze_partial_byte_final()`: when it was the first squeeze it bypassed the SHAKE `1111`
      domain suffix and returned raw Keccak output, and it returned the wrong `num_bits` bits of the output byte. The
      existing test used
      `0xFF`, which masked the second error.
    * Changed the order of bits when absorbing a final partial byte to match ASN.1 DER BIT_STRING bit ordering.
