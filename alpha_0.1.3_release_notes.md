# 0.1.3 Features / Changelog

## Major features

* New algorithms added to crypto/ :
    * SM3 -- the SM3 hash (GB/T 32905-2016 / ISO/IEC 10118-3:2018), ported from bc-java.
    * AES -- AES-128/192/256, along with its modes AES_ECB, AES_CBC, AES_GCM.
    * ASCON -- Ascon-AEAD128, Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128 (NIST SP 800-232).
      `AsconAead128Encryptor` / `AsconAead128Decryptor` implement the generated-nonce
      `AEADCipherEncryptor` / `AEADCipherDecryptor` pair, and `core::tagged_aead` adapts a
      detached-tag AEAD to the common `ciphertext || tag` layout.
    * `bouncycastle-ascon` is re-exported as `bouncycastle::ascon`; `Ascon-Hash256` and
      `Ascon-XOF128` are registered in the factories, and the CLI adds `ascon-hash256`,
      `ascon-xof128`, `ascon-cxof128` and `ascon-aead128`. The AEAD command generates and prefixes
      the nonce by default, with `--nonce`/`--nonce-file` retained for deterministic vectors.
      Streaming decrypt releases plaintext before the final tag check, so callers must discard any
      output if finalization or the CLI exit status reports authentication failure.
    * `core` gains the streaming AEAD split: `AEADCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN,
      FINAL_LEN>` and `AEADCipherDecryptor<...>`, with AAD updates, exact `update_out_len`,
      detached tags, one-shot helpers and a `FINAL_LEN` flush buffer for implementations that hold
      data back.
    * Testing covers the ASCON NIST LWC KAT sweeps from `bc-test-data` (1089 AEAD128, 1025
      Hash256, 1025 XOF128 and 1089 CXOF128 cases when the data repository is present), plus
      embedded always-on vectors. Mutation testing for `bouncycastle-ascon` currently reports 735
      mutants, 604 caught, 111 unviable and 20 missed before the XOF/CXOF boundary-test additions.

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
