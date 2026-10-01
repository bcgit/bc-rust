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
* Added the `hazmat` module convention for primitives whose safe use is the caller's job; `bouncycastle_core::hazmat` defines it.
* Moved `ElectronicCodeBook`, `KeyStream`, `do_hazardous_operations`, the `AES*Internal` types, `Ecb` and `AES_ECB_*`, and `CtrKeyStream` under their crates' `hazmat` modules. No behaviour change.
* ML-KEM `encaps_internal` is now `hazmat::EncapsWithRandomness::encaps_with_randomness`, and `HashDRBG80090A::new_unititialized` is `hazmat::NewUninitialized::new_uninitialized` (typo fixed); both are extension traits, so the call needs the `hazmat` import.
