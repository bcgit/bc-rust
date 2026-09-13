# 0.1.3 Features / Changelog

## Major features

* New algorithms added to crypto/ :
    * SM3 -- the SM3 hash (GB/T 32905-2016 / ISO/IEC 10118-3:2018), ported from bc-java.
    * AES -- AES-128/192/256, along with its modes AES_ECB, AES_CBC, AES_GCM.

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
