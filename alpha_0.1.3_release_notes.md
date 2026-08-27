# 0.1.3 Features / Changelog

## Major features

* New algorithms added to crypto/ (PR #89):
    * sm3 -- the SM3 hash (GB/T 32905-2016 / ISO/IEC 10118-3:2018), ported from bc-java. Implements `Hash`,
      `Suspendable` and `AlgorithmOID`, supports bit-oriented (partial final byte) messages per GB/T 32905-2016 s. 5.2
      using the same least-significant-bits convention as SHA-2/SHA-3, and is registered in `HashFactory`
      (`"SM3"`) with a `bc-rust sm3` CLI subcommand.
    * HMAC-SM3, in the hmac crate, registered in `MACFactory` (`"HMAC-SM3"`) with a `bc-rust hmac-sm3` CLI subcommand.
    * Test vectors are the GB/T 32905-2016 Appendix A examples plus the bc-java `SM3DigestTest` / `HMac` vectors, with
      additional digests cross-checked against OpenSSL and bc-java.

## Minor features / bug fixes
