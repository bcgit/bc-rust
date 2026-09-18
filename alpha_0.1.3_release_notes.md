# 0.1.3 Features / Changelog

## Major features

## Minor features / bug fixes

* bug fixes to the way SHA3/SHAKE handled absorbing and squeezing a partial final byte.
* Design discussions about whether core::traits::XOF (in the abstract) should allow interleaving absorb -> squeeze ->
  absorb (ie "absorb-after-squeeze). Outcome: absorb-after-squeeze forbidden. Could be changed in the future.
* Re-arranged the HMAC and HKDF crates so that they are utility crates, and the pub types HMAC_SHA256, HMAC_SHA3_256,
  HKDF_SHA256, and so on now live in the `bouncycastle_sha2::hmac`, `bouncycastle_sha3::hmac`, and
  `bouncycastle_sha2::hkdf` namespaces. At the same time, adjustments were made to the MAX_SECURITY_STRENGTH of the HMAC
  and HKDF algorithms because SP 800-107r1 allows them to be higher than what we had previously.