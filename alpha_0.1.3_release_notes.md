# 0.1.3 Features / Changelog

## Major features

* New crate `bouncycastle-aes-lowmemory` (`bouncycastle::aes_lowmemory`): AES-128/192/256 as a raw keyed block
  permutation (NIST FIPS 197).

## Minor features / bug fixes

* bug fixes to the way SHA3/SHAKE handled absorbing and squeezing a partial final byte.
* Design discussions about whether core::traits::XOF (in the abstract) should allow interleaving absorb -> squeeze ->
  absorb (ie "absorb-after-squeeze). Outcome: absorb-after-squeeze forbidden. Could be changed in the future.