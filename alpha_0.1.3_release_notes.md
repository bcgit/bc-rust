# 0.1.3 Features / Changelog

## Major features

## Minor features / bug fixes

* bug fixes to the way SHA3/SHAKE handled absorbing and squeezing a partial final byte.
* Design discussions about whether core::traits::XOF (in the abstract) should allow interleaving absorb -> squeeze ->
  absorb (ie "absorb-after-squeeze). Outcome: absorb-after-squeeze forbidden. Could be changed in the future.
* Refactored constant-time ct_equals_bytes () to use an optimization barrier based on unsafe read_volatile /
  write_volatile insead of core::mem::black_box. 
