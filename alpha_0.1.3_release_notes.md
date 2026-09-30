# 0.1.3 Features / Changelog

## Major features

## Minor features / bug fixes

* bug fixes to the way SHA3/SHAKE handled absorbing and squeezing a partial final byte.
* Design discussions about whether core::traits::XOF (in the abstract) should allow interleaving absorb -> squeeze ->
  absorb (ie "absorb-after-squeeze). Outcome: absorb-after-squeeze forbidden. Could be changed in the future.
* The constant-time helpers in bouncycastle-utils (`ct_eq_bytes`, `ct_eq_zero_bytes`, `conditional_copy_bytes` and
  the `Condition` mask type's `select`/`negate`/`swap`/`is_in_list`) now use an optimization barrier based on unsafe
  `read_volatile` / `write_volatile` instead of `core::hint::black_box`, which is documented as best-effort only.
  `Condition::select`, `swap` and `negate` are no longer `const fn` as a consequence.
