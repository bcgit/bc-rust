# 0.1.3 Features / Changelog

## Major features

## Minor features / bug fixes

Housekeeping:

* `no_std` progress: `std::marker::PhantomData` and `std::fmt` replaced with their `core::` equivalents in the SHA-3
  and Hash_DRBG crates, and the `Copy` types `KeyType` / `SecurityStrength` are now copied rather than `.clone()`d.
  Removed a redundant second zeroization of the caller's output buffer in `Hash::hash_out()` / `XOF::hash_xof_out()`.
