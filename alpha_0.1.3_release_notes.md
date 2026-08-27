# 0.1.3 Features / Changelog

## Major features

## Minor features / bug fixes

Bit-oriented messages:

* `Hash::do_final_partial_bits()` / `do_final_partial_bits_out()` accept `num_partial_bits` in 0..=7 (0 meaning the
  message ends on a byte boundary); larger values return `HashError::InvalidLength` instead of panicking. The convention
  is the same for every hash family: the trailing bits are in the least significant bits of `partial_byte` (FIPS 202
  Appendix B.1) -- see the `Hash` trait docs, including the note on the MSB-first packing used by the NIST CAVP SHA-2
  vector files.

SHA-3 / SHAKE bug fixes:

* Fixed `XOF::squeeze_partial_byte_final()`: when it was the first squeeze it bypassed the SHAKE `1111` domain suffix
  and returned raw Keccak output, and it returned the *high* rather than the low `num_bits` bits of the output byte.
  The existing test used `0xFF`, which masked the second error.
* Fixed `XOF::absorb_last_partial_byte()` for `num_partial_bits == 4`: the 4 message bits plus the `1111` suffix
  exactly filled a byte and the sponge did not switch to squeezing, so the first squeeze appended the suffix a second
  time. Every SHAKE message with a bit length of 4 mod 8 was affected. Found while building the CAVP SHA3VS harness.
* `absorb_last_partial_byte()` and `do_final_partial_bits*()` now validate `num_partial_bits` before use; previously
  SHA-3 accepted 8..15 and absorbed garbage, panicked for >= 16, and SHAKE rejected 0 with an error message claiming
  `[0,7]`.
* Interleaving absorb -> squeeze -> absorb remains rejected with `HashError::InvalidState`; the `XOF` trait docs now
  explain why (it is the duplex construction, not SHAKE).

Testing:

* SHA-3 / SHAKE now run the NIST CAVP SHA3VS vector sets from bc-test-data (`crypto/sha3`: ShortMsg, LongMsg, Monte
  Carlo and SHAKE VariableOut; bit- and byte-oriented, ~13k cases) using the same `../bc-test-data` lookup convention as
  the mldsa/mlkem crates; the tests skip with a warning if the repo is not checked out. The vendored FIPS 202 example
  vectors in `crypto/sha3/tests/data` were removed in favour of the bc-test-data copies. Note that `cargo mutants` runs
  in a copied tree where `../bc-test-data` does not resolve, so these tests do not contribute to mutation coverage.
