# 0.1.3 Features / Changelog

## Major features

## Minor features / bug fixes

SHA-2 (PR #88):

* `Hash::do_final_partial_bits()` / `do_final_partial_bits_out()` are now implemented for SHA-224/256/384/512
  (FIPS 180-4 s. 5.1), bringing SHA-2 to parity with SHA-3 for messages whose length is not a multiple of 8 bits.
  Previously these methods hit `unimplemented!()` -- a panic behind a `Result`-returning API. `num_partial_bits` may be
  0..=7 (0 behaves exactly as `do_final_out()`); larger values return `HashError::InvalidLength`. The trailing bits are
  taken from the least significant bits of `partial_byte`, the same convention as SHA-3 (see the `Hash` trait docs).
* Initial hash values are now compile-time constants (`const H0` on the params traits), removing a runtime
  match-on-`OUTPUT_LEN` and its `panic!` arm. `HashAlgParams` for the public types is forwarded from the `*Params`
  structs, so `OUTPUT_LEN` / `BLOCK_LEN` are defined once.
* Crate docs: fixed SHA-3/SHAKE copy-paste text, added a partial-bits usage example, "Memory Usage" and
  "Security Considerations" sections, and documented the `*_NAME` constants. The 2^64-byte message-length limit is
  now stated.

Testing:

* SHA-2 now runs the NIST CAVP SHAVS vector sets from bc-test-data (`crypto/sha2`: ShortMsg, LongMsg and Monte Carlo;
  bit- and byte-oriented, ~12k cases of which ~5.4k are bit-length messages) using the same `../bc-test-data` lookup
  convention as the mldsa/mlkem crates; the tests skip with a warning if the repo is not checked out. The SHAVS files
  pack trailing message bits MSB-first, so the harness shifts them into the LSB convention used by the API. Note that
  `cargo mutants` runs in a copied tree where `../bc-test-data` does not resolve, so these tests do not contribute to
  mutation coverage.
