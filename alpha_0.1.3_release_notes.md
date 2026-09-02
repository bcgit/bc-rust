# 0.1.3 Features / Changelog

## Major features

## Minor features / bug fixes

SHA-3 documentation:

* Crate docs gained "Memory Usage" and "Security Considerations" sections.
* New `mem_usage_benches/bench_sha3_mem_usage.rs` reports `size_of` for the SHA-3 / SHAKE objects (440 bytes) and the
  suspended state (415 bytes) -- the figures in the crate's Memory Usage table -- and provides valgrind massif entry
  points for the hash, XOF and suspend/resume paths.
