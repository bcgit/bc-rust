# TODO

[remove this section before publication]

* ML-DSA & ML-KEM
    * Check the crate release checklist and run claude against the style guide (maybe Francis could cross-check me)
    * Run Crucible testing
    * Add factories for ML-DSA and ML-KEM (if we are keeping factories, see below)
* Ensure that all crates have `#![forbid(missing_docs)]`
* Apply Secret trait consistently across the library --> study the `Zeroize` trait in RustCrypto
* Deal with as many of the inline TODOs as possible
* Close all open github issues and document them in this file.
* After everything is merged, circle back to crucible, and make sure that the harness still works (and maybe remove the
  nightly build toolchain)

# 0.1.2 Features / Changelog

* New algorithms added to crypto/ :
    * mldsa (FIPS 204)
    * mldsa-lowmemory -- runs in about 1/10th of the usual memory (~ 30 kb of stack) with comparable performance impact.
    * mlkem (FIPS 203)
    * mlkem-lowmemory -- runs in about 1/4th of the usual memory (~ 12 kb of stack) with comparable performance impact.
* All public `*_out(.., out: &mut [u8])` functions now begin by zeroizing the entire output buffer with `.fill(0)`,
  preventing exposure of stale data in oversized output buffers or on early error returns.
* Reworked the way KeyMaterial hazardous operations work; instead of a stateful .allow_hazardous_operations() /
  .drop_hazardous_operations(), it now uses a closure-based do_hazardous_operations(). Github issue #39.me
* Renamed KeyMaterial::KeyType's and deleted KeyMaterial::concatenate in order to give a better intuition and
  FIPS-alignment.
* Github issues resolved:
    * #6: https://github.com/bcgit/bc-rust/issues/6, thanks to Q. T. Felix (github: @Quant-TheodoreFelix)
    * #10: https://github.com/bcgit/bc-rust/issues/10, thanks to Nicola Tuveri (github: @romen)