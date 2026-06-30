# TODO

[remove this section before publication]

* ML-DSA & ML-KEM
    * Check the crate release checklist and run claude against the style guide (maybe Francis could cross-check me)
    * Run Crucible testing
    * Add factories for ML-DSA and ML-KEM (if we are keeping factories, see below)
* Check out Megan's email May 13 about KeyMaterial: "I was wondering if there might be scope for a closure based
  approach that could guarantee encapsulation of the state change from safe to hazardous back to safe again."
* Go back to previous algs and apply memory optimization tricks like internal functions. And add a docs section "Memory
  Usage" that measures with valgrind.
* Ensure that all crates have `#![forbid(missing_docs)]`
* Apply Secret trait consistently across the library --> study the `Zeroize` trait in RustCrypto
* Change all "[u8;0]" to "[]" throughout the code and docs ... or better yet, change the APIs to take an Option<>
* Change all `-> Vec<u8>` to `-> [u8; CONST_LEN]`, and the `output: &mut [u8]` to `output: &mut [u8; CONST_LEN]` where
  appropriate.
* Probably it makes sense to leave Hex and Base64 as requiring std; ... or maybe add a no_std version that uses
  fixed-sized blocks?
* Make this build on the stable compiler. IE Remove the rust-toolchain.toml file that builds with nightly. Will require
  some refactoring.
* Create a cargo feature #[cfg(feature='rng')] and put it around things like keygen that takes an rng so that the build
  dependency on bouncycastle_rng is optional.
* Factories ... Are they worth it? Michael Richardson says Very Yes. If we are keeping them, then we need a serious
  re-engineering of them because I really dislike that currently they make it hard for the underlying primitive to have
  static one-shot APIs.
* Deal with as many of the inline TODOs as possible
* Close all open github issues and document them in this file.
* After everything is merged, circle back to crucible, and make sure that the harness still works (and maybe remove the
  nightly build toolchain)
* Search for all the uses of .unwrap() in non-test code and replace each with either a comment or an expect with a
  meaningful error string.

# 0.1.2 Features / Changelog

* New algorithms added to crypto/ :
    * mldsa (FIPS 204)
    * mldsa-lowmemory -- runs in about 1/10th of the usual memory (~ 30 kb of stack) with comparable performance impact.
    * mlkem (FIPS 203)
    * mlkem-lowmemory -- runs in about 1/4th of the usual memory (~ 12 kb of stack) with comparable performance impact.
* All public `*_out(.., out: &mut [u8])` functions now begin by zeroizing the entire output buffer with `.fill(0)`,
  preventing exposure of stale data in oversized output buffers or on early error returns.
* Reworked the way KeyMaterial hazardous operations work; instead of a stateful .allow_hazardous_operations() /
  .drop_hazardous_operations(), it now uses a closure-based do_hazardous_operations(). Github issue #39.
* Renamed KeyMaterial::KeyType's and deleted KeyMaterial::concatenate in order to give a better intuition and
  FIPS-alignment.
* Github issues resolved:
    * #6: https://github.com/bcgit/bc-rust/issues/6, thanks to Q. T. Felix (github: @Quant-TheodoreFelix)
    * #10: https://github.com/bcgit/bc-rust/issues/10, thanks to Nicola Tuveri (github: @romen)