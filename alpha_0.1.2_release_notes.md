# TODO
[remove this section before publication]

[ ] EdDSA
[ ] ML-DSA + EdDSA Composet
[ ] Ensure that all crates have `#![forbid(missing_docs)]`
[ ] Apply Secret trait consistently across the library --> study the `Zeroize` trait in RustCrypto
[ ] Change all "[u8;0]" to "[]" throughout the code and docs ... or better yet, change the APIs to take an Option<>
[ ] Enhance the default HashDRBG instantiation to take in NIST-compatible CPU jitter entropy
[ ] Get an opinion from Bob Beck or Dennis about the factories ... Are they worth it?
[ ] Do a pass over KeyMaterial, taking into account Dennis Jackson's input (maybe ping him for a phone call?)
[ ] Open github issues
[ ] Add to CONTRIBUTING.md:
  * benchmarks
  * unit tests that (mostly) satisfy cargo mutants
  * lib.rs needs: #![forbid(missing_docs)], #![no_std]

# 0.1.2 Features / Changelog

* ML-DSA
* Low-Memory ML-DSA -- runs in about 1/10th of the usual memory (~ 30 kb of stack) with only minor performance impact.
* Github issues resolved:
  * #2, or whatever