# TODO
[remove this section before publication]

[ ] EdDSA
[ ] ML-DSA + EdDSA Composite
[ ] Ensure that all crates have `#![forbid(missing_docs)]`
[ ] Apply Secret trait consistently across the library --> study the `Zeroize` trait in RustCrypto
[ ] Change all "[u8;0]" to "[]" throughout the code and docs ... or better yet, change the APIs to take an Option<>
[ ] For all higher-level algorithms, put a cargo #[cfg(feature='rng')] around the keygen that takes an rng so that the dependency on bouncycastle_rng is optional.
[ ] Enhance the default HashDRBG instantiation to take in NIST-compatible CPU jitter entropy
[ ] Get an opinion from Bob Beck or Dennis about the factories ... Are they worth it?
[ ] Do a pass over KeyMaterial, taking into account Dennis Jackson's input (maybe ping him for a phone call?)
[ ] Need a rust expert: I use a bunch of #![feature(_)]'s that are only available in nightly. ... what should I do about that?
[ ] Open github issues

# 0.1.2 Features / Changelog

* ML-DSA
* Low-Memory ML-DSA -- runs in about 1/10th of the usual memory (~ 30 kb of stack) with only minor performance impact.
* Github issues resolved:
  * #2, or whatever