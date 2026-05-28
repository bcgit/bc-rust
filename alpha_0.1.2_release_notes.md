# TODO

[remove this section before publication]

[ ] EdDSA
[ ] ML-DSA & ML-KEM
* Look a close look at Kris' ICMC slides on low_memory
* lowmemory: Play with packing Polynomials into 12 / 23 bits.
* Polynomial (and maybe Matrix and Vec) might want custom indexing
https://doc.rust-lang.org/core/ops/trait.Index.html
https://doc.rust-lang.org/core/ops/trait.IndexMut.html
* Check the crate release checklist
* Run Crucible testing
* Run Wycheproof tests
[ ] Check out Megan's email May 13: "I was wondering if there might be scope for a closure based approach that could
guarantee encapsulation of the state change from safe to hazardous back to safe again."
[ ] Anywhere that you have an `_out(.. out: &mut [u8])`, start by zeroizing it with .fill(0); .. a good task for Claude?
[ ] Go back to previous algs and apply memory optimization tricks like unnamed scopes. And add a docs section "Memory
Usage" that measures with valgrind.
[ ] Ensure that all crates have `#![forbid(missing_docs)]`
[ ] Apply Secret trait consistently across the library --> study the `Zeroize` trait in RustCrypto
[ ] Change all "[u8;0]" to "[]" throughout the code and docs ... or better yet, change the APIs to take an Option<>
[ ] Change all `-> Vec<u8>` to `-> [u8; CONST_LEN]`, and the `output: &mut [u8]` to `output: &mut [u8; CONST_LEN]` where
appropriate.
* After doing that, do I even need the _out() versions? Since everything is no_std now.
* Probably it makes sense to leave Hex and Base64 as requiring std; ... or maybe add a no_std version that uses
fixed-sized blocks?
[ ] For all higher-level algorithms, put a cargo #[cfg(feature='rng')] around the keygen that takes an rng so that the
dependency on bouncycastle_rng is optional.
[ ] Enhance the default HashDRBG instantiation to take in NIST-compatible CPU jitter entropy
[ ] Get an opinion from Bob Beck or Dennis about the factories ... Are they worth it? Michael Richardson says Very Yes.

* Add factories for ML-DSA and ML-KEM
  [ ] Add back the Memoable trait from nursery (maybe under a different name) that lets you serialize out the
  intermediate state, especially important for SHA2, SHA3, and HMAC because TLS needs to be able to fork a state,
  finalize() a copy and then keep feeding the other copy.
* Add unit tests.
  [ ] Make crypto one crate
  [ ] Do some science about perf impacts of acting on a local hard-copy vs acting in-place on some specific bit of
  memory
* Bob suggests: feed a function in question to GodBolt.
  [ ] Change the tone of the documentation (both the crate docs and the inline comments) to be less individual ("I"
  statements) and be more factual ("it is", or "the project", or "the bc-rust library" as appropriate).
  [ ] Relax the requirement on XOF that once you start squeezing, you can't absorb anymore. ... this might need to be
  specifically forbidden in FIPS mode.
  [ ] Do a pass over KeyMaterial, taking into account Dennis Jackson's input (maybe ping him for a phone call?)
  [ ] Need a rust expert: I use a bunch of #![feature(_)]'s that are only available in nightly. ... what should I do
  about that?
  [ ] Deal with as many of the inline TODOs as possible
  [ ] Open github issues

# 0.1.2 Features / Changelog

* ML-DSA
* Low-Memory ML-DSA -- runs in about 1/10th of the usual memory (~ 30 kb of stack) with only minor performance impact.
* Github issues resolved:
    * #2, or whatever