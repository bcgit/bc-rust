# TODO

[remove this section before publication]

* ML-DSA & ML-KEM
    * Check the crate release checklist and run claude against the style guide (maybe Francis could cross-check me)
    * Run Crucible testing
    * Add factories for ML-DSA and ML-KEM (if we are keeping factories, see below)
* Split the Signature trait into a Signer and a Verifier so that, for example, we can implement the verifier for MTC in
  a different struct from the signer; or so that you can get FIPS compliance on old algorithms that are currently only
  FIPS-allowed for verification of existing signatures but not for creation of new ones.
* Check out Megan's email May 13 about KeyMaterial: "I was wondering if there might be scope for a closure based
  approach that could
  guarantee encapsulation of the state change from safe to hazardous back to safe again."
* Anywhere that you have an `_out(.. out: &mut [u8])`, start by zeroizing it with .fill(0); .. a good task for Claude?
  And should be documented in the style guide?
* Go back to previous algs and apply memory optimization tricks like internal functions. And add a docs section "Memory
  Usage" that measures with valgrind.
* Ensure that all crates have `#![forbid(missing_docs)]`
* Apply Secret trait consistently across the library --> study the `Zeroize` trait in RustCrypto
* Change all "[u8;0]" to "[]" throughout the code and docs ... or better yet, change the APIs to take an Option<>
* Change all `-> Vec<u8>` to `-> [u8; CONST_LEN]`, and the `output: &mut [u8]` to `output: &mut [u8; CONST_LEN]` where
  appropriate.
* Probably it makes sense to leave Hex and Base64 as requiring std; ... or maybe add a no_std version that uses
  fixed-sized blocks?
* Create a cargo feature #[cfg(feature='rng')] and put it around things like keygen that takes an rng so that the build
  dependency on bouncycastle_rng is optional.
* Enhance the default HashDRBG instantiation to take in NIST-compatible CPU jitter entropy? Or not? Maybe this is the
  problem of the caller to properly seed the RNG?
* Factories ... Are they worth it? Michael Richardson says Very Yes. If we are keeping them, then we need a serious
  re-engineering of them because I really dislike that currently they make it hard for the underlying primitive to have
  static one-shot APIs.
* Add back the Memoable trait from nursery (maybe under a different name) that lets you serialize out the
  intermediate state, especially important for SHA2, SHA3, and HMAC because TLS needs to be able to fork a state,
  finalize() a copy and then keep feeding the other copy.
* Do some science about perf impacts of acting on a local hard-copy vs acting in-place on some specific bit of
  memory
* Change the tone of the documentation (both the crate docs and the inline comments) to be less individual ("I"
  statements) and be more factual ("it is", or "the project", or "the bc-rust library" as appropriate).
* Relax the requirement on XOF that once you start squeezing, you can't absorb anymore. This will likely need to be an
  exposed "bell & whistle" because it is an obvious way to do something like the TLS handshake transcript where you need
  to periodically spit out hashes and then continue absorbing more input. We'll need to study the SHA3 / SHAKE FIPS
  documents because it might be that this is forbidden as part of the definition of SHAKE, but is allowed if you use the
  KECCAK primitive raw. We need to make a decision on how to handle this, and provide some sample code in crate docs.
* Need a rust expert: I use a bunch of #![feature(_)]'s that are only available in nightly. ... what should I do
  about that?
* Research task: no_std means that everything is on the stack, which can cause you to blow your stack limit. Research
  how an application that itself is not no_std can put our large structs (like key objects) on the heap. Is this what
  Box is for?
* Deal with as many of the inline TODOs as possible
* Close all open github issues and document them in this file.

# 0.1.2 Features / Changelog

* ML-DSA
* Low-Memory ML-DSA -- runs in about 1/10th of the usual memory (~ 30 kb of stack) with only minor performance impact.
* Github issues resolved:
    * #2, or whatever