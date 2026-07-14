# TODO

[remove this section before publication]

* Deal with as many of the inline TODOs as possible
* Close all open github issues and document them in this file.
* Clean up `cargo doc --all` warnings
* On release/0.1.2alpha, get Claude to make a cosmetic change to the docs for all crates to use [`Secret`] instead
  of [Secret] because this renders better.
* After everything is merged, circle back to crucible, and make sure that the harness still works
* Delete this file and stuff it into the Description of a github Release.

# 0.1.2 Features / Changelog

## Major features

* New algorithms added to crypto/ :
    * mldsa (FIPS 204)
    * mldsa-lowmemory -- runs in about 1/10th of the usual memory (~ 30 kb of stack) with comparable performance impact.
    * mlkem (FIPS 203)
    * mlkem-lowmemory -- runs in about 1/4th of the usual memory (~ 12 kb of stack) with comparable performance impact.
* New traits [Suspendable] and [SuspendableKeyed] allow algorithms with a streaming API (`do_update()` ->
  `do_final()`) to be suspended to a small byte array and then resumed later, potentially from a different host and
  potentially across versions of the library. The intended use case is if you are processing a large input that depends
  on one or more network round-trips and you wish to suspend to a cache and potentially transfer to a new host while
  waiting for network IO.
* dyn RNG: anywhere that consumes randomness (such as keygen and non-deterministic sign / encaps functions) can now be
  handed an instance of an object that impl's `bouncycastle-core::traits::RNG`.
* Rework of the Secret system for protecting secret data against leakage via returning to the memory pool unzeroized,
  or being logged in debug messages, stack traces, and crash dumps. Now properly uses `core::mem::write_volatile` to
  prevent
  the compiler from eliding writes on drop, and introduced a new type system `Secret<T>` that is used across the library
  to give more fine-grained control over which objects (and which fields within objects) get this extra protection.
  Bonus: this is a public type that you can use to protect your application data as well!

## Minor features / bug fixes

Trait system:

* Split the Signature trait into a Signer and a Verifier trait. This is for two reasons: 1) some of the future signature
  algorithms (like hash-based signatures) the verifier code is substantially lighter than the signer code, or we may not
  even want to implement a signer in software, and 2) NIST likes to soft-deprecate algorithms by disallowing generation
  of new signatures, but still allowing verification of existing signatures.
* Added traits for symmetric ciphers in the block cipher, stream cipher, and AEAD families. We don't have any of these
  algorithms implemented yet, but they're coming!

The KeyMaterial object:

* Reworked the way KeyMaterial hazardous operations work; instead of a stateful .allow_hazardous_operations() /
  .drop_hazardous_operations(), it now uses a closure-based do_hazardous_operations(). Github issue #39.
* Renamed KeyMaterial::KeyType's and deleted KeyMaterial::concatenate in order to give a better intuition and
  FIPS-alignment.
* Tightened up the entropy-tracking behaviour of the KeyMaterial object, thanks to Q. T. Felix (github:
  @Quant-TheodoreFelix, github issue #6)

Docs:

* All crypto algorithm crates now have Memory Usage docs that list the stack memory usage of the implementation.
* All crypto algorithm crates now have `#![forbid(missing_docs)]` to ensure that they have a fully-documented public
  API.

* Other miscellaneous Github issues resolved:
    * #10: https://github.com/bcgit/bc-rust/issues/10, thanks to Nicola Tuveri (github: @romen)
    * #18: All public `*_out(.., out: &mut [u8])` functions now begin by zeroizing the entire provided output buffer
      with `.fill(0)`,
      preventing exposure of stale data in oversized output buffers or on early error returns. Thanks to Q. T. Felix (
      github: @Quant-TheodoreFelix)
    * #27: "SHAKE absorb-after-squeeze": clarified and hardened the behaviour of SHAKE with respect to absorbing more
      input after having been squeezed.
    * #28: Removed the dependence on nightly / experimental compiler features; the library now builds on stable.
