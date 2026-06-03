This document lists general quality and style guidelines used across the library.
Hint: ask an AI to help review your PR against this style guide.

# Architecture

The Bounce Castle Rust project should be broken up into individual modular crates named `bouncycastle_*`.

The project aims to be completely self-contained with zero external dependencies in the runtime code. External
dependencies are ok in test or benchmarking code.

lib.rs for all crates needs to contain: `#![forbid(missing_docs)]`, `#![no_std]`.

All primitives must be accompanied by a CLI in `/cli`.

# Quality

## Tests

All crates must have tests in `src/tests`. Part of writing code that treats future maintainers as malicious is that all
functions that form part of the public interface should have their expected behaviour fully constrained with tests. In
other words, any behaviour change of the library that could cause a change in a calling application should also cause a
test in bc-rust to fail. An excellent tool for achieving this is `cargo mutants` which must be run on every crate and
each failed mutant must be investigated. We do not require `cargo mutants` to be clean because it's reasonably common,
especially in low-level crypto code, that there are multiple correct ways to write the same code; for example where
swapping an OR for an XOR results in functionally equivalent code.

Where the behaviour of a function is critical to test but cannot be tested from outside the crate because it is on a
private function, in-line tests in the source file should be used.

All traits in `bouncycastle-core` must have corresponding tests in `bouncycastle-core-test-framework` that exercise all
behaviours and error conditions that are comment to all implementations of that trait.

## Performance Benchmarks

Any crate that contains an algorithm were runtime matters must have cargo-compatible performance benchmarks in a
`<crate_root>/benches` folder.

The benches must cover all algorithms. If there are multiple variants of an algorithm with different performance
characteristics (such as with pre-expanded keys), then these must each be benchmarked separately. Separate benchmarks
should not be written for different APIs for accessing the same underlying implementation; such as one-shot and
streaming APIs that use the same core algorithm implementation.

## Stack Usage Benchmarks

Bouncy Castle Rust cares about the peak stack memory usage of its algorithms. Crates should be accompanied by a memory
usage test harness in `/mem_usage_benches`.

# Style

Part of writing code that treats future maintainers as malicious is good inline comments. Anything even remotely tricky,
or where naive modification would put it out of alignment with, for example, sample code in an RFC or FIPS spec should
be commented line-by-line with the corresponding lines from the spec. This also helps with code review and
certification. Any deviations from the spec should be noted and explained / justified. A good rule-of-thumb is to ask
yourself whether this function would take 6-months-from-now-you more than 10 minutes to understand thoroughly, and are
there comments you could add that would help future you get back up to speed faster about what this code is doing and
which parts were done for a very specific reason and should not be changed on a whim.

## Naming Conventions

All normal rust naming convensions from clippy apply. In addition, some library-specific naming conventions:

* In constants, "LEN" is the length of a value in bytes (typically used for sizing arrays), whereas "SIZE" is a value in
  bits (typically used as a security parameter). For example SHA256 could have constants `HASH_SIZE = 256` and
  `HASH_LEN = 32`.
* Functions that are part of a stateful streaming api should be named `do_*()`.
* We use "pk" for public key and "sk" for secret key / private key. (some other libraries use "pub" and "priv", but "
  pub" is a keyword in rust, and "pubkey / privkey" is verbose :P )

## APIs

Where possible, primitives should expose "one-shot APIs" that simply take data and return a result as a static member
function that does not require object instantiation.

Other version of Bouncy Castle have a design pattern where stateful objects follow a pattern of new() -> init() ->
do_update() -> do_final(), and then optionally reset() that sets the object back to an unitialized state. Instead,
bc-rust does not have init() functions (moving this logic into new() or from() as appropriate), and consequently it also
does not have reset(). Also, we take advantage of the rust borrow checker's syntax so that all do_final() functions are
actually final, in other words they must take ownership of self `do_final(self, ...)` so that no subsequent calls can be
made to this object (as opposed to the usual pattern of taking a ref to self as in `do_update(&self, ...)`). These
tricks go a long way to reducing fallibility since now in general there is no (or very very little) object state to
track and return errors about.

Any struct that holds sensitive data must impl the `core::Secret` trait and all associated super-traits.

## Fallibility

As much as humanly possible, Result and unwrap() should be used for "Bad input data" type things and not "Programmer
didn't read the docs" type things.

`.unwrap()` causes system crashes. The use of `.unwrap()` should always be preceeded by testing that we're in a state
where we know the call will succeed, or else there should be an inline comment explaining why the `.unwrap()` will
always succeed.

Also, we want to avoid forcing users of the library from needing excessive amounts of `.unwrap()`. To this end, any
function that returns a `Result` should be inspected closely to ensure that

Therefore, public APIs should aim to avoid the use of Result if it is not strictly needed. This generally means that
returning a `Result` is only used for instances where bad data was handed in to the function, or where something
unrecoverable happened, like the internal RNG failed to initialize. `Result` must never be thrown out of convenience to
the maintainer of bc-rust -- instead, get creative about how to check for and resolve error conditions within the
function so that valid input will always produce valid output. Also, the rust language has a lot of features for turning
runtime error conditions into compile-time error conditions. For example, if you find yourself taking in a reference to
bytes `in: &[u8]` and then checking its length `if in.len() != LEN { return Err() }`, stop and instead change the
function signature to `in: &[u8; LEN]` so that it is simply impossible for the caller to hand you data of the wrong
length (this also has a small performance benefit since you don't need to do that if-check). In other contexts it might
be possible to use rust typing system to track state change of an object instead of carrying a member variable that
tracks it.

Use `./dev_scripts/quality_stats.sh` to see the fallibility metrics for the crate you're working on and try to get those
numbers down.

# Docs

## Usage Examples

The crate docs needs a section "Usage Examples" with sample code for all the major usage patterns of the primitives in
the crate.

## Memory Usage

The crate docs needs a section "Memory Usage" with a table of the stack memory usage of each algorithm or primitive in
the crate.

## Security Considerations

Most crates should have a "Security Considerations" section that documents any footguns where the user of this crate
could undermine their own security; for example where providing a seed or a nonce that is not truly random would
completely undermine the algorithm.