This document lists general quality and style guidelines used across the library.
Hint: ask an AI to help review your PR against this style guide.

# Architecture

The Bounce Castle Rust project should be broken up into individual modular crates named `bouncycastle_*`.

The project aims to be completely self-contained with zero external dependencies in the runtime code. External
dependencies are ok in test or benchmarking code.

lib.rs for all crates needs to contain: `#![forbid(missing_docs)]`, `#![no_std]`. Basic structs and macros should be
used from `core` not `std`. If it's not in `core`, then get creative about a different way to do what you're trying to
do!

All primitives must be accompanied by a CLI in `/cli`.

# Quality

## Tests

All crates must have tests in `src/tests`. Part of writing code that treats future maintainers as malicious is that all
functions that form part of the public interface should have their expected behaviour fully constrained with tests. In
other words, any behaviour change of the library that could cause a change in a calling application should also cause a
test in bc-rust to fail; that doesn't mean we _can't_ change these things, but such changes should be reserved for major
version bumps, and tests help to prevent accidental breaking changes. An excellent tool for achieving this is
`cargo mutants` which must be run on every crate and each failed mutant must be investigated. We do not require
`cargo mutants` to be clean because it's reasonably common, especially in low-level crypto code, that there are multiple
correct ways to write the same code; for example where swapping an OR for an XOR results in functionally equivalent
code. Since cargo mutants has no false positive tracking mechanism, code should be annotated where appropriate with
inline `// mutants note:` comments explaining why a mutation at thes line is untestable.

Where the behaviour of a function is critical to test but cannot be tested from outside the crate because it is on a
private function, in-line tests in the source file should be used.

All traits in `bouncycastle-core` must have corresponding tests in `bouncycastle-core-test-framework` that exercise all
behaviours and error conditions that are comment to all implementations of that trait.

## Performance Benchmarks

Any crate that contains an algorithm were runtime matters must have cargo-compatible performance benchmarks in a
`benches` folder.

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

## APIs

Where possible, primitives should expose "one-shot APIs" that simply take data and return a result as a static member
function that does not require object instantiation.

Other version of Bouncy Castle (ie bc-java) have a design pattern where stateful objects follow a pattern of new() ->
init() ->
do_update() -> do_final(), and then optionally reset() that sets the object back to an unitialized state. This works
well in the java environment, but in order to be more rust-native,
bc-rust does not have init() functions (moving this logic into new() or from() as appropriate), and consequently it also
does not have reset(). We take advantage of the rust borrow checker's "move" syntax so that all do_final() functions are
actually final, in other words they must take ownership of self `do_final(self, ...)` so that no subsequent calls can be
made to this object (as opposed to the usual pattern of taking a ref to self as in `do_update(&self, ...)`). These
tricks go a long way to reducing fallibility since now in general there is no (or very very little) object state to
track and return errors about.

All public functions that return data as a byte array must be implemented in two versions:

* `do_something() -> [u8; LEN]` where LEN is a compile-time parameter of the trait or struct, and
* `do_someching_out(output: &mut [u8]) -> Result<usize, Error>` or `do_someching_out(output: &mut [u8; LEN]) -> usize`
  which writes the data to the provided output buffer, and where the output usize tells how many bytes were actually
  written to the output buffer. The second form where the output array has a fixed parametrized length LEN is preferred
  because then you don't have to check the length and you don't have to throw an Err about it. When taking an array of
  unspecified size, you will almost always need the ability to return a Result::Err if the provided array is too small (
  unless you've specified the behaviour of the API as auto-truncating or something). The first line of any
  `*_out(output: &mut [u8])` function should be `output.fill(0);` to make sure that you're starting with a clean buffer
  and will not accidentally return stale data, which can lead to all sorts of hard-to-debug conditions.

Any struct that holds sensitive data must impl the `core::Secret` trait and all associated super-traits.

## Error-handling and Fallibility

We take panic-safety and reducing error conditions very seriously. Generally speaking, we follow the following mantras:

* Errors (and the corresponding Result / unwrap) should only be used for "bad data" type conditions, and not "programmer
  didn't read the docs" type conditions. The later can almost always be turned into compile-time errors through a bit of
  cleverness in how you define the struct, trait, and functions.
* Strive for infallibility, which means that functions take input and return output, and will never panic, crash, abort,
  or throw errors (except as noted above for bad input data that simply cannot be acted upon).

All public APIs that are capable of returning errors should return an error type enum registered in
`bouncycastle-core/errors.rs`. The use of `panic!` and related macros such as `assert!` in non-test code is forbidden (
except for things like satisfying the compiler by flagging unreachable code branches with `unreachable!`.)

`.unwrap()` causes application crashes. The use of `.unwrap()` should always be preceeded by testing that we're in a
state where we know the call will succeed, or else there should be an inline comment explaining why the `.unwrap()` will
always succeed. Also, we want to avoid forcing users of the library from needing excessive amounts of `.unwrap()` when
calling our APIs. To this end, any function that returns a `Result` should be inspected closely to ensure that this is a
necessary error condition and not something that can be handled via a clever type system. `Result` must never be thrown
out of convenience to the maintainer of bc-rust -- instead, get creative about how to check for and resolve error
conditions within the
function so that valid input will always produce valid output. For example, if you find yourself taking in a reference
to bytes `in: &[u8]` and then checking its length `if in.len() != LEN { return Err() }`, stop and instead change the
function signature to `in: &[u8; LEN]` so that it is simply impossible for the caller to hand you data of the wrong
length (this also has a small performance benefit since you don't need to do that if-check). In other contexts it might
be possible to use rust typing system to track state change of an object instead of carrying a member variable that
tracks it.

Use `./dev_scripts/quality_stats.sh` to see the fallibility metrics for the crate you're working on and try to get those
numbers down.

# Docs

Placing `#![forbid(missing_docs)]` at the top of each `lib.rs` will force every public mod, struct, enum, trait, and
function to have a docstring. The documentation is written with a tutorial feel and should read a bit like a textbook,
given a gentle introduction to the cryptographic primitive or protocol that it is implementing.

## Usage Examples

The crate docs needs a section "Usage Examples" with sample code for all the major usage patterns of the primitives in
the crate.

It should start with usage examples for the simplified "one-shot APIs" that even a user who is brand new to cryptography
can use without getting themselves into trouble. Advanced "bells & whistles" features that expose more dangerous
functionality (like setting nonces for deterministinc modes of operation) should be burried in a sub-crate and tagged
with appropriate security consideration notes.

## Memory Usage

The crate docs needs a section "Memory Usage" with a table of the stack memory usage of each algorithm or primitive in
the crate.

## Security Considerations

Most crates should have a "Security Considerations" section that documents any footguns where the user of this crate
could undermine their own security; for example where providing a seed or a nonce that is not truly random would
completely undermine the algorithm.