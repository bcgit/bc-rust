This document lists general quality and style guidelines used across the library. Hint: ask an AI to help review your PR
against this style guide.

# Architecture

The Bounce Castle Rust project should be broken up into individual modular crates named `bouncycastle_*`.

The project aims to be completely self-contained with zero external dependencies in the runtime code. External
dependencies are ok in test or benchmarking code.

lib.rs for all crates needs to contain: `#![forbid(missing_docs)]`, `#![no_std]`.

All primitives must be accompanied by a CLI in `/cli`.

All algorithms with a state that is exercised across multiple API calls -- typically through a `do_update()`,
`do_final()` pattern -- should implement SerializableState so that the user can pause the execution of this algorithm to
a cache and resume later.

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
private function, in-line tests in the source file should be used. In-file unit tests go in a single #[cfg (test)] `mod
tests {}` block at the end of the file, not as bare #[test] functions beside the code. Any helper functions needed for
testing must also be contained within the `mod tests {}` block.

All traits in `bouncycastle-core` must have corresponding tests in `bouncycastle-core-test-framework` that exercise all
behaviours and error conditions that are common to all implementations of that trait.
`bouncycastle-core-test-framework` is test infrastructure only: it goes under `[dev-dependencies]` and is never a
runtime dependency, since it ships a deterministic `FixedSeedRNG` and a deliberately insecure `ToyBlockCipher`.

All crypto algorithms must have tests against the bc-test-data repo and against wycheproof.

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

All normal rust naming conventions from clippy apply, with one exception:

* Where a type, constant or variable corresponds to something a specification (FIPS, RFC, etc) names, keep the
  specification's spelling and capitalization, and `#[allow(non_camel_case_types)]`, `#[allow(non_snake_case)]` or
  `#[allow(non_upper_case_globals)]` the item locally. So the FIPS 204 signature algorithm is `MLDSA65`, not `MlDsa44`,
  and it's `AES_CBC_128`, not `AesCbc128`, and if a specification writes `A` for a matrix and `a` for a vector then
  `let A = ...; let a = ...;` is the right thing to do for code readability and correspondence with the spec. The point
  is that a reviewer with the specification open can match names by eye; that matters more here than rust convention.

In addition, some library-specific naming conventions:

* In constants, "LEN" is the length of a value in bytes (typically used for sizing arrays), whereas "SIZE" is a value in
  bits (typically used as a security parameter). For example SHA256 could have constants `HASH_SIZE = 256` and
  `HASH_LEN = 32`.
* Functions that are part of a stateful streaming api should be named `do_*()`.
* We use "pk" for public key and "sk" for secret key / private key. (some other libraries use "pub" and "priv", but "
  pub" is a keyword in rust, and "pubkey / privkey" is verbose :P )

## APIs

Where possible, primitives should expose "one-shot APIs" that simply take data and return a result as a static member
function that does not require object instantiation.

Other version of Bouncy Castle have a design pattern where stateful objects follow a pattern of new () -> init () ->
do_update () -> do_final (), and then optionally reset () that sets the object back to an unitialized state. Instead,
bc-rust does not have init () functions (moving this logic into new () or from () as appropriate), and consequently it
also does not have reset (). Also, we take advantage of the rust borrow checker's syntax so that all do_final ()
functions are actually final, in other words they must take ownership of self `do_final(self, ...)` so that no
subsequent calls can be made to this object (as opposed to the usual pattern of taking a ref to self as in
`do_update(&self, ...)`). These tricks go a long way to reducing fallibility since now in general there is no (or very
very little) object state to track and return errors about.

Any struct that holds sensitive data must impl the `core::Secret` trait and all associated super-traits.

A primitive whose safe use depends on the caller composing it correctly -- a raw block permutation, a raw keystream
-- lives under a `hazmat` module in its crate or sub-module, never at the crate root or next to the safe API;
`bouncycastle_core::hazmat` defines the term and the supported uses. A crate or sub-module with such items declares
`pub mod hazmat;`
in its `lib.rs` and neither the crate nor the sub-module ever `pub use`s anything out of it, since a re-export would
bypass the notice.

Any function that writes into a caller-provided output buffer must report how many bytes it wrote, as a `usize` in
its `Ok` value (on its own, or alongside anything else the function needs to return, such as a generated IV). This
holds even when the count is fully determined by the input -- a fixed-length `[u8; LEN]` buffer, say, always writes
exactly `LEN` -- so that callers never have to remember which output-buffer methods report their length and which
don't.

### fn prefixes and suffixes

Function prefixes and suffixes are used consistently across the library.

Take, for example a one-shot API `fn encrypt(plaintext: &[u8]) -> Result<Vec<u8>, SymmetricCipherError>`.

The following prefixes can be applied:

* `do_`: this implies that it is part of a stateful streaming API, will typically take `&mut self`, and is likely
  accompanied by a `do_encrypt_init()` and `do_encrypt_final()`.

The following suffixes can be applied

* `_init / _update / _final`: indicates phase of a stateful streaming API. Other verbs can be used here as appropriate
  to the primitive, such as `absorb / squeeze`, `encrypt / decrypt`, etc. `_init` is typically a static constructor
  (though exceptions may exist), and `_final` indicates that this function call renders the object unusable afterwards
  by consuming `self` via a move: `_final(self, ..)`.
* `_rng`: indicates that this version of the function sources its random numbers from a provided `&mut dyn RNG` instead
  of
  from the default library RNG. `_rng(.., &mut dyn RNG)`.
* `_out / _inplace`: indicates that the function works in the provided buffer. `_out` indicates that the function takes
  an output buffer, which may be oversized, and returns the number of bytes written to it:
  `_out(.., out: &mut [u8] -> Result<usize, SymmetricCipherError>`. `_inplace` indicates that the input and output are
  required to be the same size, and so the function uses the same buffer for input and output:
  `_inplace(.., data: &mut [u8]) -> Result<usize, SymmetricCipherError>`. It is assumed that these will be
  memory-efficient and work in the provided buffer instead of creating duplicate data on the stack.
* `_out_len`: a pair for an `_out` function that computes the minimum size of the output buffer required for the paired
  `_out` function to succeed. This may be an over-estimate in order to guarantee success, for example if the size of the
  required output buffer depends on the contents, and a subsequent call to the paired `_out` function does not actually
  fill all of the requested space.

Where multiple suffixes are present on a single function, they should go in this order:

```text
_{init, update, final, etc}_{rng}_{out, out_len, inplace}
```

Any function that takes an output buffer via an `_out` function must zeroize the provided output buffer via a
`out.fill(0)` prior to writing to it. This must be done first, before even any error checking so that no stale content
is left in the output buffer, even in the case of an error.

## Fallibility

As much as humanly possible, Result and unwrap () should be used for "Bad input data" type things and not "Programmer
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

## Macros

Fundamentally, macros are an optimization that allows future maintainers to easily add existing boilerplate code to a
new type. That said, macros are typically more complex, harder to code review, and harder to debug than the unrolled
boilerplate code that they are replacing.

Any PR that uses macros will need to justify that the macros are clearly reducing future maintainer complexity compared
to the equivalent unrolled code. Simply reducing the number of lines of code is not a sufficient justification.

Note that rust macros tend not to play well with a lot of dev tooling for compiler errors, debuggers, profilers, and
`cargo mutants`, which is a good reason to avoid macros in core algorithm or data processing code. Macros can be used
more freely within test code.

## Unit tests vs integration tests

Unit tests are test code (and supporting helper functions) embedded in src/**.rs files. They have access to
crate-private or module-private functions and constants.

Integration tests are test code (and supporting helper functions) in tests/**.rs files. They test the crate's code from
the outside -- ie through its public APIs -- since tests/ is a separate crate from src/.

In general, integration tests are preferred over unit tests. This is for a number of reasons:

* To reduce reviewer burden; reviewers will typically focus more effort on the src/ than the tests/, so we want to keep
  src/ as short as is reasonable.
* Usually it is easier to determine what is the correct behaviour at the public API level. For example, this is the
  level at which we typically have KATs and test vectors.
* Tools like cargo mutants are very helpful at detecting branches that are not exercisable via the public APIs, which
  often is an indicator that the branch isn't doing what you think it's doing, or is simply not useful and can be
  deleted. Unit tests that bypass the public APIs to pin these sorts of branches obscure the fact that this code is
  unreachable.

Unit tests are reasonable to include in the following cases:

* There is high-risk code (usually meaning that it is complex code whose behaviour is not obvious from inspection) where
  unit tests help to document the behaviour and protect against accidental breakage via a benign-looking change.
* AND where known answer tests are available.
* AND where this behaviour cannot be tested from integration tests.

When writing unit tests, they should be contained with an `mod tests` at the bottom of the file, and ALL helper
functions that support the unit tests must be contained within that module. The intention is to clearly signal to a code
reviewer what is test code vs functional code.

# Docs

## Proportion

Docs are a reading cost, so default to short. Each fact has one home: the crate docs are an overview plus links, and
the detail lives on the type or module it describes. Rationale is a sentence or two next to the code; history and
derivations go in the commit message. Give a few examples, not one per variant; keep memory tables to the figures,
without a per-row essay; keep CLI docs out of library crates; and never repeat a spec quote across files. Before adding
material, check whether the crate already states it.

## No internal implementation detail in public API docs

The doc comment on a `pub` item is read by a calling application, so it says what the caller can observe and must
do: the contract, the buffers and lengths involved, the errors and when they occur. How the implementor meets that
contract -- which bytes it holds back and why, which private helper runs, how another implementor does it, the design
rationale for a trait's shape -- belongs in a `//` comment next to the code, on the private item, or in the commit
message. A trait's docs in particular describe the trait, not any one implementor. When reviewing, read each public
doc comment as a user with no access to the source and strike anything that only makes sense with it.

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

The heading is always exactly `# 🚨 Security Considerations 🚨`, wherever it appears: crate docs, module docs, or the
docs of an individual type or function. A consistent heading makes these sections easy to spot when reading and to find
with a search.

## Release Notes

For release note entries, keep succinct, one line per significant change at most.
