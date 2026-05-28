# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Toolchain

- Uses Rust **nightly** (pinned in `rust-toolchain.toml`) — `core/src/lib.rs` uses `#![feature(adt_const_params)]`.
- 2024 edition (set workspace-wide in the root `Cargo.toml`).

## Common commands

Build / test / bench / docs run against the cargo workspace from the repo root:

```
cargo build                     # whole workspace incl. `bc-rust` CLI binary
cargo build -p bouncycastle-sha3   # one sub-crate
cargo test                      # all tests
cargo test -p bouncycastle-mlkem   # tests for one crate
cargo test -p bouncycastle-mlkem ml_kem_tests   # one integration test file
cargo bench --all               # all criterion benches
cargo bench -p bouncycastle-mlkem
cargo doc                       # rustdoc (published to gh-pages by CI on main)
cargo run -p cli -- --help      # run the `bc-rust` CLI
```

Quality / mutation testing:

```
./dev_scripts/quality_stats.sh ./crypto    # lines-of-code, docstring & fallibility metrics; CI publishes this
cargo mutants                              # config in .cargo/mutants.toml (output: custom_mutants_output/)
```

Stack-memory benches are separate binaries under `mem_usage_benches/`:

```
cargo run --release -p mem_usage_benches --bin bench_mlkem_mem_usage
cargo run --release -p mem_usage_benches --bin bench_mldsa_mem_usage
```

## Workspace architecture

The workspace has three top-level kinds of member:

1. `crypto/*` — one sub-crate per primitive (`sha2`, `sha3`, `hmac`, `hkdf`, `mlkem`, `mlkem_lowmemory`, `mldsa`, `mldsa_lowmemory`, `rng`, `hex`, `base64`, `utils`) plus the spine crates `core`, `core-test-framework`, and `factory`. Each crate is published as `bouncycastle-<name>` and depended on internally via the `workspace.dependencies` table in the root `Cargo.toml`.
2. `src/` — the umbrella `bouncycastle` crate, which is just `pub use` re-exports of every sub-crate (e.g. `bouncycastle::sha3`, `bouncycastle::mlkem`). It exists so downstream users can pull the whole library with one dependency; it has no code of its own.
3. `cli/` — the `bc-rust` binary built on top of `bouncycastle`, exposing every primitive as a streaming stdin→stdout subcommand using `clap`.
4. `mem_usage_benches/` — stand-alone binary crates that measure peak stack usage of algorithms (cannot be done via criterion).

### The `core` / `core-test-framework` / `factory` spine

- `crypto/core` defines the abstract traits (`Hash`, `KDF`, `MAC`, `KEM`, `Signature`, `RNG`, `Algorithm`, `HashAlgParams`, …), error enums (`HashError`, `KDFError`, `KEMError`, `MACError`, `RNGError`, `SignatureError`), and the `KeyMaterial` / `KeyType` wrapper that all sensitive byte buffers are required to use (see `Secret` super-trait requirement in QUALITY_AND_STYLE.md).
- `crypto/core-test-framework` contains the shared per-trait test suite (`hash.rs`, `kdf.rs`, `kem.rs`, `mac.rs`, `signature.rs`). New implementations of a core trait must be exercised through this framework — it's how trait conformance and error-condition coverage stay consistent across implementations.
- `crypto/factory` provides enum-based string-name factories (`HashFactory`, `KDFFactory`, `MACFactory`, `RNGFactory`, `XOFFactory`). Each factory enum impls the underlying trait so it can be used transparently as that primitive, and each impls `AlgorithmFactory` (`new(name)`, `default_128_bit()`, `default_256_bit()`). When adding a new primitive that fits an existing trait, register it in the corresponding factory.

Trait/factory/CLI is the standard layering: a new algorithm typically requires (a) the primitive crate, (b) implementing the relevant `core` trait, (c) wiring it into the matching factory, (d) a CLI subcommand in `cli/src/*_cmd.rs` registered in `cli/src/main.rs`.

### Sub-crate layout convention

A typical primitive crate looks like:

```
crypto/<name>/
  Cargo.toml          # depends on bouncycastle-core; dev-deps on core-test-framework, hex, rng, criterion
  src/lib.rs          # must contain #![forbid(unsafe_code)], #![forbid(missing_docs)], aim for #![no_std]
  src/*.rs            # implementation
  tests/*.rs          # integration tests, usually driven via core-test-framework
  benches/*.rs        # criterion benches (declared as [[bench]] with harness=false)
```

`#![no_std]` is the long-term goal but the `core` crate still has a `Vec`-removal TODO blocking it (see the comment at the top of `crypto/core/src/lib.rs`). Don't add new `Vec` usage where a const-sized array would do.

## Project-specific conventions (from QUALITY_AND_STYLE.md and INTRODUCTION.md)

These are non-obvious house rules — follow them when writing or modifying code:

- **No `unsafe`, no runtime third-party deps.** `#![forbid(unsafe_code)]` is required at every crate's `lib.rs`. Avoid adding any non-internal runtime dependency; dev/bench dependencies (`criterion`, `clap`) are fine.
- **Push errors to compile time.** Prefer `&[u8; N]` over `&[u8]` + length-check, prefer the typestate pattern over runtime "initialized" booleans. `Result` should only carry truly-uncontrollable failures (bad user input, RNG init failure). If you're returning `Result` for something the caller can't reasonably hit with valid usage, redesign the signature instead. Run `./dev_scripts/quality_stats.sh` before and after to confirm you haven't increased unwrap/`Err()` counts.
- **No `init()` / `reset()`; `do_final` takes `self` by value.** Constructors set up state; consumption methods consume. This is the deliberate departure from other Bouncy Castle ports. Stateful builder-style patterns are discouraged.
- **One-shot static APIs are the default.** Every primitive should expose a take-data-return-result static method in addition to any streaming API.
- **Sensitive types impl `core::Secret` (and its supertraits).** Anything that holds key material needs this — don't reach for raw byte arrays for secrets.
- **`unwrap()` requires justification.** Either a preceding check that proves success, or an inline comment explaining why it's infallible.
- **Spec correspondence in comments.** Code that mirrors a FIPS/NIST/RFC spec should be commented line-by-line against the spec. Any deliberate deviation must be called out and justified. The "would 6-months-from-now me need >10 minutes to re-understand this?" check is the bar.
- **Every primitive crate must ship: tests (`src/tests` or `tests/`), criterion benches in `benches/`, and a CLI subcommand.** Stack-memory characteristics matter — algorithms with non-trivial stack usage get a `mem_usage_benches/` harness.
- **CLI commands stream.** The `cli/` binary's design is stdin→stdout with ~1 KB buffers so commands compose in shell pipelines; preserve that when adding subcommands.
- **Crate docs must include sections:** "Usage Examples", "Memory Usage" (stack-usage table), and usually "Security Considerations".

## Notes on testing

- `cargo mutants` is expected to be run on each crate; surviving mutants must be investigated but not all need to die (e.g. XOR/OR equivalences in crypto code are acceptable). Config lives in `.cargo/mutants.toml` (output dir `custom_mutants_output/`).
- Behaviour-critical private functions can use in-file `#[cfg(test)] mod tests` blocks when they can't be exercised from outside the crate.
- For traits in `core`, the canonical tests live in `core-test-framework` and are invoked from each implementor's integration tests — don't duplicate them per-implementation.

## CI

The only workflow is `.github/workflows/publish_doc_benches_to_ghpages.yaml`: on every PR it builds rustdoc and runs `quality_stats.sh`; on `main` it additionally runs `cargo bench --all` and publishes docs, code stats, and benchmark results to GitHub Pages (`https://bcgit.github.io/bc-rust/`). There is no separate CI test/lint job — local `cargo test` is the gate.