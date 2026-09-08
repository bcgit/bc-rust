# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Required reading

This file is a *map*, not a rulebook. It records repo mechanics — commands, layout, where things live, how to work
here. The project's binding standards live in their own documents, which are authoritative and are updated
independently of this file. Read them; do not infer their contents from this file, and do not work from memory of a
previous session's reading of them.

- **[QUALITY_AND_STYLE.md](QUALITY_AND_STYLE.md) — read before writing or changing code, and before reviewing a
  diff.** The authority on architecture, crate and API shape, naming conventions, fallibility, macros, what tests and
  benchmarks a crate owes, and which sections crate docs must have. Its own opening line invites an AI to review a PR
  against it, so treat it as exactly that checklist.
- **[CONTRIBUTING.md](CONTRIBUTING.md) — read before writing a commit message, opening a PR, or advising on how a
  change gets merged.** The authority on coding philosophy, PR hygiene and self-review, the quality bar a submission
  must clear to be accepted, how merges actually happen in this project, and the AI policy. That policy places
  requirements on the commit messages and PR descriptions of AI-assisted work, which covers anything written here:
  never compose a commit message or PR description for this repo without checking it first. It links onward to
  [SECURITY.md](SECURITY.md) for anything security-sensitive and [ISSUES_STYLE_GUIDE.md](ISSUES_STYLE_GUIDE.md) for
  issue and sub-issue structure.
- **[INTRODUCTION.md](INTRODUCTION.md) — read for design intent**, when a change touches public API shape or you need
  the reasoning behind a convention rather than the convention itself.

Where this file and one of those documents disagree, the document wins — and say so, so the stale line here gets
fixed.

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

## Project-specific conventions

The house rules are deliberately **not** reproduced here — see [Required reading](#required-reading) above.
QUALITY_AND_STYLE.md governs API shape, naming, fallibility, macro use, and the tests, benches and doc sections a
crate owes; CONTRIBUTING.md governs what a submission must satisfy to be accepted. Both cover ground that is easy to
violate without noticing, so read them at the start of a session that will touch code rather than guessing which
conventions apply.

Repo mechanics behind those rules, which the documents don't spell out:

- `./dev_scripts/quality_stats.sh` produces the fallibility metrics both documents ask you to check. Run it before
  and after a change and compare, rather than eyeballing the diff.
- **CLI commands stream.** The `cli/` binary is stdin→stdout with ~1 KB buffers so commands compose in shell
  pipelines; preserve that when adding subcommands.
- Trait → factory → CLI is the wiring path for a new primitive; see [the workspace architecture](#the-core--core-test-framework--factory-spine) above for the crates involved.

## Working from specifications

QUALITY_AND_STYLE.md is where the requirement for spec-corresponding comments and justified deviations lives. This
section is only about *how* to satisfy it without introducing errors.

**Never cite, paraphrase, or implement a specification from recall.** Model recall of RFC text, FIPS algorithm steps, NIST parameter tables, and section numbering is unreliable — plausible-looking but wrong step numbers and subtly wrong constants are the failure mode. Before writing or reviewing any code, comment, or doc that references a spec, download a fresh copy and read the relevant part of it.

Where to get them:

```
# RFCs — plain text is easiest to grep and quote
curl -sL https://www.rfc-editor.org/rfc/rfc8446.txt -o "$SCRATCH/rfc8446.txt"

# NIST FIPS (e.g. FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 202 SHA-3, FIPS 180-4 SHA-2)
curl -sL https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf -o "$SCRATCH/FIPS-203.pdf"

# NIST SP 800-series (note the revision suffix, e.g. r2)
curl -sL https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr2.pdf -o "$SCRATCH/SP-800-56Cr2.pdf"
```

Download into the session scratchpad directory, not into the repo — spec PDFs must never be committed. Read PDFs with the `Read` tool's `pages` parameter (max 20 pages per call); if a download fails or the URL 404s, say so and ask rather than falling back on recall.

Rules when working from the downloaded copy:

- **Quote exactly, and locate precisely.** Comments and commit messages should name the document with its revision (e.g. "FIPS 203, Algorithm 13 (ML-KEM.Encaps_internal), step 2", "RFC 5869 §2.2"), and quote the spec verbatim where a quote is clearer than a paraphrase. Verify every section/algorithm/step number against the file you just downloaded — including numbers already present in the code, which may predate a spec revision.
- **The specification is the source of truth for correct behaviour** — not the C/Java/Go implementation you have seen, not the BC Java or BC C# port, and not another crate. When an existing implementation appears to disagree with the spec, re-read the spec, and if the disagreement is real, follow the spec and note the discrepancy in the PR description rather than silently copying the other implementation.
- **Optimizations are allowed, provided externally-visible behaviour is identical.** Restructuring loops, fusing steps, precomputing tables, constant-time rewrites, and in-place buffer reuse are all fine — the spec constrains observable outputs (and, for this library, timing behaviour on secret data), not the shape of the code. Any such deviation from the spec's literal steps gets a comment saying which spec steps it implements and why it is equivalent.
- **Test vectors come from the spec or its official companion files** (NIST CAVP / ACVP vectors, RFC test-vector appendices), downloaded the same way. Never hand-write an "expected" value from recall.

## Notes on testing

What a crate must be tested against — including the mutation-testing expectation, the trait test framework, and the
external vector suites — is specified in QUALITY_AND_STYLE.md and CONTRIBUTING.md. Repo-specific mechanics:

- `cargo mutants` is expected to be run on each crate; surviving mutants must be investigated but not all need to die (e.g. XOR/OR equivalences in crypto code are acceptable). Config lives in `.cargo/mutants.toml` (output dir `custom_mutants_output/`).
- Behaviour-critical private functions can use in-file `#[cfg(test)] mod tests` blocks when they can't be exercised from outside the crate.
- For traits in `core`, the canonical tests live in `core-test-framework` and are invoked from each implementor's integration tests — don't duplicate them per-implementation.
- The per-width `impl Condition<W>` blocks in `crypto/utils/src/ct.rs` (and their test modules) are deliberately duplicated rather than macro-generated: `cargo mutants` cannot see into `macro_rules!` bodies, so a macro would hide the mask identities from mutation testing. Do not fold them back into a macro. Any change to one width in a group (i64/i32, u64/u32) must be applied to every width in that group.

## CI

The only workflow is `.github/workflows/publish_doc_benches_to_ghpages.yaml`: on every PR it builds rustdoc and runs `quality_stats.sh`; on `main` it additionally runs `cargo bench --all` and publishes docs, code stats, and benchmark results to GitHub Pages (`https://bcgit.github.io/bc-rust/`). There is no separate CI test/lint job — local `cargo test` is the gate.