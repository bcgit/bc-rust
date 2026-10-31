# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Required reading

This file is a *map*, not a rulebook. It records repo mechanics — commands, layout, where things live, how to work
here. The project's binding standards live in their own documents, which are authoritative and are updated
independently of this file. Read them; do not infer their contents from this file, and do not work from memory of a
previous session's reading of them.

- **[QUALITY_AND_STYLE.md](QUALITY_AND_STYLE.md) — read before writing or changing code, and before reviewing a
  diff.** The authority on architecture, crate and API shape, naming conventions, fallibility, macros, what tests and
  benchmarks a crate owes, which sections crate docs must have, and how much they should say. Its own opening line
  invites an AI to review a PR against it, so treat it as exactly that checklist.
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

## Project status: ALPHA

The library is pre-1.0 alpha (workspace version `0.1.x`, release branches named `release/<ver>alpha`) and has no
users to protect yet. Until the first stable release:

- **Breaking changes are fine.** Public API shape, trait signatures, crate layout and encodings may change in any
  PR without deprecation cycles, compatibility shims, or migration notes. Prefer the right design over continuity.
- **Security bugs are ordinary bugs.** Fix them on a normal branch and PR, with a regression test and a plain
  description of the defect and its impact. No security advisory, CVE, embargo, or coordinated release is needed.
  SECURITY.md's reporting address still applies to reports from outside the project.

Revisit this section at the first non-alpha release.

## Toolchain

- Builds on Rust **stable**: there is no toolchain pin, and no crate enables a `#![feature(...)]` gate, so
  nightly-only tooling (`-Z` flags and the like) is not available. CI builds, tests and docs on stable; only the
  `rustfmt` job installs nightly.
- 2024 edition (set workspace-wide in the root `Cargo.toml`).
- Minimum Rust is 1.88: `rust-version` in the root `Cargo.toml`, inherited by `bouncycastle-utils` (the crate that
  needs it, for `slice::as_chunks`) and so enforced for every crate that depends on it.

## Common commands

Build / test / bench / docs run against the cargo workspace from the repo root. `--workspace` is
not optional: the root manifest is both the workspace and the umbrella `bouncycastle` package, so a
bare `cargo build` builds only that package (no `cli`, no benches) and a bare `cargo test` runs
**zero** tests and still exits 0, because the umbrella crate has none of its own.

```
cargo build --workspace         # whole workspace incl. `bc-rust` CLI binary
cargo build -p bouncycastle-sha3   # one sub-crate
cargo test --workspace          # all tests
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
cargo mutants -p bouncycastle-sha3         # config in .cargo/mutants.toml (output: custom_mutants_output/)
```

`-p` is as non-optional here as `--workspace` is for build and test, and for the same reason: a bare
`cargo mutants` examines only the root `bouncycastle` package, whose single `src/lib.rs` yields no
mutants, so it prints "No mutants found under the active filters" and exits **0**. See
[the mutation-testing mechanics](#notes-on-testing) for scoping a run to one file, for crates whose
tests live elsewhere, and for the test-data symlink.

Stack-memory benches are separate binaries under `mem_usage_benches/src/`, each declared as a
`[[bin]]` in that crate's `Cargo.toml`:

```
cargo run --release -p mem_usage_benches --bin bench_mlkem_mem_usage
cargo run --release -p mem_usage_benches --bin bench_mldsa_mem_usage
```

`mem_usage_benches/src/lib.rs` makes those sources modules of a lib target as well, so their `//!`
headers are rustdoc'd and any indented or fenced block in them is compiled as a Rust doctest. The
valgrind and `ms_print` recipes there are fenced as ```` ```text ```` for that reason — keep it that
way when adding a harness, or `cargo test --workspace` fails to compile them.

## Workspace architecture

The workspace has four top-level kinds of member:

1. `crypto/*` — the library's sub-crates, plus the spine crates `core`, `core-test-framework`, and `factory` described below. Most are one primitive each; some, such as `cipher`, hold generic building blocks (modes, padding) as sub-modules. The set changes over time, so take it from `ls crypto/` or the root `Cargo.toml` rather than from a list here. Each crate is published as `bouncycastle-<name>` and depended on internally via the `workspace.dependencies` table in the root `Cargo.toml`.
2. `src/` — the umbrella `bouncycastle` crate, which is just `pub use` re-exports of every sub-crate (e.g. `bouncycastle::sha3`, `bouncycastle::sm3`, `bouncycastle::mlkem`). It exists so downstream users can pull the whole library with one dependency; it has no code of its own.
3. `cli/` — the `bc-rust` binary built on top of `bouncycastle`, exposing every primitive as a streaming stdin→stdout subcommand using `clap`.
4. `mem_usage_benches/` — stand-alone binary crates that measure peak stack usage of algorithms (cannot be done via criterion).

### The `core` / `core-test-framework` / `factory` spine

- `crypto/core` defines the abstract traits (`Hash`, `KDF`, `MAC`, `KEM`, `Signature`, `RNG`, `Algorithm`, `HashAlgParams`, …), error enums (`HashError`, `KDFError`, `KEMError`, `MACError`, `RNGError`, `SignatureError`), and the `KeyMaterial` / `KeyType` wrapper that all sensitive byte buffers are required to use (see `Secret` super-trait requirement in QUALITY_AND_STYLE.md).
- `crypto/core-test-framework` contains the shared per-trait test suite (`hash.rs`, `kdf.rs`, `kem.rs`, `mac.rs`, `signature.rs`). New implementations of a core trait must be exercised through this framework — it's how trait conformance and error-condition coverage stay consistent across implementations.
- `crypto/factory` provides enum-based string-name factories (`HashFactory`, `KDFFactory`, `MACFactory`, `RNGFactory`, `XOFFactory`). Each factory enum impls the underlying trait so it can be used transparently as that primitive, except `MACFactory`, which is a key enum implementing the MAC role traits and handing out a `MACFactoryWorker` that impls `MAC`; and each impls `AlgorithmFactory` (`new(name)`, `default_128_bit()`, `default_256_bit()`). When adding a new primitive that fits an existing trait, register it in the corresponding factory.

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
  pipelines; preserve that when adding subcommands. The exception is a construction that is not
  itself streamable, such as CCM (SP 800-38C Sec 3: "CCM is not designed to support partial
  processing or stream processing", because the payload length is inside the first block the MAC
  covers) -- there, read the whole input once and process it in place, rather than adding a second
  buffer the size of the input on top of it; see `aes_ccm_cmd.rs`.
- Trait → factory → CLI is the wiring path for a new primitive; see [the workspace architecture](#the-core--core-test-framework--factory-spine) above for the crates involved.
- AI-drafted docs and comments run long. Before committing, check them against QUALITY_AND_STYLE.md's "Proportion"
  rule: cut duplicated material, long rationale and restated spec text rather than adding more.

## Scope of changes

Implement what was asked and stop. Unrequested refactors — extracting a trait, renaming for
readability, restructuring impls — are not free even when they are correct: bundled into a feature
commit they make the diff unreviewable, because a reviewer cannot separate the new behaviour from
the restructuring, and the review time that costs is the reason not to do it.

- If a refactor genuinely unblocks the task, give it **its own commit ahead of** the feature, so it
  can be reviewed or dropped on its own.
- If it unblocks nothing, propose it and wait rather than doing it.
- The same goes for drive-by comment rewrites, reformatting and file moves in code you are only
  passing through.

## Lessons from the Ascon-AEAD128 refactors (October 2026)

A series of PRs took `AsconAead128` from one struct serving both directions through a runtime
flag, with a parallel inherent API and two newtype wrappers, to `Ascon_AEAD128<Dir>`. What that
taught, as mechanics to apply next time a cipher type is shaped or reshaped:

- **The direction goes in the type.** `Cipher<Dir>` with `Encrypting` / `Decrypting` and one
  `impl` block per direction turns wrong-direction calls into compile errors and shrinks the
  call-order state machine to the phases alone. Reach for `Direction::Select` only when the two
  directions really are different types (padded CBC); when they share their state, one generic
  struct under the spec-spelled name (`Ascon_AEAD128<Dir>`, `#[allow(non_camel_case_types)]`)
  is the whole public type, with no CamelCase twin and no alias to it.
- **The trait pair is the API.** Do not keep an inherent streaming or one-shot API beside the
  `AEADCipher*` / `SymmetricCipher*` impls; everything a caller needs is on the traits, and
  everything that takes a key or draws a nonce, including a supplied nonce
  (`create_encryptor_nonce`, `encrypt_with_aad_nonce_out`), is on the key object. The only
  inherent methods a cipher adds are for what the traits lack, in-place streaming
  (`do_*_inplace`), and their decrypt form keeps the same tag hold-back as `do_decrypt_out` so
  the two interleave.
- **Private helpers must not share a trait method's name.** An inherent `do_encrypt_final` with a
  different signature from the trait's is what forced the wrapper newtypes; name the core
  helpers for what they do (`absorb_aad`, `encrypt_bytes`, `finish_tag`, `verify_tag`).
- **Fold wrapper state into the struct.** A decrypt-only buffer (the held-back tag) is carried on
  both directions, unused when encrypting, as `Gcm` already does; that is cheaper than a second
  type and keeps `SuspendableKeyed` on the cipher itself.
- **Suspended-state formats are frozen.** Moving the impl or splitting the type must not change a
  byte of the layout; the call-state byte keeps its direction bits and resume refuses the other
  direction. When the two directions' states differ in length, publish a constant per direction.
- **When public items go, the tests follow the API, and the benches get built.** Integration
  tests move onto the trait methods rather than the inherent ones surviving for their sake.
  `cargo test --workspace` does not compile `benches/` or `mem_usage_benches`, so finish with
  `cargo test --workspace --all-targets --no-run`, and put `compile_fail` doctests on public items
  only: on a private item they pass vacuously once the import they name is gone. After rewriting
  a CLI path, run it against a known-answer vector (`--nonce` on `ascon-aead128` reproduces the
  LWC KAT tag).
- **A rename stays in the crate it was asked for.** `do_*_update` to `do_*_inplace` was done for
  Ascon; the CCM type still has its namesake. Note the follow-up rather than widening the
  change.

## Lessons from the key-object rework (October 2026)

The symmetric cipher and MAC traits lost their constructors and key-taking one-shots; keys took them.
What that taught, as mechanics for the next trait that sheds a constructor:

- **The trait describes a worker that exists.** `SymmetricCipherEncryptor`, `AEADCipherEncryptor`,
  `BlockCipherEncryptor`, `StreamCipherEncryptor`, their decrypting halves and `MAC` carry only
  streaming methods and length helpers. Construction is a key object's (`create_encryptor(rng)`,
  `create_decryptor(init)`, `create_generator()`), and the one-shots are provided on the role
  traits in `core::symmetric_key` over those. `KEY_LEN` is on the role and mode traits, never on
  a worker trait.
- **Mode types carry the role.** A key is `AESKey<P, M>`; which role pairs it implements is
  decided by `M`'s mode-trait impls in `core::hazmat::mode` (`SymmetricEncryptMode`,
  `BlockEncryptMode`, `EcbEncryptMode`, `AeadEncryptMode`, `AeadDeclaredEncryptMode`, `MacMode`).
  Padding and frame parameters live in the mode type (`CBC<PKCS7>`, `CBC<Blocks>`,
  `ECB<Blocks>`, `CTR<12>`, `CCM_Packet<12, 16, 64, 1024>`), not on a worker alias.
- **The key length stops at the key.** `BlockPermutation<BLOCK_LEN>` carries the block methods
  and `ElectronicCodeBook<KEY_LEN, BLOCK_LEN>` adds only `new`, so a worker and a mode's
  `Mode<P>` impl bound on the former and never name a key length; the GCM, GMAC and CMAC impls
  are generic in `cipher` for that reason. `KEY_LEN` stays on the mode traits' worker-producing
  halves as the tie between a key's length and its permutation's, through
  `P: ElectronicCodeBook<KEY_LEN, ..>`, which is what keeps a key object's role impls to the one
  length. A mode that must know the block length (`CMAC<BLOCK_LEN>`, `CTR<N, BLOCK_LEN>`) takes
  it as a parameter, since stable Rust cannot read it off the permutation inside the impl.
- **Test the key, not the worker pair.** The framework runners are `test_key` over a role pair
  and the construction suites in `core_test_framework::from_key_material`; a test of "a key of the
  wrong type is rejected" belongs to the construction suite, once, not to each mode's tests.
  Known-answer suites keep pinning their IV through `create_encryptor` and a `FixedSeedRNG`.
- **Workers borrow the key.** The role and mode traits hand out workers through a generic
  associated type with a lifetime, `type Encryptor<'k>`, and the cipher-crate workers hold
  `&'k` to the mode's key state, so `create_encryptor` copies no schedule and a worker cannot
  outlive its key. Spell the mode traits' GAT bound `where P: 'k`, not `where Self::KeyState: 'k`:
  rustc rejects a generic impl whose key state is a struct over `P` (E0276) under the latter. A
  function handed `key: &'k K` that names the worker is generic over `'k`; one that builds its
  key locally bounds `for<'k> K::Encryptor<'k>: ..` with `K: 'static`. A test binds the key
  before the worker, since `key_fn().create_encryptor(..)` borrows a temporary.
- **Resume takes the key object.** `SuspendableKeyed<'k, N>` and `SuspendableComponent<'k>` take
  the key by `&'k`: a cipher-mode worker's `Key` is the mode's `KeyState`, reached through
  `hazmat::ModeKey::state`, HMAC's is `HmacKey`, Ascon's is `AsconAEAD128Key`, and HKDF's stays
  the salt material, since HKDF is not a key object. The suspended layouts did not change. A
  worker that owns a copy of its key (Ascon, KMAC) implements the traits for every `'k` and
  ignores it. A struct cannot hold a worker that borrows a key it also owns: HKDF runs its
  extract-phase HMAC as the two halves `HmacKey::inner_state` / `finish_out`, and the MAC
  factory is a key enum that hands out a worker enum.
- **What has no key-path twin is dropped, and said so.** `new_allow_weak_key` on a cipher-based
  MAC, a wrong-length `KeyMaterial512` into a fixed-length key, GCM's verify-before-decrypt
  one-shot override: each went with a line in the commit message rather than a shim.

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

- `cargo mutants` is expected to be run on each crate; surviving mutants must be investigated but not all need to die (e.g. XOR/OR equivalences in crypto code are acceptable). Config lives in `.cargo/mutants.toml` (output dir `custom_mutants_output/`). Four things about running it here:
  - **Always pass `-p <crate>`.** Without it only the root package is examined, which has no mutants, and the run "passes" vacuously — see [Common commands](#common-commands).
  - **`-f`/`--file` does nothing while the checked-in config is in play**, because its `examine_globs` wins over the CLI filter: `cargo mutants -p bouncycastle-sha3 -f '**/kmac.rs'` still examines all ~874 mutants in the crate. To scope a run to the files you changed, copy `.cargo/mutants.toml` somewhere outside the repo, delete its `examine_globs` block, and pass `--config <copy>`; `-f` then filters as documented. (`--config /dev/null` also works but throws away `skip_calls`, `error_values`, `cap_lints` and the timeout multipliers with it.)
  - **Add `--test-workspace true` when a crate's mutants are killed by another crate's tests.** The `core` traits are the case that matters: their default method bodies are exercised from `sha3` and `factory`, so a `-p bouncycastle-core` run alone reports them all as missed.
  - **Symlink the test data into `/tmp`.** `cargo mutants` copies the tree to `/tmp/cargo-mutants-<dir>-XXXX.tmp/`, so the `../../../bc-test-data/...` paths the vector suites use resolve to `/tmp/bc-test-data`. Without `ln -s <path-to>/bc-test-data /tmp/bc-test-data` those tests print their "not found" warning, pass vacuously, and every mutant they would have killed is reported as missed. The exception is `bouncycastle-ecdsa`, whose CAVP and wycheproof suites **fail** when their data is missing instead of skipping, so a mutants baseline for that crate also needs `ln -s <path-to>/wycheproof /tmp/wycheproof`. Use `--jobs 3` and an explicit `--timeout`; note that a mutant which makes a squeeze return no bytes hangs a fill loop for real, so some timeouts are kills rather than false alarms.
- Integration tests in `tests/` are preferred over in-file `#[cfg(test)] mod tests` blocks — see "Unit tests vs integration tests" in QUALITY_AND_STYLE.md for the reasoning and the exceptions. A unit test is justified for high-risk code that has known-answer values and cannot be reached through the public API; when you write one, all of its helpers go inside that `mod tests`.
- A property that can be asserted at compile time (`const _: () = assert!(...)`) stays a compile-time assertion even when a test also covers it: `cargo mutants` cannot see a const assertion fail, so pair the two rather than trading the guarantee for the coverage.
- For traits in `core`, the canonical tests live in `core-test-framework` and are invoked from each implementor's integration tests — don't duplicate them per-implementation.
- The per-width `impl Condition<W>` blocks in `crypto/utils/src/ct.rs` (and their test modules) are deliberately duplicated rather than macro-generated: `cargo mutants` cannot see into `macro_rules!` bodies, so a macro would hide the mask identities from mutation testing. Do not fold them back into a macro. Any change to one width in a group (i64/i32, u64/u32) must be applied to every width in that group.

## CI

Five workflows under `.github/workflows/`, all triggered by pull requests:

- `rust-build.yml`: `cargo build --workspace --all-targets --all-features` on stable.
- `rust-test.yml`: `cargo test --all` on stable.
- `rust-style.yml`: `cargo fmt --all --check` on **nightly** rustfmt, so format before every commit.
- `rust-docs.yml`: `cargo doc --all` on stable.
- `publish_doc_benches_to_ghpages.yaml`: builds rustdoc and runs `quality_stats.sh`; on `main` it also
  publishes docs and code stats to GitHub Pages (`https://bcgit.github.io/bc-rust/`). Its bench step is
  commented out because the benches are too slow on the hosted runner, so benchmark figures come from a
  developer's machine, not CI.

`cargo test --all` is the workspace run, so a failing test does block a PR; what CI does not run is
`cargo mutants`, the CLI shell tests under `cli/tests/`, or rustdoc with warnings denied.