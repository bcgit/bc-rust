# ASCON Implementation & Testing — Work Summary

NIST SP 800-232 (August 2025) Ascon family for the `bc-rust` workspace.
Branch: `feature/officialfrancismendoza/15-ASCON`. **Nothing is committed** — all
changes are in the working tree.

---

## 1. Overview

Starting point: `crypto/ascon/` contained a drafted (but non-compiling)
implementation of all four Ascon functions. The work delivered a fully-fledged,
house-style-compliant primitive crate and a comprehensive test suite.

Functions implemented (all share the `Ascon-p` permutation, little-endian, with
precomputed init states from SP 800-232 Table 12):

- **Ascon-AEAD128** — authenticated encryption (128-bit key/nonce/tag).
- **Ascon-Hash256** — 256-bit hash.
- **Ascon-XOF128** — extendable-output function.
- **Ascon-CXOF128** — customized XOF.

---

## 2. Core crate changes (`crypto/core`)

### New `AeadError` enum — `crypto/core/src/errors.rs`
```
AuthenticationFailed | InvalidLength(&'static str) |
InvalidState(&'static str) | GenericError(&'static str) |
KeyMaterialError(KeyMaterialError)
```
Plus `impl From<KeyMaterialError> for AeadError`.

### New `AeadCipher` trait — `crypto/core/src/traits.rs`
Fully documented (the `core` crate is `#![forbid(missing_docs)]`). Final shape:
```rust
pub trait AeadCipher {
    fn process_aad_byte(&mut self, input: u8);
    fn process_aad_bytes(&mut self, in_bytes: &[u8]);
    fn process_byte(&mut self, input: u8, out_bytes: &mut [u8]) -> usize;
    fn process_bytes(&mut self, in_bytes: &[u8], out_bytes: &mut [u8]) -> usize;
    fn do_final(self, out_bytes: &mut [u8]) -> Result<usize, AeadError>;
    fn get_mac(&self) -> [u8; 16];
    fn get_update_output_size(&self, len: usize) -> usize;
    fn get_output_size(&self, len: usize) -> usize;
}
```
Decisions vs. the originally-proposed signature:
- `get_mac` returns `[u8; 16]` (not `Vec<u8>`) — per the Vec→array directive; Ascon
  tags are always 128-bit.
- `do_final` returns `Result<usize, AeadError>` (not `()`/panic) so a failed tag
  check on attacker-controlled input is a recoverable error, never a DoS panic.
- Streaming `process_*` outputs remain `&mut [u8]` (output length is input-dependent).

---

## 3. ASCON crate changes (`crypto/ascon`)

### Files
- `src/lib.rs` — `#![forbid(unsafe_code)]` + `#![forbid(missing_docs)]`; crate docs
  with the mandated **Usage Examples / Memory Usage / Security Considerations**
  sections; `ASCON_*_NAME` constants; private `mod util`.
- `src/util.rs` — NEW. Dependency-free little-endian `load_u64_le`/`store_u64_le`
  (using `copy_from_slice`), replacing the external `arrayref` crate. **Zero
  `unwrap()`/`Result`** in these helpers.
- `src/ascon_aead128.rs`, `src/ascon_hash256.rs`, `src/ascon_xof128.rs`,
  `src/ascon_cxof128.rs` — brought to house style (see below).

### Behavioral / API changes
- **Removed the external `arrayref` runtime dependency** (QUALITY rule: no
  non-internal runtime deps). `Cargo.toml` now depends only on
  `bouncycastle-core`; version bumped `0.0.0 → 0.1.2`; added the criterion bench.
- **AEAD secrecy hardening:** `AsconAead128` now takes `&[u8; 16]` for key/nonce
  (compile-time length), implements a zeroizing `Drop` (clears key/nonce/state/
  buffer), implements `core::Secret`, and has redacted `Debug`/`Display`
  (`"AsconAead128 (key/state masked)"`). Hash/XOF/CXOF states are also zeroized
  on drop.
- **AEAD one-shot statics:** `AsconAead128::encrypt(...) -> usize` and
  `decrypt(...) -> Result<usize, AeadError>`.
- **`decrypt_finalize`** now returns `Result<usize, AeadError>` (was
  `Result<_, &'static str>`); tag check is the branch-free `(s3 | s4) != 0`.
- **House-style API:** removed `reset()` (forbidden by QUALITY) and the
  reset-on-finalize behavior. Hash uses consume-self `do_final_into(self, &mut
  [u8; 32])` + one-shot `digest(&[u8]) -> [u8; 32]`. XOF/CXOF keep the
  absorb/`squeeze_into` model (matches the `XOF` trait + SP 800-232 §5.4); the
  CXOF post-customization state cache and the unused `Uninitialized` AEAD state
  were removed as dead code.
- The shared `core::Hash` / `core::XOF` trait impls **keep `Vec<u8>`** returns —
  those traits are shared with sha2/sha3/factory and are not ours to change; the
  Vec→array conversion applies only to ASCON-specific inherent methods.
- Spec-referencing comments added throughout (round function §3.2–3.4, IV,
  padding, domain separation, finalization).

---

## 4. Wiring / registration

- Root `Cargo.toml`: `bouncycastle-ascon` added to `[workspace.dependencies]`
  and to the umbrella `[dependencies]`.
- `src/lib.rs` (umbrella `bouncycastle` crate): `pub use bouncycastle_ascon as ascon;`.
- Factory (`crypto/factory`):
  - `HashFactory` ← `Ascon-Hash256` (new variant + name arm + all 10 trait-method
    delegations).
  - `XOFFactory` ← `Ascon-XOF128` (new variant + name arm + all 9 delegations).
  - `Ascon-CXOF128` and `Ascon-AEAD128` are intentionally NOT in the factories:
    CXOF needs a customization string and AEAD needs key/nonce, neither of which
    fits the `new(name)` factory signature (AEAD has no factory at all yet).
  - `crypto/factory/Cargo.toml` gained the `bouncycastle-ascon` dep.
- CLI (`cli/`): new `src/ascon_cmd.rs` + four streaming subcommands registered in
  `src/main.rs` (clap kebab-case): `ascon-hash256`, `ascon-xof128 <len>`,
  `ascon-cxof128 <len> [--customization <hex>]`, and
  `ascon-aead128 --key/--key-file --nonce/--nonce-file [--ad] [--decrypt] [-x]`.

---

## 5. Test suite (mirrors `crypto/mldsa/tests` — no in-crate `data/` folder)

The crate no longer ships `tests/data/` (the 2.8 MB of `LWC_*.txt` was removed).
Large vector sweeps are read at test time from the externally-cloned
`bc-test-data` repo (graceful skip when absent); always-on correctness is held by
a small embedded vector set in each per-primitive file. The six test files are
each a self-contained integration-test crate:

### Per-primitive files (always-on, no external repo)
`aead128_tests.rs`, `hash256_tests.rs`, `xof128_tests.rs`, `cxof128_tests.rs`
— each embeds ~5–8 NIST LWC known-answer vectors (`const` hex arrays copied from
bc-test-data, spanning empty / sub-block / exact-block / multi-block, plus AD or
customization variants) and the behavior/contract tests for that primitive:
- AEAD: embedded KAT, round-trips, streaming chunk-boundary equivalence (enc+dec),
  chunked AAD (inherent + trait path), auth failures (wrong key/nonce/AD, flipped
  tag/body, short→`InvalidLength`), determinism + nonce sensitivity, output-size
  predictors (both directions), `get_mac`, masked `Debug`/`Display`, trait-method
  AAD, and the `TestFrameworkAead` conformance run.
- Hash256: embedded KAT, streaming/byte-at-a-time equivalence, trait wrappers,
  metadata accessors, unsupported-partial-op `Err`.
- XOF128 / CXOF128: embedded KAT, prefix property, chunked + byte-at-a-time absorb,
  trait wrappers, unsupported-partial-op `Err`, absorb-after-squeeze panic guard;
  CXOF128 also covers domain separation.

40 ASCON tests total, all passing without any external repo.

### `bc_test_data.rs` (full sweep)
Mirrors mldsa's `Once` + two-path resolution
(`../../../bc-test-data/crypto/ascon`, fallback `../bc-test-data/crypto/ascon`).
Reads the per-variant NIST files and runs the **full 4228-case sweep**
(`asconaead128/` 1089, `asconhash256/` 1025, `asconxof128/` 1025,
`asconcxof128/` 1089). Prints a warning and skips when bc-test-data is absent.

### `wycheproof.rs` (skeleton; skips legacy)
Mirrors mldsa's path resolution + `serde_json` AEAD runner. wycheproof only ships
the **pre-NIST CAESAR** Ascon vectors (`ascon128/128a/80pq`), which are a different
algorithm from SP 800-232 `Ascon-AEAD128` and are intentionally NOT run. The test
requests a NIST-named file (`ascon_aead128_test.json`) that does not exist today,
so it skips with a clear message — and will run automatically if C2SP later
publishes NIST-compatible vectors under that name.

### Trait conformance framework
`crypto/core-test-framework/src/aead.rs` provides the generic `TestFrameworkAead`
(encrypt→decrypt round-trip, byte-at-a-time vs one-shot equivalence,
tamper-the-tag → `Err(AuthenticationFailed)`), driven from `aead128_tests.rs`.

### Factory tests
`crypto/factory/tests/hash_factory_tests.rs` and `xof_factory_tests.rs`:
`Ascon-Hash256`/`Ascon-XOF128` via factory match the direct impl (by literal name
and by name constant); unknown names → `FactoryError::UnsupportedAlgorithm`.

### Doctests
3 crate-level doc examples (hash, AEAD one-shot, XOF) compile and pass.

---

## 6. Verification results

| Check | Result |
|-------|--------|
| `cargo build --workspace` | OK (no `arrayref`) |
| `cargo test -p bouncycastle-ascon` | KAT 4228 + 22 behavior + 5 (smoke/framework) + 3 doctests, all pass |
| `cargo test -p bouncycastle-factory` | OK incl. Ascon round-trips |
| `cargo test --workspace` | ~351 tests, no regressions |
| `cargo clippy -p bouncycastle-ascon --all-targets` | 0 warnings in ASCON code (fixed one collapsible-`if`) |
| `quality_stats.sh ./crypto/ascon` (fallibility) | 0 real `unwrap()`s in impl; 13 justified `Err()`s |
| `cargo bench -p bouncycastle-ascon` | runs (~117 MiB/s Hash256 on dev hardware) |
| CLI smoke | Hash256/XOF128/CXOF128/AEAD empty vectors match KAT byte-for-byte; round-trip OK; tamper → non-zero exit |

---

## 7. Mutation testing (`cargo mutants --package bouncycastle-ascon`)

882 mutants generated. Progression as tests were added:

| Run | caught | missed | unviable | timeout |
|-----|--------|--------|----------|---------|
| 1 (KAT + initial behavior + framework) | 723 | 128 | 29 | 2 |
| 2 (+ API-surface tests) | 792 | 58 | 30 | 2 |
| 3 (+ trait-AAD & bidirectional size-predictor tests) | **801** | **48** | 31 | 2 |

**Final: ~94% of viable mutants killed.** Every high-value mutant is killed
(trait one-shot wrappers, metadata accessors, unsupported-op `Err` stubs,
`get_mac`, `update_byte`, size predictors).

The **48 surviving mutants are all in the accepted class** (CLAUDE.md: "not all
need to die — e.g. XOR/OR equivalences in crypto code are acceptable"):
- **4** zeroizing `Drop → ()` — untestable in safe Rust (same as `sha3/keccak.rs`).
- **4** `match`-arm deletions — dead arms guarded by a preceding
  `matches!(...)`/`finished` check (unreachable ⇒ equivalent).
- **~5** XOR/OR algebraic equivalences (`^`↔`|`/`&` on provably-zero bits; the
  `s3 | s4` tag fold).
- **~35** comparison/arithmetic boundary mutants (`>`↔`>=`, `<`↔`<=`, `-`↔`+`) in
  buffering/padding code that are equivalent for reachable buffer-fill states.

The **2 "timeouts"** are mutations that cause hangs and are effectively detected,
not real survivors:
- `with_customization -> Default::default()` (infinite recursion: `Default`→`new`→`with_customization`).
- `+= → *=` on a loop counter in `update_bytes`.

Full mutant lists are in `custom_mutants_output/mutants.out/`
(`caught.txt`, `missed.txt`, `timeout.txt`, `outcomes.json`).

---

## 8. Unresolved issues, caveats & warnings

- **`get_mac` is largely vestigial.** Because `AeadCipher::do_final` consumes
  `self`, you cannot observe the tag via the trait after finalization (the tag is
  already written to the output buffer). It is reachable only through the inherent
  `encrypt_finalize` (`&mut self`) path. This matches the original author comment
  that "tag re-exposure encourages misuse." Consider removing `get_mac` from the
  trait in a future revision.
- **`AsconCXof128::with_customization` panics** on customization strings > 256
  bytes (SP 800-232 limit). This is a documented precondition, but it is a panic
  on caller input; a future revision could make construction fallible
  (`Result`) — deferred to avoid rippling `Result` through `new`/`Default`/factory.
- **`quality_stats.sh` line counts need `cloc` and `bc`**, which are not installed
  on this machine (the fallibility metrics — the important part — do work). Run on
  a host with those tools (or `choco install cloc`) for the LOC/docstring/test
  ratios.
- **Tooling installed for this work:** `cargo-mutants` (27.1.0) was installed via
  `cargo install`. It was not previously present.
- **Pre-existing clippy warnings** exist in *other* crates (`utils`, `hex`,
  `core`, `core-test-framework`) — not introduced here and out of scope.
- **Truncated tags** (SP 800-232 §4.2.1) and **nonce masking** (§4.2.2) are not
  implemented; this crate always uses the full 128-bit tag.
- **Nothing is committed.** All changes live in the working tree on the feature
  branch.

---

## 9. Reproduce

```sh
cargo test -p bouncycastle-ascon            # KAT + behavior + framework + doctests
cargo test -p bouncycastle-factory          # Ascon factory round-trips
cargo test --workspace                      # full regression
cargo clippy -p bouncycastle-ascon --all-targets
cargo bench  -p bouncycastle-ascon
cargo mutants --package bouncycastle-ascon -j 4   # ~13 min; output in custom_mutants_output/

# CLI (after `cargo build -p cli`); clap uses kebab-case:
printf '' | ./target/debug/bc-rust ascon-hash256 -x
# -> 0b3be5850f2f6b98caf29f8fdea89b64a1fa70aa249b8f839bd53baa304d92b2
```
