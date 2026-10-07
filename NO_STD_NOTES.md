# no_std notes

This document is both the guide and the status record for adding `no_std` support to bc-rust. It is the
authority for anything `no_std`-specific: what the terms mean, how a crate is converted, how support is validated,
and where each crate currently stands.

**Keep it current:** any PR that changes a crate's `no_std` state, its `std` feature, or how a dependency on it is
declared must update the [status table](#crate-status) in the same PR.

Tracking issue: [#49 — Ensure that all crates are `#![no_std]`](https://github.com/bcgit/bc-rust/issues/49).

## Definitions

- **`no_std`** — in this project, `no_std` means **no `std` and no `alloc`**. A `no_std` build cannot use `Vec`,
  `Box`, `String`, or anything else that allocates.
- **The `std` feature** — enables both `std` and `alloc`. It is on by default, so ordinary users see no change.
- **`--no-default-features`** — the build-time switch that turns `std` off. It is only supported per crate
  (`cargo build -p <crate> --no-default-features`), and only for crates that have reached one of the levels below.
  Building the whole workspace, or a crate that hasn't been converted, with `--no-default-features` is unsupported.
- **`alloc` (future)** — a separate `alloc` feature is planned but does not exist yet. When added:
  `std` on → `std` and `alloc` (`alloc` feature ignored); `std` off, `alloc` on → `#![no_std]` with an external
  allocator; neither → `no_std` with no allocation.

## Support levels

`no_std_self`
: The crate itself builds as `#![no_std]`, but some of its non-dev dependencies still need `std`.
  Validated by building and testing with `--no-default-features` on the host.

`no_std_complete`
: The crate **and** all of its non-dev dependencies build as `#![no_std]`.
  Validated as above, plus a release build for `thumbv7em-none-eabi`, a target with no `std` at all.

Tests always run on a host with `std` available, so a `no_std` crate's tests and dev-dependencies may use `std`.

## Crate status

Each crate is listed under its current state. If your commit changes this state, move it to the
correct section, and update the `justfile` list named in the heading if necessary.

### `no_std_complete` (`justfile`: `no-std-complete-crates`)

- `core` — `std` feature gates the `Vec`/`Box` APIs.
- `utils` — no dependencies.

### `no_std_self` (`justfile`: `no-std-self-crates`)

- none

### Dependency changes done, crate itself not yet `no_std`

- `hkdf`, `hmac`, `rng`, `sha2` — have a `std` feature that forwards to their dependencies.

### Not started

- `base64`, `hex`, `mlkem`, `mlkem-lowmemory`, `mldsa`, `mldsa-lowmemory`, `sha3`

### Not expected to support `no_std`

- `core-test-framework` — changes done: has a `std` feature so it can test implementors built without `std`.

### Target not yet decided

- `factory`, `cli`, `bouncycastle` (umbrella), `mem_usage_benches`

## Converting a crate

Do this incrementally: aim for PRs under ~1000 lines, or one crate plus the minimum dependency changes it needs. A PR
only has to make its own crate build without `std` (reach `no_std_self`); its dependencies can follow later. Each PR
must leave every existing `std` build working.

### 1. `lib.rs`

Either the crate never needs `std` (preferred):

```rust
#![no_std]
```

or its allocating APIs sit behind the `std` feature (the pattern `core` uses):

```rust
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
extern crate alloc;
```

with `use alloc::vec::Vec;` (also gated) wherever `Vec` is needed.

### 2. Code

- Prefer fixed-size arrays and caller-provided buffers (`*_out(&mut [u8])`) to `Vec`. Every trait in `core` already
  has an allocation-free `_out` form for each `Vec`-returning method.
- Gate whatever must allocate behind `#[cfg(feature = "std")]`. This includes trait-method impls whose trait
  declaration is gated: for example `Hash::hash`, `Hash::do_final`, `MAC::mac`, `KDF::derive_key`, `XOF::squeeze` and
  `RNG::next_bytes` only exist when `bouncycastle-core/std` is on.
- Tests inside the crate (`#[cfg(test)]`) that use std-only APIs get the same gate.

### 3. `Cargo.toml`

Add the feature, and forward it to **every** internal dependency that has one, including dev-dependencies:

```toml
[features]
default = ["std"]
std = [
    "bouncycastle-core/std",
    "bouncycastle-core-test-framework/std",
    # … every other internal dependency that has a `std` feature
]

[dependencies]
bouncycastle-core = { workspace = true, default-features = false }
```

In the root `Cargo.toml`, every crate that has a `std` feature is declared in `[workspace.dependencies]` with
`default-features = false`. That has two consequences:

- A crate with a `std` feature uses `default-features = false` on those dependencies and forwards `std` as above.
- A crate **without** its own `std` feature must write `default-features = true` on those dependencies, or it silently
  loses their `std` APIs. That's why `sha3`, `mlkem` and `factory` currently set it.

When you give a crate a `std` feature for the first time, add `default-features = false` to its entry in
`[workspace.dependencies]`, then check every crate that depends on it.

Mistakes here usually only show up when a crate is built **on its own** (`-p`). Building the workspace merges
features across crates and hides them, which is why validation builds each crate on its own.

### 4. Tests through `core-test-framework`

`core-test-framework` always needs `std`, but it has a `std` feature (forwarded to `core`) so it can exercise
implementors built without `std`. Inside it:

- Tests of std-only APIs are wrapped in `#[cfg(feature = "std")]`.
- Each gated test sits **directly after** its ungated `_out` counterpart. The `_out` test carries the comment
  describing the test case; the gated one gets a one-line comment such as `// ... and the same via do_final()`.
- Anything common to both versions (inputs, keys, setup that changes the expected values) goes before the pair, so
  both run against the same state.
- Test coverage without `std` should match coverage with it: only the calls to std-only APIs should be gated, never
  the behaviour being tested.

### 5. Record it

- Add the crate to `no-std-self-crates` or `no-std-complete-crates` in the root `justfile`. Move it to
  `no-std-complete-crates` once all its non-dev dependencies are `no_std` too.
- Update the [status table](#crate-status) above, including any crates whose state changed as a side effect.
- State the `no_std` state of every affected crate in the PR description.

## Validation

`just` (in the repo root) builds and tests every crate **on its own** in every supported configuration. Before the
first run:

```bash
rustup target add thumbv7em-none-eabi
```
```bash
cargo install just
```

Then run everything (the default recipe is `validate-all`):

```bash
just
```

`just` runs, for each set of crates:

- **every crate in `all-crates`**, default features —
  `cargo test -p <crate>` and `cargo build --release -p <crate>`
- **the whole workspace** —
  `cargo test --workspace` and `cargo build --release --workspace`
- **`no-std-self-crates`** — both of the per-crate commands again, with `--no-default-features`
- **`no-std-complete-crates`** — as `no-std-self-crates`, but the release build also adds
  `--target thumbv7em-none-eabi`

Use `just --list` to see the individual recipes; for example `just test-crate-no-std-self bouncycastle-hmac` tests
one crate. CI runs the same thing (`.github/workflows/rust-validate.yml`) on every PR, so whoever introduces a
`no_std` regression fixes it in their own PR.

### Checking status

To check which crates currently build with no `std` at all:

```bash
for c in base64 core core-test-framework factory hex hkdf hmac mldsa mldsa-lowmemory mlkem mlkem-lowmemory rng sha2 sha3 utils; do cargo build -q -p bouncycastle-$c --no-default-features --target thumbv7em-none-eabi 2>/dev/null && echo "OK   $c" || echo "FAIL $c"; done
```

## Known issues and open questions

- **Feature unification can break trait impls.** Whether a `core` trait *requires* a std-only method depends on
  `bouncycastle-core/std`; whether an implementor *provides* it depends on the implementor's own `std` feature. Cargo
  merges features across the whole dependency graph, so if another crate turns on `bouncycastle-core/std`, an
  implementor built without `std` fails with "not all trait items implemented". It doesn't affect any supported
  configuration yet, but it will once an implementing crate reaches `no_std_self`. Proposed fix: give the std-only
  methods default bodies in `core`, built on the `_out` methods, so implementors don't have to write them.
- **Docs built without `std` have broken links.** `cargo doc -p bouncycastle-core --no-default-features` warns about
  13 unresolved links from `_out` and `_array` docs to std-only methods.
- **Some crates' own tests don't compile without `std`.** For example, `crypto/hkdf/tests/hkdf_tests.rs` calls
  `derive_key` directly. These need gating before the crate is added to a `justfile` list.
- **Validation gaps.**
  - `mem_usage_benches` is not in `all-crates`.
  - No recipe compiles benches (`cargo test` doesn't build `harness = false` benches).
- **Intended targets are still open** for `factory`, `cli`, the `bouncycastle` umbrella crate and `mem_usage_benches`.