# Rules for code that reaches `unsafe` in `bouncycastle-asm`

These add to QUALITY_AND_STYLE.md and CONTRIBUTING.md. They cover this crate and the code in `bouncycastle-aes` and
`bouncycastle-cipher` that builds the values its kernels take. Across an `unsafe` boundary a wrong length or index is
not a panic but an out-of-bounds read or write, and a kernel run on a CPU without its instructions is an
illegal-instruction fault, so every value that reaches one must be in range by its type or by a tested check.

## Values

- **Typed boundary.** A kernel or proof method takes fixed-length arrays (`&[u8; 16]`, `&[Block; N]`, `[u64; 2]`),
  never `&[u8]`, a `usize` length or a raw pointer. Admissible const-generic values are checked with
  `const { assert!(..) }`. A raw pointer exists only inside the `unsafe` block, made from a typed reference for the
  call that consumes it.
- **No hand-made slices.** No `from_raw_parts`, `get_unchecked`, `set_len`, pointer arithmetic or pointer casts
  between element types. Bytes become words through `from_*_bytes` / `to_*_bytes`, and only `V128::from_bytes`
  and `V128::to_bytes` move a vector to or from memory.
- **Fixed-size pieces are typed, not sliced.** A key, block or tag travels as `&[u8; N]`; the one `try_into()` from a
  slice is at a validated boundary with a wrong-length test.
- **Endpoints are constants or checked.** Prefer `as_chunks`, `chunks_exact` with its remainder, `split_at_checked`
  and `get` to index arithmetic. Other arithmetic that feeds an index or length uses an explicit `checked_*`,
  `wrapping_*` or `saturating_*` operation with a comment giving the bound, and a length narrows only through `try_from`
  with the error handled, never `as`.
- **One buffer, one borrow.** In-place APIs take a single `&mut [u8]`; nothing documents "may overlap".

## CPU-feature proofs

- An `Aes` value comes only from `detect()` or `declared()`; its field stays private.
- The features `detect()` queries cover every feature in the kernels' `#[target_feature]` attributes. They may
  cover more (`pmull` has no attribute of its own), never fewer.
- `declared()` exists only under a cfg that names every feature in the kernel attribute.
- No NEON vector type crosses the proof boundary.
- The engine is chosen from the CPU alone, once, at construction; never from key or data.
- Each `SAFETY` comment names every precondition of the callee and what discharges it: the proof for the features,
  the array type for pointer validity and length.
- Every public function with a `#[target_feature]` attribute has a one-sentence `# Safety` section
  naming the proof whose existence is its precondition, so clippy's `missing_safety_doc` stays at
  zero.

## Operating-system calls

- The crate is `#![no_std]` and stays so. Detection asks the operating system through the
  declarations in `src/arm64_le/cpu/os/`, never through std, `libc` or any other dependency, and a
  target without a back end gets no features. The table in the `arm64_le::cpu` module docs lists the
  back ends.
- Each back end has one call site, in the `ffi` module of its file in `src/arm64_le/cpu/os/`
  (`linux.rs`, `macos.rs`, `windows.rs`): an `unsafe extern` block with the documented signature and
  the one function that calls it. The file is `#![deny(unsafe_code)]` and only `ffi` allows it. On
  Windows the block carries `#[link(name = "kernel32")]`, since a `no_std` crate names its import
  library itself.
- A pointer passed to the call comes from a typed local whose size is `size_of::<T>()`, and a C
  string is a `c"..."` literal.
- Every return value and out-parameter is range-checked before use, as `sysctl_present` accepts an
  answer only if `rc == 0 && len == size_of::<i32>() && value != 0`.
- Each back end's parser has tests on crafted answers, the call itself has an error-path test where
  the operating system allows one (`os/macos.rs`'s unit test of a known and an unknown name on
  macOS), and `tests/arm64_le_detect_matches_std.rs` checks the result against std.
- There is no `asm!` in the crate. If the bare-metal opt-in that reads the ID registers is built,
  its three `mrs` reads are the only `asm!` blocks, with `options(nomem, nostack, preserves_flags)`,
  behind its cargo feature, with the EL1 contract documented and the parser tested on crafted
  register words. This rule is not yet exercised.

## The `unsafe` budget

`dev_scripts/quality_stats.sh` counts `unsafe {`, `unsafe fn`, `unsafe impl` and `unsafe trait`, so
the three `unsafe extern` blocks are declarations and are not counted. The figure is 13: the eight
proof methods, the two load/store wrappers and one operating-system call per back end. A PR that
changes it says why. The script matches text, doc comments included, so prose in a `.rs` file must
not spell those four patterns out.

## Tests

- Each const-generic check has a `compile_fail` doctest on the public item showing a rejected value.
- Each runtime bound is tested at its maximum, one past it, zero, and at `u32::MAX` / `u64::MAX` / `usize::MAX` where
  a width changes.
- Every whole-block loop is fed each length from 0 to two blocks plus one and across each batching boundary (four
  blocks for GHASH), against the one-shot result.
- Run in the declared, run-time and portable configurations (see the crate docs).
- `cargo mutants -p bouncycastle-asm` before a PR that touches the crate, with survivors explained in the PR.

## Status

The crate's callers meet these rules as of the 2026-10 migration (steps 1a-3, 2 and 3): typed
keys into `RoundKeys::expand`, and GHASH's bounds and stored proof.

A PR is held to these rules for the code it adds or changes. Two further proposals wait on decisions and are not rules yet:
denying `clippy::arithmetic_side_effects`, `indexing_slicing` and `cast_possible_truncation` (nothing in CI runs
clippy), and `overflow-checks = true` in release (its cost on the constant-time code is unmeasured).
