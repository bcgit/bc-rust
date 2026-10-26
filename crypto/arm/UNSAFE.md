# Rules for code that reaches `unsafe` in `bouncycastle-arm`

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

## Tests

- Each const-generic check has a `compile_fail` doctest on the public item showing a rejected value.
- Each runtime bound is tested at its maximum, one past it, zero, and at `u32::MAX` / `u64::MAX` / `usize::MAX` where
  a width changes.
- Every whole-block loop is fed each length from 0 to two blocks plus one and across each batching boundary (four
  blocks for GHASH), against the one-shot result.
- Run in the declared, run-time and portable configurations (see the crate docs).
- `cargo mutants -p bouncycastle-arm` before a PR that touches the crate, with survivors explained in the PR.

## Not yet met

The crate's callers break these rules in three places:

- `RoundKeys::expand` in `aes/src/hazmat/engine.rs` takes the key as `&[u8]` and converts it with
  `try_into().expect(..)`.
- GHASH in `cipher/src/modes/gcm.rs` does `pending_len` arithmetic without bound comments, slices a `[u8; 16]` with
  `expect` in `block_from_bytes` and `Ghash::new`, and has no resume test at `pending_len` 15 and 16.
- GHASH asks the CPU on every call instead of storing the proof at construction.

A PR is held to these rules for the code it adds or changes. Two further proposals wait on decisions and are not rules yet:
denying `clippy::arithmetic_side_effects`, `indexing_slicing` and `cast_possible_truncation` (nothing in CI runs
clippy), and `overflow-checks = true` in release (its cost on the constant-time code is unmeasured).
