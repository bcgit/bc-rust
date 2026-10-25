# Case studies behind the rules (bc-rust, September 2026)

Every number is a massif peak in bytes on the `mem_usage_benches` harness, release build, x86_64,
measured before and after a single change. "Full" is `bouncycastle-mldsa` / `-mlkem`; "lowmem" is
the `-lowmemory` crate.

## 1. "Only 32 bytes" was not free

`make_hint_row` in mldsa-lowmemory took `out: &mut HintRow` (32 bytes) and returned the weight.
Changing it to return `(HintRow, i32)` by value, on the argument that 32 bytes cannot matter, added
exactly **+16 bytes** of peak on all three lowmem sign benches. Returning just `HintRow` and computing
the weight with popcount: also +16. Reverted. The sibling `unpack_h_row` on the verify path went to
`Option<HintRow>` at measured **0** bytes, because it was already the deepest frame there. Same
type, same size, opposite results: the frame context decides, not the type.

## 2. Decaps benches were measuring keygen

Every ML-KEM decaps bench called `keygen_from_seed` inside the measured binary. Hard-coding the
encoded private key instead:

| | old | in-main decode | helper decode |
|---|---|---|---|
| ML-KEM-512 decaps | 24136 | 28408 | 21592 |
| ML-KEM-768 decaps | 39800 | 44072 | 33416 |
| ML-KEM-1024 decaps | 63800 | 62792 | 49224 |

The "in-main" column is the first attempt, with the key byte array and `from_bytes` in the bench
body: worse than keygen for 512 and 768, because the array and the `Result` temporary stayed live
under decaps. Moving the load into an `#[inline(never)]` helper gave the third column. The old table
had over-reported decaps by up to 14.6 kB.

## 3. Sign 44 went up 8.7 kB with no code change in sign

After item 2's helper pattern was applied to ML-DSA, `Sign/ML-DSA-44` rose 93720 → 102456 with
identical instruction counts. Frame remarks: the bench `main` was 73608 bytes in both builds with
sign fully inlined into it. The key-load helper (12.5 kB) and `from_bytes` (14.6 kB) were being
called from that `main`, so they stacked on top of the already-allocated 73.6 kB frame. Fix: run the
operation in a separate non-inlined, non-returning closure so load and op are sibling frames.
Residual after the fix: **+2.1 kB**, the boundary's own spills. A wrapper that *returned* the
signature cost 4.6 kB instead: the 2.4 kB result was copied across the boundary.

## 4. Plain/expanded pairs reporting identical peaks

Before the harness rework, every `Encaps`/`Encaps_expanded_pk` pair and every
`Sign`/`Sign_expanded_sk` pair reported byte-identical peaks. That only happens when the key decode
in the bench body, not the operation, sets the peak. Treat identical numbers across variants that
do different work as a harness bug, not a coincidence.

## 5. A heap `Vec` deleted 3 to 5 kB from two table rows

`bench_mldsa65_lowmemory_verify` and the 87 variant decoded their signature with `hex::decode` into
a `Vec<u8>`. Massif `--heap=no` ignores the heap, so those rows under-reported by one signature
each (3309 and 4627 bytes) relative to the 44 row, which used a stack array. Converting them moved
the rows 15864 → 19096 and 17784 → 22328.

## 6. `sig_decode` returned an 11 kB tuple

`fn sig_decode(sig) -> Result<(SigCTilde, VecL, VecK), ()>`. When LLVM inlined it, fine. When fed a
runtime-length slice it did not inline it, and the remarks showed three copies of the 11.3 kB tuple
live at once (local, return slot, destructured bindings) plus `sig_decode`'s own 23.6 kB frame under
verify: **+18 to +24 kB** depending on caller shape. Out-parameters (`c_tilde: &mut, z: &mut,
h: &mut`, returning `Result<(), ()>`) removed it structurally: full-crate verify −6 to −20 kB across
parameter sets, 44 sign −9 to −12 kB.

## 7. `Matrix::new()` built a 56 kB temporary through `array::map`

`Self { elems: [[(); l]; k].map(|_| [(); l].map(|_| Polynomial::new())) }` goes through
`core::array::drain::drain_array_with`, which materialises the full matrix before copying it. It was
invisible until the fix in item 6 changed inlining and a **57368-byte** `drain_array_with` frame
appeared under `expandA`, adding 47 kB to one bench. Repeat expression `[[Polynomial::new(); l]; k]`
(elements are `Copy`, `new` is `const`) removed it. The same pattern in the full `mlkem` crate was
*not* being materialised (its matrix is 4 to 16 kB and LLVM folded it); changing it there moved
three table rows up 2 to 3 kB from inlining alone, so it was reverted. Structural correctness did
not win over measurement.

## 8. An unused `match` arm cost 57 kB

```rust
match a_hat {
    Some(a) => sign_internal(sk, a, ...),
    None => { let mut a = Matrix::new(); sk.expand_into(&mut a); sign_internal(sk, &a, ...) }
}
```
The `None` arm's local is allocated in the frame on both paths, so every expanded-key caller paid
for a matrix it never used (`sign_mu_deterministic` frame 62 kB). Fix: the arm calls an
`#[inline(never)]` helper that owns the local. Cost: 5 to 6 kB on the plain paths for the extra
boundary, which was accepted.

## 9. Converting a return to an out-parameter added a copy

`fn A_hat(&self) -> M { expandA(&self.rho) }` was a tail call; LLVM forwarded the return slot into
`expandA`, so only `expandA`'s own local existed. After `expandA` took `&mut M`, `A_hat` became
`let mut m = M::new(); expandA(&self.rho, &mut m); m`, and LLVM did not elide the move: the by-value
`A_hat()` path gained a full extra matrix. Keygen and plain verify improved by 13 to 49 kB and 12 to
50 kB from the same change, expanded-key construction regressed by 10 to 53 kB. Constructors of the
form `let mut s = Self { big: M::new(), .. }; fill(&mut s.big); s` showed three copies; returning a
struct literal built from locals showed two. Getting to one copy for a by-value constructor was not
achievable in safe Rust without an out-parameter API; that became a follow-up.

## 10. The deleted reduction

Not a memory case, but found with the same tools and worth keeping next to them. A plain `reduce32`
before `inv_ntt` existed from the first ML-DSA commits, was commented out on 2026-03-20 because
`cargo mutants` and the full bc-test-data set passed without it, and was deleted the next day. In
September 2026 Wycheproof's `MissingReduction` vectors showed the 8-level inverse-NTT butterflies
overflow `i32` when fed an unreduced sum of `l+1` Montgomery products: a valid signature rejected and
a forgery accepted in release. Restored at all nine accumulation sites in both crates; Criterion
showed the cost below the noise floor (median −0.7 % across 30 benches, one +5 % outlier that
re-ran at −1.3 %). Bound-keeping steps are dead code to every test that uses honest inputs.

## Measured noise floors on this harness

| Crate family | Layout noise between builds |
|---|---|
| lowmem (ML-KEM, ML-DSA) | ≤ 0.2 kB |
| full ML-KEM | 1 to 4 kB |
| full ML-DSA | 2 to 9 kB |

Massif itself is deterministic: identical binaries give identical peaks. The noise is in what the
compiler does with a differently shaped caller, not in the measurement.
