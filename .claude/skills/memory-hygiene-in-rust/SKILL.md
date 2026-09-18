---
name: memory-hygiene-in-rust
description:
  How to keep peak stack memory down for free in any Rust crypto code, and how to measure it honestly. Applies to every crate under crypto/*, not only the *_lowmemory ones: those crates trade performance for memory by algorithmic design, whereas everything here costs nothing and there is no reason to be wasteful anywhere. Use this whenever work adds or changes a function signature, return type, constructor, key or signature decoder, or anything holding a polynomial, vector, matrix or byte array of a kilobyte or more; whenever a change touches `mem_usage_benches` or a "Memory Usage" table in a crate's docs; and for any claim about copies, stack frames, out-parameters, `.try_into()`, return-by-value, `#[inline(never)]`, `.clone()`, `Copy` derives, valgrind/massif, or "does this change affect memory". Also use it when reviewing a PR that says a change is "free", "zero-cost" or "just a small struct", and when a bench number moved and nobody knows why. This work is easier to get right with a strong model (Fable or higher); if the session model is weaker, say so and measure twice as much.
---

# Memory Hygiene in Rust

Peak stack usage is a property of the compiled binary, not of the source. Two pieces of code that are equivalent to a
human can differ by tens of kilobytes at run time depending on what LLVM inlines, which copies it elides, and how the
*caller* is shaped. Everything below follows from that. The single rule: **a claim about stack cost is a hypothesis
until massif has measured it.**
Type size is not a result. "It's only 32 bytes" cost 16 bytes of peak in this repo; "it's a 56 kB matrix, of course it
copies" turned out to be already elided. Measure, then say.

Read `references/case-studies.md` when you want the measured numbers behind any rule here; each rule cites its case.

**Scope: every crate, not just the low-memory ones.** In this library "lowmemory" names an algorithmic trade: those
crates drop intermediate values immidiately after use and re-derive them as-needed on-demand instead of holding them,
and pay for it in throughput. That trade is a design decision confined to the
`*_lowmemory` crates and is out of scope here. This skill is about the other kind of saving, the copies and frames that
cost nothing to remove and nothing to keep removed: a borrowed field instead of a clone, an out-parameter instead of a
return slot copy, a repeat expression instead of an array `map`. Those apply identically to `mldsa`, `mlkem`, the hashes
and everything else under
`crypto/`. Being wasteful in a full-featured crate is not a feature of that crate.

## 1. Where copies come from

Rust moves are memcpys unless the optimizer proves it can build the value in place. It often can, and the exceptions are
what this section is about. In descending order of how often they bit:

- **Return-by-value of a large type.** The callee builds the value in its own frame and copies to the caller's slot,
  unless LLVM forwards the slot. Passing an out-parameter (`out: &mut T`) makes the destination explicit. The lowmem
  crates use this everywhere; the full crates should too. *But see §2: converting a tail-call return into an
  out-parameter can add a copy.*
- **Tuples and `Result`/`Option` of large types.** `fn f() -> Result<(A, B, C), E>` for kilobyte
  `A, B, C` left three copies live at once when not inlined: the local, the return slot, and the destructured bindings.
  Write into caller buffers and return `Result<(), E>`.
- **`.try_into()` from a slice.** `let x: [u8; N] = s.try_into().unwrap()` copies N bytes.
  `let x: &[u8; N] = s.try_into().unwrap()` borrows. Always write the type; the difference is one
  `&`.
- **`.clone()` of a stored field to pass a reference.** `f(&self.matrix.clone())` when
  `f(&self.matrix)` was possible. Give the field a `pub(crate)` or a `&`-returning accessor.
- **Array `map` / `array::from_fn` to build a big array.** `[[(); l]; k].map(|_| ...)` goes through `core::array::drain`
  and materialises the whole array in a temporary before copying it into place. Use a repeat expression instead:
  `[[Polynomial::new(); l]; k]` for a `Copy` element, or `[[ZERO; l]; k]` with a `const ZERO` for any type.
- **Copying a `Copy` type by naming it.** `let r0 = w;` on a `Copy` polynomial vector is a copy unless `w` is dead
  afterwards and LLVM reuses the slot. Reuse the buffer explicitly (`w.sub_vector(&x)` in place) when the old value is
  not read again, and say so in a comment.
- **Pass-by-value parameters** for anything bigger than a couple of machine words. Take `&T`.
- **Building `Self` in a local, mutating it, returning it.**
  `let mut s = Self { a, big: Big::new() }; fill(&mut s.big); s` was three copies of `Big`
  (local, return slot, binding). Build parts in locals and return a struct literal, or better, expand directly into a
  caller-owned struct through an in-place method.

### The structural answer: kilobyte types should not be `Copy`

Most of the list above exists because `Polynomial` (1 kB) and `Vector<LEN>` (4 to 8 kB) derive
`Copy`. A `Copy` type duplicates silently: `let r0 = w;` is an 8 kB memcpy the compiler never mentions, and whether it
survives depends on the optimizer. Wrapping the array in a newtype that derives `Clone` but not `Copy` changes the
accounting rather than the code: moves still compile to the same memcpys and are elided exactly as before, but every
duplication is now either a move (the source becomes unusable, so it cannot be an accident) or an explicit `.clone()`
that shows up in a grep. Implicit copies become compile errors, and the copy audit in §3 becomes complete by
construction. `Secret<T>` already uses this shape for zeroization, so the pattern is established.

Two couplings to handle when doing it here:

- `ZeroizablePrimitive` currently requires `Copy` on the wrapped type as a proxy for "has no
  `Drop`", so `Secret<Polynomial>` stops compiling until that bound is replaced by a sealed marker trait that says the
  same thing directly.
- Array repeat expressions need `Copy` or a `const` operand. `[[Polynomial::new(); l]; k]` becomes
  `[[ZERO; l]; k]` with `const ZERO: Polynomial = Polynomial::new();`, which is allowed for any type.

## 2. Frames, not values: what actually sets the peak

Peak = the deepest stack pointer ever reached = sum of all frames live at that instant. Frames are allocated in full at
function entry, so what matters is *which function a value's slot lands in*
and *what else is live in that function*.

- **Inlining merges frames.** When `verify` is inlined into its caller, verify's 36 kB of working vectors are allocated
  for the caller's entire lifetime, including while the caller is still doing something else (expanding a key,
  decoding). Two frames that would have been siblings become one large frame. This is the mechanism behind most "why did
  the number move?" mysteries.
- **A `let` in an unused `match` arm still costs its full size.** The slot exists on every path.
  `None => { let mut a = Matrix::new(); ... }` charged every `Some` caller 57 kB. Move the arm's body into a separate
  `#[inline(never)]` function so the slot exists only when taken.
- **Every boundary costs a copy of what crosses it.** A non-inlined call returning a 2.4 kB signature by value costs 2.4
  kB in the caller and 2.4 kB in the callee. A closure that returns a value has the same cost. If you add a boundary to
  isolate a frame, make nothing cross back.
- **`#[inline(never)]` is a tool, not a fix.** It guarantees a frame is popped before the next call, which is exactly
  right for one-shot setup such as key loading or decoding. It costs a few kB of spills on hot paths and should never be
  sprinkled on the algorithm itself without a measurement showing why.
- **LLVM's copy elision is fragile.** A tail call `fn a() -> M { expand(rho) }` has its return slot forwarded straight
  through; the copy never exists. Rewriting `expand` to an out-parameter turns that into
  `let mut m = M::new(); expand(rho, &mut m); m`, a local plus a move that LLVM does *not*
  reliably elide, so the "optimisation" added a 57 kB copy. Whenever you change a return convention, measure both the
  callers that were fine and the ones you were fixing.

## 3. Rules of engagement for a change

1. **Baseline first.** Measure the benches the change could touch on the unmodified tree. Use a git worktree if you need
   to keep editing meanwhile; never `git stash` while a bench runner is rewriting files in the same tree.
2. **Change one thing.** Each structural edit (a signature, a constructor shape, an inlining attribute) can move numbers
   in unrelated benches through layout. If you bundle three edits and the numbers move, you will not know which one did
   it.
3. **Measure after, in bytes, for every affected bench**, not a sample. Report a table of before / after / delta and
   state the *cause* of each delta, not just the sign. Deltas you cannot explain are not done.
4. **Verify outputs are identical** (same signature, same shared secret, verify still succeeds). A memory optimisation
   that changes output is a bug, and the bench is the cheapest place to catch it.
5. **Audit every `.clone()` on a kilobyte-sized type**, and put each into one of four bins:
    - *Field-wise `Clone` impl of a key struct*: the copy is the point. Keep.
    - *Storing a key or seed into long-lived state* (a streaming verifier's `Option<PK>`): once per session. Keep.
    - *Clone-then-transform*: `let mut y_hat = y.clone(); y_hat.ntt();`. A second buffer is real, but
      copy-then-transform writes every coefficient twice. Prefer `ntt_into(&y, &mut y_hat)`
      when the transform can write its output directly; same peak, less work, explicit destination.
    - *Clone to hand out a reference*: `f(&self.matrix.clone())`. Never. Borrow the field or add a
      `&`-returning accessor. This bin held the 57 kB case. Twenty-odd clones per crate is normal; the audit is a
      ten-minute grep and it is where the large, avoidable copies hide. With non-`Copy` newtypes (§1) these bins are the
      *only*
      duplications in the crate.
6. **Prefer structural fixes over lucky ones.** If a copy disappears only because the inliner happened to cooperate, it
   will reappear when the caller changes shape. The fix is real when the copy is *impossible*: an out-parameter, a
   repeat expression, a borrowed field.
7. **Expect noise and know its size.** On this repo's harness, lowmem crates move by about ±0.1 kB between layouts; full
   crates by ±1 to ±9 kB. A change inside that band on a full crate is not evidence of anything. Run twice if it
   matters; massif itself is deterministic.
8. **Never trade a table-row increase for an off-table benefit silently.** If a change helps
   `Verify_with_expanded_key` (no table row) and costs plain `Verify` (a table row) 6 kB, say so and let the maintainer
   choose.

## 4. Building a measurement harness

The repo's harness is `mem_usage_benches/`: one binary per algorithm family, `main()` calls exactly one bench function,
and the peak is read from valgrind massif with `--heap=no
--stacks=yes`. `scripts/massif_peak.sh` in this skill does the whole loop for a list of bench functions. What it took
several iterations to learn about the *shape* of a bench function:

```rust
/// Loads the key. #[inline(never)] so its byte array and decode temporaries are popped
/// before the operation runs; otherwise the bench reports load + op instead of max(load, op).
#[inline(never)]
fn load_mldsa44_sk() -> MLDSA44PrivateKey {
    MLDSA44PrivateKey::from_bytes(&[ /* hard-coded encoded key */ ]).unwrap()
}

/// Runs the operation in its own frame. Returns nothing so no result crosses the boundary.
#[inline(never)]
fn measure(f: impl FnOnce()) { f() }

fn bench_mldsa44_sign() {
    eprintln!("MLDSA44/Sign");
    let sk = load_mldsa44_sk();
    let msg = b"...";
    measure(|| {
        let mu = MLDSA44::compute_mu_from_sk(&sk, msg, None).unwrap();
        let sig = MLDSA44::sign_mu_deterministic(&sk, None, &mu, [0u8; 32]).unwrap();
        print!("{:x?}", sig);   // inside: keeps the optimizer honest, and nothing is returned
    });
}
```

Why each part is the way it is:

- **Hard-coded keys, never `keygen` in the bench.** Keygen's frame is often larger than the operation's, so the old
  benches were reporting keygen. Dump the encoded key once from a commented-out setup block and paste the bytes.
- **Key load in a non-inlined helper.** The operation gets inlined into whatever function calls it, so that function's
  frame is allocated on entry; a load done in the same function stacks on top of it. Sibling frames give max (load, op);
  parent/child gives the sum. This mattered by up to 14.6 kB per row.
- **Operation in a non-inlined, non-returning closure.** For the same reason, in the other direction: it keeps the
  operation's frame from being allocated during the load, and it keeps a by-value result from being copied back.
- **Inputs (ciphertext, signature) on the stack in the bench body, never in a heap `Vec`.**
  Massif with `--heap=no` does not measure the heap cheaply, it ignores it. A `hex::decode`
  into a `Vec` silently deleted 3 to 5 kB from two table rows for months. If you want to exclude inputs from the number,
  put them in `static` storage and say so in the methodology text; the heap is never the honest answer for a `no_std`
  target.
- **Expanded-key variants** expand inside `measure`, since the expansion is the cost being measured, but from a plain
  key loaded by the helper.
- **Keep the do-nothing baseline** (`bench_do_nothing`) and quote it under the table; a row equal to it is at the noise
  floor, not a measurement.

Massif gives a time series too. When a peak moves, look at *when* it occurs (`time=` vs
`mem_stacks_B=` in the massif file) before theorising: a peak at 4 % of the run is key loading, a peak at 40 % is the
operation.

## 5. Finding the copy: frame layout remarks

Do not read `objdump` prologues for this: any frame over 4 kB is allocated by a stack-probe loop, so every large
function shows `sub rsp, 0x1000`. Use LLVM's remarks, which work on stable:

```
RUSTFLAGS="-C remark=stack-frame-layout -C remark=prologepilog -C debuginfo=1" \
  CARGO_TARGET_DIR=/tmp/remarks cargo build --release -p mem_usage_benches --bin <bin> 2> remarks.txt
python3 .claude/skills/memory-hygiene-in-rust/scripts/frame_layout.py remarks.txt [name-filter]
```

`prologepilog` prints `N stack bytes in function 'name'` per function; `stack-frame-layout`
lists every stack object with its size. Compare the two builds (before/after, or slice-fed vs array-fed) and the extra
copy is the object that appears twice or the frame that appeared at all. Two traps: names are v0-mangled (the script
demangles crudely), and **filter on nothing at first**: the 57 kB `core::array::drain::drain_array_with` frame hid for
an hour behind a
`grep mldsa`. Use a separate `CARGO_TARGET_DIR` so the remark build does not invalidate the normal one, and note
`debuginfo=1` did not change any frame size in practice.

## 6. A different class of copy: byte views, and the `zerocopy` crate

Everything above is about copies of *typed* values: moves at return boundaries, temporaries, frames. There is a second
class this repo has not yet hit: copying bytes out of a buffer just to give them a type, i.e. parsing a wire format into
a struct by memcpy when the bytes were already laid out correctly. Signs that you are looking at it: a `from_bytes` that
does nothing but
`copy_from_slice` field by field into a `#[repr(C)]`-shaped struct, a `[u8; N]` that is only ever reinterpreted as
`[u32; N/4]`, or a parser whose output is byte-identical to its input.

For that class the right tool is the `zerocopy` crate (Google; v0.8.x, `no_std`): derive
`FromBytes`, `IntoBytes`, `KnownLayout`, `Immutable` or `Unaligned` on the type and view a `&[u8]`
as a `&T` or `&[T]` with no copy and no `unsafe` in this repo's code. The `unsafe` lives inside the crate, which is one
of the most heavily reviewed in the ecosystem and is what the Rust standard library ecosystem itself leans on for this
job.

Two cautions. First, check that the problem is really reinterpretation: the ML-DSA and ML-KEM decoders bit-unpack 10-,
13-, 18- and 20-bit fields into `i32` arrays, which is a transformation, so there is nothing there for `zerocopy` to
remove, and the only pure reinterpretation in those paths, `&[u8]` to `&[u8; N]`, is already free via `try_into` on a
reference. Second, QUALITY_AND_STYLE.md's rule is zero external runtime dependencies, and every crypto crate is
`#![forbid(unsafe_code)]`. `zerocopy` is a plausible candidate for a deliberate exception to the dependency rule on
reputation grounds, but that is a maintainer decision to raise explicitly in the PR, with the measured copy it removes,
not something to pull in quietly.

## 7. Related lessons that are not about memory but were learned the same way

- **A step that only matters in the worst case is invisible to `cargo mutants` and KATs.** The plain `reduce32` before
  `inv_ntt` was deleted in March 2026 because mutants and the full bc-test-data set passed without it; six months later
  a Wycheproof vector showed it let a forgery through. Before deleting a reduction, range check, or bound-keeping step
  because "nothing fails", find the input-bound argument it serves. Prefer a `debug_assert!` on the bound to deletion.
- **Perf claims get the same treatment as memory claims.** Criterion with `--save-baseline` /
  `--baseline`, all benches, then rerun any single outlier with a longer window before believing it. A 5 % "regression"
  on one bench whose siblings show −0.5 % is noise until it reproduces.
- **In-repo tests are for developer mistakes; adversarial vectors live in bc-test-data and wycheproof.** Do not copy
  external vectors into the repo as regression tests. Do add a unit test of a helper's contract (congruence, range,
  boundaries) when you add the helper.

## 8. Model note

Most of the wrong turns in the history behind this skill were plausible-sounding hypotheses about what the compiler did,
stated confidently and then contradicted by measurement. The work needs a model that will hold a claim loosely, run the
measurement, read a stack-frame dump without filtering it to what it expects, and change its mind in public. That has
worked with Fable-class models; with a weaker model, insist on the before/after table for every change and do not accept
"should be free" from it or from yourself.
