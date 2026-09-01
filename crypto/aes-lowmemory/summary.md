# `crypto/aes-lowmemory` — implementation summary

A constant-time, table-free AES block cipher engine (NIST FIPS 197), added on branch
`feature/officialfrancismendoza/100-AES-lightengine-CBC-mode`.

This document is the reviewer's orientation: what was built, why the design is the way it is, what
was verified and how, and — importantly — the three places where the working plan or model recall
turned out to be wrong. For end-user documentation see the crate docs in
[`src/lib.rs`](src/lib.rs); for the reasoning behind each individual constant, see the module docs
in [`src/bitslice.rs`](src/bitslice.rs) and [`src/round.rs`](src/round.rs), which are the right
place to start reading the source.

---

## 1. What this crate is (and is not)

It provides the **raw AES keyed permutation** — `Aes128`, `Aes192`, `Aes256` — transforming exactly
16 bytes at a time. It is not something you can encrypt data with: used directly on data it *is*
ECB, which is not confidential. Modes of operation and padding are separate layers.

Consistent with the earlier scoping decision for the AES engine, the crate deliberately ships:

* **no CLI subcommand** — a bare permutation can only offer ECB,
* **no factory registration**,
* **no `core` cipher-trait implementations** (`SymmetricCipher` / `BlockCipherEncryptor` /
  `BlockCipherDecryptor`) — those traits are about encrypting *data* and generating initialisation
  data, which are mode-of-operation concerns,
* **no `AlgorithmOID`** — NIST CSOR assigns AES OIDs per mode, never to the bare cipher.

It does implement `core::traits::Algorithm` (name and maximum security strength), which is
metadata rather than a data-encryption API.

---

## 2. Design

### 2.1 Why there is no lookup table

FIPS 197 Sec 5.1.1 presents the S-box as a 256-entry table (Table 4), and almost every AES
implementation stores it as one — 256 bytes, or 2–8 KiB for the "T-table" variants that fold
MixColumns in. A table indexed by a byte of the state is indexed by **secret data**, so on any CPU
with a data cache the access pattern, and therefore the timing, depends on the key. That is the
standard, repeatedly-demonstrated AES cache-timing attack, and it cannot be fixed while the lookup
remains.

Bouncy Castle's `AESLightEngine` in the Java and C# ports keeps two 256-byte S-box tables in order
to be *small*, not to be constant-time, and leaks through both the cipher and the key schedule.

This crate has no tables at all. The consequence worth stating plainly: **the low-memory AES and
the constant-time AES are the same implementation here.** Removing the tables is what makes it both.

### 2.2 Bit-slicing

The state is transposed so that each of eight `u32` words holds one *bit position* of every byte:
word `q[k]` collects bit `k` of all the bytes. In that representation the S-box becomes a fixed
Boolean circuit and one `&` or `^` applies a gate to every byte position at once. Nothing is ever
indexed by a secret and nothing branches on one.

Eight 32-bit words hold 256 bits = 32 bytes = **two** AES blocks, so blocks are processed in pairs.
ShiftRows and MixColumns become masks and rotations in the same representation, and the key
schedule is stored already bit-sliced, so no transposition happens inside the round loop.

### 2.3 The bit layout — derived, not assumed

`ortho` transposes, within each byte-lane of the eight words, the 8×8 bit matrix indexed by
(word number, bit number within the lane):

```
after ortho:  q[k] bit (8L + i)  ==  before ortho:  q[i] bit (8L + k)
```

`pack` loads block A as four little-endian `u32`s into the even words and block B into the odd
words, so before `ortho` byte-lane `L` of word `2c` holds `A[4c + L]`. Substituting `j = 4c + L`
and FIPS 197 Eq (3.6) `s[r,c] = in[r + 4c]` — which makes `r = j mod 4`, `c = j div 4` — gives:

```
q[k] bit (8r + 2c)      ==  bit k of s[r,c] of block A
q[k] bit (8r + 2c + 1)  ==  bit k of s[r,c] of block B
```

**The byte-lane of the word selects the state row `r`; the bit-pair within that lane selects the
state column `c`; the low bit of the pair is block A and the high bit is block B.**

```
           c=0   c=1   c=2   c=3
   r=0 |    0     2     4     6
   r=1 |    8    10    12    14      (bit position of block A;
   r=2 |   16    18    20    22       add 1 for block B)
   r=3 |   24    26    28    30
```

Everything else follows from this table:

* **ShiftRows** only permutes within rows, and a row is a byte-lane, so it is a rotation *inside*
  each byte-lane by `2r` positions (one column = two bit positions).
* **MixColumns** combines the four rows of a column, and `rotate_right(8)` moves one row, so it is
  expressible with rotations by 8 and 16 plus the `{1b}` reduction, with no shuffling.

`test_layout_matches_the_documented_table` pins this exhaustively. Every mask in the crate is only
correct relative to it, which is why it is written down rather than left implicit.

### 2.4 Both directions from one key schedule

Decryption follows **FIPS 197 Algorithm 3** (the straight inverse cipher), not the equivalent
inverse cipher of Sec 5.3.5. Algorithm 3 applies InvMixColumns *after* AddRoundKey, so it uses the
**unmodified** key schedule; Sec 5.3.5 reorders the round and needs a separate schedule with
InvMixColumns applied to every round key (Algorithm 5, `KEYEXPANSIONEIC()`).

Following Algorithm 3 is what lets one `Aes` value encrypt *and* decrypt from a single stored
schedule — no second copy, no transformation at construction time, no direction flag. That is the
whole reason both directions are available at 176–240 bytes of state.

### 2.5 Typing the three key sizes

The schedule length `4·(Nr+1)` (44/52/60 words) cannot be written as an expression over another
const generic parameter, so a params trait is used instead — the same pattern as the
`HashDRBG80090AParams_*` types in `bouncycastle-rng`:

```rust
pub trait AesParams: AesParamsSealed {
    const KEY_LEN: usize;   // 16 | 24 | 32      (FIPS 197 Sec 6.1)
    const NK: usize;        //  4 |  6 |  8
    const NR: usize;        // 10 | 12 | 14
    const ALG_NAME: &'static str;
    type Schedule: ZeroizablePrimitive + AsRef<[u32]> + AsMut<[u32]>;
}
```

`AesParams` has a **private** supertrait, so only the three types in `schedule.rs` can implement
it and no downstream crate can instantiate the cipher with an unapproved key length or round count.
(This is what `#![allow(private_bounds)]` in `lib.rs` is for.)

The three `new` constructors and `Algorithm` impls are written out **longhand rather than with
`macro_rules!`**, because `cargo mutants` cannot see into macro bodies and a macro would hide the
key checks and security-strength constants from mutation testing.

### 2.6 Memory

No lookup tables, no heap allocation. The only persistent state is the key schedule, stored in a
compressed bit-sliced form: bit-slicing is a permutation of bits so it does not change the size, and
because both interleaved blocks use the same key the two halves of a bit-sliced round key are
identical, so one word of each pair is redundant. `round_key` re-doubles a single round key onto the
stack when the round loop needs it.

| Type | Key | `Nr` | Schedule (persistent) | Tables |
|---|---|---|---|---|
| `Aes128` | 16 B | 10 | 176 B | 0 B |
| `Aes192` | 24 B | 12 | 208 B | 0 B |
| `Aes256` | 32 B | 14 | 240 B | 0 B |

These are **measured**, not asserted — `cargo run --release -p mem_usage_benches --bin bench_aes_mem_usage`
prints exactly 176/208/240, and `test_engine_sizes_match_the_documented_memory_table` pins them so
the doc table cannot drift.

Two things deliberately avoided: storing the doubled 8-plane schedule (352/416/480 B), and
mirroring BearSSL's `uint32_t skey[120]` 480-byte scratch buffer during expansion. `expand` writes
the classical schedule into the final array and then rewrites it in place, one round key at a time,
using eight words of stack.

Per-call stack usage is independent of key length: 32 B of bit-sliced state for the two blocks,
32 B for the expanded round key, plus circuit temporaries that mostly stay in registers.

### 2.7 API surface

```rust
Aes128::new(&KeyMaterial<16>) -> Result<Self, SymmetricCipherError>   // and 24 / 32
aes.encrypt_block(&mut [u8; 16])          // infallible
aes.decrypt_block(&mut [u8; 16])
aes.encrypt_blocks2(&mut [[u8; 16]; 2])   // the natural unit of work
aes.decrypt_blocks2(&mut [[u8; 16]; 2])
```

No `init()`, no `reset()`, no direction flag: constructors set up state and a constructed value is
always ready. There are no one-shot statics on the permutation because
`Aes128::new(&key)?.encrypt_block(..)` already *is* the one shot; data-level one-shots belong to the
modes, which take arbitrary-length input and generate their own initialisation data.

`encrypt_blocks2` / `decrypt_blocks2` are the pair form and roughly double throughput. A
single-block call duplicates the block into both halves and discards one result, so it does twice
the necessary work — modes whose blocks are independent (CTR, and the decrypt direction of CBC and
CFB) should prefer the pair form; CBC *encryption* cannot, since its blocks are serially dependent.

Duplicating rather than zero-filling the unused half costs the same and buys a free self-check (the
two halves must agree, which `debug_assert` verifies). It is not a security property — the unused
half is never returned either way.

---

## 3. Files

### New crate

| File | Lines | Contents |
|---|---|---|
| `Cargo.toml` | 18 | deps: `core`, `utils`; dev-deps: `hex`, `rng`, `criterion`, `serde_json` |
| [`src/lib.rs`](src/lib.rs) | 175 | Crate docs: Usage Examples, Design, Memory Usage, Security Considerations, Provenance |
| [`src/bitslice.rs`](src/bitslice.rs) | 210 | `ortho`, `pack`, `unpack`; the layout table and its exhaustive test |
| [`src/sbox.rs`](src/sbox.rs) | 377 | The 113-gate circuit; `inv_sbox`; Tables 4 and 6 for tests |
| [`src/round.rs`](src/round.rs) | 507 | AddRoundKey, ShiftRows, MixColumns and inverses; byte-wise references |
| [`src/schedule.rs`](src/schedule.rs) | 456 | `AesParams`, `expand` (Alg 2), `round_key`; Appendix A tables |
| [`src/aes.rs`](src/aes.rs) | 276 | `Aes<P>`, the three aliases, Alg 1 and Alg 3, key validation |
| [`tests/fips197_tests.rs`](tests/fips197_tests.rs) | 230 | Appendix B; two-block path; key handling |
| [`tests/sp800_38a_tests.rs`](tests/sp800_38a_tests.rs) | 176 | SP 800-38A F.1.1–F.1.6 |
| [`tests/acvp_tests.rs`](tests/acvp_tests.rs) | 266 | NIST ACVP `ACVP-AES-ECB` loader |
| [`benches/aes_benches.rs`](benches/aes_benches.rs) | 183 | criterion; key expansion and 16 KiB throughput, 1-block vs 2-block |

### Changed elsewhere

* `Cargo.toml` — `bouncycastle-aes-lowmemory` in `workspace.dependencies` and in the umbrella
  `[dependencies]`.
* `src/lib.rs` — `pub use bouncycastle_aes_lowmemory as aes_lowmemory;`.
* `mem_usage_benches/bench_aes_mem_usage.rs` (new, 131 lines), plus its `[[bin]]` entry in
  `mem_usage_benches/Cargo.toml` and a `mod` line in `mem_usage_benches/lib.rs`.
* `alpha_0.1.3_release_notes.md` — a "Major features" entry.

---

## 4. Verification

58 tests, all passing. The strategy is that **no expected value anywhere was written from
recall** — every one is transcribed from a downloaded specification PDF or an official vector file.

| Source | What is checked |
|---|---|
| FIPS 197 Table 4 / Table 6 | **Exhaustive**: all 256 inputs to `sbox` and `inv_sbox`. This is what makes the 113 gates trustworthy, so it must stay exhaustive. |
| FIPS 197 Sec 5.1.1 | The worked example `S[{53}] = {ed}`. |
| FIPS 197 Eq 5.5 / 5.8 / 5.12 / 5.15 | ShiftRows and MixColumns and their inverses, against byte-wise references written from the equations — plus a second literal transcription of Eq 5.8/5.15 cross-checking the matrix form. |
| FIPS 197 Sec 4.2 / Eq 4.5 | The test-only `xtimes`/`gf_mul` helpers against the Sec 4.2 worked chain and `{57}·{13} = {fe}`. |
| FIPS 197 Table 5 | `RCON` re-derived by repeated XTIMES and compared. |
| FIPS 197 Appendix A.1/A.2/A.3 | **Every one of the 156 schedule words**, for all three key lengths. |
| FIPS 197 Appendix B | The worked AES-128 block, both directions, and via the two-block path in both slots. |
| SP 800-38A F.1.1–F.1.6 | ECB known answers, all three key lengths, both directions. |
| NIST ACVP `ACVP-AES-ECB` | **2138 cases** (AES-128: 588, AES-192: 720, AES-256: 830), each checked in *both* directions and through both the single-block and two-block paths. |

### Why Appendix A is tested inside `src/schedule.rs`

The key schedule is deliberately not public API (a `Secret` field). A round-trip through the cipher
**cannot** validate it: a wrong `w[i]` is used by encryption and decryption alike, so the round trip
still succeeds. The Appendix A tests therefore live in the module, where `round_key` + `ortho`
decompress the stored schedule back to classical words so every `w[i]` can be compared against the
appendix directly. `tests/fips197_tests.rs` says so explicitly, so nobody mistakes its round-trip
test for schedule validation.

### The ACVP loader

Vectors come from `bc-test-data` at `crypto/aes_tdes_vectors/AES/ACVP-AES-ECB.4014527.rsp.json`.
If that repository is not checked out the test prints a warning and passes, matching the ML-KEM /
ML-DSA convention — `cargo test` stays green for someone who has only cloned this repo. A
`checked > 1000` assertion guards against a silently-empty run.

The response file records `key`, `pt` and `ct` for every case regardless of the group's declared
direction, so each is checked both ways; the request file's group metadata is not needed.

Two details worth knowing:

* Some AFT cases have multi-block plaintexts, so the loader iterates blocks (ECB).
* The set includes **all-zero keys** (the GFSbox-style groups). `KeyMaterial` tags an all-zero
  buffer `Zeroized` and refuses to promote it outside a hazardous closure — which is the right
  default, and `Aes128::new` rejecting it is itself tested. The *test* opts in via
  `do_hazardous_operations`; the engine's guard was **not** weakened to accommodate NIST.

### Only the ECB file belongs to this crate

`bc-test-data` ships thirteen ACVP AES vector sets, one per mode. This crate consumes only
`ACVP-AES-ECB`, because that is the set that tests the permutation rather than a mode.
`ACVP-AES-CBC` is consumed by [`crypto/modes/tests/acvp_tests.rs`](../modes/tests/acvp_tests.rs)
(2150 AFT cases). The remaining eleven — `CBC-CS1/2/3`, `CFB8`, `CFB128`, `OFB`, `CTR`, `KW`,
`KWP`, `FF1`, `FF3-1` — are unused because those modes are unimplemented, not because they are
untested. The table in the ACVP test module's docs records which file goes where, so adding a mode
includes wiring up its file.

### Constant-time hygiene audit

Mechanically checked, not merely claimed:

* **Every** indexing expression in non-test code is a literal constant (`q[0]`…`q[7]`), a loop
  counter over a fixed public range, or `4*round + j` where `round` counts over the public `Nr`.
  Not one index is derived from key or state bytes.
* The only branches in non-test code are on `i % Nk` and `Nk > 6` (public parameters) in the key
  expansion, and on key *metadata* (type, length, security strength) once at construction. None on
  key or state bytes.
* `SUBWORD()` in the key expansion goes through the same bit-sliced circuit as `SUBBYTES()`. A
  table-driven "light" AES that removes the tables only from the cipher still leaks through the
  schedule; this one does not.

Caveats are stated in the crate docs rather than glossed: the compiler is not contractually obliged
to preserve straight-line codegen; the 32-byte working state is not scrubbed after a block (only the
schedule is `Secret`); and constant-time execution says nothing about power or EM side channels.

### Gates

* `cargo fmt --all -- --check` — clean.
* `cargo build --workspace`, `cargo test --workspace` — clean, no failures.
* `cargo doc -p bouncycastle-aes-lowmemory --no-deps` — **zero warnings**.
* `cargo clippy -p bouncycastle-aes-lowmemory --all-targets` — **zero warnings** for this crate.
* `./dev_scripts/quality_stats.sh ./crypto/aes-lowmemory` — `Err()` in core code: **3**, exactly the
  three key rejections in `validate`. `unwrap()` in core code: 4, each a
  `try_into()` on a fixed-size window of a fixed-size array with a preceding justification comment.
  (Note: `cloc` and `bc` are not installed locally, so the line-count and ratio fields print 0.)

### Mutation testing

`cargo mutants -p bouncycastle-aes-lowmemory` — complete run, 32 minutes:

```
791 mutants tested: 762 caught, 19 missed, 10 unviable, 0 timeouts
```

Every one of the 19 misses was investigated. **18 are provable XOR/OR equivalences and no test can
kill them; 1 was a real coverage gap, since fixed.**

#### The 18 equivalences

| Count | Site | Mutation |
|---|---|---|
| 6 | `round.rs` `shift_rows` | `\|` → `^` |
| 6 | `round.rs` `inv_shift_rows` | `\|` → `^` |
| 2 | `bitslice.rs` `ortho::swap` | `\|` → `^` |
| 2 | `schedule.rs` `round_key` | `\|` → `^` |
| 1 | `schedule.rs` `expand` | `\|` → `^` |
| 1 | `sbox.rs` `sbox` (the `t37` gate) | `^` → `\|` |

`a | b` and `a ^ b` differ only where both operands have a set bit, so wherever the operands are
provably disjoint the two are the same function and no test can distinguish them. This is the
"XOR/OR equivalences in crypto code are acceptable" category named in `CLAUDE.md`. Each site is
disjoint for a different reason:

* **`shift_rows` / `inv_shift_rows`** — the seven masked terms have pairwise-disjoint destination
  bit ranges that together cover all 32 bits.
* **`ortho::swap`** — the masks are complementary and the shift equals the field width.
* **`expand`** — the compression combines `& 0x5555_5555` with `& 0xAAAA_AAAA`, complementary masks.
* **`round_key`** — `even` occupies only even bit positions and `even << 1` only odd ones (and
  conversely for `odd`).
* **`sbox`, the `t37 = t36 ^ t34` gate** — the interesting one, because it is a gate *inside* the
  circuit rather than a mask combination, and because a surviving mutant there would suggest the
  exhaustive Table 4 test had a hole. It does not: brute-forcing all 256 inputs shows `t36` and
  `t34` are **never both 1**, so XOR and OR agree, and the mutant changes the output for 0 of 256
  inputs. Sweeping the same mutation across every XOR gate confirms `t37` is the **only one of the
  77** with that property — every other `^ → |` mutant in the circuit is killed. So the exhaustive
  test is exactly as strong as claimed; this gate just happens to have disjoint operands.

Rather than leave the `shift_rows` case as an assertion, the underlying invariant is now tested:
`test_shift_rows_is_a_bit_permutation` pushes a single set bit through and requires exactly one bit
out, with the induced map a bijection on all 32 positions — precisely the disjointness and coverage
property, and it *would* fail if a mask ever overlapped or failed to cover. Every one of the six
sites also carries an in-code comment explaining why its mutant survives, so the next reader does
not have to repeat this investigation.

#### The one real gap, fixed

**`< → >` in `Aes<P>::validate`.** There was no test for a key whose security strength is *below*
the level its length implies; because `from_bytes_as_type` always tags a key at its length-implied
strength, neither `<` nor `>` was ever true and the two comparisons behaved identically.
`a_key_carrying_too_low_a_security_strength_is_rejected` now covers it (a 32-byte key lowered to
128-bit must be rejected by `Aes256::new`), and the fix was confirmed by hand-applying the mutation
and watching that test fail, then reverting.

This mutant still appears in the run output above, which analysed the pre-fix source — the fix
landed while the run was in flight. Re-running `cargo mutants` should therefore report **18 missed,
763 caught**, all 18 being the documented equivalences.

#### Unviable

The 10 unviable mutants are all `replace <fn> with Err(...)` / `with ()` on functions whose return
type does not admit the substituted value (`validate`, `Debug::fmt`, `encrypt2`). `cargo mutants`
counts these as unviable rather than missed; they are a property of the config's `error_values`
list, not a coverage gap.

---

## 5. Three corrections worth flagging to reviewers

### 5.1 The working plan's bit-layout claim is wrong

`bc-rust-aes-lowmemory-plan.md` §2 states the layout is "`q[k]` bit `2·j` is bit k of byte j of
block A". That is **false**. The correct layout, derived in §2.3 above and pinned exhaustively, is
`q[k]` bit `(8r + 2c)`. Anyone checking the ShiftRows or MixColumns constants against the plan's
version will conclude, wrongly, that they are all broken. The plan's own instruction — "Any place
BearSSL's constants and your FIPS 197 derivation disagree: the spec wins; re-derive, then look for
the misunderstanding (it will be in the layout table)" — turned out to point at the plan itself.

### 5.2 FIPS 197 Eq 5.6 is `[{02},{01},{01},{03}]`

Not `[{02},{03},{01},{01}]`, which is the first *row* of the Eq 5.7 matrix rather than the defining
word of Sec 4.3. Sec 4.3 Eq (4.8) defines matrix entry `(r,k)` as `a[(r-k) mod 4]`, and both
MixColumns and InvMixColumns use that same convention — Eq 5.13's `[{0e},{09},{0d},{0b}]` is
correct as printed.

This one was written into a test constant from memory and caught by the failing test. It is worth
recording because of *how* it fails: supplying the matrix row instead of the defining word silently
transposes the matrix, which leaves the InvMixColumns test **passing**, so only the forward test
detects it. A literal transcription of Eq 5.8 and Eq 5.15 was added as a second, independent
reference (`test_the_two_reference_forms_agree`) so the convention is pinned from both directions,
and `MIX_COEFFS` carries a comment about the trap.

### 5.3 The plan's "PR B" is unnecessary

The plan calls for downloading CAVP AESAVS `.rsp` files and opening a PR against `bcgit/bc-test-data`
to add them. `bc-test-data` **already** ships NIST ACVP AES vectors for every mode, including
`crypto/aes_tdes_vectors/AES/ACVP-AES-ECB.4014527.{req,rsp}.json` — 2138 AFT cases across all three
key lengths, more coverage than the AESAVS KAT/MMT files would have provided. No PR to
`bc-test-data` is needed. `serde_json` as a dev-dependency is the established way to read these
files (see the ML-KEM and ML-DSA suites).

---

## 6. Scope deliberately not implemented

| Item | Why |
|---|---|
| `BlockPermutation` trait impls, and `encrypt_blocks2`/`decrypt_blocks2` as trait methods | The trait does not exist in `crypto/core`, which has the mode-level `BlockCipher` / `BlockCipherEncryptor` / `BlockCipherDecryptor`. Introducing it is the plan's separate "PR A". The two-block entry points are inherent methods for now; promoting them to provided trait methods is a one-line delegation once the trait lands. |
| `core-test-framework` conformance test | Follows from the above — there is no test suite for a raw permutation yet. |
| ACVP MCT (Monte Carlo) groups — 6 cases | Their expected `resultsArray` comes from a chained key/plaintext update rule defined in the ACVP AES specification, not in FIPS 197. Implementing it from anything other than that specification would be guesswork. The test reports the skip count so the gap is visible rather than silent. |
| CLI subcommand | A bare permutation only does ECB. `aes128-cbc-*` / `-cfb-*` belong with the modes crate. |
| Factory registration | No `BlockCipherFactory` exists; not adding one here. |
| bc-java `AESLightEngine` cross-check | The plan marks it developer-local rather than committed, and 2138 ACVP vectors plus the spec appendices make it redundant. |

---

## 7. Provenance and attribution

* **Normative reference: NIST FIPS 197** (including Update 1). Every transformation cites its
  section, algorithm and equation numbers, verified against a freshly downloaded copy of the PDF.
* **The S-box circuit** is the 113-gate straight-line program `SLP_AES_113.txt` from Peralta's
  circuit collection — 32 AND, 77 XOR, 4 XNOR — described in J. Boyar and R. Peralta, "A new
  combinational logic minimization technique with applications to cryptology",
  <https://eprint.iacr.org/2009/191.pdf>. The gate list was transcribed **mechanically** from the
  SLP file (`+` → `^`, `x` → `&`, `#` → `!(..^..)`, names unchanged apart from case) and the result
  diffed against the generator output to rule out transcription error. It is not meaningful line by
  line and should not be "tidied"; it is verified as a whole by the exhaustive Table 4 test.
* **The bit-sliced two-block structure**, the transpose, and the ShiftRows/MixColumns mask and
  rotation constants are translated from BearSSL's `aes_ct` implementation by Thomas Pornin
  (`src/symcipher/aes_ct.c`, `aes_ct_enc.c`, `aes_ct_dec.c`, `aes_ct_cbcdec.c`), **MIT licensed**.
  Each constant is re-derived from the documented layout in the comments and pinned by a test
  against a byte-wise reference written from the FIPS 197 equations.

Two notes on where the sources disagree, both resolved in favour of the SLP file:

* Its bottom linear transformation (`tc1..tc26`) **differs from** BearSSL's (`t46..t67`), and its
  `t17`/`t21` are re-associated relative to BearSSL's. Both compute the same S-box.
* The SLP numbers inputs and outputs with `U0`/`S0` as the **most significant** bit, so `U0` is
  plane `q[7]`. Reversing this produces a wrong S-box, not a subtly different one; the exhaustive
  Table 4 test is what pins it.

**Open question for maintainers:** how attribution for the BearSSL translation and the
Boyar–Peralta circuit should be recorded — file headers only (current state), a top-level `NOTICE`
file, or both. This is a licensing/policy call rather than a technical one.

---

## 8. Reproducing the checks

```sh
cargo build -p bouncycastle-aes-lowmemory
cargo test  -p bouncycastle-aes-lowmemory              # 58 tests
cargo test  -p bouncycastle-aes-lowmemory --test acvp_tests -- --nocapture   # prints the ACVP count
cargo doc   -p bouncycastle-aes-lowmemory --no-deps    # expect zero warnings
cargo clippy -p bouncycastle-aes-lowmemory --all-targets
cargo fmt --all -- --check
cargo bench -p bouncycastle-aes-lowmemory
cargo mutants -p bouncycastle-aes-lowmemory
./dev_scripts/quality_stats.sh ./crypto/aes-lowmemory

# struct sizes; add the massif recipe in the file header for stack measurement
cargo run --release -p mem_usage_benches --bin bench_aes_mem_usage
```

The ACVP tests additionally need `bc-test-data` cloned as a sibling of this repository; without it
they print a warning and pass.

---

## 9. Open items before merge

1. **Decide the attribution form** for the BearSSL translation and the Boyar–Peralta circuit (§7):
   file headers only (current state), a top-level `NOTICE`, or both. A licensing/policy call rather
   than a technical one.
2. **Confirm the PR base branch.** The plan specifies `release/0.1.3alpha`, set explicitly — GitHub
   defaults to `main`.
3. Decide whether `BlockPermutation` (plan PR A) lands before or after this crate, since it
   determines whether the two-block entry points become trait methods now or later (§6).
4. Note in the PR description that the plan's layout claim (§5.1) and PR B (§5.3) are superseded, so
   the plan document does not mislead the next reader.
5. Optionally re-run `cargo mutants` to confirm the expected 18 missed / 763 caught (§4). The 19th
   miss was fixed while the recorded run was in flight, so the numbers above under-report by one.
