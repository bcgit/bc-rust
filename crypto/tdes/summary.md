# `crypto/tdes` — implementation summary

A constant-time, table-free Triple DES (TDEA) block cipher engine, NIST SP 800-67 Rev 2, added on
branch `feature/tdes` following the layout of `crypto/aes`.

This document is the reviewer's orientation: what was built, why the design is the way it is, what
was verified and how, and the decisions a reviewer may want to revisit. For end-user documentation
see the crate docs in [`src/lib.rs`](src/lib.rs); for the derivation of every constant, see the
module docs in [`src/sbox.rs`](src/sbox.rs), [`src/des.rs`](src/des.rs) and
[`src/schedule.rs`](src/schedule.rs), which are the right place to start reading the source.

---

## 1. What this crate is (and is not)

It provides the **raw three-key TDEA keyed permutation**, `TDES`, transforming exactly 8 bytes at a
time, plus type aliases (`TDES_CBC`, `TDES_CFB`, `TDES_CFB8`, `TDES_CTR`, `TDES_ECB`) over
`bouncycastle-modes` that fix the key and block lengths; and a **decryption-only two-key**
permutation, `TDES2Key` (16-byte `Key1 || Key2`), with `TDES2_*` decryptor aliases. Consistent
with `crypto/aes`:

* the permutation implements `core::traits::ElectronicCodeBook` and `Algorithm` only; the
  data-encryption traits belong to the modes,
* no factory registration (the factories have no block-cipher slot),
* no `AlgorithmOID`,
* one `bc-rust` subcommand per mode: `tdes-cbc`, `tdes-cfb`, `tdes-cfb8`, `tdes-ctr`, `tdes-ecb`,
  and their decrypt-only `tdes2-*` counterparts.

It is a **legacy algorithm**. SP 800-67 Rev 2 was withdrawn on 1 January 2024 and SP 800-131A Rev 2
disallows three-key TDEA encryption after 2023 (decryption is "legacy use"). The crate docs say so
prominently; the crate exists for data and protocols that still depend on TDEA.

---

## 2. Design

### 2.1 The S-box layer is a compile-time-derived Boolean circuit

The eight S-boxes are viewed as thirty-two 6-to-1-bit functions ("T-boxes", BearSSL's term). Each
has an algebraic normal form, and the 64 ANF coefficient words are computed **at compile time** by a
`const fn` Möbius transform of the S-box tables transcribed from Appendix A. The round function
evaluates all thirty-two ANFs at once by Horner's scheme: 63 ANDs and 63 XORs on `u32` words, with
each S-box's six input bits held one per word and replicated across the four bit positions of its
output nibble.

Why this rather than Kwan's per-S-box gate circuits (the usual "bitslice DES"): those need many
blocks in parallel to fill a word, whereas this runs all eight S-boxes of *one* block in parallel
across the 32 bit positions; and the only DES-specific constants in the source are the spec's own
tables, laid out as printed, so a reviewer can check them against the document by eye. The runtime
never indexes a table.

### 2.2 E, P, IP and the key schedule

* `E` is never materialised. Block `i` of `E(R)` is the `i`-th nibble of `R` plus the last bit of
  the nibble above and the first bit of the nibble below, so the six input planes are built with
  masks, shifts and two rotations by a whole nibble (`des::planes`).
* `P` is nineteen mask-and-rotate groups generated from Table 3; each line's comment lists the
  spec input bits it moves.
* `IP` / `IP^-1` are Outerbridge's five-swap transposition network (via Crypto++ and BearSSL). In
  TDEA the `IP^-1` ending one DEA transformation cancels the `IP` starting the next, so each is
  applied once around the 48 rounds. No spec-defined intermediate value changes.
* The key schedule iterates the PC-1 and PC-2 tables directly (public indices, public shift
  amounts), and stores each 48-bit round key as two words shaped to be XORed straight into the
  plane layout: 128 bytes per DEA key, 384 per bundle, no per-round rearrangement. The inverse
  transformation reads the same schedule backwards (Sec 2.2), so one `TDES` serves both directions.

### 2.3 Key-bundle checks

`TDES::new` takes `KeyMaterial<24>` (`Key1 || Key2 || Key3`) and rejects, in this order: wrong
`KeyType`; wrong length; security strength below 112 bits; component keys that are not pairwise
distinct; any component that is a weak key. Parity bits are ignored throughout (Appendix A says
they "have no effect on the operation of the algorithm").

The weak-key test is **structural**, not a table comparison: a DES key is weak, semi-weak or
possibly weak exactly when `C0` and `D0` each have period 4 under rotation. That gives 8 × 8 = 64
keys, and `tests/key_tests.rs` proves they are precisely the 4 + 12 + 48 keys Sec 3.3.2 lists, by
reconstructing all 64 through inverse PC-1 and comparing sets. The check is two rotations and a
constant-time zero test.

Rejected errors are `KeyMaterialError::WeakKey(&str)`, a variant added to `core` for this (the enum
is `#[non_exhaustive]`).

### 2.4 Two-key TDEA is a separate, decryption-only type

`TDES` rejects `Key1 = Key3`; `TDES2Key` takes the 16-byte `Key1 || Key2` instead. SP 800-67r2
Sec 3.1 allows 2TDEA "for legacy use only, as defined in SP 800-131A", and SP 800-131Ar2 Table 1
has it "Disallowed" for encryption, "Legacy use" for decryption. To make that a property of the
type rather than of the documentation, `core::traits::ElectronicCodeBook` gained an associated
`const ENCRYPTION_APPROVED: bool = true`, and every `Encrypting` mode in `bouncycastle-modes`
asserts it in an inline `const` when constructed. `TDES2Key` sets it `false`, so
`Cbc<TDES2Key, Encrypting, ..>` (and the other four) fail to compile; the `Decrypting` directions
are untouched and the `TDES2_*` aliases name them. The raw `encrypt_block` remains, because CFB and
CTR decryption are built on the forward function. `MAX_SECURITY_STRENGTH` is `None`: 2TDEA is
"<= 80" bits (SP 800-57pt1r5 Table 2), below the lowest modelled level, and there is no honest
higher value. bc-java's `DESedeEngine` accepts 16-byte keys in both directions (and reports 80 bits).

### 2.5 Decisions a reviewer may want to revisit

1. **`ENCRYPTION_APPROVED` lives on the permutation trait**, with the gate in the modes. The
   alternative -- a decrypt-only trait -- would need every mode's `Decrypting` impl duplicated.
2. **All 64 weak keys are rejected**, where bc-java's `DESedeParameters` rejects the 16 weak and
   semi-weak. The spec says all three lists "should be avoided". The structural test makes 64 no
   more code than 16.
3. **Component keys are compared with parity masked**, so two keys differing only in parity are a
   repeat. They drive the engine identically, so the bundle really would collapse.
4. **`TDES_CTR` uses a 6-byte nonce and a 2-byte counter** (512 KiB per message). The trade-off,
   with numbers, is in `src/ctr.rs`. Naming `bouncycastle_modes::Ctr` directly gives another split.
5. **No `encrypt_2blocks` / `encrypt_4blocks` override, and speed was not the goal.** Criterion on
   the development machine (`cargo bench -p bouncycastle-tdes`): about 3.8 µs for `TDES::new`
   and about 4.1 µs per block in either direction, i.e. roughly 1.9 MiB/s. A table-driven Triple
   DES is around an order of magnitude faster; the price here buys the absence of any
   secret-indexed memory access. A two-lane `u64` variant would roughly double bulk throughput
   for parallel modes at the cost of lane-masked rotations everywhere; not done for a legacy
   cipher.
6. **`ALG_NAME` is `"TDES"`** (bc-java: `"DESede"`; NIST: `"TDEA"`).

---

## 3. Verification

| What | How |
|---|---|
| S-boxes | Exhaustive: 8 × 64 inputs through the circuit vs. table lookup; every row a permutation of 0..15; `ANF[63] == 0` (balancedness) |
| `IP`, `IP^-1`, `P`, `E` | Every unit vector against the spec table (a proof for a bit permutation); `IP^-1 ∘ IP = id` on the tables themselves |
| Key schedule | Packed round keys unpacked and compared with a long-hand `KS(n, KEY)`; PC-1 selects no parity bit and each other bit once; shifts sum to 28 |
| Weak keys | The 64 listed keys rejected in every position with either parity; set equality with the structural 64; one-bit-off keys accepted |
| Whole engine | NIST CAVP `TECBMMT3`, `TCBCMMT3`, `TCFB64MMT3`, `TCFB8MMT3` (20 cases each, both sections, both directions), through the `TDES_*` aliases with a pinned RNG supplying the vector's IV; the `*MMT2` files for `TDES2Key` |
| Trait contract | `TestFrameworkElectronicCodeBook` (incl. the 112-bit security-strength policy) |
| Aliases | Both parameters select; no IV for ECB; schemes not interchangeable; fresh IV per encryption |

The two-key files `TECBMMT2`, `TCBCMMT2`, `TCFB64MMT2`, `TCFB8MMT2` are checked the same way for
`TDES2Key`, except that CBC/CFB are decrypt-only (both sections decrypted) since the encrypting
modes do not compile over it.

The CAVP Monte Carlo files were downloaded but not used: their update rule is SP 800-20's and is a
separate piece of work.

The vectors are NIST's `tdesmmt.zip` response files, added to the `bc-test-data` repository under
`crypto/aes_tdes_vectors/TDES/` (all 22 files); `tests/cavp_mmt_tests.rs` parses the `.rsp` format
and skips with a warning when the repository is absent, as the AES ACVP tests do.

---

## 4. Where the plan changed

* The first plan was to store the six expanded key planes per round (1152 bytes). The compact
  two-word packing costs one spread per plane per round and saves 768 bytes; the middle four
  planes' key XOR folds into the data spread, so the cost is four spreads, not six.
* Two-key TDEA was first rejected outright. It came back as `TDES2Key`, decryption-only, once
  the `ENCRYPTION_APPROVED` gate gave a way to say "decryption only" in the type system.
* The vectors were first embedded in the crate as a generated Rust module; they moved to
  `bc-test-data` (the repository the other CAVP suites already depend on).
* Weak keys were first going to be a 16-entry table, as in bc-java. Working out why the semi-weak
  and possibly-weak lists have the shapes they do gave the period-4 characterisation, which covers
  all 64 with no table and turned the transcription of the 48 into a *test* of that claim.
* The CLI's `block_mode_cmd` had `BLOCK_LEN = 16` baked in; it is now a const parameter of the
  streaming loops and `CHUNK_LEN` is a fixed 1 KiB that both block lengths divide.

---

## 5. Sources consulted

Downloaded fresh into the session scratchpad, read, and quoted: SP 800-67 Rev 2 (withdrawn), FIPS
46-3 (Appendix 1 cross-check), SP 800-38A (Appendix E), SP 800-131A Rev 2 (Table 1), SP 800-57
Part 1 Rev 5 (Table 2), SP 800-20 (for the MMT file semantics), CAVP `tdesmmt.zip`. Reference
implementations read for design and behaviour, not copied: BearSSL `des_ct.c` / `des_support.c`,
bc-java `DESEngine`, `DESedeEngine`, `DESParameters`, `DESedeParameters`.
