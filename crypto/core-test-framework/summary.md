# `crypto/core-test-framework` — changes for `BlockPermutation` and CBC

Changes made on branch `feature/officialfrancismendoza/98-AES-lowmemory` (2026-08-31) while adding
`crypto/aes-lowmemory` and `crypto/modes`. Two things: a **new** per-trait suite for
`core::traits::BlockPermutation`, and a **bug fix** to the existing `TestFrameworkBlockCipher`.

For what this crate is for in general, see its [`src/lib.rs`](src/lib.rs) docs: one KAT-style
harness per `core` trait, so that behaviour which should be consistent across implementations of a
trait — error handling, input/output lengths, `KeyMaterial` entropy enforcement — is asserted once
here rather than re-written per implementation.

---

## 1. New: `TestFrameworkBlockPermutation`

[`src/block_permutation.rs`](src/block_permutation.rs), registered as `pub mod block_permutation;`
in [`src/lib.rs`](src/lib.rs).

`core::traits::BlockPermutation<KEY_LEN, BLOCK_LEN>` is new in this branch: the raw keyed
permutation (`CIPH_K` / `CIPH^-1_K` of SP 800-38A Sec 5.1) that a mode of operation is built on.
It needed a conformance suite like every other `core` trait.

```rust
TestFrameworkBlockPermutation::new().test::<KEY_LEN, BLOCK_LEN, P>();
```

### What it checks, and why each check exists

| Check | What it catches |
|---|---|
| `decrypt_block` inverts `encrypt_block`, **and vice versa** | A direction implemented only one way round. A mode may call either direction first, so both orders are exercised. |
| Neither direction is the identity | A stub, or a key schedule that never got applied. |
| Distinct blocks give distinct outputs | An implementation that is not injective — e.g. one masking part of the block away. A permutation must be. |
| `encrypt_blocks2` == two `encrypt_block` calls, **including their order**; same for decrypt | The whole reason the pair methods are safe to override. See below. |
| The pair methods round-trip each other | A pair path correct in one direction only. |
| Identical inputs give identical outputs from `*_blocks2` | Lanes that are not actually independent — a real hazard for a bit-sliced implementation that interleaves two blocks in one word. |
| A key of the wrong `KeyType` is rejected | A seed or MAC key being reused as a cipher key. |
| The security-strength policy matches `BlockCipher::MAX_SECURITY_STRENGTH` | A `new()` that accepts a key weaker than the algorithm, or rejects one strong enough. |

### The order check is the load-bearing one

`BlockPermutation::encrypt_blocks2` and `decrypt_blocks2` are *provided* methods: the default is
two single-block calls, and implementations are free to override them. `bouncycastle-aes-lowmemory`
does, because a pair of blocks is exactly what its bit-sliced state holds, so the pair form costs
barely more than one block.

An override is therefore a place where an implementation can silently disagree with the trait's
semantics — most easily by returning the two results in the wrong order, which round-trips
perfectly and so passes any test that only checks encrypt-then-decrypt. Asserting equality against
two explicit single-block calls, slot by slot, is what makes an override trustworthy. That check is
the reason this suite is worth having rather than leaving each implementor to test itself.

The mirror image of this check lives in `crypto/modes/tests/common/mod.rs` as `SwappedPairToy`, a
permutation whose pair methods deliberately swap their results, used to prove the *mode* really
takes the pair path.

### Current implementors

* `crypto/aes-lowmemory/tests/block_permutation_tests.rs` — AES-128, AES-192, AES-256.
* `crypto/modes/tests/cbc_tests.rs` — the toy permutation, checked before anything is concluded
  from it.

---

## 2. Fixed: `TestFrameworkBlockCipher` panicked for any key under 32 bytes

### The bug

`TestFrameworkBlockCipher::test` ended with a loop that tagged the test key at each of the five
`SecurityStrength` values and checked the `_init` constructor's accept/reject decision against
`MAX_SECURITY_STRENGTH`:

```rust
for ss in security_strengths.iter() {
    do_hazardous_operations(&mut key, |key| key.set_security_strength(ss.clone())).unwrap();
    // ...
}
```

`KeyMaterial::set_security_strength` enforces a key-length guard — a key cannot be tagged at a
strength its own length cannot carry — and it enforces it **even inside a
`do_hazardous_operations` closure**. So for a 16-byte key the loop reached `_192bit`, got
`Err(SecurityStrength("Security strength cannot be larger than key length."))`, and the `unwrap()`
panicked. The comment above the loop asserted the opposite ("bypasses the key-length guard"), which
is what made it look correct.

The result: the harness was unusable for AES-128 or AES-192, i.e. for most block ciphers.

### Why nobody had noticed

Nothing in the workspace implemented `BlockCipherEncryptor`/`BlockCipherDecryptor`. The traits
landed in PR #96 with the harness written against them but no implementor — the toy XOR-CBC cipher
that would have exercised it lives in `crypto/padding`, which is PR #97 and has not merged to this
branch. `crypto/modes`' CBC is the first implementor in the tree, and it hit the panic immediately.

### The fix

Skip the strengths the key length cannot hold, rather than unwrapping the error:

```rust
if ss > &SecurityStrength::from_bytes(KEY_LEN) {
    continue;
}
```

For a 16-byte key this tests `None`, `_112bit` and `_128bit` — which still spans the
`MAX_SECURITY_STRENGTH` boundary for AES-128, so the accept/reject decision is still exercised on
both sides. Nothing is lost; the skipped cases were never reachable.

### What **not** to do instead

Do not relax the guard in `KeyMaterial::set_security_strength`. `core`'s
`test_hazardous_ops_error_handling` requires it to stay enforced even inside
`do_hazardous_operations`. A comment at the fix says so, because "make the setter permissive" is
the tempting one-line alternative and it breaks a core test. This is the same conclusion reached
independently on the ASCON branch.

---

## 3. Still outstanding: the same bug, twice more

The identical loop appears in two other suites in
[`src/symmetric_ciphers.rs`](src/symmetric_ciphers.rs) and is **not** fixed:

| Suite | Loop at | Implementors in tree | Status |
|---|---|---|---|
| `TestFrameworkSymmetricCipher` | line 87 | 0 | latent, unfixed |
| `TestFrameworkBlockCipher` | line 240 | 1 (`crypto/modes`) | **fixed** |
| `TestFrameworkAEADCipher` | line 386 | 0 | latent, unfixed |
| `TestFrameworkStreamCipher` | — | 0 | unaffected (no strength handling) |

Both unfixed suites will panic the first time anything implements their trait with a key shorter
than 32 bytes — which for `AEADCipher` includes ASCON-128 and AES-128-GCM. They were left alone to
keep this change scoped to what CBC needed; the fix is the same three lines in each. Worth doing
before the next implementor arrives rather than after.

Note that `TestFrameworkStreamCipher` is a different case: it has no security-strength handling at
all, so there is nothing to fix there and nothing being checked either.

---

## 4. Unchanged but newly exercised: `FixedSeedRNG`

[`src/fixed_seed_rng.rs`](src/fixed_seed_rng.rs) already existed and was not modified. It is worth
recording that it is now what makes CBC's known-answer tests possible.

`Cbc` deliberately has no API for a caller-supplied IV — SP 800-38A Sec 5.3 requires the CBC IV to
be *unpredictable*, so `do_encrypt_init` generates one and returns it. That leaves a problem for
testing: Appendix F.2 specifies the IV, and there is no way to pass it in.

`BlockCipherEncryptor::do_encrypt_init_rng(key, &mut dyn RNG)` is the seam.
`FixedSeedRNG::<16>::new(iv)` emits the vector's IV as its first sixteen bytes, so the test can pin
the IV without the production API ever accepting one. `crypto/modes/tests/sp800_38a_tests.rs`
asserts the returned init data really is the expected IV before comparing any ciphertext, so a
change that ignored the RNG could not pass silently.

This is the pattern to reuse for CFB, OFB and CTR when they land.

---

## 5. Verification

```sh
cargo build -p bouncycastle-core-test-framework
cargo test --workspace          # 500 tests, 0 failures
cargo fmt --all -- --check
```

This crate has no tests of its own — it *is* tests — so it is verified by its consumers. The two
new suites are exercised by:

* `cargo test -p bouncycastle-aes-lowmemory --test block_permutation_tests` (3 tests)
* `cargo test -p bouncycastle-modes --test cbc_tests` (11 tests, including
  `cbc_conforms_to_the_block_cipher_framework`, which is what the §2 fix unblocked, and
  `the_toy_permutation_conforms_to_the_trait`)

---

## 6. Open items

1. **Fix the same loop in `TestFrameworkSymmetricCipher` and `TestFrameworkAEADCipher`** (§3).
   Three lines each, and the next implementor of either trait will otherwise hit the panic.
2. **Decide whether the `Default` impl added to `TestFrameworkBlockPermutation` should be added to
   the other suites** for consistency — they all have `new()` and no `Default`, which clippy
   flags on new code but not on existing code.
3. When `crypto/padding` (PR #97) merges, its toy XOR-CBC cipher becomes a second
   `TestFrameworkBlockCipher` implementor. Worth re-running that suite then: an XOR-based cipher has
   `encrypt_block == decrypt_block`, which is exactly the property `crypto/modes`' non-XOR toy was
   chosen to avoid, so it may expose gaps this branch's tests do not.
