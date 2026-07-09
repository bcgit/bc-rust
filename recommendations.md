# PR #48 — Round 2: Comments to Post

Each item = file, line, the exact code it anchors to, and the comment to paste. Ordered by priority.

---

## 1. Keccak deserialization can panic on corrupt state (blocking)

**File:** `crypto/sha3/src/keccak.rs`
**Line:** 420–422 (inside `KeccakDigest::from_serialized_state`)

```rust
let bits_in_queue = u64::from_le_bytes(input[392..400].try_into().unwrap()) as usize;
if bits_in_queue > rate {
    return Err(SuspendableError::InvalidData);
}
```

**Comment to post:**
> This only rejects `bits_in_queue > rate`. A corrupt/tampered state with `squeezing == false` and an
> odd `bits_in_queue` (or `bits_in_queue == rate`) still deserializes here, then panics on the next
> call: `absorb` hits `panic!("attempt to absorb with odd length queue")` (line 227), and
> `pad_and_switch_to_squeezing_phase` trips `debug_assert!(bits_in_queue < rate)`. Per the trait
> contract, corrupt input must return `InvalidData`, not panic. Please tighten to:
> ```rust
> if bits_in_queue > rate || (!/* squeezing */ && (bits_in_queue & 7 != 0 || bits_in_queue == rate)) {
>     return Err(SuspendableError::InvalidData);
> }
> ```
> (i.e. move this check below the `squeezing` parse and gate the extra conditions on `!squeezing`), and
> add a negative test — the current test only corrupts the `squeezing` byte, not `bits_in_queue`.

---

## 2. `HashFactory` ships a knowingly-broken `Algorithm` impl (blocking)

**File:** `crypto/factory/src/hash_factory.rs`
**Line:** 86–90

```rust
// TODO -- this does't work. Perhaps Algorithm needs to be re-worked so that these are functions instead?
impl Algorithm for HashFactory {
    const ALG_NAME: &'static str = "TODO";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::None;
}
```

**Comment to post:**
> This public `impl Algorithm for HashFactory` ships `ALG_NAME = "TODO"` and
> `MAX_SECURITY_STRENGTH = None`, with a "this does't work" TODO. It was only added to satisfy the new
> `Hash: Algorithm` supertrait bound (so HMAC's new `Display`/`Debug` can read `HASH::ALG_NAME`), but
> `Algorithm`'s associated **consts** can't express a per-variant value for a runtime factory enum —
> hence the stub. Please don't merge a knowingly-wrong public `Algorithm` impl. Suggest sourcing HMAC's
> display name from HMAC's own `Algorithm` alias (or a small `fn alg_name(&self)`) instead of widening
> the `Hash` supertrait, so `HashFactory` doesn't need this impl at all.

---

## 3. Add a "Breaking changes" changelog entry (three breaking items)

**File:** `alpha_0.1.2_release_notes.md`
**Line:** 54 (add a section under `## Minor features / bug fixes`, or a new `## Breaking changes`)

```markdown
## Minor features / bug fixes
```

The three breaking items live at:
- `crypto/sha2/src/lib.rs:75` — `pub use self::sha512::SHA512Internal;` (was `Sha512Internal`)
- `crypto/core/src/traits.rs:20` — `pub trait Hash: Algorithm + Default {` (new supertrait)
- `MLDSATrait::verify_mu_internal(->bool)` → public `verify_mu(->Result)` (mldsa & mldsa-lowmemory)

**Comment to post:**
> Please add a "Breaking changes" section. This PR has three source-breaking public changes not listed:
> (1) `Sha512Internal` → `SHA512Internal` (sha2/src/lib.rs:75); (2) `Hash` now requires `Algorithm` as
> a supertrait (core/src/traits.rs:20), so every external `Hash` impl must now also impl `Algorithm`;
> (3) the public `MLDSATrait` method `verify_mu_internal(->bool)` became `verify_mu(->Result)`.

---

## 4. `LIB_VERSION` is `core`'s version (0.1.1) and is the only compat gate

**File:** `crypto/core/Cargo.toml`
**Line:** 3

```toml
version = "0.1.1"
```

Related anchor — **File:** `crypto/core/src/suspendable_state.rs`, **Line:** 112–113:

```rust
let patch_stream = SemVer::from([LIB_VERSION.major, LIB_VERSION.minor, 255]);
if ver > patch_stream {
```

**Comment to post:**
> `LIB_VERSION` comes from `bouncycastle-core`, which is still `0.1.1` here while the release is
> `0.1.2` — so every serialized state gets stamped `0.1.1`. Two asks: (a) reconcile `core`'s version
> with the release; (b) since this stamp is the *only* compat gate and the policy (suspendable_state.rs:112)
> accepts any future patch on the same major.minor, any change to a serialized layout MUST bump `core`'s
> **minor** (never just the patch) or old readers will silently misparse newer blobs. Worth a one-line
> maintainer note next to `check_lib_ver`.

---

## 5. (Optional, style) Uncommented infallible `.unwrap()`s in serialization paths

QUALITY_AND_STYLE requires each `.unwrap()` to carry a justification. These fixed-size slice→array
unwraps are infallible by const construction but uncommented:

- `crypto/sha2/src/sha256.rs:322` — `let out: &mut [u8; 105] = add_lib_ver(&mut out_to_return).try_into().unwrap();`
- `crypto/sha2/src/sha256.rs:351` — `let input: &[u8; 105] = check_lib_ver(&serialized_state, None)?.try_into().unwrap();`
- `crypto/sha2/src/sha512.rs:337` — `add_lib_ver(&mut out_to_return).try_into().unwrap();`
- `crypto/sha2/src/sha512.rs:364` — `check_lib_ver(&serialized_state, None)?.try_into().unwrap();`
- `crypto/hkdf/src/lib.rs:852` and `:871` — `state[..].try_into().unwrap()`

**Comment to post (put on sha256.rs:322, reference the rest):**
> Style nit per QUALITY_AND_STYLE: these `.try_into().unwrap()`s are infallible by const sizing but
> lack the required justification comment. Suggest a one-line `// infallible: slice is exactly N bytes
> by const construction` on each (same pattern in sha512.rs:337/364 and hkdf/src/lib.rs:852/871), and
> a `quality_stats.sh` before/after to confirm the fallibility count didn't rise.

---

## 6. (Separate / pre-existing) wycheproof sign harness fails on the `Randomized` case

**File:** `crypto/mldsa/tests/wycheproof.rs`
**Line:** 353 (and identically 421, 489, and the `sign_seed` equivalents)

```rust
let sig = MLDSA44::sign_mu_deterministic(&sk, None, &mu, [0u8; 32]).unwrap();
assert_eq!(sig, hex::decode(&self.sig).unwrap().as_slice());
```

**Comment to post:**
> Not introduced by this PR (pre-existing on base), but the 6 `*_sign_*` wycheproof tests fail because
> the harness signs every case with a hardcoded all-zero `rnd` and byte-compares to `sig`, while each
> file's one `Randomized`-flagged case (tcId 73/90/78/109/69/100) was generated with a non-zero `rnd`
> (per wycheproof `doc/mldsa.md` lines 33–36). The `MLDSASign*TestCase` struct doesn't parse `rnd`.
> Fix: skip cases flagged `Randomized` / carrying an `rnd` field, or parse `rnd` and pass it through.
> Worth a tracking issue so the suite goes green.

---

## Just reply "resolved" (no code-anchored comment needed)

F1 (HKDF hmac/state consistency), F3 (HKDF version header), F5 (HMAC `Secret`/`Drop`), F6
(`IncorrectKey` removed), F9 (version policy) — all addressed in round 2; close them with a reply.
