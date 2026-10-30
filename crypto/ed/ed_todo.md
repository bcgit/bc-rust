# bouncycastle-ed TODO

Work for the `bouncycastle-ed` crate, in priority order. Each algorithm family goes through three
phases, in order, each in stacked commits:

1. x25519
2. x448
3. ed25519 / ed448

Within each, the priority order is:

1. **Functional**: correct output, passing the RFC and Wycheproof vectors.
2. **Traits**: implementing the appropriate traits from `crypto/core/src/traits.rs`.
3. **Polish**: docs, API ergonomics, and the extra APIs.

---

# X25519 (RFC 7748)

## Phase 1: Functional

- [x] Add a Wycheproof suite `tests/x25519_wycheproof.rs` over `x25519_test.json`: 518 vectors,
  264 valid and 254 acceptable, 31 with an all-zero shared secret. (maybe need to be renamed / refactored to match other
  crates)
- [x] Close the TODO comments in `x25519.rs` and `curve25519.rs` about RFC §5 top-bit masking and
  non-canonical input; the Wycheproof suite now covers both.
- [x] Add the RFC 7748 §6.1 Diffie-Hellman vectors: Alice's and Bob's public keys and the shared
  secret K.
- [x] Document `check_iterated` as the RFC 7748 §5.2 iterated test.
- [x] Label `vector_1`/`vector_2` as RFC 7748 §5.2, and drop the stale comment on `scalar_mult`
  that said these vectors are not exercised.
- [x] Remove the unused imports (`bouncycastle_core`, `bouncycastle_rng`) from `x25519_tests.rs`.
- [x] Remove the commented-out `decode_hex` from `x25519_tests.rs`.
- [x] Review `FieldElement25519` in `curve25519.rs`. Ed25519 reuses it, so get it right here first:
    - [x] Review every method marked `// TODO: Claude-generated, double-check`, plus
      `decode_scalar_25519` and `scalar_mult` in `x25519.rs`.
    - [x] Enforce the normalization precondition: typestate. `normalize` returns a
      `NormalizedFieldElement25519`, which alone has `encode_255`, `is_zero`/`is_one`, `parity`
      and (once restored) `are_equal`.
    - [x] `normalize`'s own input bound: the value in `[0, 2^255)` (limbs may exceed 51 bits),
      checked by a `debug_assert` at its top. Output range checked by `NormalizedFieldElement25519::debug_check_range`.
    - [x] Identify `C_A` (486662) and `C_A24` and document them against RFC 7748.
- [x] Remove the dead code: `precompute()` is gone, and `P32`, `P64` and the methods X25519 does
  not use are commented out; the crate builds with no warnings.
- [x] `cargo mutants -p bouncycastle-ed` (without Wycheproof).

## Phase 2: Traits, Bells & Whistles

- [ ] Finish the `KeyAgreement` / `KeyAgreementPublicKey` / `KeyAgreementPrivateKey` traits in
  `traits.rs`. They need:
    - [ ] key `from_bytes`/encoding, by analogy with `KEMPublicKey`/`KEMPrivateKey` (lengths as
      const generics). Partly there: `KeyAgreementPublicKey` requires `AsRef<[u8]>`, and the X25519
      keys get `from_bytes`/`encode` from `KEMPublicKey`/`KEMPrivateKey`, but the `KeyAgreement*`
      traits themselves have no decoding.
    - [x] the output type. Decided: `key_agreement` returns a `PK`, and the caller applies a KDF;
      the KEM traits are the API that hands back a `KeyMaterial` shared secret.
    - [x] an error type: `KeyAgreementError`.
- [x] Add X25519 key types: `X25519PrivateKey` (`Secret`-backed, zeroized, redacted `Debug`) and
  `X25519PublicKey`, used by `X25519::key_agreement` and `X25519PrivateKey::pk`.
- [x] Add `struct X25519` (`Algorithm`). It and the key types are public through `pub mod x25519`
  (no crate-root re-exports).
- [x] Implement the traits for X25519. Move the Wycheproof and RFC suites onto the trait API.
- [x] Re-enable the `agreement` round-trip test. Later removed as redundant: the RFC 7748 iterated
  and Wycheproof known answers, and the KEM framework round trip, cover it.
- [ ] Add a shared `KeyAgreement` conformance suite in `core-test-framework` and invoke it from
  X25519.
- [x] Decide what happens on an all-zero shared secret (low-order public key): `key_agreement`
  rejects it with `KeyAgreementError::InvalidPublicKey`. RFC 7748 §6.1 makes the check a MAY;
  RFC 8446 §7.4.2 and RFC 9180 §7.1.4 make it a MUST.
    - [ ] Open: detect a small-order public key before the private-key operation, rather than
      from the output.
- [x] A `KEM` impl over X25519: `KEMEncapsulator`/`KEMDecapsulator` on `X25519` as DHKEM (X25519,
  HKDF-SHA256) (RFC 9180 §4.1), built on the generic `DHKEM` in the new `bouncycastle-hpke`
  utility crate. Tested against RFC 9180 A.1.1/A.1.2 and the core-test-framework KEM suites.
- [x] Keygen, mirroring ML-KEM, on `X25519` with `KeyAgreementError` (added to `core`):
    - [x] `keygen` (OS-seeded `HashDRBG_SHA512`) and `keygen_from_rng`;
    - [x] `keygen_from_seed`, from a 32-byte `KeyMaterial256`;
    - [x] `keypair_consistency_check`. No `keygen_from_seed_and_encoded`: the seed *is* the
      private key encoding, so there is nothing to compare.
- [ ] Wire into the factory (a `KeyAgreementFactory`, if that fits the factory pattern) and add a
  CLI subcommand (`cli/src/*_cmd.rs`).
- [ ] `cargo mutants -p bouncycastle-ed` (without Wycheproof). Scoped runs done on the KEM code (one survivor: an
  error-mapping arm unreachable with a well-behaved RNG) and on `bouncycastle-hpke`;
  a full-crate run is still to do.

## Phase 3: Docs and ergonomics

- [x] `FieldElement25519` and its methods are `pub(crate)`.
- [x] Remove `calculate_agreement`; the tests and Wycheproof suite use `X25519::key_agreement`.
- [x] `FieldElement25519` cleanups:
    - [x] `[Secret<i64>; 5]`? Block `Debug`? Prune the derive list.
    - [x] In-place methods (`*_mut`, `cmov`, `cnegate`) return `()`, not `&mut Self`.
    - [x] Do we need both value and `_mut` forms? No: only the value forms remain.
    - [x] Construct from `[u64; 4]` / `Nat<4>` instead of `new(x0..x4)`. Moot: `new` is removed.
    - [x] Rename `parity` (to `is_odd`?).
    - [x] Remove the answered "why are we cloning?" TODO.
- [ ] Docs:
    - [ ] Re-enable `#![forbid(missing_docs)]`.
    - [ ] Write the crate doc sections required by QUALITY_AND_STYLE.md:
        - [x] Usage Examples (`lib.rs`, linking to the `x25519` module's examples);
        - [ ] Memory Usage (needs the benches below);
        - [ ] Security Considerations.
    - [x] Is XDH in a NIST document? No: RFC 7748 only. SP 800-186 specifies the curves but does not
      list them for key establishment, and SP 800-56A Rev. 3 does not include XDH (`lib.rs`
      `# Standards`).
- [ ] Benches: criterion, plus a `mem_usage_benches` harness and a `# Memory Usage` docs section.
- [ ] Rethink the name of this crate: `bouncycastle-ed` is kindo the wrong name (but maybe nothing better exists?)

---

# X448 (RFC 7748)

Not started on this branch; earlier work is in `bc-rust-nursery/crates/{curve448,x448}`. Mostly a
twin of X25519 over the second field: start once X25519's Phase 2 has settled the traits and key
types, and carry each X25519 item across. Only the differences are listed here.

## Phase 1: Functional

- [ ] Twin `curve25519.rs` / `x25519.rs` as `curve448.rs` / `x448.rs`: field element mod
  p = 2^448 − 2^224 − 1, 56-byte scalars and u-coordinates, and the same ladder.
- [ ] Differences from X25519 (RFC 7748 §5):
    - [ ] `decodeScalar448` clears the two low bits and sets bit 447; no high bit to clear.
    - [ ] No masking of the top bit of u: that rule is X25519-only.
    - [ ] a24 = (156326 − 2) / 4 = 39081.
- [ ] Vectors: RFC 7748 §5.2 (single-call and iterated), §6.2, and Wycheproof `x448_test.json`
  (510 vectors; its 12 `PublicKeyTooLong` cases have no X25519 counterpart).
- [ ] Field unit tests; `cargo mutants`.

## Phase 2: Traits, Bells & Whistles

- [ ] Same as X25519, for X448: key types, `KeyAgreement` impls (same all-zero-secret decision),
  conformance suite, KEM if X25519 has one, keygen (56-byte seed), fixed-base scalar
  multiplication, factory and CLI.

## Phase 3: Docs and ergonomics

- [ ] Same as X25519: docs, Wycheproof, benches and
  `mem_usage_benches`.

---

# Ed25519 / Ed448 (RFC 8032, FIPS 186-5)

## Phase 1: Functional

### Ed25519

- [ ] Port from `bc-rust-nursery/crates/{curve25519,ed25519}` onto the shared `FieldElement25519`:
  Edwards point arithmetic, point encoding/decoding, and SHA-512 from `bouncycastle-sha2`.
- [ ] Move what X25519 shares with Ed25519 (e.g. curve constants) into `curve25519.rs`. Not
  `ladder_double`: that is Montgomery u-only doubling, while Ed25519 doubles in extended
  coordinates (RFC 8032 §5.1.4).
- [ ] Pure Ed25519: RFC 8032 §7.1 vectors.
- [ ] Ed25519ctx: RFC 8032 §7.2 vectors.
- [ ] Ed25519ph: RFC 8032 §7.3 vectors.
- [ ] Wycheproof `ed25519_test.json`, including the malleability and non-canonical-encoding
  cases.
- [ ] `sqrt_ratio_var`: check whether it branches on secret data, and constrain its use to public
  inputs (decoding during verification).
- [ ] `inv_var`: real variable-time inverse for public operands (verification); today it is the
  constant-time `inv`.
- [ ] `pow_p_sub5_div8`: document the addition chain's source; consider an addition-chain helper.
- [ ] Unit tests for the point arithmetic; `cargo mutants`.

### Ed448

- [ ] Port from `bc-rust-nursery/crates/{curve448,ed448}`, reusing the X448 field element and
  SHAKE256 from `bouncycastle-sha3`.
- [ ] Ed448: RFC 8032 §7.4 vectors.
- [ ] Ed448ph: RFC 8032 §7.5 vectors.
- [ ] Wycheproof `ed448_test.json`.
- [ ] Unit tests; `cargo mutants`.

## Phase 2: Traits

- [ ] Ed25519/Ed448 key types implementing `SignaturePrivateKey` / `SignaturePublicKey`.
- [ ] `Signer` / `SignatureVerifier` for pure Ed25519/Ed448, including the context string for
  Ed25519ctx and Ed448.
- [ ] `PHSigner` / `PHSignatureVerifier` for Ed25519ph / Ed448ph.
- [ ] Run the `core-test-framework` `signature.rs` suite against all variants; move the RFC and
  Wycheproof suites onto the trait API.
- [ ] Factory and CLI wiring, following ML-DSA's (`cli/src/mldsa_cmd.rs`).

## Phase 3: Docs and ergonomics

- [ ] Deterministic keygen from a 32/57-byte seed, plus random keygen from an `RNG`.
- [ ] Expose the pre-expanded private key: the hashed seed, i.e. the clamped scalar s and the
  prefix. Keygen, sign-from-expanded, and serialization, so repeated signing skips the hash.
- [ ] Precomputed / cached public-key decompression for repeated verification.
- [ ] Fixed-base comb tables for keygen and signing; batch verification if wanted.
- [ ] Docs: the crate doc sections; cite FIPS 186-5 §7 alongside RFC 8032 (verify section numbers
  against a downloaded copy).
- [ ] Benches: criterion, plus `mem_usage_benches`.
