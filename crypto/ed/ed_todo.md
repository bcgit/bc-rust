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

## Status and Gap analysis (2026-10-28)

Status as of 2026-10-28: X25519 passes every RFC 7748 vector and all 518 Wycheproof
`x25519_test.json` vectors, all checked in as tests (`x25519_tests.rs`,
`x25519_wycheproof.rs`). X448, Ed25519 and Ed448 are not started on this
branch; `../bc-rust-nursery/crates/{x448,ed25519,ed448,curve448}` hold earlier work to port from.
bc-test-data has no vectors for any of the four.

The vector-suite loaders will skip silently here: the local bc-test-data checkout is named
`bc-test-data.donttest`, so `core-test-framework`'s loaders would skip it with a warning. That has
no effect today because it has no vectors for these algorithms, but bear it in mind when adding
suites.

How each vector source fares on `feature/x25519` at `cf2677ba`. "Checked in" means a test in
`tests/` runs it.

| Source                                      | X25519                                | Checked in?                 |
|---------------------------------------------|---------------------------------------|-----------------------------|
| RFC 7748 §5.2 single-call vectors (2)       | pass                                  | yes: `vector_1`, `vector_2` |
| RFC 7748 §5.2 iterated, 1 and 1,000 rounds  | pass                                  | yes: `iterated`             |
| RFC 7748 §5.2 iterated, 1,000,000 rounds    | pass (~39 s in release)               | yes, but `#[ignore]`        |
| RFC 7748 §6.1 Diffie-Hellman                | pass (both public keys and K)         | yes: `rfc7748_section_6_1`  |
| Wycheproof `x25519_test.json`               | 518/518 output bytes match            | yes: `x25519_wycheproof.rs` |
| Wycheproof `x25519_{asn,jwk,pem}_test.json` | not run (needs key decoding, Phase 3) | no                          |
| bc-test-data                                | no X25519 vectors exist               | n/a                         |

What the analysis found:

- **X25519 arithmetic is correct.** The Wycheproof run covered the flags `EdgeCaseMultiplication`,
  `EdgeCasePrivateKey`, `EdgeCaseShared`, `Ktv`, `LowOrderPublic`, `NonCanonicalPublic`,
  `Normal`, `SmallPublicKey`, `SpecialPublicKey`, `Twist` and `ZeroSharedSecret`. So the open
  TODO comments about RFC §5 masking and non-canonical input describe missing tests, not missing
  behaviour.
- **Low-order public keys** produce the all-zero shared secret, which matches Wycheproof's bytes.
  `calculate_agreement` returns `false` for these. Wycheproof grades them "acceptable", so
  whether to reject them is still an API decision (Phase 2).
- **The X25519 gaps are test coverage and API, not correctness.** The only callable surface is
  free functions over `[u8; 32]` (`calculate_agreement`, `generate_public_key`). There is no
  private-key generation, and the round-trip test `agreement` is commented out.
- **Build warnings:** 7 dead-code warnings in the lib and 2 unused imports in the test.

## Phase 1: Functional

- [x] Add a Wycheproof suite `tests/x25519_wycheproof.rs` over `x25519_test.json`: 518 vectors,
  264 valid and 254 acceptable, 31 with an all-zero shared secret. (maybe need to be renamed / refactored to match other
  crates)
- [ ] Decide what happens on an all-zero shared secret (low-order public key). Today
  `calculate_agreement` outputs zeros and returns `false`; Wycheproof marks these vectors
  "acceptable". Reject, or pass through? This maybe requires some research to see if this condition can be detected on
  the public inputs before peforming the private key operations (would be better for constan-time concerns).
- [ ] Close the TODO comments in `x25519.rs` and `curve25519.rs` about RFC §5 top-bit masking and
  non-canonical input; the Wycheproof suite now covers both.
- [x] Add the RFC 7748 §6.1 Diffie-Hellman vectors: Alice's and Bob's public keys and the shared
  secret K.
- [ ] Label `vector_1`/`vector_2` and the iterated test as RFC 7748 §5.2 (the comment says
  "RFC7749"), and drop the "what is this?" TODO on `check_iterated`; it is the §5.2 iterated
  test. Fix the stale comment on `scalar_mult` that says these vectors are not exercised.
- [ ] Re-enable the `agreement` round-trip test. It currently calls a non-existent
  `generate_private_key_rng`.
- [ ] Remove the unused imports (`bouncycastle_core`, `bouncycastle_rng`) and the commented-out
  `decode_hex` from `x25519_tests.rs`.
- [ ] Review `CoordField` in `curve25519.rs`. Ed25519 reuses it, so get it right here first:
    - [ ] Review every method marked `// TODO: Claude-generated, double-check`, plus
      `decode_scalar_25519` and `scalar_mult` in `x25519.rs`.
    - [ ] Think about whether each field-arithmetic function needs a basic unit test.
    - [ ] Decide how the normalization precondition is enforced. `encode_255`, `encode64_255`,
      `are_equal(_var)` and `parity` need normalized input. The options, from the comment in
      `curve25519.rs`, are: fold `normalize` into `encode_255`, add a `Normalized` typestate, or
      add debug-only magnitude tracking.
    - [x] Identify `C_A` (486662) and `C_A24` and document them against RFC 7748.
- [ ] Remove the dead code: `Scalar25519`/`UCoordinate25519` (`todo!()`), `encode_u_coordinate`,
  `P32`, `P64`, and the empty `precompute()`. Or finish them, if Phase 3 wants them.
- [ ] `cargo mutants -p bouncycastle-ed` (without Wycheproof).

## Phase 2: Traits, Bells & Whistles

- [ ] Finish the `KeyAgreement` / `KeyAgreementPublicKey` / `KeyAgreementPrivateKey` traits in
  `traits.rs`. Today they are empty markers. They need:
    - [ ] key `from_bytes`/encoding, by analogy with `KEMPublicKey`/`KEMPrivateKey` (lengths as
      const generics);
    - [ ] the output type, wrapped in `KeyMaterial` (the shared secret is sensitive);
    - [ ] an error type.
- [ ] Add X25519 key types: `Secret`-backed private keys, zeroized, no `Debug` leak.
- [ ] Implement the traits for X25519. Move the Wycheproof and RFC suites onto the trait API.
- [ ] Add a shared `KeyAgreement` conformance suite in `core-test-framework` and invoke it from
  X25519.
- [ ] A `KEM` impl over X25519 (DHKEM-style). Mentioned in an `x25519.rs` TODO; decide if it
  belongs here.
- [ ] Keygen:
    - [ ] random keygen from an `RNG`;
    - [ ] deterministic keygen from a supplied 32-byte seed;
    - [ ] public-from-private derivation and consistency-check.
- [ ] Fast fixed-base `scalar_mult_base`. Today it runs the generic ladder with u = 9; there is a
  commented-out Edwards-form path.
- [ ] Wire into the factory (a `KeyAgreementFactory`, if that fits the factory pattern) and add a
  CLI subcommand (`cli/src/*_cmd.rs`).

## Phase 3: Docs and ergonomics

- [ ] Settle visibility: `CoordField` and most of its methods, and `calculate_agreement`, are
  `pub`; should they be `pub(crate)`?
- [ ] `CoordField` cleanups:
    - [ ] `[Secret<i64>; 5]`? Block `Debug`? Prune the derive list.
    - [ ] Should the `*_mut` methods return `&mut Self`, and do we need both value and `_mut`
      forms?
    - [ ] Construct from `[u64; 4]` / `Nat<4>` instead of `new(x0..x4)`.
    - [ ] Rename `parity` (to `is_odd`?).
    - [ ] Remove the answered "why are we cloning?" TODO.
- [ ] Docs:
    - [ ] Re-enable `#![forbid(missing_docs)]`.
    - [ ] Write the crate doc sections required by QUALITY_AND_STYLE.md.
    - [ ] Is XDH in a NIST document? (`lib.rs` `# Standards`.)
- [ ] Benches: criterion, plus a `mem_usage_benches` harness and a `# Memory Usage` docs section.

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

- [ ] Port from `bc-rust-nursery/crates/{curve25519,ed25519}` onto the shared `CoordField`:
  Edwards point arithmetic, point encoding/decoding, and SHA-512 from `bouncycastle-sha2`.
- [ ] Move what X25519 shares with Ed25519 (e.g. `point_double`) into `curve25519.rs`.
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
