# 0.1.4 Features / Changelog

## Major features

* CHACHA20 -- ChaCha20, Poly1305 and ChaCha20-Poly1305 (RFC 8439).
* AES Key Wrap -- AES_KW and AES_KWP (NIST SP 800-38F; RFC 3394 / RFC 5649) over any 128-bit block permutation,
  with the `KeyWrapper` / `KeyUnwrapper` core traits and the `aes*-kw` / `aes*-kwp` CLI commands.
* ECDSA -- FIPS 186-5 signatures over P-256, P-384, P-521, secp256k1, brainpoolP256r1, brainpoolP384r1 and
  brainpoolP512r1, with the RFC 6979 deterministic variant, through the `SigningKey` / `DeterministicSigningKey` /
  `VerifyingKey` core roles; the `ecdsa-*` CLI commands.
* SM2 -- the GB/T 32918.2-2016 signature algorithm with SM3, on the same roles; the `sm2` CLI command.
* `bouncycastle-ec` -- the constant-time, fixed-width curve arithmetic under both: per-curve field, scalar and
  Jacobian-point arithmetic, SEC 1 codec and comb, wNAF and variable-base multipliers, all under `hazmat`, with the
  generic limb arithmetic (`nat`, `montgomery`, `barrett`, `inverse_vartime`) at the crate root.

## Minor features / bug fixes

* Cipher and MAC workers no longer implement `SuspendableKeyed` (#173): a resumed worker is a second copy of a
  nonce, counter or keystream position. The AES modes, CMAC and Ascon-AEAD128 lose their suspended-state
  constants and `hazmat::ModeKey` goes with them; HMAC and HKDF still suspend, and hashes, XOFs and KMAC keep
  `Suspendable`.

