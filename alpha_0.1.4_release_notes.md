# 0.1.4 Features / Changelog

## Major features

* CHACHA20 -- ChaCha20, Poly1305 and ChaCha20-Poly1305 (RFC 8439).
* AES Key Wrap -- AES_KW and AES_KWP (NIST SP 800-38F; RFC 3394 / RFC 5649) over any 128-bit block permutation,
  with the `KeyWrapper` / `KeyUnwrapper` core traits and the `aes*-kw` / `aes*-kwp` CLI commands.

## Minor features / bug fixes

* Cipher and MAC workers no longer implement `SuspendableKeyed` (#173): a resumed worker is a second copy of a
  nonce, counter or keystream position. The AES modes, CMAC and Ascon-AEAD128 lose their suspended-state
  constants and `hazmat::ModeKey` goes with them; HMAC and HKDF still suspend, and hashes, XOFs and KMAC keep
  `Suspendable`.

