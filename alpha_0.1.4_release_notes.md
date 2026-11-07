# 0.1.4 Features / Changelog

## Major features

* ARIA -- `bouncycastle-aria`, the RFC 5794 block cipher at 128, 192 and 256 bits, constant-time and table-free (the
  S-boxes as bit-sliced Boolean circuits, four blocks at a time), on the key objects as `ARIA128Key<M>` and friends
  with CBC, CFB, CFB8, CTR, GCM, CCM, CMAC, GMAC, KW and KWP; the `aria*-{cbc,cfb,cfb8,ctr,gcm,ccm,kw,kwp}` CLI
  commands.
* Camellia -- `bouncycastle-camellia`, the RFC 3713 block cipher at 128, 192 and 256 bits, constant-time and table-free
  (the S-box as a bit-sliced Boolean circuit, four blocks at a time), on the key objects as `Camellia128Key<M>` and
  friends with CBC, CFB, CFB8, CTR, GCM, CCM, CMAC, GMAC and KW; the `camellia*-{cbc,cfb,cfb8,ctr,gcm,ccm,kw}` CLI
  commands.
* SM4 -- `bouncycastle-sm4`, the GB/T 32907-2016 block cipher (draft-ribose-cfrg-sm4-10), constant-time and
  table-free (the S-box as a bit-sliced Boolean circuit, four blocks at a time), on the key object `SM4Key<M>` with
  CBC, CFB, CFB8, CTR, GCM and CCM (RFC 8998's AEAD_SM4_GCM and AEAD_SM4_CCM), KW and KWP; the
  `sm4-{cbc,cfb,cfb8,ctr,gcm,ccm,kw,kwp}` CLI commands.
* CHACHA20 -- ChaCha20, Poly1305 and ChaCha20-Poly1305 (RFC 8439).
* TDES -- three-key TDEA (NIST SP 800-67 Rev 2) as a constant-time, table-free bit-sliced engine under `hazmat`,
  with ECB, CBC, CFB64, CFB8 and CTR (SP 800-38A Appendix E) and TDEA Key Wrap (SP 800-38F TKW) through the key
  role traits; two-key TDEA decrypts and unwraps only, which `BlockPermutation::DECRYPT_ONLY` makes a compile
  error for every encrypting route; the `tdes-*` and `tdes2-*` CLI commands, whose `encrypt` refuses input past
  SP 800-67 Rev 2 Sec 3.4's 2^20 blocks counted as the blocks TDEA processes (8 MiB; 1 MiB for CFB8, 699,048
  bytes for TKW).
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

* The key-wrap workers `Kw`, `Kwp` and `Tkw` carry their direction in the type, as the cipher modes do:
  `KeyWrapper` is implemented for the encrypting worker only, so an unwrapper has no wrapping method and a
  permutation that decrypts only is refused a wrapper at compile time by every route. The `AES_KW_*`, `AES_KWP_*`
  and `TDES_TKW` aliases gain the `Dir` parameter; `TDES2_TKW` is the decrypting one.
* Cipher and MAC workers no longer implement `SuspendableKeyed` (#173): a resumed worker is a second copy of a
  nonce, counter or keystream position. The AES modes, CMAC and Ascon-AEAD128 lose their suspended-state
  constants and `hazmat::ModeKey` goes with them; HMAC and HKDF still suspend, and hashes, XOFs and KMAC keep
  `Suspendable`.

