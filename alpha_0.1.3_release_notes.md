# 0.1.3 Features / Changelog

## Major features

New crate `bouncycastle-aes-lowmemory` (`bouncycastle::aes_lowmemory`): AES-128/192/256 as a raw keyed block
permutation (NIST FIPS 197), re-exported from the umbrella crate.

* **Constant-time and table-free.** The S-box is evaluated as a Boolean circuit -- the 113-gate Boyar-Peralta
  straight-line program, 32 AND / 77 XOR / 4 XNOR -- over eight `u32` bit-planes, so there is no secret-indexed
  memory access and no secret-dependent branch anywhere, including in the key schedule. A table-driven "light"
  AES that removes the tables only from the cipher still leaks through `SUBWORD()` in the expansion.
* **Low memory.** No lookup tables at all (0 bytes, against 512 bytes for BC Java's `AESLightEngine` and 2-8 KiB
  for T-table engines) and no heap allocation. The only persistent state is the key schedule, stored bit-sliced
  in a compressed form that is exactly the FIPS 197 Sec 5.2 size: `Aes128` 176 B, `Aes192` 208 B, `Aes256` 240 B.
* **Both directions from one value.** Decryption follows FIPS 197 Algorithm 3 (the straight inverse cipher) rather
  than the equivalent inverse cipher of Sec 5.3.5, so it uses the unmodified key schedule -- one stored schedule
  encrypts and decrypts, with no second copy and no transformation at construction time.
* **Two-block entry points.** The bit-sliced state holds two blocks, so `encrypt_blocks2` / `decrypt_blocks2` are
  the natural unit of work and roughly double single-block throughput. `encrypt_block` / `decrypt_block` are
  provided but do twice the necessary work; modes whose blocks are independent (CTR, and CBC/CFB decryption)
  should prefer the pair form.
* Verified against FIPS 197 Appendix A.1/A.2/A.3 (every schedule word), FIPS 197 Appendix B, an exhaustive check
  of all 256 S-box and inverse S-box inputs against Tables 4 and 6, SP 800-38A Appendix F.1 (ECB, all three key
  lengths, both directions), and 2138 NIST ACVP `ACVP-AES-ECB` cases from `bc-test-data` (skipped with a warning
  if that repository is not checked out).
* Deliberately ships no CLI subcommand, no factory entry and no `core` cipher-trait impls: a raw permutation can
  only offer ECB, and those are mode-of-operation concerns. `Algorithm` is implemented (name and security
  strength); per-mode OIDs and the `BlockCipherEncryptor` / `BlockCipherDecryptor` impls belong to the mode crates.

## Minor features / bug fixes

* bug fixes to the way SHA3/SHAKE handled absorbing and squeezing a partial final byte.
* Design discussions about whether core::traits::XOF (in the abstract) should allow interleaving absorb -> squeeze ->
  absorb (ie "absorb-after-squeeze). Outcome: absorb-after-squeeze forbidden. Could be changed in the future.

Block cipher traits (PR #96):

* The single `BlockCipher` streaming trait is split into `BlockCipherEncryptor` and `BlockCipherDecryptor` (mirroring
  `KEMEncapsulator` / `KEMDecapsulator`) so the direction is encoded in the implementing type. A minimal `BlockCipher`
  supertrait carries the shared `MAX_SECURITY_STRENGTH`; the `SymmetricCipher` one-shot API is no longer a supertrait.
* The single-block `do_{en,de}crypt_block[_out]` methods are replaced by multi-block
  `do_{en,de}crypt_blocks[_out]<const N>`, taking `&[[u8; BLOCK_LEN]; N]` so the block count is compile-time and
  input/output lengths cannot disagree.
* `do_encrypt_init_rng(key, &mut dyn RNG)` is added alongside `do_encrypt_init`, matching the `encaps` / `encaps_rng`
  pattern.
* The `do_{en,de}crypt_final[_out]` methods are removed: the traits are now strictly block-aligned, and padding of
  arbitrary-length data belongs to a separate `PaddedEncryptor` / `PaddedDecryptor` layer built on top.
* One-shot static APIs are provided (default) methods implemented once in the traits -- `encrypt_blocks`,
  `encrypt_blocks_rng`, `encrypt_blocks_out`, `encrypt_blocks_out_rng` on `BlockCipherEncryptor` and `decrypt_blocks`,
  `decrypt_blocks_out` on `BlockCipherDecryptor` -- so every block-aligned mode gets the house-standard
  take-data-return-result API at no cost to implementors.

Testing:

* The core-test-framework block cipher test now takes separate encryptor/decryptor type parameters, exercises N = 1 and
  N = 2 (including mixed single/multi-block encrypt vs decrypt sequences), and checks the one-shots agree with the
  streaming API and round-trip.
