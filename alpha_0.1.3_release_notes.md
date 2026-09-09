# 0.1.3 Features / Changelog

## Major features

* New algorithms added to crypto/ :
    * SM3 -- the SM3 hash (GB/T 32905-2016 / ISO/IEC 10118-3:2018), ported from bc-java.
    * AES -- AES-128/192/256, along with its modes AES_ECB, AES_CBC, AES_CCM, AES_GCM.
    * ascon -- SP 800-232 Ascon-AEAD128/Hash256/XOF128/CXOF128, ported from bc-java.

`core`: new `AEADCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>` and
`AEADCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>` traits (#119/#120), the streaming API
for an authenticated cipher, shaped like `SimpleCipherEncryptor` / `SimpleCipherDecryptor` (separate
input/output buffers, exact `update_out_len`, generated nonce) with the two things authentication
adds: an AAD phase (`do_update_aad`, repeatable before the first `do_update_out`, refused with
`StateError` once data has started) and a finalizer that also produces the tag
(`do_encrypt_final`/`do_decrypt_final`, flushing up to `FINAL_LEN` held-back bytes alongside it).
`FINAL_LEN` is `0` for a cipher like Ascon-AEAD128 that never buffers; a block-oriented AEAD or one
whose wire format inlines the tag would need it non-zero. The one-shots (`encrypt_out[_rng]`,
`decrypt_out`, and the `std` `Vec` forms) are provided over the streaming methods, so an implementor
writes seven. `bouncycastle-ascon`'s `AsconAead128Encryptor` / `AsconAead128Decryptor` are the first
implementors.

Mutation-tested with `cargo mutants -p bouncycastle-core -F 'AEADCipher(Encryptor|Decryptor)'
--test-package bouncycastle-ascon` (`core` has no implementor of its own to test against): 68
mutants, 49 caught, 10 unviable, 9 missed -- all nine equivalent given `FINAL_LEN = 0`, the only
value Ascon-AEAD128 exercises. Six are `written + final_len` vs `written - final_len` in
`encrypt_out`/`encrypt_out_rng`/`decrypt_out`'s final-buffer splice, indistinguishable because
`final_len` is always `0` there; the other three are the one-shots' own buffer-length guard
(`plaintext.len() < needed` / `ciphertext.len() < needed`) against `>`, indistinguishable because
`needed` at `FINAL_LEN = 0` is exactly the bound Ascon's own `do_update_out` already enforces one
call deeper, so the outer guard's direction is never the only thing standing between a short buffer
and an error. A future `FINAL_LEN > 0` implementor (a block-oriented AEAD) would give both classes
of mutant something to bite on.

Where the tag goes is deliberately not fixed by the pair (contrast `AEADCipher`, whose one-shots
pick a layout): `core::tagged_aead::TaggedEncryptor<E>` / `TaggedDecryptor<D, TAG_LEN>` adapt any
`FINAL_LEN = 0` implementor to `SimpleCipherEncryptor` / `SimpleCipherDecryptor`, producing and
consuming the inline `ciphertext || tag` layout most wire formats and files use, with the AAD phase
still reachable through an inherent `do_update_aad` the `SimpleCipher*` traits have no slot for.
`TaggedDecryptor` holds back exactly the last `TAG_LEN` bytes it has seen at any point, releasing
everything older through the wrapped decryptor as soon as it is known not to be the tag -- the same
technique `bc-rust`'s `ascon-aead128 --decrypt` used by hand before this adapter existed, now
provided once. (A fully general adapter over a implementor whose own `FINAL_LEN` is non-zero needs
this adapter's `FINAL_LEN` to be `INNER_FINAL_LEN + TAG_LEN`, a value derived from two other const
generics that stable const generics cannot express as a trait argument; left to a future adapter.)

New crate `bouncycastle-ascon` (`bouncycastle::ascon`): Ascon-AEAD128 / Ascon-Hash256 / Ascon-XOF128
/ Ascon-CXOF128 (NIST SP 800-232), the lightweight cryptography suite selected from the NIST
Lightweight Cryptography competition.

* `AsconAead128` is the streaming primitive (rate 128 bits, capacity 192 bits, `Ascon-p[12]` at
  init/finalization and `Ascon-p[8]` on AAD/data blocks), with a caller-supplied nonce for KAT and
  protocol use. Every plaintext/ciphertext byte is transformed and emitted the moment it is seen --
  no held-back buffering across calls -- because within a rate block each byte is independent of
  the others in it; this is what lets its finalizers have nothing left to flush.
  `AsconAead128Encryptor` / `AsconAead128Decryptor` are thin newtypes over it implementing the new
  `AEADCipherEncryptor` / `AEADCipherDecryptor` pair with an internally-generated nonce; `AsconAead128`
  itself keeps implementing the one-shot-only `AEADCipher` (both directions on one type, chosen by a
  runtime flag), which the newtype split cannot replace since that trait needs both directions
  available on a single implementor.
* `AsconHash256` (`Hash`) and `AsconXof128` (`XOF`) are sponge constructions over the same
  permutation; `AsconCXof128` (`XOF`) adds the customization string of SP 800-232 Algorithm 7 (up to
  256 bytes). All four are byte-oriented: `do_final_partial_bits`/the equivalent XOF methods always
  return an error rather than accept a partial final byte, unlike SHA-2/SHA-3. Registered in
  `HashFactory` (`"Ascon-Hash256"`) and `XOFFactory` (`"Ascon-XOF128"`), with `ascon-hash256`,
  `ascon-xof128`, `ascon-cxof128` and `ascon-aead128` CLI subcommands; the last streams both
  directions in 1 KiB chunks, decrypting through `TaggedDecryptor` rather than a hand-rolled tail
  buffer.
* **Decryption releases plaintext before the tag is checked**, streaming or through the CLI: bytes
  are necessarily written to the caller's buffer (or stdout) before the last `TAG_LEN` bytes -- the
  tag -- can be read and compared. A non-zero exit from the CLI, or an `Err` from the streaming
  finalizer, means the input was tampered with and any output already produced must be discarded;
  do not treat it as authentic before that point. The one-shot APIs (`AsconAead128::decrypt`, both
  `AEADCipher` and `AEADCipherDecryptor` views) do not have this caveat: they own the whole message
  and zeroize the output buffer before returning an error.
* Verified against 4228 NIST LWC KAT vectors from `bc-test-data` (1089 each for AEAD128 and
  CXOF128, 1025 each for Hash256 and XOF128), plus embedded always-on vectors for when that
  repository is not checked out. Mutation-tested with `cargo mutants -p bouncycastle-ascon`: 665
  mutants, 558 caught, 103 unviable, 4 missed -- all four the same equivalent survivors as the
  crate's introduction (PR #21): the `Sponge::absorb`/`squeeze` boundary pair and the disjoint-bit
  `set_state_byte` OR-vs-XOR pair, neither touched by the `AEADCipherEncryptor`/`AEADCipherDecryptor`
  work.

## Minor features / bug fixes

* Design discussions about whether core::traits::XOF (in the abstract) should allow interleaving absorb -> squeeze ->
  absorb (ie "absorb-after-squeeze). Outcome: absorb-after-squeeze forbidden. Could be changed in the future.
* SHA2:
    * Implemented SHA512/224 and SHA512/256.
    * `Hash::do_final_partial_bits()` / `do_final_partial_bits_out()` are now implemented for SHA-2 (FIPS 180-4 s. 5.1).
* SHA3:
    * Fixed a bug in `XOF::squeeze_partial_byte_final()`: when it was the first squeeze it bypassed the SHAKE `1111`
      domain suffix and returned raw Keccak output, and it returned the wrong `num_bits` bits of the output byte. The
      existing test used
      `0xFF`, which masked the second error.
    * Changed the order of bits when absorbing a final partial byte to match ASN.1 DER BIT_STRING bit ordering.
