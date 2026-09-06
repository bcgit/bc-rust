# 0.1.3 Features / Changelog

## Major features

* New algorithms added to crypto/ (PR #89):
    * sm3 -- the SM3 hash (GB/T 32905-2016 / ISO/IEC 10118-3:2018), ported from bc-java. Implements `Hash`,
      `Suspendable` and `AlgorithmOID`, supports bit-oriented (partial final byte) messages per GB/T 32905-2016 s. 5.2
      with the partial byte in ASN.1 BIT STRING order like SHA-2/SHA-3, and is registered in `HashFactory`
      (`"SM3"`) with a `bc-rust sm3` CLI subcommand.
    * HMAC-SM3, in the hmac crate, registered in `MACFactory` (`"HMAC-SM3"`) with a `bc-rust hmac-sm3` CLI subcommand.
    * Test vectors are the GB/T 32905-2016 Appendix A examples plus the bc-java `SM3DigestTest` / `HMac` vectors, with
      additional digests cross-checked against OpenSSL and bc-java.

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
* Ships the type aliases `AES_CBC_128` / `AES_CBC_192` / `AES_CBC_256` and `AES_CFB_128` /
  `AES_CFB_192` / `AES_CFB_256`, which fill in the const parameters of `bouncycastle-modes`' `Cbc`
  and `Cfb` and leave the direction as the type parameter. They are aliases only -- no new engine
  code, and each one's doctest round-trips and shows that a misaligned length fails to compile.

New crate `bouncycastle-modes` (`bouncycastle::modes`): block cipher modes of operation
(NIST SP 800-38A), providing **CBC** (Sec 6.2) and **CFB128** (Sec 6.3). Re-exported from the
umbrella crate.

* `Cbc<P, Dir, KEY_LEN, BLOCK_LEN>` and `Cfb<P, Dir, KEY_LEN, BLOCK_LEN>` over any
  `ElectronicCodeBook`, so the crate depends on no concrete cipher. The direction is a type parameter:
  `BlockCipherEncryptor` is implemented only for `<_, Encrypting, _, _>` and `BlockCipherDecryptor`
  only for `<_, Decrypting, _, _>`, making a wrong-direction call a compile error rather than a
  runtime check. The two types have identical APIs and identical size, so swapping one for the other
  is a one-word change.
* **The IV is generated, never accepted.** SP 800-38A Sec 5.3 requires the CBC *and CFB* IV to be
  *unpredictable*, not merely unique, so `do_encrypt_init` draws one from the library's default
  OS-backed DRBG (Appendix C's second recommended method) and returns it; there is no API for
  supplying your own. Known-answer tests drive `do_encrypt_init_rng` with a fixed-output test RNG.
  This matters more for CFB than for CBC: CFB XORs a keystream, so a repeated key-and-IV pair leaks
  `P1 XOR P1'` outright rather than merely whether the blocks were equal.
* **Parallel decryption.** Sec 6.2 notes CBC decryption's inverse cipher calls can run in
  parallel, so `do_decrypt_blocks` walks the ciphertext in eights through
  `ElectronicCodeBook::decrypt_blocks8`, then pairs through `decrypt_blocks2`, then a one-block
  remainder. A toy permutation that rotates its eight results proves the eight path is taken, and
  only for full eights. Measured against an
  otherwise identical permutation that does not override the pair methods, this is **1.83x** the
  decryption throughput (67.9 vs 37.1 MiB/s, AES-128, 16 KiB, N=8). CBC encryption is serial by
  construction and does not use it.
* Strictly block-aligned, as Sec 5.2 requires of CBC. Arbitrary-length data goes through
  `bouncycastle-padding`'s `PaddedEncryptor` / `PaddedDecryptor`, which wrap either mode; no padding
  logic lives in this crate. `crypto/modes/tests/cfb_tests.rs` round-trips every length from 0 to
  `3 * BLOCK_LEN + 1` through PKCS7 to pin that the two crates compose.
* Verified against all six SP 800-38A Appendix F.2 vectors (CBC-AES128/192/256, Encrypt and
  Decrypt), each checked in one call, one block at a time, in a `3 + 1` grouping that exercises the
  pair remainder, and through the `_out` variant. Appendix D error propagation is tested
  exhaustively for the IV (every one of the 128 bit positions flips exactly its own bit of P1) and
  for a ciphertext bit error (affects exactly two blocks).
* Also verified against the **2150 NIST ACVP `ACVP-AES-CBC` AFT cases** from `bc-test-data` (all
  three key lengths, both directions, 60 of them spanning 2-10 blocks). Each case is run twice --
  block by block, and in pairs with a one-block remainder -- so the `decrypt_blocks2` path is
  exercised against real vectors, not only against the toy permutation. Unlike the ECB response
  file, the CBC one carries only the answer against a `tcId`, so the request and response files are
  joined; the 6 MCT groups are skipped and the count reported. These vectors were already in
  `bc-test-data` and previously unused.
CFB (`Cfb`), SP 800-38A Sec 6.3:

* **Full-block segment only.** Sec 6.3 parameterises CFB by a segment size `s` with `1 <= s <= b`;
  `Cfb` implements `s = b` -- CFB128 for AES -- because that is the only segment size that is
  block-aligned and therefore the only one that fits `BlockCipherEncryptor` /
  `BlockCipherDecryptor`. With `s = b` the spec's `LSB_{b-s}(I_{j-1}) | C#_{j-1}` collapses to
  `Ij = C_{j-1}` and `MSB_s(Oj)` to `Oj`, which the module docs derive step by step. **CFB8 and
  CFB1 are different, non-interoperable modes and are not provided**; they need a `StreamCipher`
  shape, and both the crate docs and the CLI help say so explicitly.
* **Decryption uses the forward cipher function.** Sec 6.3 applies `CIPH_K` in both directions, so
  `Cfb<_, Decrypting, _, _>` never calls `decrypt_block` or `decrypt_blocks2`. This is pinned by a
  test permutation whose inverse methods panic, run over both the pair and single-block paths -- so
  the claim is enforced rather than merely documented.
* **Parallel decryption**, via `encrypt_blocks8` / `encrypt_blocks2` (eights, then pairs, then a single block, like CBC): Sec 6.3 notes CFB decryption's forward cipher
  calls "can be performed in parallel if the input blocks are first constructed (in series) from the
  IV and the ciphertext", and with `s = b` those input blocks simply *are* the IV followed by the
  ciphertext. Measured against an otherwise identical permutation that does not override the pair
  methods, this is **2.08x** the decryption throughput (110.9 vs 53.3 MiB/s, AES-128, 16 KiB, N=8).
  In the same run CFB decryption was **1.37x** CBC decryption (110.9 vs 80.8 MiB/s), because the
  bit-sliced engine's forward direction is cheaper than its inverse and CFB only ever needs the
  forward one. CFB encryption is serial by construction and does not use the pair path -- verified,
  not assumed: the swapped-pair test permutation produces identical ciphertext under `Cfb` encrypt.
* Same size as `Cbc` -- one permutation plus one block of feedback (192/224/256 B for
  AES-128/192/256) -- because the keystream block `Oj` is recomputed per call and lives only in a
  local, so no keystream outlives the call that used it.
* Verified against all six SP 800-38A **Appendix F.3.13-F.3.18** vectors (CFB128-AES128/192/256,
  Encrypt and Decrypt) in the same four groupings as CBC. F.3 additionally tabulates the *output
  blocks* -- the keystream -- so those are checked against the raw permutation too
  (`Oj == CIPH_K(I_j)` and `Cj == Pj XOR Oj` for all four segments of all three key lengths), which
  pins the mode's internals and not just its final output. As a transcription cross-check, CFB128
  is required to agree with **Appendix F.4.1 (OFB)** on the first block -- both compute
  `C1 = P1 XOR CIPH_K(IV)` -- and to disagree from the second.
* Also verified against the **2138 NIST ACVP `ACVP-AES-CFB128` AFT cases** from `bc-test-data` (all
  three key lengths, both directions, 54 of them spanning 2-10 blocks), each run twice, block by
  block and in pairs with a remainder. The 6 MCT groups are skipped and the count reported. These
  vectors were already in `bc-test-data` and previously unused.
* Appendix D error propagation is tested in the direction that distinguishes CFB from CBC. Table D.2
  gives CFB "SBE in the decryption of Cj": every one of the 128 bit positions of `C2` is flipped and
  required to flip *exactly* that bit of `P2` (the block the attacker aimed at, unlike CBC where it
  lands in `P3`), to randomise `P3`, and to leave `P1` and `P4` untouched. The IV case is checked
  with real AES, where a corrupted IV must *randomise* `P1` rather than flip a bit in place, and
  must not affect any later block -- with `s = b`, Appendix D's "first `i/s` (rounding up)"
  segments is one segment for every bit position.
* Mutation-tested: `cargo mutants -p bouncycastle-modes` reports **0 surviving mutants** (72
  mutants, 39 caught, 33 unviable), including every `^`-to-`|`/`&` substitution and every
  keystream-stubbing mutant in `cfb.rs`.
* Still not implemented, and listed in the crate docs: the CFB segment sizes below the block size
  (`s = 8`, `s = 1`), and ECB, OFB and CTR.

`cli`: six new subcommands -- `aes128-cbc`, `aes192-cbc`, `aes256-cbc`, `aes128-cfb`, `aes192-cfb`
and `aes256-cfb` -- each taking `encrypt` or `decrypt` and streaming stdin to stdout in 1 KiB
chunks.

* All the mode-independent plumbing -- key loading, stdin framing, block-alignment enforcement,
  hex/binary output -- lives once in `cli/src/block_mode_cmd.rs`, generic over the mode via
  `BlockCipherEncryptor` / `BlockCipherDecryptor`. `aes_cbc_cmd.rs` and `aes_cfb_cmd.rs` are thin
  dispatchers over it, so the two commands cannot drift apart on the parts that affect correctness.
* Key from `--key` (hex) or `--key-file` (binary or hex), with the usual note that secrets on the
  command line end up in shell history. The key length must match the variant exactly.
* **The IV travels in the ciphertext**: since there is no API for supplying one, `encrypt` writes
  the generated IV as the first 16 bytes of its output and `decrypt` reads it back from the first
  16 bytes of its input, so `encrypt | decrypt` composes with no `--iv` flag anywhere. The IV need
  not be secret (SP 800-38A Sec 5.3), so this is sound.
* Input must be a whole number of 16-byte blocks. Unaligned input is rejected with a message saying
  the commands apply no padding rather than being silently padded.
* The `-cfb` commands are **CFB128**, and both the subcommand help and the alignment error name the
  segment size, because `CFB8` and `CFB1` are different modes that would silently produce
  incompatible output.
* Reads need not respect block boundaries: bytes accumulate in a 1 KiB buffer that goes through the flat
  `do_*_out::<1024>` when full, and the whole-block remainder at end of input goes one block at a time; verified by
  round-tripping 64 KiB through `dd bs=3`.
* Verified against SP 800-38A F.2 (CBC) and F.3.13/F.3.15/F.3.17 (CFB128): prepending the spec's IV
  to the spec's ciphertext and running `decrypt` reproduces the spec's plaintext for all three key
  lengths in both modes. The CBC `encrypt` direction was cross-checked against an independent CBC
  implementation under the IV the CLI generated.
* `cli/tests/aes_cbc_cli_tests.rs` (16 tests) drives the built binary as a subprocess via
  `CARGO_BIN_EXE_bc-rust`, so all of the above is asserted by `cargo test` rather than by hand:
  the F.2 vectors, round trips across the chunk boundary, a fresh IV per invocation, hex/binary
  agreement, `--key-file` in both hex and binary, and every error path with its message.
* `cli/tests/aes_cfb_cli_tests.rs` (18 tests) mirrors that suite -- the shared plumbing is generic
  over the mode, so a wiring mistake in the CFB dispatcher would not show up in the CBC tests -- and
  adds three CFB-specific checks: the F.3 vectors, the Appendix D single-bit malleability observed
  end to end through the pipe, and a guard that a CFB ciphertext does not decrypt as CBC or vice
  versa (neither mode is authenticated, so the mismatch is otherwise silent).

`core`: new `ElectronicCodeBook<KEY_LEN, BLOCK_LEN>` trait (`crypto/core/src/traits.rs`), the raw
keyed permutation -- `CIPH_K` / `CIPH^-1_K` of SP 800-38A Sec 5.1 -- that a mode is built on.
`new`, `encrypt_block`, `decrypt_block`, plus provided `encrypt_blocks2` / `decrypt_blocks2` that
default to two single-block calls and `encrypt_blocks8` / `decrypt_blocks8` that default to four pair
calls, all of which bit-sliced implementations override (AES the pair form, SM4 both). The block methods
are infallible; only `new` can fail, and only on the key. `bouncycastle-aes-lowmemory` implements
it for all three key lengths (the data-encryption traits are still deliberately not implemented
there).

`core`: new `SymmetricCipherEncryptor<KEY_LEN, INIT_DATA_LEN, FINAL_LEN>` and
`SymmetricCipherDecryptor<KEY_LEN, INIT_DATA_LEN, FINAL_LEN>` traits, the arbitrary-length data API a
caller uses, as opposed to the block-aligned `BlockCipher*` traits a mode implements. Their shape is
taken from `PaddedEncryptor` / `PaddedDecryptor`, which now implement them: streaming
`do_{en,de}crypt_init[_rng]`, exact `update_out_len`, `do_update_out`, and a consuming `do_final` that
returns the fixed `FINAL_LEN` trailing bytes (the padded block; a tag or nothing for other cipher kinds),
the decryptor's paired with how many of them are data. `do_final_out`, the `_out` one-shots
(`encrypt_out[_rng]`, `decrypt_out`, with `encrypt_out_len` exact and `decrypt_out_max_len` an upper
bound, checked before any work is done) and the `std` `Vec` one-shots are provided over the streaming
methods, so an implementor writes six methods. The older one-shot-only `SymmetricCipher` trait is
unchanged for now; `AEADCipher` and `StreamCipher` still build on it and are the next to migrate.

Testing:

* `core-test-framework` gains `TestFrameworkSymmetricCipher::test_encryptor_decryptor`, which pins the
  paired contract: one-shot round trips at every length up to a few final chunks, the `std` one-shots
  against the `_out` ones, streaming in eight chunkings with `update_out_len` exact on every call,
  `do_final_out` against `do_final`, a driven RNG reproducing its init data and determining the
  ciphertext, corruption detection, short output buffers refused with the required length, and the
  key-type and security-strength policy. The padded adapters run it.
* `core-test-framework` gains `TestFrameworkElectronicCodeBook`, which pins the trait contract:
  both directions are inverses either way round, the permutation is injective, and the pair
  methods are indistinguishable from two single-block calls **including their order** -- the check
  that makes an override safe.
* Fixed a latent bug in `TestFrameworkBlockCipher`: it unwrapped `set_security_strength` at all
  five strengths, which a key shorter than 32 bytes cannot carry, so the framework panicked for
  any 16- or 24-byte key. It now skips the strengths the key length cannot hold. The bug was
  invisible until now because nothing in the workspace implemented the block cipher traits. The
  identical loop in `TestFrameworkSymmetricCipher` and `TestFrameworkAEADCipher` is still unfixed;
  both still have no implementors, so it stays latent. (`TestFrameworkStreamCipher` has no
  security-strength handling at all and is unaffected.)

* Block cipher padding (PR #97):
    * padding -- new crate (`bouncycastle-padding`, no_std, re-exported as `bouncycastle::padding`) providing `PKCS7`,
      the padding scheme of RFC 5652 s. 6.3, for any block length 1..=255 (enforced at compile time). `unpad` examines
      every byte with `Condition<i64>` mask arithmetic and has a single public decision point, so it does not leak a
      padding oracle through timing or error detail.
    * `PaddedEncryptor<E, P>` / `PaddedDecryptor<D, P>` adapt a block-aligned `BlockCipherEncryptor` /
      `BlockCipherDecryptor` to arbitrary-length data: streaming `do_update_out` / `do_final(self)` plus one-shot
      `encrypt_out` / `decrypt_out`, with exact output-length helpers. The buffered partial plaintext block is held in
      a `Secret`, and the decryptor withholds one complete block until `do_final`, since only the last block carries
      padding.
    * `core` gains the `Padding<const BLOCK_LEN>` trait (in-place `pad(block, data_len)`, constant-time
      `unpad(block) -> data_len`) and `PaddingError { DataLengthTooLong, InvalidPadding }`, wrapped as a new variant of
      `SymmetricCipherError`.
    * Tests are derived from the RFC 5652 padding rule; the adapters are driven with a toy XOR-CBC cipher implementing
      the new block cipher traits, covering every data length, ten chunkings in both directions, tampering, malformed
      lengths, and buffer sizing. Criterion bench included.

## Minor features / bug fixes

* bug fixes to the way SHA3/SHAKE handled absorbing and squeezing a partial final byte.
* Design discussions about whether core::traits::XOF (in the abstract) should allow interleaving absorb -> squeeze ->
  absorb (ie "absorb-after-squeeze). Outcome: absorb-after-squeeze forbidden. Could be changed in the future.

SHA-2 (PR #88):

* `Hash::do_final_partial_bits()` / `do_final_partial_bits_out()` are now implemented for SHA-224/256/384/512
  (FIPS 180-4 s. 5.1), bringing SHA-2 to parity with SHA-3 for messages whose length is not a multiple of 8 bits.
  Previously these methods hit `unimplemented!()` -- a panic behind a `Result`-returning API. `num_partial_bits` may be
  0..=7 (0 behaves exactly as `do_final_out()`); larger values return `HashError::InvalidLength`. The trailing bits are
  the most significant bits of `partial_byte`, the same convention as SHA-3 (see "Bit-oriented messages" below).
* Initial hash values are now compile-time constants (`const H0` on the params traits), removing a runtime
  match-on-`OUTPUT_LEN` and its `panic!` arm. `HashAlgParams` for the public types is forwarded from the `*Params`
  structs, so `OUTPUT_LEN` / `BLOCK_LEN` are defined once.
* Crate docs: fixed SHA-3/SHAKE copy-paste text, added a partial-bits usage example, "Memory Usage" and
  "Security Considerations" sections, and documented the `*_NAME` constants. The 2^64-byte message-length limit is
  now stated.

Testing:

* SHA-2 now runs the NIST CAVP SHAVS vector sets from bc-test-data (`crypto/sha2`: ShortMsg, LongMsg and Monte Carlo;
  bit- and byte-oriented, ~12k cases of which ~5.4k are bit-length messages) using the same `../bc-test-data` lookup
  convention as the mldsa/mlkem crates; the tests skip with a warning if the repo is not checked out. The SHAVS files
  pack trailing message bits MSB-first (left-justified), which is the convention used by the API. Note that
  `cargo mutants` runs in a copied tree where `../bc-test-data` does not resolve, so these tests do not contribute to
  mutation coverage.

Bit-oriented messages:

* `Hash::do_final_partial_bits()` / `do_final_partial_bits_out()` and `XOF::absorb_last_partial_byte()` accept
  `num_partial_bits` in 0..=7 (0 meaning the message ends on a byte boundary); larger values return
  `HashError::InvalidLength` instead of panicking.
* The partial byte is taken as it arrives in the final octet of an ASN.1 BIT STRING (X.690 s. 8.6.2): the
  `num_partial_bits` message bits are the most significant bits of `partial_byte`, leading bit first, and the low
  `8 - num_partial_bits` bits (the BIT STRING's "unused bits") are ignored -- so for a BIT STRING with `unused` in
  1..=7, pass the final content octet with `num_partial_bits = 8 - unused`. The convention is the same for every hash
  family; SHA-3/SHAKE reverse the bits internally into the FIPS 202 Appendix B.1 order that Keccak absorbs (bit 0
  first). `XOF::squeeze_partial_byte_final()` returns its bits the same way: in the most significant `num_bits` bits,
  first output bit first, low bits zero. (Previously the API documented FIPS 202 B.1 order -- message bits in the
  least significant bits, bit 0 first -- but SHA-2 in fact treated the low bits as a left-justified group, so the two
  families only agreed on palindromic bit patterns. The BIT STRING convention is now applied uniformly.)
* Test vectors: the NIST CAVP SHAVS (SHA-2) bit-oriented files are left-justified and are passed to the API directly;
  the SHA3VS files and the FIPS 202 example vectors use the Appendix B.1 packing and are bit-reversed by the harness.

SHA-3 / SHAKE (PR #87):

* Fixed `XOF::squeeze_partial_byte_final()`: when it was the first squeeze it bypassed the SHAKE `1111` domain suffix
  and returned raw Keccak output, and it returned the wrong `num_bits` bits of the output byte. The existing test used
  `0xFF`, which masked the second error.
* Fixed `XOF::absorb_last_partial_byte()` for `num_partial_bits == 4`: the 4 message bits plus the `1111` suffix
  exactly filled a byte and the sponge did not switch to squeezing, so the first squeeze appended the suffix a second
  time. Every SHAKE message with a bit length of 4 mod 8 was affected. Found by the new CAVP harness.
* `absorb_last_partial_byte()` and `do_final_partial_bits*()` now validate `num_partial_bits` before use; previously
  SHA-3 accepted 8..15 and absorbed garbage, panicked for >= 16, and SHAKE rejected 0 with an error message claiming
  `[0,7]`.
* Interleaving absorb -> squeeze -> absorb remains rejected with `HashError::InvalidState`; the `XOF` trait docs now
  explain why (it is the duplex construction, not SHAKE).
* `HashAlgParams` for the SHA-3 types is now forwarded from the `*Params` structs, so `OUTPUT_LEN` / `BLOCK_LEN` are
  defined once. Removed misleading leftover SHA-2 block-size comments.
* Crate docs gained "Memory Usage" and "Security Considerations" sections.

Testing:

* SHA-3 / SHAKE now run the NIST CAVP SHA3VS vector sets from bc-test-data (`crypto/sha3`: ShortMsg, LongMsg, Monte
  Carlo and SHAKE VariableOut; bit- and byte-oriented, ~13k cases) using the same `../bc-test-data` lookup convention as
  the mldsa/mlkem crates; the tests skip with a warning if the repo is not checked out. The vendored FIPS 202 example
  vectors in `crypto/sha3/tests/data` were removed in favour of the bc-test-data copies. Note that `cargo mutants` runs
  in a copied tree where `../bc-test-data` does not resolve, so these tests do not contribute to mutation coverage.

SHA-512/224 and SHA-512/256:

* `bouncycastle-sha2` adds SHA-512/t (FIPS 180-4 s. 5.3.6) as the generic `SHA512t<const T: usize>`, with
  `SHA512_224` and `SHA512_256` as the two NIST-approved instantiations; any other `T` fails to compile. The initial
  hash value is derived at compile time by the s. 5.3.6 "SHA-512/t IV Generation Function" (the SHA-512 compression
  function is now a `const fn`) and `const`-asserted against the words listed in s. 5.3.6.1 / s. 5.3.6.2. Names are
  "SHA512/224" / "SHA512/256"; OIDs are id-sha512-224 { hashAlgs 5 } and id-sha512-256 { hashAlgs 6 }. Registered in
  `HashFactory` and exposed as the `sha512-224` / `sha512-256` CLI subcommands. Every step of both SHA-2 compression
  functions, the padding, parsing and truncation now carries a FIPS 180-4 section citation.
* `bouncycastle-hmac` adds `HMAC_SHA512_224` and `HMAC_SHA512_256` (names "HMAC-SHA512/224" / "HMAC-SHA512/256"; OIDs
  id-hmacWithSHA512-224 { digestAlgorithm 12 } and id-hmacWithSHA512-256 { digestAlgorithm 13 }, RFC 8018 Appendix
  B.1.2), registered in `MACFactory` and exposed as the `hmac-sha512-224` / `hmac-sha512-256` CLI subcommands.

Testing:

* The SHA-2 CAVP SHAVS harness (bit- and byte-oriented ShortMsg, LongMsg and Monte Carlo) now also runs the
  SHA512_224 and SHA512_256 vector sets, and additionally re-feeds every whole-byte message through the streaming API
  in uneven chunks.
* NIST publishes no full-length known-answer vectors for HMAC-SHA512/224 and /256; the tests use the 160-bit truncated
  ACVP cases and compare the leading bytes, with full-length output cross-checked against OpenSSL.

Housekeeping:

* `no_std` progress: `std::marker::PhantomData` and `std::fmt` replaced with their `core::` equivalents in the SHA-3
  and Hash_DRBG crates, and the `Copy` types `KeyType` / `SecurityStrength` are now copied rather than `.clone()`d.
  Removed a redundant second zeroization of the caller's output buffer in `Hash::hash_out()` / `XOF::hash_xof_out()`.

Block cipher traits (PR #96):

* The single `BlockCipher` streaming trait is split into `BlockCipherEncryptor` and `BlockCipherDecryptor` (mirroring
  `KEMEncapsulator` / `KEMDecapsulator`) so the direction is encoded in the implementing type. Both, and
  `ElectronicCodeBook`, are bounded on `Algorithm`, whose `MAX_SECURITY_STRENGTH` is the strength the `_init`
  constructors enforce (a mode reports its permutation's name and strength); the `SymmetricCipher` one-shot API is no
  longer a supertrait.
* The single-block `do_{en,de}crypt_block[_out]` methods are replaced by multi-block
  `do_{en,de}crypt_blocks[_out]<const N>`, taking `&[[u8; BLOCK_LEN]; N]` so the block count is compile-time and
  input/output lengths cannot disagree.
* `do_encrypt_init_rng(key, &mut dyn RNG)` is added alongside `do_encrypt_init`, matching the `encaps` / `encaps_rng`
  pattern.
* The `do_{en,de}crypt_final[_out]` methods are removed: the traits are now strictly block-aligned, and padding of
  arbitrary-length data belongs to a separate `PaddedEncryptor` / `PaddedDecryptor` layer built on top.
* One-shot static APIs are provided (default) methods implemented once in the traits -- `encrypt`, `encrypt_rng` on
  `BlockCipherEncryptor` and `decrypt` on `BlockCipherDecryptor` -- so every block-aligned mode gets the
  house-standard one-shot API at no cost to implementors. They take a flat `&mut [u8; LEN]` and work **in place**
  (plaintext in, ciphertext out in the same bytes; `encrypt` returns the generated init data). `LEN` must be a whole
  number of blocks, and this is enforced at **compile time** by an inline `const` assertion at the instantiating call
  site, so there is no runtime length check and no error variant for it. Data whose length is only known at run
  time goes block by block or through the padding layer. (Earlier forms took `[[u8; BLOCK_LEN]; N]`, then separate
  input and output arrays; both were replaced before release.)
* The streaming API is flat and in place as well: `do_{en,de}crypt<LEN>(&mut [u8; LEN])`, with the same compile-time
  alignment check, are provided methods. The single block-shaped method left is the implementor hook
  `do_{en,de}crypt_blocks(&mut [[u8; BLOCK_LEN]])`, which is what guarantees an implementation never sees a
  partial block; an implementor writes only `do_{en,de}crypt_init[_rng]` and that hook. The hook takes a *slice* of
  blocks rather than a `[[u8; BLOCK_LEN]; N]` array (it did at first): every whole number of blocks is valid, so
  there is no length invariant for a const parameter to carry, and batching -- singly, in pairs, in eights -- is the
  mode's decision. `do_{en,de}crypt<LEN>` therefore hands the whole buffer to the hook in one call, and CBC
  decryption chunks it into pairs for `decrypt_blocks2` itself. The data methods keep a
  `Result` only for modes with a per-initialization data limit (counter-based modes); CBC never fails them.

Testing:

* The core-test-framework block cipher test now takes separate encryptor/decryptor type parameters, exercises N = 1 and
  N = 2 (including mixed single/multi-block encrypt vs decrypt sequences), and checks the one-shots agree with the
  streaming API and round-trip.
