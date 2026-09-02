//! Structural tests for CFB, driven by a toy permutation.
//!
//! These check the properties of the *mode* -- keystream generation, feedback, call sequencing, the
//! pair/remainder split, direction typing, SP 800-38A Appendix D error propagation -- independently
//! of any real cipher. The known-answer tests against SP 800-38A Appendix F.3.13 through F.3.18 are
//! in `sp800_38a_tests.rs`.
//!
//! Two things here have no counterpart in `cbc_tests.rs`, because they are what distinguishes CFB:
//!
//! * `cfb_decryption_never_calls_the_inverse_cipher` -- Sec 6.3 defines both directions in terms of
//!   `CIPH_K`, so a permutation with no inverse must still work.
//! * `a_ciphertext_bit_error_flips_exactly_that_bit_of_the_same_block` -- Table D.2 gives CFB
//!   *specific* bit errors in the block attacked, where CBC gives random ones. This is the
//!   malleability difference the crate docs warn about, asserted rather than asserted-in-prose.

mod common;

use bouncycastle_aes_lowmemory::{Aes128, Aes192, Aes256};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_core_test_framework::symmetric_ciphers::TestFrameworkBlockCipher;
use bouncycastle_modes::{Cfb, Decrypting, Encrypting};
use common::{ForwardOnlyToy, SwappedPairToy, TOY_LEN, Toy, toy_key};

type ToyCfb<Dir> = Cfb<Toy, Dir, TOY_LEN, TOY_LEN>;
type SwappedCfb<Dir> = Cfb<SwappedPairToy, Dir, TOY_LEN, TOY_LEN>;
type ForwardOnlyCfb<Dir> = Cfb<ForwardOnlyToy, Dir, TOY_LEN, TOY_LEN>;

/// A fixed IV, so encryption runs are comparable. `do_encrypt_init` would generate a fresh one.
fn pinned_iv() -> [u8; TOY_LEN] {
    core::array::from_fn(|i| 0x5A ^ (i as u8).wrapping_mul(3))
}

// ---- the mode against the shared framework -----------------------------------------------

/// The toy's own conformance is checked in `cbc_tests.rs`; this is the mode's.
#[test]
fn cfb_conforms_to_the_block_cipher_framework() {
    TestFrameworkBlockCipher::new()
        .test::<TOY_LEN, TOY_LEN, TOY_LEN, ToyCfb<Encrypting>, ToyCfb<Decrypting>>();
}

// ---- the defining property: forward function only ----------------------------------------

/// SP 800-38A Sec 6.3 defines **both** directions of CFB with the forward cipher function:
/// "Oj = CIPH_K(Ij) for j = 1, 2 ... n" appears identically under "CFB Encryption" and "CFB
/// Decryption", and the prose confirms it ("The *forward cipher* function is applied to each input
/// block to produce the output blocks ... to recover the plaintext segments").
///
/// [`ForwardOnlyToy`] panics if its `decrypt_block` is ever called. So this test failing means the
/// implementation reached for the inverse cipher somewhere, which would make CFB unusable with a
/// forward-only primitive and would not match the spec.
///
/// Both the single-block and the pair path are covered: `N = 1` skips the pair loop, `N = 2` is a
/// pure pair, and `N = 3` is a pair plus a remainder.
#[test]
fn cfb_decryption_never_calls_the_inverse_cipher() {
    let key = toy_key();
    let iv = pinned_iv();
    let plaintext: [[u8; TOY_LEN]; 3] =
        core::array::from_fn(|i| core::array::from_fn(|j| (i * 37 + j) as u8));

    // Encryption, too -- it should also only ever use the forward function.
    let (mut enc, got_iv) =
        ForwardOnlyCfb::<Encrypting>::do_encrypt_init_rng(&key, &mut FixedSeedRNG::new(iv))
            .unwrap();
    assert_eq!(got_iv, iv);
    let ct = enc.do_encrypt_blocks(&plaintext).unwrap();

    // N = 3: one pair through the pair path, then a one-block remainder.
    let mut dec = ForwardOnlyCfb::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    assert_eq!(dec.do_decrypt_blocks(&ct).unwrap(), plaintext, "N=3 (pair + remainder)");

    // N = 1 three times: never forms a pair.
    let mut dec = ForwardOnlyCfb::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    for (c, p) in ct.iter().zip(plaintext.iter()) {
        assert_eq!(dec.do_decrypt_blocks(&[*c]).unwrap(), [*p], "N=1");
    }

    // N = 2: a pure pair.
    let mut dec = ForwardOnlyCfb::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    assert_eq!(
        dec.do_decrypt_blocks(&[ct[0], ct[1]]).unwrap(),
        [plaintext[0], plaintext[1]],
        "N=2 (pure pair)"
    );
}

/// The same ciphertext must come out of the real toy and the forward-only one, so the test above is
/// not passing because `ForwardOnlyToy` behaves differently rather than because CFB avoids the
/// inverse.
#[test]
fn the_forward_only_toy_agrees_with_the_real_one() {
    let key = toy_key();
    let iv = pinned_iv();
    let plaintext = [[0x11u8; TOY_LEN], [0x22u8; TOY_LEN], [0x33u8; TOY_LEN]];

    let (mut a, _) =
        ToyCfb::<Encrypting>::do_encrypt_init_rng(&key, &mut FixedSeedRNG::new(iv)).unwrap();
    let (mut b, _) =
        ForwardOnlyCfb::<Encrypting>::do_encrypt_init_rng(&key, &mut FixedSeedRNG::new(iv))
            .unwrap();

    assert_eq!(a.do_encrypt_blocks(&plaintext).unwrap(), b.do_encrypt_blocks(&plaintext).unwrap());
}

// ---- keystream and feedback --------------------------------------------------------------

/// At `s = b` the first ciphertext block is `C1 = P1 XOR CIPH_K(IV)`, which makes the keystream
/// directly observable: encrypting an all-zero block yields `CIPH_K(IV)` itself.
///
/// This pins the collapse of the Sec 6.3 equations documented in `cfb.rs`: `I1 = IV`,
/// `MSB_b(O1) = O1`. If the implementation XOR-ed the plaintext in before the cipher call (i.e. did
/// CBC), or fed back the plaintext instead of the ciphertext, this would not hold.
#[test]
fn the_first_keystream_block_is_the_encrypted_iv() {
    use bouncycastle_core::traits::BlockPermutation;

    let key = toy_key();
    let iv = pinned_iv();

    // What the raw permutation makes of the IV.
    let perm = <Toy as BlockPermutation<TOY_LEN, TOY_LEN>>::new(&key).unwrap();
    let mut expected = iv;
    perm.encrypt_block(&mut expected);

    // Encrypting zeros exposes the keystream.
    let (mut enc, _) =
        ToyCfb::<Encrypting>::do_encrypt_init_rng(&key, &mut FixedSeedRNG::new(iv)).unwrap();
    let [c1] = enc.do_encrypt_blocks(&[[0u8; TOY_LEN]]).unwrap();
    assert_eq!(c1, expected, "C1 = 0 XOR CIPH_K(IV) = CIPH_K(IV)");

    // And the second input block is C1, not P1: encrypting zeros again gives CIPH_K(C1).
    let mut expected2 = c1;
    perm.encrypt_block(&mut expected2);
    let [c2] = enc.do_encrypt_blocks(&[[0u8; TOY_LEN]]).unwrap();
    assert_eq!(c2, expected2, "I2 = C1, so C2 = CIPH_K(C1)");
}

/// CFB feeds back the *ciphertext*. Two identical plaintext blocks in one message must therefore
/// still give different ciphertext blocks, and -- unlike a mode that fed back the plaintext -- the
/// keystream must not repeat when the plaintext does.
#[test]
fn identical_plaintext_blocks_give_different_ciphertext_blocks() {
    let key = toy_key();
    let plaintext = [[0x99u8; TOY_LEN]; 4];

    let (_, ct) = ToyCfb::<Encrypting>::encrypt_blocks(&key, &plaintext).unwrap();
    for i in 0..4 {
        for j in (i + 1)..4 {
            assert_ne!(ct[i], ct[j], "blocks {i} and {j} of the ciphertext repeat");
        }
    }
}

// ---- call sequencing ---------------------------------------------------------------------

/// Grouping the calls differently must not change the result, in either direction. For decryption
/// the odd groupings matter specifically: `N = 3` and `N = 5` leave a one-block remainder after the
/// pair loop, and `N = 1` skips the pair loop entirely.
#[test]
fn call_grouping_does_not_change_the_result() {
    let key = toy_key();
    let iv = pinned_iv();
    let plaintext: [[u8; TOY_LEN]; 8] =
        core::array::from_fn(|i| core::array::from_fn(|j| (i * TOY_LEN + j) as u8));

    // Reference: all eight in one call.
    let (mut enc, got_iv) =
        ToyCfb::<Encrypting>::do_encrypt_init_rng(&key, &mut FixedSeedRNG::new(iv)).unwrap();
    assert_eq!(got_iv, iv);
    let reference = enc.do_encrypt_blocks(&plaintext).unwrap();

    // Encryption, grouped 1 + 2 + 3 + 2.
    let (mut enc, _) =
        ToyCfb::<Encrypting>::do_encrypt_init_rng(&key, &mut FixedSeedRNG::new(iv)).unwrap();
    let mut got = [[0u8; TOY_LEN]; 8];
    let a = enc.do_encrypt_blocks(&[plaintext[0]]).unwrap();
    let b = enc.do_encrypt_blocks(&[plaintext[1], plaintext[2]]).unwrap();
    let c = enc.do_encrypt_blocks(&[plaintext[3], plaintext[4], plaintext[5]]).unwrap();
    let d = enc.do_encrypt_blocks(&[plaintext[6], plaintext[7]]).unwrap();
    got[0] = a[0];
    got[1..3].copy_from_slice(&b);
    got[3..6].copy_from_slice(&c);
    got[6..8].copy_from_slice(&d);
    assert_eq!(got, reference, "grouping must not change the ciphertext");

    // Decryption, in uniform groups.
    let ct = reference;
    let mut dec = ToyCfb::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    assert_eq!(dec.do_decrypt_blocks(&ct).unwrap(), plaintext);

    for grouping in [1usize, 2, 4] {
        let mut dec = ToyCfb::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
        let mut out = [[0u8; TOY_LEN]; 8];
        let mut at = 0;
        while at < 8 {
            match grouping {
                1 => {
                    let [p] = dec.do_decrypt_blocks(&[ct[at]]).unwrap();
                    out[at] = p;
                }
                2 => {
                    let p = dec.do_decrypt_blocks(&[ct[at], ct[at + 1]]).unwrap();
                    out[at..at + 2].copy_from_slice(&p);
                }
                _ => {
                    let p = dec
                        .do_decrypt_blocks(&[ct[at], ct[at + 1], ct[at + 2], ct[at + 3]])
                        .unwrap();
                    out[at..at + 4].copy_from_slice(&p);
                }
            }
            at += grouping;
        }
        assert_eq!(out, plaintext, "decrypting in groups of {grouping}");
    }

    // 3 + 5: both leave a one-block remainder after the pair loop.
    let mut dec = ToyCfb::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    let three = dec.do_decrypt_blocks(&[ct[0], ct[1], ct[2]]).unwrap();
    let five = dec.do_decrypt_blocks(&[ct[3], ct[4], ct[5], ct[6], ct[7]]).unwrap();
    assert_eq!(three, [plaintext[0], plaintext[1], plaintext[2]]);
    assert_eq!(five, [plaintext[3], plaintext[4], plaintext[5], plaintext[6], plaintext[7]]);
}

/// The pair path in `do_decrypt_blocks_out` must actually be taken.
///
/// [`SwappedPairToy`] returns its two pair results in the wrong order while its single-block
/// methods are correct. CFB decryption calls `encrypt_blocks2` (not `decrypt_blocks2`), which that
/// toy also swaps, so a pair must come out wrong and a lone block must come out right. If both were
/// right, the pair path would be dead code.
#[test]
fn the_pair_path_is_really_used() {
    let key = toy_key();
    let iv = pinned_iv();
    let plaintext = [[0xA5u8; TOY_LEN], [0x5Au8; TOY_LEN]];

    // The correct toy round-trips.
    let (mut enc, _) =
        ToyCfb::<Encrypting>::do_encrypt_init_rng(&key, &mut FixedSeedRNG::new(iv)).unwrap();
    let ct = enc.do_encrypt_blocks(&plaintext).unwrap();
    let mut dec = ToyCfb::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    assert_eq!(dec.do_decrypt_blocks(&ct).unwrap(), plaintext);

    // CFB *encryption* uses only the single-block forward call, so the swapped toy encrypts
    // identically to the correct one.
    let (mut enc, _) =
        SwappedCfb::<Encrypting>::do_encrypt_init_rng(&key, &mut FixedSeedRNG::new(iv)).unwrap();
    let swapped_ct = enc.do_encrypt_blocks(&plaintext).unwrap();
    assert_eq!(swapped_ct, ct, "encryption must not use the pair path");

    // ...but decrypting the pair together must now be wrong.
    let mut dec = SwappedCfb::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    assert_ne!(
        dec.do_decrypt_blocks(&swapped_ct).unwrap(),
        plaintext,
        "decrypting a pair must go through encrypt_blocks2"
    );

    // One block at a time avoids the pair path, so it is correct even for this toy.
    let mut dec = SwappedCfb::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    let [p0] = dec.do_decrypt_blocks(&[swapped_ct[0]]).unwrap();
    let [p1] = dec.do_decrypt_blocks(&[swapped_ct[1]]).unwrap();
    assert_eq!([p0, p1], plaintext, "the single-block path must not pair");
}

/// The `_out` variants must agree with the by-value ones and report the byte count.
#[test]
fn out_variants_agree_with_by_value() {
    let key = toy_key();
    let iv = pinned_iv();
    let plaintext = [[0x11u8; TOY_LEN], [0x22u8; TOY_LEN], [0x33u8; TOY_LEN]];

    let (mut enc, _) =
        ToyCfb::<Encrypting>::do_encrypt_init_rng(&key, &mut FixedSeedRNG::new(iv)).unwrap();
    let by_value = enc.do_encrypt_blocks(&plaintext).unwrap();

    let (mut enc, _) =
        ToyCfb::<Encrypting>::do_encrypt_init_rng(&key, &mut FixedSeedRNG::new(iv)).unwrap();
    let mut out = [[0u8; TOY_LEN]; 3];
    let n = enc.do_encrypt_blocks_out(&plaintext, &mut out).unwrap();
    assert_eq!(n, 3 * TOY_LEN);
    assert_eq!(out, by_value);

    let mut dec = ToyCfb::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    let mut back = [[0u8; TOY_LEN]; 3];
    let n = dec.do_decrypt_blocks_out(&out, &mut back).unwrap();
    assert_eq!(n, 3 * TOY_LEN);
    assert_eq!(back, plaintext);
}

// ---- SP 800-38A Appendix D error propagation ---------------------------------------------

/// Appendix D, Table D.2, CFB row: bit errors in `Cj` give "SBE in the decryption of Cj", where SBE
/// means "bit errors occur in the same bit position(s) as the original bit error(s)".
///
/// This is the CFB-specific malleability, and it is the opposite way round from CBC: there the
/// targeted flip lands in `Cj+1` and `Cj` is randomised. Because `Pj = Cj XOR Oj` and `Oj` does not
/// depend on `Cj`, flipping a bit of `Cj` flips exactly that bit of `Pj`.
///
/// Checked for every one of the 128 bit positions, on a middle block so the knock-on effect on the
/// next block can be checked at the same time.
#[test]
fn a_ciphertext_bit_error_flips_exactly_that_bit_of_the_same_block() {
    let key = toy_key();
    let iv = pinned_iv();
    let plaintext = [[0x00u8; TOY_LEN], [0x11u8; TOY_LEN], [0x22u8; TOY_LEN], [0x33u8; TOY_LEN]];

    let (mut enc, _) =
        ToyCfb::<Encrypting>::do_encrypt_init_rng(&key, &mut FixedSeedRNG::new(iv)).unwrap();
    let ct = enc.do_encrypt_blocks(&plaintext).unwrap();

    for byte in 0..TOY_LEN {
        for bit in 0..8 {
            let mut corrupt = ct;
            corrupt[1][byte] ^= 1 << bit;

            let mut dec = ToyCfb::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
            let got = dec.do_decrypt_blocks(&corrupt).unwrap();

            // P1 depends on the IV only, so it is untouched.
            assert_eq!(got[0], plaintext[0], "byte {byte} bit {bit}: P1 must be unaffected");

            // SBE: exactly the flipped bit of P2, and nothing else in that block.
            let mut expected_p2 = plaintext[1];
            expected_p2[byte] ^= 1 << bit;
            assert_eq!(
                got[1], expected_p2,
                "byte {byte} bit {bit}: P2 should show exactly that bit flipped"
            );

            // RBE in the next block: C2 is the cipher input for P3, so P3 is randomised. The
            // toy is not a random function, but the value must at least differ.
            assert_ne!(got[2], plaintext[2], "byte {byte} bit {bit}: P3 must be disturbed");

            // ...and, at s = b, b/s = 1, so nothing beyond P3 is affected.
            assert_eq!(got[3], plaintext[3], "byte {byte} bit {bit}: P4 must be unaffected");
        }
    }
}

/// Appendix D, Table D.2, CFB row: bit errors in the IV give "RBE in the decryption of
/// C1, C2, ..., Cj for some j between 1 and b/s". At `s = b` that is `j = 1`, so only `P1` is
/// affected -- and randomly, not in the same bit position, because the IV is a cipher *input* here
/// rather than an XOR operand.
///
/// The contrast with CBC is the point: the identical test in `cbc_tests.rs` asserts the flipped bit
/// appears verbatim in `P1`. Here it must not.
#[test]
fn an_iv_bit_error_randomises_only_the_first_block() {
    let key = toy_key();
    let iv = pinned_iv();
    let plaintext = [[0x00u8; TOY_LEN], [0x11u8; TOY_LEN], [0x22u8; TOY_LEN]];

    let (mut enc, _) =
        ToyCfb::<Encrypting>::do_encrypt_init_rng(&key, &mut FixedSeedRNG::new(iv)).unwrap();
    let ct = enc.do_encrypt_blocks(&plaintext).unwrap();

    let mut single_bit_flips = 0usize;

    for byte in 0..TOY_LEN {
        for bit in 0..8 {
            let mut corrupt_iv = iv;
            corrupt_iv[byte] ^= 1 << bit;

            let mut dec = ToyCfb::<Decrypting>::do_decrypt_init(&key, &corrupt_iv).unwrap();
            let got = dec.do_decrypt_blocks(&ct).unwrap();

            assert_ne!(got[0], plaintext[0], "IV byte {byte} bit {bit}: P1 must be disturbed");
            assert_eq!(got[1], plaintext[1], "IV byte {byte} bit {bit}: P2 must be unaffected");
            assert_eq!(got[2], plaintext[2], "IV byte {byte} bit {bit}: P3 must be unaffected");

            // Count the cases where the damage happened to be a single bit in the same position,
            // which is what CBC would give every time.
            let mut cbc_like = plaintext[0];
            cbc_like[byte] ^= 1 << bit;
            if got[0] == cbc_like {
                single_bit_flips += 1;
            }
        }
    }

    // The toy is a byte-wise permutation, not a random function, so a handful of coincidences are
    // possible; what must not happen is CBC's behaviour across the board.
    assert!(
        single_bit_flips < 8,
        "an IV bit error should randomise P1, not flip the same bit ({single_bit_flips}/128 \
         positions behaved like CBC)"
    );
}

// ---- IV handling -------------------------------------------------------------------------

/// Sec 5.3 covers CFB with CBC: the IV "must be unpredictable". A fresh one per encryption is the
/// mechanism, and for CFB an IV repeat is worse than for CBC (see the crate docs) -- with the same
/// key and IV, the first keystream block repeats and the ciphertexts leak the XOR of the
/// plaintexts.
#[test]
fn each_encryption_gets_a_fresh_iv() {
    let key = toy_key();
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..64 {
        let (_, iv) = ToyCfb::<Encrypting>::do_encrypt_init(&key).unwrap();
        assert!(seen.insert(iv), "IV repeated across encryptions: {iv:02x?}");
    }
}

/// The consequence of the above, stated as a test: identical plaintext encrypts differently, and
/// the reason is the IV.
#[test]
fn identical_plaintext_gives_different_ciphertext() {
    let key = toy_key();
    let plaintext = [[0x77u8; TOY_LEN], [0x77u8; TOY_LEN]];

    let (_, first) = ToyCfb::<Encrypting>::encrypt_blocks(&key, &plaintext).unwrap();
    let (_, second) = ToyCfb::<Encrypting>::encrypt_blocks(&key, &plaintext).unwrap();
    assert_ne!(first, second);
}

/// Reusing an IV under CFB gives a two-time pad on the first block: `C1 XOR C1' = P1 XOR P1'`.
///
/// This documents the hazard the crate docs describe, and pins the arithmetic behind it. It is not
/// a property of this implementation to be fixed -- it is why `do_encrypt_init` refuses to take an
/// IV -- so the test asserts the leak exists, which is what makes the warning true.
#[test]
fn an_iv_repeat_leaks_the_xor_of_the_plaintexts() {
    let key = toy_key();
    let iv = pinned_iv();

    let p1 = [[0x01u8; TOY_LEN]];
    let p2 = [[0xFEu8; TOY_LEN]];

    let (mut a, _) =
        ToyCfb::<Encrypting>::do_encrypt_init_rng(&key, &mut FixedSeedRNG::new(iv)).unwrap();
    let (mut b, _) =
        ToyCfb::<Encrypting>::do_encrypt_init_rng(&key, &mut FixedSeedRNG::new(iv)).unwrap();

    let c1 = a.do_encrypt_blocks(&p1).unwrap();
    let c2 = b.do_encrypt_blocks(&p2).unwrap();

    for i in 0..TOY_LEN {
        assert_eq!(
            c1[0][i] ^ c2[0][i],
            p1[0][i] ^ p2[0][i],
            "byte {i}: the shared keystream cancels, leaving the plaintext XOR"
        );
    }
}

// ---- key handling ------------------------------------------------------------------------

#[test]
fn a_key_of_the_wrong_type_is_rejected() {
    let bytes: [u8; TOY_LEN] = core::array::from_fn(|i| (i as u8) + 1);
    let seed = KeyMaterial::<TOY_LEN>::from_bytes_as_type(&bytes, KeyType::Seed).unwrap();
    assert!(ToyCfb::<Encrypting>::do_encrypt_init(&seed).is_err());
    assert!(ToyCfb::<Decrypting>::do_decrypt_init(&seed, &[0u8; TOY_LEN]).is_err());
}

// ---- memory ------------------------------------------------------------------------------

/// Pins the "Memory Usage" table in the crate docs, including the claim that CFB and CBC are the
/// same size.
#[test]
fn sizes_match_the_documented_memory_table() {
    use bouncycastle_modes::Cbc;
    use core::mem::size_of;

    assert_eq!(size_of::<Cfb<Aes128, Encrypting, 16, 16>>(), 176 + 16);
    assert_eq!(size_of::<Cfb<Aes192, Encrypting, 24, 16>>(), 208 + 16);
    assert_eq!(size_of::<Cfb<Aes256, Encrypting, 32, 16>>(), 240 + 16);

    // The direction marker is free.
    assert_eq!(
        size_of::<Cfb<Aes128, Encrypting, 16, 16>>(),
        size_of::<Cfb<Aes128, Decrypting, 16, 16>>()
    );

    // The general rule the docs state.
    assert_eq!(size_of::<Cfb<Aes256, Encrypting, 32, 16>>(), size_of::<Aes256>() + 16);

    // ...and that the two modes cost the same, which the docs claim explicitly.
    assert_eq!(
        size_of::<Cfb<Aes128, Encrypting, 16, 16>>(),
        size_of::<Cbc<Aes128, Encrypting, 16, 16>>()
    );
}
