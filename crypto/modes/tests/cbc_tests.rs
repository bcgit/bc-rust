//! Structural tests for CBC, driven by a toy permutation.
//!
//! These check the properties of the *mode* -- chaining, call sequencing, the pair/remainder split,
//! direction typing, SP 800-38A Appendix D error propagation -- independently of any real cipher.
//! The known-answer tests against SP 800-38A Appendix F.2 are in `sp800_38a_tests.rs`.

mod common;

use bouncycastle_aes_lowmemory::{Aes128, Aes192, Aes256};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor};
use bouncycastle_core_test_framework::block_permutation::TestFrameworkBlockPermutation;
use bouncycastle_core_test_framework::symmetric_ciphers::TestFrameworkBlockCipher;
use bouncycastle_modes::{Cbc, Decrypting, Encrypting};
use common::{SwappedPairToy, TOY_LEN, Toy, toy_key};

type ToyCbc<Dir> = Cbc<Toy, Dir, TOY_LEN, TOY_LEN>;
type SwappedCbc<Dir> = Cbc<SwappedPairToy, Dir, TOY_LEN, TOY_LEN>;

// ---- the toy itself, and the mode, against the shared frameworks -------------------------

/// The toy must be a real permutation before any conclusion drawn from it is worth anything.
#[test]
fn the_toy_permutation_conforms_to_the_trait() {
    TestFrameworkBlockPermutation::new().test::<TOY_LEN, TOY_LEN, Toy>();
}

#[test]
fn cbc_conforms_to_the_block_cipher_framework() {
    TestFrameworkBlockCipher::new()
        .test::<TOY_LEN, TOY_LEN, TOY_LEN, ToyCbc<Encrypting>, ToyCbc<Decrypting>>();
}

// ---- chaining and call sequencing --------------------------------------------------------

/// Encrypting `n` blocks must not depend on how the calls are grouped, and likewise for
/// decryption. This is the "a sequence of calls is equivalent to one call over the concatenation"
/// contract of the trait, and for CBC it is entirely about the chaining value surviving across
/// calls.
///
/// The odd groupings matter for decryption specifically: `N = 3` and `N = 5` leave a one-block
/// remainder after the pair loop, and `N = 1` skips the pair loop altogether.
#[test]
fn call_grouping_does_not_change_the_result() {
    let key = toy_key();
    let plaintext: [[u8; TOY_LEN]; 8] =
        core::array::from_fn(|i| core::array::from_fn(|j| (i * TOY_LEN + j) as u8));

    // Both encryption runs must use the same IV to be comparable, so pin it with the fixed RNG
    // rather than letting `do_encrypt_init` generate a fresh one.
    let iv: [u8; TOY_LEN] = core::array::from_fn(|i| 0xF0 ^ (i as u8));
    let pinned_rng = || bouncycastle_core_test_framework::FixedSeedRNG::<TOY_LEN>::new(iv);

    // Reference: all eight blocks in one call.
    let (mut enc, got_iv) =
        ToyCbc::<Encrypting>::do_encrypt_init_rng(&key, &mut pinned_rng()).unwrap();
    assert_eq!(got_iv, iv, "the pinned RNG should reproduce the IV");
    let reference = enc.do_encrypt_blocks(&plaintext).unwrap();

    // The same eight blocks, grouped every way that exercises a different code path.
    let (mut enc, _) = ToyCbc::<Encrypting>::do_encrypt_init_rng(&key, &mut pinned_rng()).unwrap();
    let mut got = [[0u8; TOY_LEN]; 8];
    let a = enc.do_encrypt_blocks(&[plaintext[0]]).unwrap(); // N = 1
    let b = enc.do_encrypt_blocks(&[plaintext[1], plaintext[2]]).unwrap(); // N = 2
    let c = enc.do_encrypt_blocks(&[plaintext[3], plaintext[4], plaintext[5]]).unwrap(); // N = 3
    let d = enc.do_encrypt_blocks(&[plaintext[6], plaintext[7]]).unwrap(); // N = 2
    got[0] = a[0];
    got[1..3].copy_from_slice(&b);
    got[3..6].copy_from_slice(&c);
    got[6..8].copy_from_slice(&d);

    assert_eq!(got, reference, "grouping must not change the ciphertext");

    // Now the decrypt side: one call vs several groupings, all from the same ciphertext.
    let ct = reference;

    let mut dec = ToyCbc::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    let all_at_once = dec.do_decrypt_blocks(&ct).unwrap();
    assert_eq!(all_at_once, plaintext);

    for grouping in [1usize, 2, 4] {
        let mut dec = ToyCbc::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
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

    // N = 3 and N = 5 both leave a one-block remainder after the pair loop.
    let mut dec = ToyCbc::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    let three = dec.do_decrypt_blocks(&[ct[0], ct[1], ct[2]]).unwrap();
    let five = dec.do_decrypt_blocks(&[ct[3], ct[4], ct[5], ct[6], ct[7]]).unwrap();
    assert_eq!(three, [plaintext[0], plaintext[1], plaintext[2]]);
    assert_eq!(five, [plaintext[3], plaintext[4], plaintext[5], plaintext[6], plaintext[7]]);
}

/// The pair path in `do_decrypt_blocks_out` must actually be taken.
///
/// [`SwappedPairToy`] returns its two pair results in the wrong order while its single-block
/// methods are correct. So a CBC decryptor that uses `decrypt_blocks2` gives the wrong answer for
/// even-length input, and the right answer for a single block. If both came out right, the pair
/// path would be dead code and every claim about it would be untested.
#[test]
fn the_pair_path_is_really_used() {
    let key = toy_key();
    let plaintext = [[0xA5u8; TOY_LEN], [0x5Au8; TOY_LEN]];

    // The correct toy round-trips.
    let (mut enc, iv) = ToyCbc::<Encrypting>::do_encrypt_init(&key).unwrap();
    let ct = enc.do_encrypt_blocks(&plaintext).unwrap();
    let mut dec = ToyCbc::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    assert_eq!(dec.do_decrypt_blocks(&ct).unwrap(), plaintext);

    // The swapped-pair toy encrypts identically (encryption is serial and never pairs)...
    let (mut enc, iv) = SwappedCbc::<Encrypting>::do_encrypt_init(&key).unwrap();
    let ct = enc.do_encrypt_blocks(&plaintext).unwrap();

    // ...but decrypting the pair together must now be wrong, because the pair path is used.
    let mut dec = SwappedCbc::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    assert_ne!(
        dec.do_decrypt_blocks(&ct).unwrap(),
        plaintext,
        "decrypting a pair must go through decrypt_blocks2"
    );

    // Decrypting one block at a time avoids the pair path, so it is correct even for this toy.
    let mut dec = SwappedCbc::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    let [p0] = dec.do_decrypt_blocks(&[ct[0]]).unwrap();
    let [p1] = dec.do_decrypt_blocks(&[ct[1]]).unwrap();
    assert_eq!([p0, p1], plaintext, "the single-block path must not pair");
}

/// The `_out` variants must agree with the by-value ones and report the byte count.
#[test]
fn out_variants_agree_with_by_value() {
    let key = toy_key();
    let plaintext = [[0x11u8; TOY_LEN], [0x22u8; TOY_LEN], [0x33u8; TOY_LEN]];

    let (mut enc, iv) = ToyCbc::<Encrypting>::do_encrypt_init(&key).unwrap();
    let by_value = enc.do_encrypt_blocks(&plaintext).unwrap();

    let (mut enc, iv2) = ToyCbc::<Encrypting>::do_encrypt_init_rng(
        &key,
        &mut bouncycastle_core_test_framework::FixedSeedRNG::<TOY_LEN>::new(iv),
    )
    .unwrap();
    assert_eq!(iv2, iv, "the pinned RNG should reproduce the IV");
    let mut out = [[0u8; TOY_LEN]; 3];
    let n = enc.do_encrypt_blocks_out(&plaintext, &mut out).unwrap();
    assert_eq!(n, 3 * TOY_LEN);
    assert_eq!(out, by_value);

    let mut dec = ToyCbc::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    let mut back = [[0u8; TOY_LEN]; 3];
    let n = dec.do_decrypt_blocks_out(&out, &mut back).unwrap();
    assert_eq!(n, 3 * TOY_LEN);
    assert_eq!(back, plaintext);
}

// ---- SP 800-38A Appendix D error propagation ---------------------------------------------

/// Appendix D: "In the CBC mode, if bit errors occur in the IV, then the first ciphertext block
/// will be decrypted incorrectly, and bit errors will occur in exactly the same bit positions as
/// in the IV; the decryptions of the other ciphertext blocks are not affected."
///
/// This is a property of the construction (`P1 = CIPH^-1(C1) XOR IV`), so it holds for any
/// permutation, and getting it wrong would mean the IV is not being XOR-ed where the spec says.
#[test]
fn an_iv_bit_error_flips_exactly_that_bit_of_the_first_block() {
    let key = toy_key();
    let plaintext = [[0x00u8; TOY_LEN], [0x11u8; TOY_LEN], [0x22u8; TOY_LEN]];

    let (mut enc, iv) = ToyCbc::<Encrypting>::do_encrypt_init(&key).unwrap();
    let ct = enc.do_encrypt_blocks(&plaintext).unwrap();

    for byte in 0..TOY_LEN {
        for bit in 0..8 {
            let mut corrupt_iv = iv;
            corrupt_iv[byte] ^= 1 << bit;

            let mut dec = ToyCbc::<Decrypting>::do_decrypt_init(&key, &corrupt_iv).unwrap();
            let got = dec.do_decrypt_blocks(&ct).unwrap();

            let mut expected = plaintext;
            expected[0][byte] ^= 1 << bit;
            assert_eq!(
                got, expected,
                "IV byte {byte} bit {bit}: only that bit of P1 should change"
            );
        }
    }
}

/// Appendix D, the ciphertext half: bit errors in `Cj` randomise the decryption of `Cj` and flip
/// the same bit positions of `Cj+1`'s decryption, leaving later blocks alone.
#[test]
fn a_ciphertext_bit_error_affects_only_two_blocks() {
    let key = toy_key();
    let plaintext = [[0x00u8; TOY_LEN], [0x11u8; TOY_LEN], [0x22u8; TOY_LEN], [0x33u8; TOY_LEN]];

    let (mut enc, iv) = ToyCbc::<Encrypting>::do_encrypt_init(&key).unwrap();
    let ct = enc.do_encrypt_blocks(&plaintext).unwrap();

    let mut corrupt = ct;
    corrupt[1][3] ^= 0b0010_0000;

    let mut dec = ToyCbc::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    let got = dec.do_decrypt_blocks(&corrupt).unwrap();

    assert_eq!(got[0], plaintext[0], "P1 depends only on C1 and the IV");
    assert_ne!(got[1], plaintext[1], "P2 comes from the corrupted C2");
    // P3 = CIPH^-1(C3) XOR C2, so the flipped bit of C2 appears verbatim in P3.
    let mut expected_p3 = plaintext[2];
    expected_p3[3] ^= 0b0010_0000;
    assert_eq!(got[2], expected_p3, "P3 should show the same bit flipped, and nothing else");
    assert_eq!(got[3], plaintext[3], "P4 is unaffected");
}

// ---- IV handling -------------------------------------------------------------------------

/// Two encryption flows under the same key must not reuse an IV. The framework checks this too;
/// repeated here because for CBC it is the single most important operational requirement.
#[test]
fn each_encryption_gets_a_fresh_iv() {
    let key = toy_key();
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..64 {
        let (_, iv) = ToyCbc::<Encrypting>::do_encrypt_init(&key).unwrap();
        assert!(seen.insert(iv), "IV repeated across encryptions: {iv:02x?}");
    }
}

/// Identical plaintext under the same key must give different ciphertext, because the IV differs.
/// This is the property ECB lacks and the reason CBC needs an IV at all.
#[test]
fn identical_plaintext_gives_different_ciphertext() {
    let key = toy_key();
    let plaintext = [0x77u8; 2 * TOY_LEN];

    let (_, first) = ToyCbc::<Encrypting>::encrypt(&key, &plaintext).unwrap();
    let (_, second) = ToyCbc::<Encrypting>::encrypt(&key, &plaintext).unwrap();
    assert_ne!(first, second);

    // ...and, within one message, two identical plaintext blocks must not give identical
    // ciphertext blocks either, because the chaining value differs.
    assert_ne!(
        first[..TOY_LEN],
        first[TOY_LEN..],
        "chaining should break the ECB pattern within a message"
    );
}

// ---- key handling ------------------------------------------------------------------------

#[test]
fn a_key_of_the_wrong_type_is_rejected() {
    let bytes: [u8; TOY_LEN] = core::array::from_fn(|i| (i as u8) + 1);
    let seed = KeyMaterial::<TOY_LEN>::from_bytes_as_type(&bytes, KeyType::Seed).unwrap();
    assert!(ToyCbc::<Encrypting>::do_encrypt_init(&seed).is_err());
    assert!(ToyCbc::<Decrypting>::do_decrypt_init(&seed, &[0u8; TOY_LEN]).is_err());
}

// ---- memory ------------------------------------------------------------------------------

/// Pins the "Memory Usage" table in the crate docs.
#[test]
fn sizes_match_the_documented_memory_table() {
    use core::mem::size_of;

    assert_eq!(size_of::<Cbc<Aes128, Encrypting, 16, 16>>(), 176 + 16);
    assert_eq!(size_of::<Cbc<Aes192, Encrypting, 24, 16>>(), 208 + 16);
    assert_eq!(size_of::<Cbc<Aes256, Encrypting, 32, 16>>(), 240 + 16);

    // The direction marker is free, and does not change the layout.
    assert_eq!(
        size_of::<Cbc<Aes128, Encrypting, 16, 16>>(),
        size_of::<Cbc<Aes128, Decrypting, 16, 16>>()
    );
    assert_eq!(size_of::<Encrypting>(), 0);
    assert_eq!(size_of::<Decrypting>(), 0);

    // ...and the general rule the docs state.
    assert_eq!(size_of::<Cbc<Aes256, Encrypting, 32, 16>>(), size_of::<Aes256>() + 16);
}

/// The one-shots (`encrypt` / `decrypt` on a `[u8; LEN]`) must produce exactly what the streaming
/// API produces over the same blocks, for an odd block count (pairs plus a one-block tail) and an
/// even one (pairs only), in both directions and through the `_out` variants.
#[test]
fn one_shots_agree_with_the_streaming_api() {
    let key = toy_key();
    let iv: [u8; TOY_LEN] = core::array::from_fn(|i| 0x0F ^ (i as u8));
    let pinned_rng = || bouncycastle_core_test_framework::FixedSeedRNG::<TOY_LEN>::new(iv);

    // 3 blocks = 48 bytes: one pair and a tail.
    let flat3: [u8; 3 * TOY_LEN] = core::array::from_fn(|i| (i * 7) as u8);
    let blocks3: [[u8; TOY_LEN]; 3] =
        core::array::from_fn(|b| flat3[b * TOY_LEN..][..TOY_LEN].try_into().unwrap());
    let (iv_a, ct_blocks) = {
        let (mut enc, iv) =
            ToyCbc::<Encrypting>::do_encrypt_init_rng(&key, &mut pinned_rng()).unwrap();
        (iv, enc.do_encrypt_blocks(&blocks3).unwrap())
    };
    let (iv_b, ct_flat) =
        ToyCbc::<Encrypting>::encrypt_rng(&key, &mut pinned_rng(), &flat3).unwrap();
    assert_eq!(iv_a, iv_b);
    assert_eq!(ct_flat, *ct_blocks.as_flattened(), "3 blocks: one-shot must equal streaming");
    assert_eq!(ToyCbc::<Decrypting>::decrypt(&key, &iv, &ct_flat).unwrap(), flat3);
    let mut ct_out = [0u8; 3 * TOY_LEN];
    let (_, n) =
        ToyCbc::<Encrypting>::encrypt_out_rng(&key, &mut pinned_rng(), &flat3, &mut ct_out)
            .unwrap();
    assert_eq!((n, ct_out), (3 * TOY_LEN, ct_flat));
    let mut pt_out = [0u8; 3 * TOY_LEN];
    assert_eq!(
        ToyCbc::<Decrypting>::decrypt_out(&key, &iv, &ct_out, &mut pt_out).unwrap(),
        3 * TOY_LEN
    );
    assert_eq!(pt_out, flat3);

    // 4 blocks = 64 bytes: pairs only, no tail.
    let flat4: [u8; 4 * TOY_LEN] = core::array::from_fn(|i| (i * 13 + 1) as u8);
    let blocks4: [[u8; TOY_LEN]; 4] =
        core::array::from_fn(|b| flat4[b * TOY_LEN..][..TOY_LEN].try_into().unwrap());
    let (_, ct_blocks) = {
        let (mut enc, iv) =
            ToyCbc::<Encrypting>::do_encrypt_init_rng(&key, &mut pinned_rng()).unwrap();
        (iv, enc.do_encrypt_blocks(&blocks4).unwrap())
    };
    let (_, ct_flat) = ToyCbc::<Encrypting>::encrypt_rng(&key, &mut pinned_rng(), &flat4).unwrap();
    assert_eq!(ct_flat, *ct_blocks.as_flattened(), "4 blocks: one-shot must equal streaming");
    assert_eq!(ToyCbc::<Decrypting>::decrypt(&key, &iv, &ct_flat).unwrap(), flat4);

    // The OS-RNG variant round-trips too.
    let (iv_fresh, ct) = ToyCbc::<Encrypting>::encrypt(&key, &flat3).unwrap();
    assert_eq!(ToyCbc::<Decrypting>::decrypt(&key, &iv_fresh, &ct).unwrap(), flat3);
}
