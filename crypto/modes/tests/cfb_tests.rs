//! Structural tests for CFB, driven by a toy permutation.
//!
//! These check the properties of the *mode* -- the keystream construction, chaining, call
//! sequencing, the pair/remainder split, direction typing, SP 800-38A Appendix D error propagation,
//! and the "forward cipher function only" rule of Sec 6.3 -- independently of any real cipher. The
//! known-answer tests against SP 800-38A Appendix F.3.13-F.3.18 are in `sp800_38a_cfb_tests.rs`,
//! and the ACVP CFB128 set is in `acvp_cfb_tests.rs`.
//!
//! The toy's own conformance to [`BlockPermutation`] is pinned once, by
//! `the_toy_permutation_conforms_to_the_trait` in `cbc_tests.rs`; it is the same `Toy` here, so it
//! is not re-run.

mod common;

use bouncycastle_aes_lowmemory::{Aes128, Aes192, Aes256};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor, BlockPermutation};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_core_test_framework::symmetric_ciphers::TestFrameworkBlockCipher;
use bouncycastle_modes::{Cbc, Cfb, Decrypting, Encrypting};
use bouncycastle_padding::{PKCS7, PaddedDecryptor, PaddedEncryptor};
use common::{ForwardOnlyToy, SwappedPairToy, TOY_LEN, Toy, toy_key};

type ToyCfb<Dir> = Cfb<Toy, Dir, TOY_LEN, TOY_LEN>;
type SwappedCfb<Dir> = Cfb<SwappedPairToy, Dir, TOY_LEN, TOY_LEN>;
type ForwardOnlyCfb<Dir> = Cfb<ForwardOnlyToy, Dir, TOY_LEN, TOY_LEN>;

/// The implementor hook `do_encrypt_blocks`, by value, for tests whose data is block-shaped.
fn enc_blocks<const N: usize>(
    enc: &mut impl BlockCipherEncryptor<TOY_LEN, TOY_LEN, TOY_LEN>,
    plaintext: &[[u8; TOY_LEN]; N],
) -> [[u8; TOY_LEN]; N] {
    let mut blocks = *plaintext;
    enc.do_encrypt_blocks(&mut blocks).unwrap();
    blocks
}

/// The implementor hook `do_decrypt_blocks`, by value.
fn dec_blocks<const N: usize>(
    dec: &mut impl BlockCipherDecryptor<TOY_LEN, TOY_LEN, TOY_LEN>,
    ciphertext: &[[u8; TOY_LEN]; N],
) -> [[u8; TOY_LEN]; N] {
    let mut blocks = *ciphertext;
    dec.do_decrypt_blocks(&mut blocks).unwrap();
    blocks
}

/// The flat streaming method `do_encrypt`, by value.
fn enc_flat<const LEN: usize>(
    enc: &mut impl BlockCipherEncryptor<TOY_LEN, TOY_LEN, TOY_LEN>,
    plaintext: &[u8; LEN],
) -> [u8; LEN] {
    let mut data = *plaintext;
    enc.do_encrypt(&mut data).unwrap();
    data
}

/// The flat streaming method `do_decrypt`, by value.
fn dec_flat<const LEN: usize>(
    dec: &mut impl BlockCipherDecryptor<TOY_LEN, TOY_LEN, TOY_LEN>,
    ciphertext: &[u8; LEN],
) -> [u8; LEN] {
    let mut data = *ciphertext;
    dec.do_decrypt(&mut data).unwrap();
    data
}

/// A pinned IV, so two runs are comparable. Encryption never accepts one, so it is fed through the
/// fixed-output RNG that `do_encrypt_init_rng` takes.
fn pinned_iv() -> [u8; TOY_LEN] {
    core::array::from_fn(|i| 0xF0 ^ (i as u8))
}

fn pinned_rng(iv: [u8; TOY_LEN]) -> FixedSeedRNG<TOY_LEN> {
    FixedSeedRNG::<TOY_LEN>::new(iv)
}

// ---- the mode against the shared framework ------------------------------------------------

#[test]
fn cfb_conforms_to_the_block_cipher_framework() {
    TestFrameworkBlockCipher::new()
        .test::<TOY_LEN, TOY_LEN, TOY_LEN, ToyCfb<Encrypting>, ToyCfb<Decrypting>>();
}

// ---- the spec equations -------------------------------------------------------------------

/// CFB with `s = b` from SP 800-38A Sec 6.3, written out longhand against the raw permutation:
///
/// ```text
/// I1 = IV;  Ij = C_{j-1} (j >= 2);  Oj = CIPH_K(Ij);  Cj = Pj XOR Oj
/// ```
///
/// This is the independent reference the mode is checked against below. It uses only
/// [`BlockPermutation::encrypt_block`], because that is all the spec calls for.
fn reference_cfb(
    perm: &Toy,
    iv: [u8; TOY_LEN],
    input: &[[u8; TOY_LEN]],
    encrypt: bool,
) -> Vec<[u8; TOY_LEN]> {
    let mut chain = iv; // I1 = IV
    let mut out = Vec::with_capacity(input.len());
    for block in input {
        let mut o = chain;
        perm.encrypt_block(&mut o); // Oj = CIPH_K(Ij)
        let result: [u8; TOY_LEN] = core::array::from_fn(|k| block[k] ^ o[k]);
        // I_{j+1} is always the *ciphertext* block, whichever direction we are going.
        chain = if encrypt { result } else { *block };
        out.push(result);
    }
    out
}

/// The mode must reproduce the Sec 6.3 equations exactly, in both directions.
///
/// A reference implementation is a weak test on its own -- both could be wrong the same way -- so
/// this also pins the two anchors that follow directly from the equations and that no plausible
/// mistake preserves: `C1 = P1 XOR CIPH_K(IV)`, and encrypting an all-zero block reveals the
/// keystream block itself.
#[test]
fn the_mode_matches_the_spec_equations() {
    let key = toy_key();
    let iv = pinned_iv();
    let perm = <Toy as BlockPermutation<TOY_LEN, TOY_LEN>>::new(&key).unwrap();
    let plaintext: [[u8; TOY_LEN]; 5] =
        core::array::from_fn(|i| core::array::from_fn(|j| (i * 31 + j * 7 + 1) as u8));

    let (mut enc, got_iv) =
        ToyCfb::<Encrypting>::do_encrypt_init_rng(&key, &mut pinned_rng(iv)).unwrap();
    assert_eq!(got_iv, iv, "the pinned RNG should reproduce the IV");
    let ct = enc_blocks(&mut enc, &plaintext);

    assert_eq!(
        ct.to_vec(),
        reference_cfb(&perm, iv, &plaintext, true),
        "encryption must match the Sec 6.3 equations"
    );

    let mut dec = ToyCfb::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    let recovered = dec_blocks(&mut dec, &ct);
    assert_eq!(recovered, plaintext, "round trip");
    assert_eq!(
        recovered.to_vec(),
        reference_cfb(&perm, iv, &ct, false),
        "decryption must match the Sec 6.3 equations"
    );

    // Anchor 1: `O1 = CIPH_K(IV)` and `C1 = P1 XOR O1`.
    let mut o1 = iv;
    perm.encrypt_block(&mut o1);
    let expected_c1: [u8; TOY_LEN] = core::array::from_fn(|k| plaintext[0][k] ^ o1[k]);
    assert_eq!(ct[0], expected_c1, "C1 = P1 XOR CIPH_K(IV)");

    // Anchor 2: with `P1 = 0`, `C1 = O1`. CFB is a keystream mode, and this is what that means.
    let (mut enc, _) =
        ToyCfb::<Encrypting>::do_encrypt_init_rng(&key, &mut pinned_rng(iv)).unwrap();
    assert_eq!(enc_flat(&mut enc, &[0u8; TOY_LEN]), o1, "encrypting zero yields the keystream");

    // ...and CFB is not CBC: CBC computes `CIPH_K(P1 XOR IV)`, CFB computes `P1 XOR CIPH_K(IV)`.
    let (mut cbc, _) =
        Cbc::<Toy, Encrypting, TOY_LEN, TOY_LEN>::do_encrypt_init_rng(&key, &mut pinned_rng(iv))
            .unwrap();
    assert_ne!(enc_flat(&mut cbc, &plaintext[0]), ct[0], "CFB must not agree with CBC");
}

// ---- the forward-cipher-only rule ---------------------------------------------------------

/// SP 800-38A Sec 6.3: "The *forward cipher* function is applied to each input block to produce the
/// output blocks" -- in CFB *decryption* as well as encryption.
///
/// [`ForwardOnlyToy`] panics from both `decrypt_block` and `decrypt_blocks2`, so this test fails
/// loudly if either direction of the mode ever reaches the inverse cipher. Both the pair path (even
/// `N`) and the single-block path are exercised, and the result is required to agree with the plain
/// [`Toy`] -- otherwise the test could pass by not really encrypting anything.
#[test]
fn neither_direction_uses_the_inverse_cipher() {
    let key = toy_key();
    let iv = pinned_iv();
    let plaintext: [[u8; TOY_LEN]; 4] =
        core::array::from_fn(|i| core::array::from_fn(|j| (i * 17 + j) as u8));

    let (mut enc, _) =
        ForwardOnlyCfb::<Encrypting>::do_encrypt_init_rng(&key, &mut pinned_rng(iv)).unwrap();
    let ct = enc_blocks(&mut enc, &plaintext);

    // The pair path: N = 4 is two pairs, so `encrypt_blocks2` is used and `decrypt_blocks2` is not.
    let mut dec = ForwardOnlyCfb::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    assert_eq!(dec_blocks(&mut dec, &ct), plaintext, "pair path, forward cipher only");

    // The single-block path.
    let mut dec = ForwardOnlyCfb::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    for (c, p) in ct.iter().zip(plaintext.iter()) {
        assert_eq!(&dec_flat(&mut dec, c), p, "single-block path, forward cipher only");
    }

    // N = 3 leaves a remainder after the pair loop, so both paths run in one call.
    let mut dec = ForwardOnlyCfb::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    let three = dec_blocks(&mut dec, &[ct[0], ct[1], ct[2]]);
    assert_eq!(three, [plaintext[0], plaintext[1], plaintext[2]], "pairs + remainder");

    // The forward-only toy must agree with the real one, or the above proves nothing.
    let (mut enc, _) =
        ToyCfb::<Encrypting>::do_encrypt_init_rng(&key, &mut pinned_rng(iv)).unwrap();
    assert_eq!(enc_blocks(&mut enc, &plaintext), ct, "the two toys must agree going forward");
}

/// The decryptor must feed the **ciphertext** block back, not the plaintext it just recovered.
///
/// Getting this wrong is invisible in the first block -- `O1 = CIPH_K(IV)` either way -- and wrong
/// from the second onwards. An encryptor run over ciphertext is exactly that mistake: it XORs the
/// right keystream into block 1 and then chains on its own output. So block 1 agreeing while
/// block 2 disagrees is the signature of the bug, and is what this asserts.
#[test]
fn the_decryptor_chains_on_ciphertext_not_plaintext() {
    let key = toy_key();
    let iv = pinned_iv();
    let plaintext = [[0x11u8; TOY_LEN], [0x22u8; TOY_LEN], [0x33u8; TOY_LEN]];

    let (mut enc, _) =
        ToyCfb::<Encrypting>::do_encrypt_init_rng(&key, &mut pinned_rng(iv)).unwrap();
    let ct = enc_blocks(&mut enc, &plaintext);
    assert_ne!(ct[0], plaintext[0], "the two feedback choices must actually differ here");

    let (mut wrong, _) =
        ToyCfb::<Encrypting>::do_encrypt_init_rng(&key, &mut pinned_rng(iv)).unwrap();
    let out = enc_blocks(&mut wrong, &ct);

    assert_eq!(out[0], plaintext[0], "block 1 cannot tell the two apart");
    assert_ne!(out[1], plaintext[1], "block 2 must, so the feedback source is pinned");
}

// ---- chaining and call sequencing --------------------------------------------------------

/// Encrypting `n` blocks must not depend on how the calls are grouped, and likewise for
/// decryption. This is the "a sequence of calls is equivalent to one call over the concatenation"
/// contract of the trait, and for CFB it is entirely about `Ij` surviving across calls.
///
/// The odd groupings matter for decryption specifically: `N = 3` and `N = 5` leave a one-block
/// remainder after the pair loop, and `N = 1` skips the pair loop altogether.
#[test]
fn call_grouping_does_not_change_the_result() {
    let key = toy_key();
    let iv = pinned_iv();
    let plaintext: [[u8; TOY_LEN]; 8] =
        core::array::from_fn(|i| core::array::from_fn(|j| (i * TOY_LEN + j) as u8));

    // Reference: all eight blocks in one call.
    let (mut enc, got_iv) =
        ToyCfb::<Encrypting>::do_encrypt_init_rng(&key, &mut pinned_rng(iv)).unwrap();
    assert_eq!(got_iv, iv, "the pinned RNG should reproduce the IV");
    let reference = enc_blocks(&mut enc, &plaintext);

    // The same eight blocks, grouped every way that exercises a different code path.
    let (mut enc, _) =
        ToyCfb::<Encrypting>::do_encrypt_init_rng(&key, &mut pinned_rng(iv)).unwrap();
    let mut got = [[0u8; TOY_LEN]; 8];
    let a = enc_flat(&mut enc, &plaintext[0]); // one block, flat
    let b = enc_blocks(&mut enc, &[plaintext[1], plaintext[2]]); // N = 2
    let c = enc_blocks(&mut enc, &[plaintext[3], plaintext[4], plaintext[5]]); // N = 3
    let d = enc_blocks(&mut enc, &[plaintext[6], plaintext[7]]); // N = 2
    got[0] = a;
    got[1..3].copy_from_slice(&b);
    got[3..6].copy_from_slice(&c);
    got[6..8].copy_from_slice(&d);

    assert_eq!(got, reference, "grouping must not change the ciphertext");

    // Now the decrypt side: one call vs several groupings, all from the same ciphertext.
    let ct = reference;

    let mut dec = ToyCfb::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    assert_eq!(dec_blocks(&mut dec, &ct), plaintext);

    for grouping in [1usize, 2, 4] {
        let mut dec = ToyCfb::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
        let mut out = [[0u8; TOY_LEN]; 8];
        let mut at = 0;
        while at < 8 {
            match grouping {
                1 => {
                    out[at] = dec_flat(&mut dec, &ct[at]);
                }
                2 => {
                    let p = dec_blocks(&mut dec, &[ct[at], ct[at + 1]]);
                    out[at..at + 2].copy_from_slice(&p);
                }
                _ => {
                    let p = dec_blocks(&mut dec, &[ct[at], ct[at + 1], ct[at + 2], ct[at + 3]]);
                    out[at..at + 4].copy_from_slice(&p);
                }
            }
            at += grouping;
        }
        assert_eq!(out, plaintext, "decrypting in groups of {grouping}");
    }

    // N = 3 and N = 5 both leave a one-block remainder after the pair loop.
    let mut dec = ToyCfb::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    let three = dec_blocks(&mut dec, &[ct[0], ct[1], ct[2]]);
    let five = dec_blocks(&mut dec, &[ct[3], ct[4], ct[5], ct[6], ct[7]]);
    assert_eq!(three, [plaintext[0], plaintext[1], plaintext[2]]);
    assert_eq!(five, [plaintext[3], plaintext[4], plaintext[5], plaintext[6], plaintext[7]]);
}

/// The pair path in `do_decrypt_blocks` must actually be taken.
///
/// [`SwappedPairToy`] returns its two pair results in the wrong order while its single-block methods
/// are correct. CFB decryption pairs through `encrypt_blocks2`, so with this permutation a pair
/// comes out wrong and a lone block comes out right. If both came out right, the pair path would be
/// dead code and every claim about it would be untested.
#[test]
fn the_pair_path_is_really_used() {
    let key = toy_key();
    let iv = pinned_iv();
    let plaintext = [[0xA5u8; TOY_LEN], [0x5Au8; TOY_LEN]];

    // The correct toy round-trips.
    let (mut enc, _) =
        ToyCfb::<Encrypting>::do_encrypt_init_rng(&key, &mut pinned_rng(iv)).unwrap();
    let ct = enc_blocks(&mut enc, &plaintext);
    let mut dec = ToyCfb::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    assert_eq!(dec_blocks(&mut dec, &ct), plaintext);

    // The swapped-pair toy encrypts identically -- CFB encryption is serial and never pairs, so its
    // `encrypt_blocks2` override is not reached from the encryptor at all.
    let (mut enc, _) =
        SwappedCfb::<Encrypting>::do_encrypt_init_rng(&key, &mut pinned_rng(iv)).unwrap();
    let swapped_ct = enc_blocks(&mut enc, &plaintext);
    assert_eq!(swapped_ct, ct, "CFB encryption must not use the pair path");

    // ...but decrypting the pair together must now be wrong, because the pair path is used.
    let mut dec = SwappedCfb::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    assert_ne!(
        dec_blocks(&mut dec, &swapped_ct),
        plaintext,
        "decrypting a pair must go through encrypt_blocks2"
    );

    // Decrypting one block at a time avoids the pair path, so it is correct even for this toy.
    let mut dec = SwappedCfb::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    let p0 = dec_flat(&mut dec, &swapped_ct[0]);
    let p1 = dec_flat(&mut dec, &swapped_ct[1]);
    assert_eq!([p0, p1], plaintext, "the single-block path must not pair");
}

/// The flat streaming method must agree with the block-shaped implementor hook.
#[test]
fn flat_streaming_agrees_with_the_block_hook() {
    let key = toy_key();
    let iv = pinned_iv();
    let plaintext = [[0x11u8; TOY_LEN], [0x22u8; TOY_LEN], [0x33u8; TOY_LEN]];
    let flat_plaintext: [u8; 3 * TOY_LEN] = plaintext.as_flattened().try_into().unwrap();

    let (mut enc, _) =
        ToyCfb::<Encrypting>::do_encrypt_init_rng(&key, &mut pinned_rng(iv)).unwrap();
    let flat_ct = enc_flat(&mut enc, &flat_plaintext);

    let (mut enc, _) =
        ToyCfb::<Encrypting>::do_encrypt_init_rng(&key, &mut pinned_rng(iv)).unwrap();
    let block_ct = enc_blocks(&mut enc, &plaintext);
    assert_eq!(*block_ct.as_flattened(), flat_ct, "flat streaming must equal the block hook");

    let mut dec = ToyCfb::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    assert_eq!(dec_blocks(&mut dec, &block_ct), plaintext);
    let mut dec = ToyCfb::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    assert_eq!(dec_flat(&mut dec, &flat_ct), flat_plaintext);
}

/// The one-shots (`encrypt` / `decrypt` on a `[u8; LEN]`, in place) must produce exactly what the
/// streaming API produces over the same blocks, for an odd block count (pairs plus a one-block
/// tail) and an even one (pairs only), in both directions.
#[test]
fn one_shots_agree_with_the_streaming_api() {
    let key = toy_key();
    let iv = pinned_iv();

    // 3 blocks = 48 bytes: one pair and a tail.
    let flat3: [u8; 3 * TOY_LEN] = core::array::from_fn(|i| (i * 7) as u8);
    let blocks3: [[u8; TOY_LEN]; 3] =
        core::array::from_fn(|b| flat3[b * TOY_LEN..][..TOY_LEN].try_into().unwrap());
    let (iv_a, ct_blocks) = {
        let (mut enc, got) =
            ToyCfb::<Encrypting>::do_encrypt_init_rng(&key, &mut pinned_rng(iv)).unwrap();
        (got, enc_blocks(&mut enc, &blocks3))
    };
    let mut buf = flat3;
    let iv_b = ToyCfb::<Encrypting>::encrypt_rng(&key, &mut pinned_rng(iv), &mut buf).unwrap();
    assert_eq!(iv_a, iv_b);
    assert_eq!(buf, *ct_blocks.as_flattened(), "3 blocks: one-shot must equal streaming");
    ToyCfb::<Decrypting>::decrypt(&key, &iv, &mut buf).unwrap();
    assert_eq!(buf, flat3);

    // 4 blocks = 64 bytes: pairs only, no tail.
    let flat4: [u8; 4 * TOY_LEN] = core::array::from_fn(|i| (i * 13 + 1) as u8);
    let blocks4: [[u8; TOY_LEN]; 4] =
        core::array::from_fn(|b| flat4[b * TOY_LEN..][..TOY_LEN].try_into().unwrap());
    let ct_blocks = {
        let (mut enc, _) =
            ToyCfb::<Encrypting>::do_encrypt_init_rng(&key, &mut pinned_rng(iv)).unwrap();
        enc_blocks(&mut enc, &blocks4)
    };
    let mut buf = flat4;
    ToyCfb::<Encrypting>::encrypt_rng(&key, &mut pinned_rng(iv), &mut buf).unwrap();
    assert_eq!(buf, *ct_blocks.as_flattened(), "4 blocks: one-shot must equal streaming");
    ToyCfb::<Decrypting>::decrypt(&key, &iv, &mut buf).unwrap();
    assert_eq!(buf, flat4);

    // The OS-RNG variant round-trips too.
    let mut buf = flat3;
    let iv_fresh = ToyCfb::<Encrypting>::encrypt(&key, &mut buf).unwrap();
    assert_ne!(buf, flat3);
    ToyCfb::<Decrypting>::decrypt(&key, &iv_fresh, &mut buf).unwrap();
    assert_eq!(buf, flat3);
}

// ---- SP 800-38A Appendix D error propagation ---------------------------------------------

/// The parts of Appendix D that follow from the equations and hold for *any* permutation.
///
/// Table D.2 for CFB: a bit error in `Cj` gives "SBE in the decryption of `Cj`" -- specific bit
/// errors, i.e. the same bit positions -- because `Pj = Cj XOR Oj` and `Oj = CIPH_K(C_{j-1})` does
/// not depend on `Cj` at all. Earlier blocks are untouched, and with `s = b` the damage reaches
/// exactly one block further (`Cj+1`, since `b/s = 1`).
#[test]
fn a_ciphertext_bit_error_flips_exactly_that_bit_of_its_own_block() {
    let key = toy_key();
    let iv = pinned_iv();
    let plaintext = [[0x00u8; TOY_LEN], [0x11u8; TOY_LEN], [0x22u8; TOY_LEN], [0x33u8; TOY_LEN]];

    let (mut enc, _) =
        ToyCfb::<Encrypting>::do_encrypt_init_rng(&key, &mut pinned_rng(iv)).unwrap();
    let ct = enc_blocks(&mut enc, &plaintext);

    // Every bit of C2, so the SBE claim is checked exhaustively rather than at one position.
    for byte in 0..TOY_LEN {
        for bit in 0..8 {
            let mut corrupt = ct;
            corrupt[1][byte] ^= 1 << bit;

            let mut dec = ToyCfb::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
            let got = dec_blocks(&mut dec, &corrupt);

            assert_eq!(got[0], plaintext[0], "P1 depends only on the IV and C1");

            let mut expected_p2 = plaintext[1];
            expected_p2[byte] ^= 1 << bit;
            assert_eq!(
                got[1], expected_p2,
                "C2 byte {byte} bit {bit}: exactly that bit of P2 should change"
            );

            assert_ne!(got[2], plaintext[2], "P3 comes from CIPH_K of the corrupted C2");
            assert_eq!(got[3], plaintext[3], "P4 is unaffected: b/s = 1, so damage stops at P3");
        }
    }
}

/// The parts of Appendix D that need a real cipher's diffusion, checked with AES-128.
///
/// Table D.2 for CFB says the *other* affected block gets "RBE" -- random bit errors, "bit errors
/// occur independently in any bit position with an expected probability of 1/2". That is a property
/// of the block cipher, not of the mode, so the toy (whose rounds are byte-local) cannot show it.
///
/// The point worth pinning is that CFB and CBC differ here, and in which direction: under CBC a
/// corrupted IV flips *exactly* the corresponding bit of `P1` (Appendix D, and
/// `an_iv_bit_error_flips_exactly_that_bit_of_the_first_block` in `cbc_tests.rs`), whereas under CFB
/// the IV goes through the cipher first, so `P1` is randomised instead. Confusing the two would be a
/// real bug and this is what catches it.
#[test]
fn an_iv_bit_error_randomises_only_the_first_block() {
    type Aes128Cfb<Dir> = Cfb<Aes128, Dir, 16, 16>;
    const LEN: usize = 16;

    let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
        .expect("a valid AES-128 key");
    let iv: [u8; LEN] = core::array::from_fn(|i| 0x0F ^ (i as u8));
    let plaintext = [[0x00u8; LEN], [0x11u8; LEN], [0x22u8; LEN]];

    let (mut enc, got_iv) =
        Aes128Cfb::<Encrypting>::do_encrypt_init_rng(&key, &mut FixedSeedRNG::<LEN>::new(iv))
            .unwrap();
    assert_eq!(got_iv, iv);
    let mut ct = plaintext;
    enc.do_encrypt_blocks(&mut ct).unwrap();

    let mut first_blocks = std::collections::BTreeSet::new();

    for byte in 0..LEN {
        for bit in 0..8 {
            let mut corrupt_iv = iv;
            corrupt_iv[byte] ^= 1 << bit;

            let mut dec = Aes128Cfb::<Decrypting>::do_decrypt_init(&key, &corrupt_iv).unwrap();
            let mut got = ct;
            dec.do_decrypt_blocks(&mut got).unwrap();

            // Only P1 is affected: with s = b, Appendix D's "first i/s (rounding up) ciphertext
            // segments" is one segment for every bit position i.
            assert_eq!(got[1], plaintext[1], "IV byte {byte} bit {bit}: P2 must be unaffected");
            assert_eq!(got[2], plaintext[2], "IV byte {byte} bit {bit}: P3 must be unaffected");

            // ...and it is randomised, not flipped in place. The CBC behaviour would be a
            // single-bit difference in exactly the position that was corrupted.
            let differing_bits: u32 =
                got[0].iter().zip(plaintext[0].iter()).map(|(a, b)| (a ^ b).count_ones()).sum();
            assert!(
                differing_bits > 1,
                "IV byte {byte} bit {bit}: P1 should be randomised, not flipped in place \
                 ({differing_bits} bit(s) differ)"
            );

            let mut cbc_style = plaintext[0];
            cbc_style[byte] ^= 1 << bit;
            assert_ne!(got[0], cbc_style, "CFB must not behave like CBC for a corrupted IV");

            assert!(first_blocks.insert(got[0]), "distinct IVs should give distinct P1");
        }
    }

    assert_eq!(first_blocks.len(), LEN * 8, "every corrupted IV should have been tried");
}

// ---- IV handling -------------------------------------------------------------------------

/// Two encryption flows under the same key must not reuse an IV. The framework checks this too;
/// repeated here because a repeated IV is worse for CFB than for CBC -- it leaks the XOR of the two
/// plaintexts, not merely their equality (see the crate docs, "Key and IV reuse").
#[test]
fn each_encryption_gets_a_fresh_iv() {
    let key = toy_key();
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..64 {
        let (_, iv) = ToyCfb::<Encrypting>::do_encrypt_init(&key).unwrap();
        assert!(seen.insert(iv), "IV repeated across encryptions: {iv:02x?}");
    }
}

/// Identical plaintext under the same key must give different ciphertext, because the IV differs.
#[test]
fn identical_plaintext_gives_different_ciphertext() {
    let key = toy_key();
    let plaintext = [0x77u8; 2 * TOY_LEN];

    let mut first = plaintext;
    ToyCfb::<Encrypting>::encrypt(&key, &mut first).unwrap();
    let mut second = plaintext;
    ToyCfb::<Encrypting>::encrypt(&key, &mut second).unwrap();
    assert_ne!(first, second);

    // ...and, within one message, two identical plaintext blocks must not give identical ciphertext
    // blocks either, because the keystream block differs.
    assert_ne!(
        first[..TOY_LEN],
        first[TOY_LEN..],
        "feedback should break the ECB pattern within a message"
    );
}

// ---- key handling ------------------------------------------------------------------------

#[test]
fn a_key_of_the_wrong_type_is_rejected() {
    let bytes: [u8; TOY_LEN] = core::array::from_fn(|i| (i as u8) + 1);
    let seed = KeyMaterial::<TOY_LEN>::from_bytes_as_type(&bytes, KeyType::Seed).unwrap();
    assert!(ToyCfb::<Encrypting>::do_encrypt_init(&seed).is_err());
    assert!(ToyCfb::<Decrypting>::do_decrypt_init(&seed, &[0u8; TOY_LEN]).is_err());
}

// ---- composition with the padding layer --------------------------------------------------

/// CFB is block-aligned by contract, so arbitrary-length data goes through `bouncycastle-padding`.
/// Nothing in either crate knows about the other, so this is the test that they actually compose --
/// across every length from empty to just past three blocks, which covers an exact multiple of the
/// block size (where PKCS7 appends a whole extra block) and every partial block.
#[test]
fn the_padding_layer_round_trips_every_length() {
    type Enc = PaddedEncryptor<ToyCfb<Encrypting>, PKCS7, TOY_LEN, TOY_LEN, TOY_LEN>;
    type Dec = PaddedDecryptor<ToyCfb<Decrypting>, PKCS7, TOY_LEN, TOY_LEN, TOY_LEN>;

    for len in 0..=(3 * TOY_LEN + 1) {
        let plaintext: Vec<u8> = (0..len).map(|i| (i * 5 + 3) as u8).collect();

        let mut ciphertext = vec![0u8; Enc::encrypt_out_len(len)];
        let (iv, written) =
            Enc::encrypt_out(&toy_key(), &plaintext, &mut ciphertext).expect("padded encryption");
        assert_eq!(written, ciphertext.len(), "len {len}: one whole number of blocks out");
        assert!(written > len, "len {len}: PKCS7 always adds at least one byte");

        let mut recovered = vec![0u8; Dec::decrypt_out_max_len(written)];
        let n = Dec::decrypt_out(&toy_key(), &iv, &ciphertext, &mut recovered)
            .expect("padded decryption");
        assert_eq!(&recovered[..n], &plaintext[..], "len {len}: round trip through PKCS7");
    }
}

// ---- memory ------------------------------------------------------------------------------

/// Pins the "Memory Usage" table in the crate docs, and the claim that CFB costs exactly what CBC
/// costs.
#[test]
fn sizes_match_the_documented_memory_table() {
    use core::mem::size_of;

    assert_eq!(size_of::<Cfb<Aes128, Encrypting, 16, 16>>(), 176 + 16);
    assert_eq!(size_of::<Cfb<Aes192, Encrypting, 24, 16>>(), 208 + 16);
    assert_eq!(size_of::<Cfb<Aes256, Encrypting, 32, 16>>(), 240 + 16);

    // The direction marker is free, and does not change the layout.
    assert_eq!(
        size_of::<Cfb<Aes128, Encrypting, 16, 16>>(),
        size_of::<Cfb<Aes128, Decrypting, 16, 16>>()
    );

    // ...and the general rule the docs state.
    assert_eq!(size_of::<Cfb<Aes256, Encrypting, 32, 16>>(), size_of::<Aes256>() + 16);

    // The docs say CFB is the same size as CBC, because it stores the same thing.
    assert_eq!(
        size_of::<Cfb<Aes128, Encrypting, 16, 16>>(),
        size_of::<Cbc<Aes128, Encrypting, 16, 16>>()
    );
    assert_eq!(
        size_of::<Cfb<Aes256, Decrypting, 32, 16>>(),
        size_of::<Cbc<Aes256, Decrypting, 32, 16>>()
    );
}
