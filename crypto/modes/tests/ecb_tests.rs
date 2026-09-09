//! Structural tests for ECB, driven by a toy permutation.
//!
//! These check the properties of the *mode* -- that it is the permutation applied block by block
//! with nothing chained, that both directions batch through the pair and four-block paths, call
//! sequencing, direction typing, the empty init data, SP 800-38A Appendix D error propagation, and
//! the codebook property that makes ECB unsuitable for data -- independently of any real cipher. The
//! known-answer tests against SP 800-38A Appendix F.1 are in `sp800_38a_ecb_tests.rs`, and the ACVP
//! set is in `acvp_ecb_tests.rs`.
//!
//! The toy's own conformance to [`ElectronicCodeBook`] is pinned once, by
//! `the_toy_permutation_conforms_to_the_trait` in `cbc_tests.rs`; it is the same `Toy` here.

mod common;

use bouncycastle_aes::{AES_128, AES_192, AES_256};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{
    BlockCipherDecryptor, BlockCipherEncryptor, ElectronicCodeBook, SimpleCipherDecryptor,
    SimpleCipherEncryptor,
};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_core_test_framework::symmetric_ciphers::TestFrameworkBlockCipher;
use bouncycastle_modes::{Cbc, Decrypting, Ecb, Encrypting};
use bouncycastle_padding::{PKCS7, PaddedDecryptor, PaddedEncryptor};
use common::{SwappedFourToy, SwappedPairToy, TOY_LEN, Toy, toy_key};

type ToyEcb<Dir> = Ecb<Toy, Dir, TOY_LEN, TOY_LEN>;
type SwappedEcb<Dir> = Ecb<SwappedPairToy, Dir, TOY_LEN, TOY_LEN>;
type SwappedFourEcb<Dir> = Ecb<SwappedFourToy, Dir, TOY_LEN, TOY_LEN>;

/// The implementor hook `do_encrypt_blocks`, by value, for tests whose data is block-shaped.
fn enc_blocks<const N: usize>(
    enc: &mut impl BlockCipherEncryptor<TOY_LEN, 0, TOY_LEN>,
    plaintext: &[[u8; TOY_LEN]; N],
) -> [[u8; TOY_LEN]; N] {
    let mut blocks = *plaintext;
    enc.do_encrypt_blocks(&mut blocks).unwrap();
    blocks
}

/// The implementor hook `do_decrypt_blocks`, by value.
fn dec_blocks<const N: usize>(
    dec: &mut impl BlockCipherDecryptor<TOY_LEN, 0, TOY_LEN>,
    ciphertext: &[[u8; TOY_LEN]; N],
) -> [[u8; TOY_LEN]; N] {
    let mut blocks = *ciphertext;
    dec.do_decrypt_blocks(&mut blocks).unwrap();
    blocks
}

/// The flat streaming method `do_encrypt`, by value.
fn enc_flat<const LEN: usize>(
    enc: &mut impl BlockCipherEncryptor<TOY_LEN, 0, TOY_LEN>,
    plaintext: &[u8; LEN],
) -> [u8; LEN] {
    let mut data = *plaintext;
    enc.do_encrypt(&mut data).unwrap();
    data
}

/// The flat streaming method `do_decrypt`, by value.
fn dec_flat<const LEN: usize>(
    dec: &mut impl BlockCipherDecryptor<TOY_LEN, 0, TOY_LEN>,
    ciphertext: &[u8; LEN],
) -> [u8; LEN] {
    let mut data = *ciphertext;
    dec.do_decrypt(&mut data).unwrap();
    data
}

fn encryptor() -> ToyEcb<Encrypting> {
    ToyEcb::<Encrypting>::do_encrypt_init(&toy_key()).unwrap().0
}

fn decryptor() -> ToyEcb<Decrypting> {
    ToyEcb::<Decrypting>::do_decrypt_init(&toy_key(), &[]).unwrap()
}

// ---- the mode against the shared framework ------------------------------------------------

#[test]
fn ecb_conforms_to_the_block_cipher_framework() {
    TestFrameworkBlockCipher::new()
        .test::<TOY_LEN, 0, TOY_LEN, ToyEcb<Encrypting>, ToyEcb<Decrypting>>();
}

// ---- the spec equations -------------------------------------------------------------------

/// SP 800-38A Sec 6.1, written out longhand against the raw permutation:
///
/// ```text
/// Cj = CIPH_K(Pj);  Pj = CIPH^-1_K(Cj)   for j = 1 ... n
/// ```
///
/// Each block is transformed "directly and independently", so this reference uses only the
/// single-block methods and never looks at a neighbouring block.
fn reference_ecb(perm: &Toy, input: &[[u8; TOY_LEN]], encrypt: bool) -> Vec<[u8; TOY_LEN]> {
    input
        .iter()
        .map(|block| {
            let mut b = *block;
            if encrypt {
                perm.encrypt_block(&mut b)
            } else {
                perm.decrypt_block(&mut b)
            }
            b
        })
        .collect()
}

/// The mode must reproduce the Sec 6.1 equations exactly, in both directions, and must therefore
/// agree with the raw permutation block for block. It must also *differ* from CBC from the very
/// first block, since CBC XORs the IV in before the cipher call.
#[test]
fn the_mode_matches_the_spec_equations() {
    let key = toy_key();
    let perm = <Toy as ElectronicCodeBook<TOY_LEN, TOY_LEN>>::new(&key).unwrap();
    let plaintext: [[u8; TOY_LEN]; 5] =
        core::array::from_fn(|i| core::array::from_fn(|j| (i * 31 + j * 7 + 1) as u8));

    let (mut enc, init) = ToyEcb::<Encrypting>::do_encrypt_init(&key).unwrap();
    assert_eq!(init, [], "ECB has no init data");
    let ct = enc_blocks(&mut enc, &plaintext);
    assert_eq!(
        ct.to_vec(),
        reference_ecb(&perm, &plaintext, true),
        "encryption is CIPH_K per block"
    );

    let mut dec = decryptor();
    let recovered = dec_blocks(&mut dec, &ct);
    assert_eq!(recovered, plaintext, "round trip");
    assert_eq!(
        recovered.to_vec(),
        reference_ecb(&perm, &ct, false),
        "decryption is CIPH^-1_K per block"
    );

    // Each block is exactly the permutation of that block, whatever surrounds it.
    for (p, c) in plaintext.iter().zip(ct.iter()) {
        let mut alone = *p;
        perm.encrypt_block(&mut alone);
        assert_eq!(&alone, c, "a block's ciphertext does not depend on its neighbours");
    }

    // ...and ECB is not CBC: CBC computes CIPH_K(P1 XOR IV), ECB computes CIPH_K(P1).
    let iv: [u8; TOY_LEN] = core::array::from_fn(|i| 0xF0 ^ (i as u8));
    let (mut cbc, _) = Cbc::<Toy, Encrypting, TOY_LEN, TOY_LEN>::do_encrypt_init_rng(
        &key,
        &mut FixedSeedRNG::<TOY_LEN>::new(iv),
    )
    .unwrap();
    let mut first = plaintext[0];
    cbc.do_encrypt(&mut first).unwrap();
    assert_ne!(first, ct[0], "ECB must not agree with CBC");
}

// ---- no state: determinism and the codebook property --------------------------------------

/// ECB is a function of the key and the block alone. Sec 6.1: "under a given key, any given
/// plaintext block always gets encrypted to the same ciphertext block." This is the property that
/// makes it unusable for data, and it is pinned here so the mode cannot quietly grow an IV or a
/// counter and stop being ECB.
#[test]
fn ecb_is_deterministic_and_leaks_equal_blocks() {
    let key = toy_key();
    let block = [0x5Au8; TOY_LEN];
    let plaintext = [block, [0x11; TOY_LEN], block, block];

    let ct_a = enc_blocks(&mut encryptor(), &plaintext);
    let ct_b = enc_blocks(&mut encryptor(), &plaintext);
    assert_eq!(ct_a, ct_b, "the same plaintext under the same key gives the same ciphertext");

    assert_eq!(ct_a[0], ct_a[2], "equal plaintext blocks give equal ciphertext blocks");
    assert_eq!(ct_a[0], ct_a[3]);
    assert_ne!(ct_a[0], ct_a[1], "different plaintext blocks give different ciphertext blocks");

    // The one-shots see the same thing: `encrypt` returns the empty init data and is repeatable.
    let flat: [u8; 4 * TOY_LEN] = plaintext.as_flattened().try_into().unwrap();
    let mut once = flat;
    let init_a: [u8; 0] = ToyEcb::<Encrypting>::encrypt(&key, &mut once).unwrap();
    let mut twice = flat;
    let init_b = ToyEcb::<Encrypting>::encrypt_rng(
        &key,
        &mut FixedSeedRNG::<TOY_LEN>::new([0xAB; TOY_LEN]),
        &mut twice,
    )
    .unwrap();
    assert_eq!(init_a, init_b);
    assert_eq!(once, twice, "the RNG variant draws nothing, so it changes nothing");
    assert_eq!(once, *ct_a.as_flattened());
}

/// The RNG-taking constructor must not consume from the RNG: there is no IV to generate. A
/// fixed-seed RNG of the wrong width would panic on its first draw, so this is observable.
#[test]
fn the_rng_constructor_draws_nothing() {
    let key = toy_key();
    let mut rng = FixedSeedRNG::<0>::new([]);
    let (mut enc, init) = ToyEcb::<Encrypting>::do_encrypt_init_rng(&key, &mut rng).unwrap();
    assert_eq!(init, []);
    let mut block = [0x42u8; TOY_LEN];
    enc.do_encrypt(&mut block).unwrap();
    assert_eq!(block, enc_flat(&mut encryptor(), &[0x42u8; TOY_LEN]));
}

// ---- batching: pairs and fours, in both directions ----------------------------------------

/// Sec 6.1: "multiple forward cipher functions and inverse cipher functions can be computed in
/// parallel" -- so, unlike CBC and CFB, *both* directions batch. [`SwappedPairToy`] swaps its two
/// pair results, so a pair handed over together comes out wrong in either direction, while blocks
/// handed over singly come out right.
#[test]
fn the_pair_path_is_used_in_both_directions() {
    let key = toy_key();
    let plaintext = [[0xA5u8; TOY_LEN], [0x5Au8; TOY_LEN]];
    let ct = enc_blocks(&mut encryptor(), &plaintext);

    // Encryption: a pair goes through encrypt_2blocks, so the swapped toy returns them swapped.
    let (mut enc, _) = SwappedEcb::<Encrypting>::do_encrypt_init(&key).unwrap();
    let swapped_ct = enc_blocks(&mut enc, &plaintext);
    assert_eq!(swapped_ct, [ct[1], ct[0]], "encrypting a pair must go through encrypt_2blocks");

    // ...and one block at a time avoids the pair path.
    let (mut enc, _) = SwappedEcb::<Encrypting>::do_encrypt_init(&key).unwrap();
    assert_eq!([enc_flat(&mut enc, &plaintext[0]), enc_flat(&mut enc, &plaintext[1])], ct);

    // Decryption likewise.
    let mut dec = SwappedEcb::<Decrypting>::do_decrypt_init(&key, &[]).unwrap();
    assert_eq!(
        dec_blocks(&mut dec, &ct),
        [plaintext[1], plaintext[0]],
        "decrypting a pair must go through decrypt_2blocks"
    );
    let mut dec = SwappedEcb::<Decrypting>::do_decrypt_init(&key, &[]).unwrap();
    assert_eq!([dec_flat(&mut dec, &ct[0]), dec_flat(&mut dec, &ct[1])], plaintext);
}

/// The four-block path must be taken, and only for full fours, in both directions.
/// [`SwappedFourToy`] rotates its four results while its pair and single-block methods are
/// correct, so five blocks handed over together are wrong (four rotated, then one right) and the
/// same blocks as two pairs or singly are right.
#[test]
fn the_four_block_path_is_used_in_both_directions() {
    let key = toy_key();
    let plaintext: [[u8; TOY_LEN]; 5] = core::array::from_fn(|i| [0x10 * i as u8 + 1; TOY_LEN]);
    let ct = enc_blocks(&mut encryptor(), &plaintext);
    assert_eq!(dec_blocks(&mut decryptor(), &ct), plaintext);

    let (mut enc, _) = SwappedFourEcb::<Encrypting>::do_encrypt_init(&key).unwrap();
    let rotated = enc_blocks(&mut enc, &plaintext);
    assert_ne!(rotated, ct, "five blocks must go through encrypt_4blocks");
    assert_eq!(rotated[4], ct[4], "the fifth block goes through the single path and is right");
    assert_eq!(&rotated[..4], &[ct[1], ct[2], ct[3], ct[0]], "four rotated");

    let (mut enc, _) = SwappedFourEcb::<Encrypting>::do_encrypt_init(&key).unwrap();
    let a = enc_blocks(&mut enc, &[plaintext[0], plaintext[1]]);
    let b = enc_blocks(&mut enc, &[plaintext[2], plaintext[3]]);
    assert_eq!([a, b].as_flattened(), &ct[..4], "pairs use the pair path only");

    let mut dec = SwappedFourEcb::<Decrypting>::do_decrypt_init(&key, &[]).unwrap();
    assert_ne!(dec_blocks(&mut dec, &ct), plaintext, "five blocks must go through decrypt_4blocks");
    let mut dec = SwappedFourEcb::<Decrypting>::do_decrypt_init(&key, &[]).unwrap();
    for (c, p) in ct.iter().zip(plaintext.iter()) {
        assert_eq!(&dec_flat(&mut dec, c), p, "the single-block path must not batch");
    }
}

/// Grouping cannot matter -- there is no state to carry between calls -- but the contract is the
/// same as for the other modes and the batching paths differ per grouping, so it is pinned.
#[test]
fn call_grouping_does_not_change_the_result() {
    let plaintext: [[u8; TOY_LEN]; 11] =
        core::array::from_fn(|i| core::array::from_fn(|j| (i * TOY_LEN + j) as u8));
    let reference = enc_blocks(&mut encryptor(), &plaintext);

    let mut enc = encryptor();
    let mut got = [[0u8; TOY_LEN]; 11];
    got[0] = enc_flat(&mut enc, &plaintext[0]);
    got[1..3].copy_from_slice(&enc_blocks(&mut enc, &[plaintext[1], plaintext[2]]));
    let rest: [[u8; TOY_LEN]; 8] = plaintext[3..11].try_into().unwrap();
    got[3..11].copy_from_slice(&enc_blocks(&mut enc, &rest));
    assert_eq!(got, reference);

    for grouping in [1usize, 2, 4, 5, 8, 11] {
        let mut dec = decryptor();
        let mut out = Vec::new();
        for chunk in reference.chunks(grouping) {
            let mut buf = chunk.to_vec();
            dec.do_decrypt_blocks(&mut buf).unwrap();
            out.extend_from_slice(&buf);
        }
        assert_eq!(out, plaintext.to_vec(), "decrypting in groups of {grouping}");
    }
}

/// The flat streaming method and the one-shots must agree with the block-shaped hook.
#[test]
fn flat_streaming_and_one_shots_agree_with_the_block_hook() {
    let key = toy_key();
    let plaintext = [[0x11u8; TOY_LEN], [0x22u8; TOY_LEN], [0x33u8; TOY_LEN]];
    let flat_plaintext: [u8; 3 * TOY_LEN] = plaintext.as_flattened().try_into().unwrap();

    let block_ct = enc_blocks(&mut encryptor(), &plaintext);
    assert_eq!(*block_ct.as_flattened(), enc_flat(&mut encryptor(), &flat_plaintext));

    let mut buf = flat_plaintext;
    let init = ToyEcb::<Encrypting>::encrypt(&key, &mut buf).unwrap();
    assert_eq!(buf, *block_ct.as_flattened(), "one-shot must equal streaming");
    ToyEcb::<Decrypting>::decrypt(&key, &init, &mut buf).unwrap();
    assert_eq!(buf, flat_plaintext);

    assert_eq!(dec_blocks(&mut decryptor(), &block_ct), plaintext);
    let flat_ct: [u8; 3 * TOY_LEN] = block_ct.as_flattened().try_into().unwrap();
    assert_eq!(dec_flat(&mut decryptor(), &flat_ct), flat_plaintext);
}

// ---- SP 800-38A Appendix D error propagation ---------------------------------------------

/// Table D.2 for ECB: a bit error in `Cj` gives "RBE in the decryption of Cj" and nothing else --
/// Appendix D: "For the ECB, OFB, and CTR modes, bit errors within a ciphertext block do not affect
/// the decryption of any other blocks." The toy is byte-local, so it can show only the "no other
/// block" half exactly; the randomisation is checked with real AES below.
#[test]
fn a_ciphertext_bit_error_affects_only_its_own_block() {
    let plaintext = [[0x00u8; TOY_LEN], [0x11u8; TOY_LEN], [0x22u8; TOY_LEN], [0x33u8; TOY_LEN]];
    let ct = enc_blocks(&mut encryptor(), &plaintext);

    for byte in 0..TOY_LEN {
        for bit in 0..8 {
            let mut corrupt = ct;
            corrupt[1][byte] ^= 1 << bit;
            let got = dec_blocks(&mut decryptor(), &corrupt);
            assert_eq!(got[0], plaintext[0]);
            assert_ne!(got[1], plaintext[1], "C2 byte {byte} bit {bit}: P2 must change");
            assert_eq!(got[2], plaintext[2], "P3 is unaffected: nothing chains");
            assert_eq!(got[3], plaintext[3]);
        }
    }
}

/// The randomisation half of Table D.2, with AES-128: every one of the 128 bit positions of `C2`
/// must randomise `P2` (more than one bit differs) and leave `P1` and `P3` untouched.
#[test]
fn with_aes_a_ciphertext_bit_error_randomises_its_block() {
    type Aes128Ecb<Dir> = Ecb<AES_128, Dir, 16, 16>;
    let key =
        KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
    let plaintext = [[0x00u8; 16], [0x11u8; 16], [0x22u8; 16]];
    let mut ct = plaintext;
    let flat: &mut [u8; 48] = ct.as_flattened_mut().try_into().unwrap();
    Aes128Ecb::<Encrypting>::encrypt(&key, flat).unwrap();

    for byte in 0..16 {
        for bit in 0..8 {
            let mut corrupt = ct;
            corrupt[1][byte] ^= 1 << bit;
            let flat: &mut [u8; 48] = corrupt.as_flattened_mut().try_into().unwrap();
            Aes128Ecb::<Decrypting>::decrypt(&key, &[], flat).unwrap();
            assert_eq!(corrupt[0], plaintext[0], "C2 byte {byte} bit {bit}: P1 unaffected");
            assert_eq!(corrupt[2], plaintext[2], "C2 byte {byte} bit {bit}: P3 unaffected");
            let differing: u32 =
                corrupt[1].iter().zip(plaintext[1].iter()).map(|(a, b)| (a ^ b).count_ones()).sum();
            assert!(
                differing > 1,
                "C2 byte {byte} bit {bit}: P2 should be randomised ({differing} bit(s) differ)"
            );
        }
    }
}

// ---- key handling ------------------------------------------------------------------------

#[test]
fn a_key_of_the_wrong_type_is_rejected() {
    let bytes: [u8; TOY_LEN] = core::array::from_fn(|i| (i as u8) + 1);
    let seed = KeyMaterial::<TOY_LEN>::from_bytes_as_type(&bytes, KeyType::Seed).unwrap();
    assert!(ToyEcb::<Encrypting>::do_encrypt_init(&seed).is_err());
    assert!(ToyEcb::<Decrypting>::do_decrypt_init(&seed, &[]).is_err());
}

// ---- composition with the padding layer --------------------------------------------------

/// ECB is block-aligned by contract, so arbitrary-length data goes through `bouncycastle-padding`
/// like the other modes; its `INIT_DATA_LEN` of 0 flows through the adapters as an empty array.
#[test]
fn the_padding_layer_round_trips_every_length() {
    type Enc = PaddedEncryptor<ToyEcb<Encrypting>, PKCS7, TOY_LEN, 0, TOY_LEN>;
    type Dec = PaddedDecryptor<ToyEcb<Decrypting>, PKCS7, TOY_LEN, 0, TOY_LEN>;

    for len in 0..=(3 * TOY_LEN + 1) {
        let plaintext: Vec<u8> = (0..len).map(|i| (i * 5 + 3) as u8).collect();
        let mut ciphertext = vec![0u8; Enc::encrypt_out_len(len)];
        let (init, written) =
            Enc::encrypt_out(&toy_key(), &plaintext, &mut ciphertext).expect("padded encryption");
        assert_eq!(init, []);
        assert_eq!(written, ciphertext.len(), "len {len}");
        let mut recovered = vec![0u8; Dec::decrypt_out_max_len(written)];
        let n = Dec::decrypt_out(&toy_key(), &init, &ciphertext, &mut recovered)
            .expect("padded decryption");
        assert_eq!(&recovered[..n], &plaintext[..], "len {len}: round trip through PKCS7");
    }
}

// ---- memory ------------------------------------------------------------------------------

/// Pins the "Memory Usage" table in the crate docs: an ECB value is exactly the permutation.
#[test]
fn sizes_match_the_documented_memory_table() {
    use core::mem::size_of;
    assert_eq!(size_of::<Ecb<AES_128, Encrypting, 16, 16>>(), 176);
    assert_eq!(size_of::<Ecb<AES_192, Encrypting, 24, 16>>(), 208);
    assert_eq!(size_of::<Ecb<AES_256, Encrypting, 32, 16>>(), 240);
    assert_eq!(
        size_of::<Ecb<AES_128, Encrypting, 16, 16>>(),
        size_of::<Ecb<AES_128, Decrypting, 16, 16>>()
    );
    assert_eq!(size_of::<Ecb<AES_256, Encrypting, 32, 16>>(), size_of::<AES_256>());
    // One block smaller than CBC, which stores a chaining value.
    assert_eq!(
        size_of::<Ecb<AES_128, Encrypting, 16, 16>>() + 16,
        size_of::<Cbc<AES_128, Encrypting, 16, 16>>()
    );
}
