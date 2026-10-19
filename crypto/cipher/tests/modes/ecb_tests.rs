//! Structural tests for ECB, driven by a toy permutation.
//!
//! These check the properties of the *mode* -- that it is the permutation applied block by block
//! with nothing chained, that both directions batch through the pair and four-block paths, call
//! sequencing, direction typing, the empty init data, SP 800-38A Appendix D error propagation, and
//! the codebook property that makes ECB unsuitable for data -- independently of any real cipher. The
//! known-answer tests against SP 800-38A Appendix F.1 are in the `aes` crate,
//! `crypto/aes/tests/sp800_38a_ecb_tests.rs`, and the ACVP set in `ecb_bc-test-data.rs` beside it.
//!
//! The toy's own conformance to [`ElectronicCodeBook`] is pinned once, by
//! `the_toy_permutation_conforms_to_the_trait` in `cbc_tests.rs`; it is the same `Toy` here.

mod common;

#[path = "../common/toy_key.rs"]
mod toy_key;

use bouncycastle_cipher::modes::hazmat::{ECB, Ecb};
use bouncycastle_cipher::modes::{Blocks, CBC, Cbc, ModeNames};
use bouncycastle_cipher::padding::PKCS7;
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::hazmat::{EcbDecryptionKey, EcbEncryptionKey, ElectronicCodeBook};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{
    BlockEncryptionKey, FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle_core::traits::{
    BlockCipherDecryptor, BlockCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_core_test_framework::block_cipher::TestFrameworkBlockCipher;
use bouncycastle_core_test_framework::from_key_material::TestFrameworkFromKeyMaterial;
use common::{SwappedFourToy, SwappedPairToy, TOY_LEN, Toy, toy_key};
use toy_key::{ToyKey, os_rng};

type ToyEcb<Dir> = Ecb<Toy, Dir, TOY_LEN, TOY_LEN>;
type ToyEcbKey = ToyKey<Toy, ECB<Blocks>>;

fn ecb_key() -> ToyEcbKey {
    ToyEcbKey::from_key_material(&toy_key()).expect("the toy key")
}

fn swapped_key() -> ToyKey<SwappedPairToy, ECB<Blocks>> {
    ToyKey::from_key_material(&toy_key()).expect("the toy key")
}

fn swapped_four_key() -> ToyKey<SwappedFourToy, ECB<Blocks>> {
    ToyKey::from_key_material(&toy_key()).expect("the toy key")
}

/// The implementor hook `do_encrypt_blocks_inplace`, by value, for tests whose data is
/// block-shaped.
fn enc_blocks<const N: usize>(
    enc: &mut impl BlockCipherEncryptor<TOY_LEN, 0, TOY_LEN>,
    plaintext: &[[u8; TOY_LEN]; N],
) -> [[u8; TOY_LEN]; N] {
    let mut blocks = *plaintext;
    enc.do_encrypt_blocks_inplace(&mut blocks).unwrap();
    blocks
}

/// The implementor hook `do_decrypt_blocks_inplace`, by value.
fn dec_blocks<const N: usize>(
    dec: &mut impl BlockCipherDecryptor<TOY_LEN, 0, TOY_LEN>,
    ciphertext: &[[u8; TOY_LEN]; N],
) -> [[u8; TOY_LEN]; N] {
    let mut blocks = *ciphertext;
    dec.do_decrypt_blocks_inplace(&mut blocks).unwrap();
    blocks
}

/// The flat streaming method `do_encrypt_inplace`, by value.
fn enc_flat<const LEN: usize>(
    enc: &mut impl BlockCipherEncryptor<TOY_LEN, 0, TOY_LEN>,
    plaintext: &[u8; LEN],
) -> [u8; LEN] {
    let mut data = *plaintext;
    enc.do_encrypt_inplace(&mut data).unwrap();
    data
}

/// The flat streaming method `do_decrypt_inplace`, by value.
fn dec_flat<const LEN: usize>(
    dec: &mut impl BlockCipherDecryptor<TOY_LEN, 0, TOY_LEN>,
    ciphertext: &[u8; LEN],
) -> [u8; LEN] {
    let mut data = *ciphertext;
    dec.do_decrypt_inplace(&mut data).unwrap();
    data
}

fn encryptor() -> ToyEcb<Encrypting> {
    ecb_key().create_encryptor()
}

fn decryptor() -> ToyEcb<Decrypting> {
    ecb_key().create_decryptor()
}

// ---- the mode against the shared framework ------------------------------------------------

#[test]
fn ecb_conforms_to_the_block_cipher_framework() {
    TestFrameworkBlockCipher::new().test_ecb_key::<TOY_LEN, TOY_LEN, _>(&ecb_key());
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
    let perm = <Toy as ElectronicCodeBook<TOY_LEN, TOY_LEN>>::new(&toy_key()).unwrap();
    let plaintext: [[u8; TOY_LEN]; 5] =
        core::array::from_fn(|i| core::array::from_fn(|j| (i * 31 + j * 7 + 1) as u8));

    let ct = enc_blocks(&mut encryptor(), &plaintext);
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
    let (mut cbc, _) = ToyKey::<Toy, CBC<Blocks>>::from_key_material(&toy_key())
        .unwrap()
        .create_encryptor(&mut FixedSeedRNG::<TOY_LEN>::new(iv))
        .unwrap();
    let mut first = plaintext[0];
    cbc.do_encrypt_inplace(&mut first).unwrap();
    assert_ne!(first, ct[0], "ECB must not agree with CBC");
}

// ---- no state: determinism and the codebook property --------------------------------------

/// ECB is a function of the key and the block alone. Sec 6.1: "under a given key, any given
/// plaintext block always gets encrypted to the same ciphertext block." This is the property that
/// makes it unusable for data, and it is pinned here so the mode cannot quietly grow an IV or a
/// counter and stop being ECB.
#[test]
fn ecb_is_deterministic_and_leaks_equal_blocks() {
    let key = ecb_key();
    let block = [0x5Au8; TOY_LEN];
    let plaintext = [block, [0x11; TOY_LEN], block, block];

    let ct_a = enc_blocks(&mut encryptor(), &plaintext);
    let ct_b = enc_blocks(&mut encryptor(), &plaintext);
    assert_eq!(ct_a, ct_b, "the same plaintext under the same key gives the same ciphertext");

    assert_eq!(ct_a[0], ct_a[2], "equal plaintext blocks give equal ciphertext blocks");
    assert_eq!(ct_a[0], ct_a[3]);
    assert_ne!(ct_a[0], ct_a[1], "different plaintext blocks give different ciphertext blocks");

    // The one-shot sees the same thing: the ECB key path takes no RNG and returns no init data,
    // so it is repeatable.
    let flat: [u8; 4 * TOY_LEN] = plaintext.as_flattened().try_into().unwrap();
    let mut once = flat;
    let n_a = key.encrypt_inplace(&mut once).unwrap();
    assert_eq!(n_a, once.len(), "encrypt must report the number of bytes written");
    let mut twice = flat;
    let n_b = key.encrypt_inplace(&mut twice).unwrap();
    assert_eq!(n_b, twice.len(), "encrypt must report the number of bytes written");
    assert_eq!(once, twice, "no init data and no randomness, so the one-shot is repeatable");
    assert_eq!(once, *ct_a.as_flattened());
}

// ---- batching: pairs and fours, in both directions ----------------------------------------

/// Sec 6.1: "multiple forward cipher functions and inverse cipher functions can be computed in
/// parallel" -- so, unlike CBC and CFB, *both* directions batch. [`SwappedPairToy`] swaps its two
/// pair results, so a pair handed over together comes out wrong in either direction, while blocks
/// handed over singly come out right.
#[test]
fn the_pair_path_is_used_in_both_directions() {
    let plaintext = [[0xA5u8; TOY_LEN], [0x5Au8; TOY_LEN]];
    let ct = enc_blocks(&mut encryptor(), &plaintext);

    // Encryption: a pair goes through encrypt_2blocks, so the swapped toy returns them swapped.
    let mut enc = swapped_key().create_encryptor();
    let swapped_ct = enc_blocks(&mut enc, &plaintext);
    assert_eq!(swapped_ct, [ct[1], ct[0]], "encrypting a pair must go through encrypt_2blocks");

    // ...and one block at a time avoids the pair path.
    let mut enc = swapped_key().create_encryptor();
    assert_eq!([enc_flat(&mut enc, &plaintext[0]), enc_flat(&mut enc, &plaintext[1])], ct);

    // Decryption likewise.
    let mut dec = swapped_key().create_decryptor();
    assert_eq!(
        dec_blocks(&mut dec, &ct),
        [plaintext[1], plaintext[0]],
        "decrypting a pair must go through decrypt_2blocks"
    );
    let mut dec = swapped_key().create_decryptor();
    assert_eq!([dec_flat(&mut dec, &ct[0]), dec_flat(&mut dec, &ct[1])], plaintext);
}

/// The four-block path must be taken, and only for full fours, in both directions.
/// [`SwappedFourToy`] rotates its four results while its pair and single-block methods are
/// correct, so five blocks handed over together are wrong (four rotated, then one right) and the
/// same blocks as two pairs or singly are right.
#[test]
fn the_four_block_path_is_used_in_both_directions() {
    let plaintext: [[u8; TOY_LEN]; 5] = core::array::from_fn(|i| [0x10 * i as u8 + 1; TOY_LEN]);
    let ct = enc_blocks(&mut encryptor(), &plaintext);
    assert_eq!(dec_blocks(&mut decryptor(), &ct), plaintext);

    let mut enc = swapped_four_key().create_encryptor();
    let rotated = enc_blocks(&mut enc, &plaintext);
    assert_ne!(rotated, ct, "five blocks must go through encrypt_4blocks");
    assert_eq!(rotated[4], ct[4], "the fifth block goes through the single path and is right");
    assert_eq!(&rotated[..4], &[ct[1], ct[2], ct[3], ct[0]], "four rotated");

    let mut enc = swapped_four_key().create_encryptor();
    let a = enc_blocks(&mut enc, &[plaintext[0], plaintext[1]]);
    let b = enc_blocks(&mut enc, &[plaintext[2], plaintext[3]]);
    assert_eq!([a, b].as_flattened(), &ct[..4], "pairs use the pair path only");

    let mut dec = swapped_four_key().create_decryptor();
    assert_ne!(dec_blocks(&mut dec, &ct), plaintext, "five blocks must go through decrypt_4blocks");
    let mut dec = swapped_four_key().create_decryptor();
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
            dec.do_decrypt_blocks_inplace(&mut buf).unwrap();
            out.extend_from_slice(&buf);
        }
        assert_eq!(out, plaintext.to_vec(), "decrypting in groups of {grouping}");
    }
}

/// The flat streaming method and the one-shots must agree with the block-shaped hook.
#[test]
fn flat_streaming_and_one_shots_agree_with_the_block_hook() {
    let key = ecb_key();
    let plaintext = [[0x11u8; TOY_LEN], [0x22u8; TOY_LEN], [0x33u8; TOY_LEN]];
    let flat_plaintext: [u8; 3 * TOY_LEN] = plaintext.as_flattened().try_into().unwrap();

    let block_ct = enc_blocks(&mut encryptor(), &plaintext);
    assert_eq!(*block_ct.as_flattened(), enc_flat(&mut encryptor(), &flat_plaintext));

    let mut buf = flat_plaintext;
    key.encrypt_inplace(&mut buf).unwrap();
    assert_eq!(buf, *block_ct.as_flattened(), "one-shot must equal streaming");
    key.decrypt_inplace(&mut buf).unwrap();
    assert_eq!(buf, flat_plaintext);

    assert_eq!(dec_blocks(&mut decryptor(), &block_ct), plaintext);
    let flat_ct: [u8; 3 * TOY_LEN] = block_ct.as_flattened().try_into().unwrap();
    assert_eq!(dec_flat(&mut decryptor(), &flat_ct), flat_plaintext);
}

// ---- SP 800-38A Appendix D error propagation ---------------------------------------------

/// Table D.2 for ECB: a bit error in `Cj` gives "RBE in the decryption of Cj" and nothing else --
/// Appendix D: "For the ECB, OFB, and CTR modes, bit errors within a ciphertext block do not affect
/// the decryption of any other blocks." The "RBE" spread is the block cipher's diffusion, which
/// the byte-local toy cannot show and this does not claim. What it pins exactly instead: the
/// corrupted block is the *only* one affected, and within it the flipped bit went through the
/// inverse cipher -- it comes out in the same byte moved by the toy's `rotate_right(1)`, the
/// signature of `CIPH^-1_K` acting on it rather than of an in-place XOR.
#[test]
fn a_ciphertext_bit_error_affects_only_its_own_block() {
    let plaintext = [[0x00u8; TOY_LEN], [0x11u8; TOY_LEN], [0x22u8; TOY_LEN], [0x33u8; TOY_LEN]];
    let ct = enc_blocks(&mut encryptor(), &plaintext);

    for byte in 0..TOY_LEN {
        for bit in 0..8 {
            let flip = 1u8 << bit;
            let mut corrupt = ct;
            corrupt[1][byte] ^= flip;
            let got = dec_blocks(&mut decryptor(), &corrupt);
            assert_eq!(got[0], plaintext[0]);
            let mut expected = plaintext[1];
            expected[byte] ^= flip.rotate_right(1);
            assert_eq!(
                got[1], expected,
                "C2 byte {byte} bit {bit}: P2 carries the flip through the toy's inverse"
            );
            assert_eq!(got[2], plaintext[2], "P3 is unaffected: nothing chains");
            assert_eq!(got[3], plaintext[3]);
        }
    }
}

// ---- key handling ------------------------------------------------------------------------

/// The key's construction suite: the type, binding and strength policy of `from_key_material`,
/// for both the block-aligned and the padded key.
#[test]
fn the_keys_enforce_the_material_policy() {
    let framework = TestFrameworkFromKeyMaterial::new();
    framework.test::<TOY_LEN, ToyEcbKey>(Toy::ECB_ALG_NAME, SecurityStrength::_128bit);
    framework
        .test::<TOY_LEN, ToyKey<Toy, ECB<PKCS7>>>(Toy::ECB_ALG_NAME, SecurityStrength::_128bit);
}

// ---- composition with the padding layer --------------------------------------------------

/// ECB is block-aligned by contract, so arbitrary-length data goes through `bouncycastle_cipher::padding`
/// like the other modes: `ECB<PKCS7>` is the symmetric key path over the adapters, with its
/// `INIT_DATA_LEN` of 0 flowing through as an empty array and the RNG unused.
#[test]
fn the_padding_layer_round_trips_every_length() {
    type Key = ToyKey<Toy, ECB<PKCS7>>;
    type Enc = <Key as SymmetricEncryptionKey<TOY_LEN, 0, TOY_LEN>>::Encryptor;
    type Dec = <Key as SymmetricDecryptionKey<TOY_LEN, 0, TOY_LEN>>::Decryptor;
    let key = Key::from_key_material(&toy_key()).expect("the toy key");

    for len in 0..=(3 * TOY_LEN + 1) {
        let plaintext: Vec<u8> = (0..len).map(|i| (i * 5 + 3) as u8).collect();
        let mut ciphertext = vec![0u8; Enc::encrypt_out_len(len)];
        let (written, init) =
            key.encrypt_out(&mut os_rng(), &plaintext, &mut ciphertext).expect("padded encryption");
        assert_eq!(init, [0u8; 0]);
        assert_eq!(written, ciphertext.len(), "len {len}");
        let mut recovered = vec![0u8; Dec::decrypt_out_len(written)];
        let n = key.decrypt_out(&init, &ciphertext, &mut recovered).expect("padded decryption");
        assert_eq!(&recovered[..n], &plaintext[..], "len {len}: round trip through PKCS7");
    }
}

// ---- memory ------------------------------------------------------------------------------

/// Pins the module docs' claim that an ECB value is exactly the permutation:
/// `size_of::<Ecb<P, ..>>() == size_of::<P>()`.
#[test]
fn sizes_match_the_documented_memory_table() {
    use core::mem::size_of;
    assert_eq!(size_of::<ToyEcb<Encrypting>>(), size_of::<Toy>());
    assert_eq!(size_of::<ToyEcb<Encrypting>>(), size_of::<ToyEcb<Decrypting>>());
    // One block smaller than CBC, which stores a chaining value.
    assert_eq!(
        size_of::<ToyEcb<Encrypting>>() + TOY_LEN,
        size_of::<Cbc<Toy, Encrypting, TOY_LEN, TOY_LEN>>()
    );
}
