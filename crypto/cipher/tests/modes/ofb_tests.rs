//! Structural tests for OFB, driven by a toy permutation.
//!
//! These check the properties of the *mode* -- the keystream construction, call sequencing at
//! arbitrary byte boundaries, the partial final block, the absence of any batch path, SP 800-38A
//! Appendix D error propagation, and the "forward cipher function only" rule of Sec 6.4 --
//! independently of any real cipher. The known-answer tests against SP 800-38A Appendix F.4 are
//! in the `aes` crate, `crypto/aes/tests/sp800_38a_ofb_tests.rs`, and the ACVP OFB set in
//! `ofb_bc-test-data.rs` beside it.

mod common;

use bouncycastle_cipher::BlockCipherKey;
use bouncycastle_cipher::modes::{CFB, Cfb, ModeNames, OFB, Ofb};
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::hazmat::FixedSeedRNG;
use bouncycastle_core::hazmat::{BlockPermutation, KeyExpansion};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{
    FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle_core::traits::{StreamCipherDecryptor, StreamCipherEncryptor};
use bouncycastle_core_test_framework::from_key_material::TestFrameworkFromKeyMaterial;
use bouncycastle_core_test_framework::symmetric_ciphers::TestFrameworkStreamCipher;
use common::os_rng;
use common::{ForwardOnlyToy, SwappedFourToy, SwappedPairToy, TOY_LEN, Toy, toy_key};

type ToyOfb<'k, Dir> = Ofb<'k, Toy, Dir, TOY_LEN>;

type ToyOfbKey = BlockCipherKey<Toy, OFB>;

fn ofb_key() -> ToyOfbKey {
    ToyOfbKey::from_key_material(&toy_key()).expect("the toy key")
}

/// The key the worker helpers below hand out borrowed workers over; a worker cannot outlive
/// its key, so the helpers' key lives for the whole test binary.
static KEY: std::sync::LazyLock<ToyOfbKey> = std::sync::LazyLock::new(ofb_key);

fn swapped_key() -> BlockCipherKey<SwappedPairToy, OFB> {
    BlockCipherKey::from_key_material(&toy_key()).expect("the toy key")
}

fn swapped_four_key() -> BlockCipherKey<SwappedFourToy, OFB> {
    BlockCipherKey::from_key_material(&toy_key()).expect("the toy key")
}

fn forward_only_key() -> BlockCipherKey<ForwardOnlyToy, OFB> {
    BlockCipherKey::from_key_material(&toy_key()).expect("the toy key")
}

/// `do_encrypt_inplace`, by value.
fn enc(e: &mut impl StreamCipherEncryptor<TOY_LEN>, plaintext: &[u8]) -> Vec<u8> {
    let mut data = plaintext.to_vec();
    e.do_encrypt_inplace(&mut data).unwrap();
    data
}

/// `do_decrypt_inplace`, by value.
fn dec(d: &mut impl StreamCipherDecryptor<TOY_LEN>, ciphertext: &[u8]) -> Vec<u8> {
    let mut data = ciphertext.to_vec();
    d.do_decrypt_inplace(&mut data).unwrap();
    data
}

/// `do_encrypt_inplace` in `chunk`-byte calls, by value. The last call may be shorter.
fn enc_chunked(
    e: &mut impl StreamCipherEncryptor<TOY_LEN>,
    plaintext: &[u8],
    chunk: usize,
) -> Vec<u8> {
    let mut data = plaintext.to_vec();
    for piece in data.chunks_mut(chunk) {
        e.do_encrypt_inplace(piece).unwrap();
    }
    data
}

/// `do_decrypt_inplace` in `chunk`-byte calls, by value. The last call may be shorter.
fn dec_chunked(
    d: &mut impl StreamCipherDecryptor<TOY_LEN>,
    ciphertext: &[u8],
    chunk: usize,
) -> Vec<u8> {
    let mut data = ciphertext.to_vec();
    for piece in data.chunks_mut(chunk) {
        d.do_decrypt_inplace(piece).unwrap();
    }
    data
}

/// A pinned IV, so two runs are comparable, fed through the fixed-output RNG that
/// `create_encryptor` takes.
fn pinned_iv() -> [u8; TOY_LEN] {
    core::array::from_fn(|i| 0xF0 ^ (i as u8))
}

fn pinned_rng(iv: [u8; TOY_LEN]) -> FixedSeedRNG<[u8; TOY_LEN]> {
    FixedSeedRNG::new(iv)
}

fn pinned_encryptor(iv: [u8; TOY_LEN]) -> ToyOfb<'static, Encrypting> {
    let (enc, got) = KEY.create_encryptor(&mut pinned_rng(iv)).expect("encrypt init");
    assert_eq!(got, iv, "the pinned RNG should reproduce the IV");
    enc
}

fn pinned_decryptor(iv: [u8; TOY_LEN]) -> ToyOfb<'static, Decrypting> {
    KEY.create_decryptor(&iv)
}

/// A test message of `len` bytes with no repeating structure at the block size.
fn message(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + (i / TOY_LEN) * 31 + 1) as u8).collect()
}

// ---- the mode against the shared framework ------------------------------------------------

#[test]
fn ofb_conforms_to_the_stream_cipher_framework() {
    TestFrameworkStreamCipher::new().test_key::<TOY_LEN, TOY_LEN, _>(&ofb_key(), &mut os_rng());
}

/// The key's construction suite: the type, binding and strength policy of `from_key_material`.
#[test]
fn the_key_enforces_the_material_policy() {
    TestFrameworkFromKeyMaterial::new()
        .test::<TOY_LEN, ToyOfbKey>(Toy::OFB_ALG_NAME, SecurityStrength::_128bit);
}

// ---- the spec equations -------------------------------------------------------------------

/// OFB from SP 800-38A Sec 6.4, written out longhand against the raw permutation:
///
/// ```text
/// I1 = IV;  Ij = O_{j-1} (j >= 2);  Oj = CIPH_K(Ij);  Cj = Pj XOR Oj;  C*n = P*n XOR MSBu(On)
/// ```
///
/// The same function in both directions. It uses only [`BlockPermutation::encrypt_block`],
/// because that is all the spec calls for.
fn reference_ofb(perm: &Toy, iv: [u8; TOY_LEN], input: &[u8]) -> Vec<u8> {
    let mut o = iv; // I1 = IV
    let mut out = Vec::with_capacity(input.len());
    for block in input.chunks(TOY_LEN) {
        perm.encrypt_block(&mut o); // Oj = CIPH_K(Ij), and Ij+1 = Oj
        // Cj = Pj XOR Oj, or the leading bytes of On for a partial final block.
        out.extend(block.iter().zip(o.iter()).map(|(d, o)| d ^ o));
    }
    out
}

/// The mode must reproduce the Sec 6.4 equations exactly, in both directions, for whole blocks
/// and for a message ending in a partial block; and encrypting zeros yields `O1, O2, ..`, each the
/// cipher of the one before.
#[test]
fn the_mode_matches_the_spec_equations() {
    let iv = pinned_iv();
    let perm = <Toy as KeyExpansion<TOY_LEN>>::new(&toy_key()).unwrap();

    for len in [5 * TOY_LEN, 5 * TOY_LEN + 9, TOY_LEN - 1, 1] {
        let plaintext = message(len);

        let ct = enc(&mut pinned_encryptor(iv), &plaintext);
        assert_eq!(
            ct,
            reference_ofb(&perm, iv, &plaintext),
            "len {len}: encryption must match the Sec 6.4 equations"
        );

        let recovered = dec(&mut pinned_decryptor(iv), &ct);
        assert_eq!(recovered, plaintext, "len {len}: round trip");
    }

    // With P = 0, C = O1 | O2 | O3, and `O_{j+1} = CIPH_K(Oj)`.
    let keystream = enc(&mut pinned_encryptor(iv), &[0u8; 3 * TOY_LEN]);
    let mut o = iv;
    for (j, block) in keystream.chunks(TOY_LEN).enumerate() {
        perm.encrypt_block(&mut o);
        assert_eq!(block, &o[..], "O{} = CIPH_K(O{})", j + 1, j);
    }
}

/// Encryption and decryption are the same function: a decryptor applied to plaintext gives the
/// ciphertext.
#[test]
fn encryption_and_decryption_are_the_same_operation() {
    let iv = pinned_iv();
    for len in [0, 1, TOY_LEN, 3 * TOY_LEN + 5] {
        let plaintext = message(len);
        assert_eq!(
            dec(&mut pinned_decryptor(iv), &plaintext),
            enc(&mut pinned_encryptor(iv), &plaintext),
            "len {len}"
        );
    }
}

/// OFB and CFB both start with `C1 = P1 XOR CIPH_K(IV)`; from block 2 CFB feeds back `C1` and OFB
/// feeds back `O1`. So the two agree on the first block and on nothing after it.
#[test]
fn ofb_agrees_with_cfb_on_the_first_block_only() {
    let iv = pinned_iv();
    let plaintext = message(3 * TOY_LEN);
    let ofb_ct = enc(&mut pinned_encryptor(iv), &plaintext);

    let cfb_key = BlockCipherKey::<Toy, CFB>::from_key_material(&toy_key()).unwrap();
    let (mut cfb, _): (Cfb<'_, Toy, Encrypting, TOY_LEN>, _) =
        cfb_key.create_encryptor(&mut pinned_rng(iv)).unwrap();
    let cfb_ct = enc(&mut cfb, &plaintext);

    assert_eq!(ofb_ct[..TOY_LEN], cfb_ct[..TOY_LEN], "both modes compute P1 XOR CIPH_K(IV)");
    for j in 1..3 {
        assert_ne!(
            ofb_ct[j * TOY_LEN..(j + 1) * TOY_LEN],
            cfb_ct[j * TOY_LEN..(j + 1) * TOY_LEN],
            "block {}: OFB must feed back Oj, not Cj",
            j + 1
        );
    }
}

// ---- forward cipher only, serial ----------------------------------------------------------

/// [`ForwardOnlyToy`] panics from every inverse entry point, so a round trip over it fails loudly
/// if either direction ever reaches the inverse cipher; and it must agree with the plain [`Toy`],
/// or the test could pass by not really encrypting anything.
#[test]
fn neither_direction_uses_the_inverse_cipher() {
    let iv = pinned_iv();
    let plaintext = message(11 * TOY_LEN + 5);

    let key = forward_only_key();
    let (mut e, _) = key.create_encryptor(&mut pinned_rng(iv)).unwrap();
    let ct = enc(&mut e, &plaintext);
    assert_eq!(ct, enc(&mut pinned_encryptor(iv), &plaintext), "the two toys must agree");

    let mut d = key.create_decryptor(&iv);
    assert_eq!(dec(&mut d, &ct), plaintext, "forward cipher only");
}

/// Sec 6.4: "multiple forward cipher functions cannot be performed in parallel". The swapped toys
/// get their two- and four-block paths wrong while their single-block path is right, so a mode
/// that batched would disagree with the plain [`Toy`] on five blocks in one call. OFB must agree,
/// in both directions -- the opposite of what `ctr_tests.rs` asserts for the same toys.
#[test]
fn no_batch_path_is_used_in_either_direction() {
    let iv = pinned_iv();
    let plaintext = message(11 * TOY_LEN + 5);
    let ct = enc(&mut pinned_encryptor(iv), &plaintext);

    let key = swapped_key();
    let (mut e, _) = key.create_encryptor(&mut pinned_rng(iv)).unwrap();
    assert_eq!(enc(&mut e, &plaintext), ct, "encryption must not use encrypt_2blocks");
    assert_eq!(dec(&mut key.create_decryptor(&iv), &ct), plaintext, "nor decryption");

    let key = swapped_four_key();
    let (mut e, _) = key.create_encryptor(&mut pinned_rng(iv)).unwrap();
    assert_eq!(enc(&mut e, &plaintext), ct, "encryption must not use encrypt_4blocks");
    assert_eq!(dec(&mut key.create_decryptor(&iv), &ct), plaintext, "nor decryption");
}

/// The caller's chunking must be invisible in the output, in both directions, whether or not a
/// chunk boundary falls on a block boundary.
#[test]
fn call_chunking_does_not_change_the_result() {
    let iv = pinned_iv();
    let plaintext = message(5 * TOY_LEN + 3);
    let whole = enc(&mut pinned_encryptor(iv), &plaintext);
    for chunk in [1, 3, 5, 7, 15, 16, 17, 31, 32, 33, 64, 100] {
        assert_eq!(
            enc_chunked(&mut pinned_encryptor(iv), &plaintext, chunk),
            whole,
            "encrypt in {chunk}-byte chunks"
        );
        assert_eq!(
            dec_chunked(&mut pinned_decryptor(iv), &whole, chunk),
            plaintext,
            "decrypt in {chunk}-byte chunks"
        );
    }
}

// ---- SP 800-38A Appendix D error propagation ---------------------------------------------

/// Table D.2 for OFB: a bit error in `Cj` gives "SBE in the decryption of `Cj`", and "bit errors
/// within a ciphertext block do not affect the decryption of any other blocks". The keystream
/// does not depend on the ciphertext, so every bit of `C2` and of the partial final block flips
/// exactly that bit of the plaintext and nothing else; contrast `cfb_tests.rs`, where `P3` is
/// damaged too.
#[test]
fn a_ciphertext_bit_error_flips_exactly_that_bit_and_nothing_else() {
    let iv = pinned_iv();
    let plaintext = message(4 * TOY_LEN + 5);
    let ct = enc(&mut pinned_encryptor(iv), &plaintext);

    for byte in (TOY_LEN..2 * TOY_LEN).chain(4 * TOY_LEN..plaintext.len()) {
        for bit in 0..8 {
            let mut corrupt = ct.clone();
            corrupt[byte] ^= 1 << bit;
            let mut expected = plaintext.clone();
            expected[byte] ^= 1 << bit;
            assert_eq!(
                dec(&mut pinned_decryptor(iv), &corrupt),
                expected,
                "byte {byte} bit {bit}: exactly that bit, and nothing else"
            );
        }
    }
}

/// Appendix D: "In the OFB mode, bit errors in the IV affect the decryption of every ciphertext
/// block". Every block of the decryption under a corrupted IV must differ from the plaintext.
/// (Which bits differ is the block cipher's diffusion; [`Toy`] permutes each byte on its own, so
/// here the damage is one byte per block, which is why the message is whole blocks.)
#[test]
fn an_iv_bit_error_damages_every_block() {
    let iv = pinned_iv();
    let plaintext = message(4 * TOY_LEN);
    let ct = enc(&mut pinned_encryptor(iv), &plaintext);

    for byte in 0..TOY_LEN {
        for bit in 0..8 {
            let mut corrupt_iv = iv;
            corrupt_iv[byte] ^= 1 << bit;
            let got = dec(&mut pinned_decryptor(corrupt_iv), &ct);
            for (j, (g, p)) in got.chunks(TOY_LEN).zip(plaintext.chunks(TOY_LEN)).enumerate() {
                assert_ne!(g, p, "IV byte {byte} bit {bit}: block {} must be damaged", j + 1);
            }
        }
    }
}

// ---- IV handling -------------------------------------------------------------------------

/// Two encryption flows under the same key must not reuse an IV: under OFB a repeated IV repeats
/// the whole keystream.
#[test]
fn each_encryption_gets_a_fresh_iv() {
    let key = ofb_key();
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..64 {
        let (_, iv) = key.create_encryptor(&mut os_rng()).unwrap();
        assert!(seen.insert(iv), "IV repeated across encryptions: {iv:02x?}");
    }
}

/// Identical plaintext under the same key must give different ciphertext, because the IV differs;
/// and within one message two identical plaintext blocks give different ciphertext blocks.
#[test]
fn identical_plaintext_gives_different_ciphertext() {
    let key = ofb_key();
    let plaintext = [0x77u8; 2 * TOY_LEN];

    let mut first = plaintext;
    key.encrypt_inplace(&mut os_rng(), &mut first).unwrap();
    let mut second = plaintext;
    key.encrypt_inplace(&mut os_rng(), &mut second).unwrap();
    assert_ne!(first, second);
    assert_ne!(first[..TOY_LEN], first[TOY_LEN..], "the keystream blocks must differ");
}

/// The supplied-IV forms produce what the drawing forms produce under the same IV.
#[test]
fn the_supplied_iv_forms_agree_with_the_drawn_ones() {
    let key = ofb_key();
    let iv = pinned_iv();
    let plaintext = message(3 * TOY_LEN + 7);
    let drawn = enc(&mut pinned_encryptor(iv), &plaintext);
    assert_eq!(enc(&mut key.create_encryptor_nonce(&iv), &plaintext), drawn);
}

// ---- every length, no padding ------------------------------------------------------------

/// OFB is a stream cipher: every length round-trips and the ciphertext is exactly as long as the
/// plaintext.
#[test]
fn every_length_round_trips_without_padding() {
    let key = ofb_key();
    for len in 0..=(4 * TOY_LEN) {
        let plaintext = message(len);
        let mut data = plaintext.clone();
        let (n, iv) = key.encrypt_inplace(&mut os_rng(), &mut data).expect("encryption");
        assert_eq!(n, len, "len {len}: encrypt must report the number of bytes written");
        // A short message can coincide with its ciphertext by chance; at 8 bytes the odds are
        // 2^-64.
        if len >= 8 {
            assert_ne!(data, plaintext, "len {len}: the data must actually be encrypted");
        }
        key.decrypt_inplace(&iv, &mut data).expect("decryption");
        assert_eq!(data, plaintext, "len {len}: round trip");
    }
}

// ---- memory ------------------------------------------------------------------------------

/// Pins the "Memory Usage" statement in the module docs: a reference to the permutation, the
/// block `Oj-1`, the pending keystream block and its byte count.
#[test]
fn sizes_match_the_documented_memory_table() {
    use core::mem::{align_of, size_of};

    assert_eq!(
        size_of::<ToyOfb<Encrypting>>(),
        (size_of::<&Toy>() + TOY_LEN + TOY_LEN + size_of::<usize>())
            .next_multiple_of(align_of::<usize>())
    );
    assert_eq!(size_of::<ToyOfb<Encrypting>>(), size_of::<ToyOfb<Decrypting>>());
}
