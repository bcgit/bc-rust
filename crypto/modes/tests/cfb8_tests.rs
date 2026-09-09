//! Structural tests for CFB8, driven by a toy permutation.
//!
//! These check the properties of the *mode* -- the shift register, the one-byte segment, call
//! sequencing at arbitrary byte boundaries, the batch split on the decrypt side, direction typing,
//! SP 800-38A Appendix D error propagation, and the "forward cipher function only" rule of
//! Sec 6.3 -- independently of any real cipher. The known-answer tests against SP 800-38A
//! Appendix F.3.7-F.3.12 are in `sp800_38a_cfb8_tests.rs`, and the ACVP CFB8 set is in
//! `acvp_cfb8_tests.rs`.
//!
//! The toy's own conformance to [`ElectronicCodeBook`] is pinned once, by
//! `the_toy_permutation_conforms_to_the_trait` in `cbc_tests.rs`; it is the same `Toy` here, so it
//! is not re-run.

mod common;

use bouncycastle_aes::{AES_128, AES_192, AES_256};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{ElectronicCodeBook, StreamCipherDecryptor, StreamCipherEncryptor};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_core_test_framework::symmetric_ciphers::TestFrameworkStreamCipher;
use bouncycastle_modes::{Cbc, Cfb, Cfb8, Decrypting, Encrypting};
use common::{ForwardOnlyToy, SwappedEightToy, SwappedPairToy, TOY_LEN, Toy, toy_key};

type ToyCfb8<Dir> = Cfb8<Toy, Dir, TOY_LEN, TOY_LEN>;
type SwappedCfb8<Dir> = Cfb8<SwappedPairToy, Dir, TOY_LEN, TOY_LEN>;
type ForwardOnlyCfb8<Dir> = Cfb8<ForwardOnlyToy, Dir, TOY_LEN, TOY_LEN>;
type SwappedEightCfb8<Dir> = Cfb8<SwappedEightToy, Dir, TOY_LEN, TOY_LEN>;

/// `do_encrypt`, by value.
fn enc(e: &mut impl StreamCipherEncryptor<TOY_LEN, TOY_LEN>, plaintext: &[u8]) -> Vec<u8> {
    let mut data = plaintext.to_vec();
    e.do_encrypt(&mut data).unwrap();
    data
}

/// `do_decrypt`, by value.
fn dec(d: &mut impl StreamCipherDecryptor<TOY_LEN, TOY_LEN>, ciphertext: &[u8]) -> Vec<u8> {
    let mut data = ciphertext.to_vec();
    d.do_decrypt(&mut data).unwrap();
    data
}

/// `do_decrypt` in `chunk`-byte calls, by value. The last call may be shorter.
fn dec_chunked(
    d: &mut impl StreamCipherDecryptor<TOY_LEN, TOY_LEN>,
    ciphertext: &[u8],
    chunk: usize,
) -> Vec<u8> {
    let mut data = ciphertext.to_vec();
    for piece in data.chunks_mut(chunk) {
        d.do_decrypt(piece).unwrap();
    }
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

fn pinned_encryptor(iv: [u8; TOY_LEN]) -> ToyCfb8<Encrypting> {
    let (enc, got) = ToyCfb8::<Encrypting>::do_encrypt_init_rng(&toy_key(), &mut pinned_rng(iv))
        .expect("encrypt init");
    assert_eq!(got, iv, "the pinned RNG should reproduce the IV");
    enc
}

fn pinned_decryptor(iv: [u8; TOY_LEN]) -> ToyCfb8<Decrypting> {
    ToyCfb8::<Decrypting>::do_decrypt_init(&toy_key(), &iv).expect("decrypt init")
}

/// A test message of `len` bytes with no repeating structure at the block size.
fn message(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + (i / TOY_LEN) * 31 + 1) as u8).collect()
}

/// The chunk sizes every "chunking must not matter" test uses: below, at, either side of and above
/// both the 8-byte batch and the 16-byte block.
const CHUNKINGS: [usize; 11] = [1, 2, 3, 7, 8, 9, 15, 16, 17, 32, 100];

// ---- the mode against the shared framework ------------------------------------------------

#[test]
fn cfb8_conforms_to_the_stream_cipher_framework() {
    TestFrameworkStreamCipher::new()
        .test::<TOY_LEN, TOY_LEN, ToyCfb8<Encrypting>, ToyCfb8<Decrypting>>();
}

// ---- the spec equations -------------------------------------------------------------------

/// CFB with `s = 8` from SP 800-38A Sec 6.3, written out longhand against the raw permutation:
///
/// ```text
/// I1 = IV;  Ij = LSB_{b-8}(I_{j-1}) | C_{j-1};  Oj = CIPH_K(Ij);  Cj = Pj XOR MSB_8(Oj)
/// ```
///
/// The shift is written here as an explicit copy of `Ij[1..]` followed by the ciphertext byte, so
/// it is an independent statement of the rule rather than a second call to the same `rotate_left`
/// the implementation uses.
///
/// This is the independent reference the mode is checked against below. It uses only
/// [`ElectronicCodeBook::encrypt_block`], because that is all the spec calls for.
fn reference_cfb8(perm: &Toy, iv: [u8; TOY_LEN], input: &[u8], encrypt: bool) -> Vec<u8> {
    let mut chain = iv; // I1 = IV
    let mut out = Vec::with_capacity(input.len());
    for &byte in input {
        let mut o = chain;
        perm.encrypt_block(&mut o); // Oj = CIPH_K(Ij)
        let result = byte ^ o[0]; // Cj = Pj XOR MSB_8(Oj)

        // I_{j+1} = LSB_{b-8}(Ij) | C#_j -- always the *ciphertext* byte, whichever direction.
        let cj = if encrypt { result } else { byte };
        let mut next = [0u8; TOY_LEN];
        next[..TOY_LEN - 1].copy_from_slice(&chain[1..]);
        next[TOY_LEN - 1] = cj;
        chain = next;

        out.push(result);
    }
    out
}

/// The mode must reproduce the Sec 6.3 `s = 8` equations exactly, in both directions, at lengths
/// either side of the shift register's own width.
///
/// A reference implementation is a weak test on its own -- both could be wrong the same way -- so
/// this also pins the anchors that follow directly from the equations and that no plausible
/// mistake preserves: `C1 = P1 XOR MSB_8(CIPH_K(IV))`, and the second input block.
#[test]
fn the_mode_matches_the_spec_equations() {
    let key = toy_key();
    let iv = pinned_iv();
    let perm = <Toy as ElectronicCodeBook<TOY_LEN, TOY_LEN>>::new(&key).unwrap();

    for len in [1, 2, TOY_LEN - 1, TOY_LEN, TOY_LEN + 1, 3 * TOY_LEN + 5] {
        let plaintext = message(len);

        let ct = enc(&mut pinned_encryptor(iv), &plaintext);
        assert_eq!(
            ct,
            reference_cfb8(&perm, iv, &plaintext, true),
            "len {len}: encryption must match the Sec 6.3 equations at s = 8"
        );

        let recovered = dec(&mut pinned_decryptor(iv), &ct);
        assert_eq!(recovered, plaintext, "len {len}: round trip");
        assert_eq!(
            recovered,
            reference_cfb8(&perm, iv, &ct, false),
            "len {len}: decryption must match the Sec 6.3 equations at s = 8"
        );
    }

    let plaintext = message(4);
    let ct = enc(&mut pinned_encryptor(iv), &plaintext);

    // Anchor 1: `O1 = CIPH_K(IV)` and `C1 = P1 XOR MSB_8(O1)` -- the *first* byte of the output
    // block, the other b - 8 bits discarded.
    let mut o1 = iv;
    perm.encrypt_block(&mut o1);
    assert_eq!(ct[0], plaintext[0] ^ o1[0], "C1 = P1 XOR MSB_8(CIPH_K(IV))");

    // Anchor 2: `I2 = LSB_{b-8}(IV) | C1`, i.e. the IV without its leading byte, then C1.
    let mut i2 = [0u8; TOY_LEN];
    i2[..TOY_LEN - 1].copy_from_slice(&iv[1..]);
    i2[TOY_LEN - 1] = ct[0];
    let mut o2 = i2;
    perm.encrypt_block(&mut o2);
    assert_eq!(ct[1], plaintext[1] ^ o2[0], "C2 = P2 XOR MSB_8(CIPH_K(LSB(IV) | C1))");

    // Anchor 3: with `P = 0`, the ciphertext is the keystream itself.
    assert_eq!(
        enc(&mut pinned_encryptor(iv), &[0u8; 2]),
        vec![o1[0], {
            let mut i = [0u8; TOY_LEN];
            i[..TOY_LEN - 1].copy_from_slice(&iv[1..]);
            i[TOY_LEN - 1] = o1[0];
            let mut o = i;
            perm.encrypt_block(&mut o);
            o[0]
        }],
        "encrypting zero yields the keystream"
    );
}

/// CFB8 and CFB128 are different, non-interoperable modes, and they differ from the very first
/// byte: with `s = b` the whole output block is used and the next input block is the ciphertext
/// block, whereas with `s = 8` one byte is used and the register shifts.
///
/// The first byte of ciphertext is the same in both -- `P1 XOR MSB_8(CIPH_K(IV))` either way -- and
/// everything from the second byte differs. That is the sharp statement of "not a variant", and it
/// is what catches a CFB8 that has quietly become CFB128 or vice versa.
#[test]
fn cfb8_is_not_cfb128() {
    let key = toy_key();
    let iv = pinned_iv();
    let plaintext = message(2 * TOY_LEN);

    let cfb8 = enc(&mut pinned_encryptor(iv), &plaintext);

    let (mut cfb, got) =
        Cfb::<Toy, Encrypting, TOY_LEN, TOY_LEN>::do_encrypt_init_rng(&key, &mut pinned_rng(iv))
            .unwrap();
    assert_eq!(got, iv);
    let mut cfb128 = plaintext.clone();
    cfb.do_encrypt(&mut cfb128).unwrap();

    assert_eq!(cfb8[0], cfb128[0], "both modes start O1 = CIPH_K(IV), so C1 agrees");
    assert_ne!(cfb8[1..], cfb128[1..], "everything after the first byte must differ");

    // ...and neither can decrypt the other's ciphertext.
    let mut wrong = cfb128.clone();
    ToyCfb8::<Decrypting>::decrypt(&key, &iv, &mut wrong).unwrap();
    assert_ne!(wrong, plaintext, "CFB8 must not decrypt a CFB128 ciphertext");

    let mut wrong = cfb8.clone();
    Cfb::<Toy, Decrypting, TOY_LEN, TOY_LEN>::decrypt(&key, &iv, &mut wrong).unwrap();
    assert_ne!(wrong, plaintext, "CFB128 must not decrypt a CFB8 ciphertext");
}

/// A stream cipher's ciphertext for a prefix of the message is the prefix of the ciphertext.
#[test]
fn the_ciphertext_of_a_prefix_is_a_prefix_of_the_ciphertext() {
    let iv = pinned_iv();
    let plaintext = message(2 * TOY_LEN + 3);
    let full = enc(&mut pinned_encryptor(iv), &plaintext);

    for k in 0..=plaintext.len() {
        assert_eq!(
            enc(&mut pinned_encryptor(iv), &plaintext[..k]),
            full[..k],
            "encrypting the first {k} bytes"
        );
        assert_eq!(
            dec(&mut pinned_decryptor(iv), &full[..k]),
            plaintext[..k],
            "decrypting the first {k} bytes"
        );
    }
}

// ---- the forward-cipher-only rule ---------------------------------------------------------

/// SP 800-38A Sec 6.3: "The *forward cipher* function is applied to each input block to produce the
/// output blocks" -- in CFB *decryption* as well as encryption.
///
/// [`ForwardOnlyToy`] panics from `decrypt_block`, `decrypt_blocks2` and `decrypt_blocks8`, so this
/// test fails loudly if either direction of the mode ever reaches the inverse cipher. Every decrypt
/// path is exercised -- eights, pairs and single bytes -- and the result is required to agree with
/// the plain [`Toy`], otherwise the test could pass by not really encrypting anything.
#[test]
fn neither_direction_uses_the_inverse_cipher() {
    let key = toy_key();
    let iv = pinned_iv();
    let plaintext = message(19);

    let (mut e, _) =
        ForwardOnlyCfb8::<Encrypting>::do_encrypt_init_rng(&key, &mut pinned_rng(iv)).unwrap();
    let ct = enc(&mut e, &plaintext);

    // One call: two eights, then a pair, then a single byte.
    let mut d = ForwardOnlyCfb8::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    assert_eq!(dec(&mut d, &ct), plaintext, "all paths, forward cipher only");

    // Byte by byte: the single-byte path only.
    let mut d = ForwardOnlyCfb8::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    assert_eq!(dec_chunked(&mut d, &ct, 1), plaintext, "single-byte path, forward cipher only");

    // The forward-only toy must agree with the real one, or the above proves nothing.
    assert_eq!(
        enc(&mut pinned_encryptor(iv), &plaintext),
        ct,
        "the two toys must agree going forward"
    );
}

/// The decryptor must shift the **ciphertext** byte into the register, not the plaintext it just
/// recovered.
///
/// Getting this wrong is invisible in the first byte -- `O1 = CIPH_K(IV)` either way -- and wrong
/// from the second onwards. An encryptor run over ciphertext is exactly that mistake, so byte 1
/// agreeing while byte 2 disagrees is the signature of the bug, and is what this asserts.
#[test]
fn the_decryptor_shifts_in_ciphertext_not_plaintext() {
    let iv = pinned_iv();
    let plaintext = message(2 * TOY_LEN);
    let ct = enc(&mut pinned_encryptor(iv), &plaintext);
    assert_ne!(ct[0], plaintext[0], "the two feedback choices must actually differ here");

    let wrong = enc(&mut pinned_encryptor(iv), &ct);
    assert_eq!(wrong[0], plaintext[0], "byte 1 cannot tell the two apart");
    assert_ne!(wrong[1..], plaintext[1..], "byte 2 onwards must, so the feedback source is pinned");
}

// ---- chaining and call sequencing --------------------------------------------------------

/// Encrypting a message must not depend on how the calls are chunked, and likewise for decryption,
/// at byte granularity. Every chunking in [`CHUNKINGS`] is checked against the one-call reference in
/// both directions, and every encrypt chunking against every decrypt chunking.
///
/// For CFB8 the decrypt side is where this bites: chunk sizes that are not multiples of 8 leave the
/// eight-byte batch loop with a different remainder each call, so the register has to carry across
/// calls correctly for every alignment.
#[test]
fn call_chunking_does_not_change_the_result() {
    let iv = pinned_iv();
    let plaintext = message(3 * TOY_LEN + 7);

    let reference = enc(&mut pinned_encryptor(iv), &plaintext);
    assert_eq!(dec(&mut pinned_decryptor(iv), &reference), plaintext);

    for &enc_chunk in &CHUNKINGS {
        let mut ct = plaintext.clone();
        let mut e = pinned_encryptor(iv);
        for piece in ct.chunks_mut(enc_chunk) {
            e.do_encrypt(piece).unwrap();
        }
        assert_eq!(ct, reference, "encrypting in {enc_chunk}-byte calls");

        for &dec_chunk in &CHUNKINGS {
            let pt = dec_chunked(&mut pinned_decryptor(iv), &ct, dec_chunk);
            assert_eq!(
                pt, plaintext,
                "encrypted in {enc_chunk}-byte calls, decrypted in {dec_chunk}-byte calls"
            );
        }
    }

    // Empty calls anywhere are no-ops.
    let mut e = pinned_encryptor(iv);
    e.do_encrypt(&mut []).unwrap();
    let mut ct = plaintext.clone();
    e.do_encrypt(&mut ct[..5]).unwrap();
    e.do_encrypt(&mut []).unwrap();
    e.do_encrypt(&mut ct[5..]).unwrap();
    e.do_encrypt(&mut []).unwrap();
    assert_eq!(ct, reference, "empty calls must not disturb the state");
}

/// The same equivalence with **real AES**, at all three key lengths.
///
/// `call_chunking_does_not_change_the_result` proves the property over the toy permutation. This
/// repeats it with the cipher the mode is actually used with, so a chunking bug that only appears
/// under a real key schedule cannot hide. The AES coverage elsewhere
/// (`sp800_38a_cfb8_tests.rs`, `acvp_cfb8_tests.rs`) chunks against *published* ciphertext; this is
/// the direct single-call-versus-chunked comparison.
///
/// The message is 171 bytes, which is 21 eight-byte batches and a 3-byte tail, so the chunkings
/// leave the batch loop with a different remainder each time.
#[test]
fn aes_chunking_matches_a_single_call() {
    fn check<P, const KEY_LEN: usize>(name: &str)
    where
        P: ElectronicCodeBook<KEY_LEN, 16>,
    {
        let key_bytes: [u8; KEY_LEN] =
            core::array::from_fn(|i| (i as u8).wrapping_mul(31).wrapping_add(7));
        let key =
            KeyMaterial::<KEY_LEN>::from_bytes_as_type(&key_bytes, KeyType::SymmetricCipherKey)
                .expect("a valid AES key");
        let iv: [u8; 16] = core::array::from_fn(|i| 0xC3 ^ (i as u8));
        let plaintext: Vec<u8> = (0..171).map(|i| (i * 7 + i / 16) as u8).collect();

        let encryptor = || {
            let (enc, got) = Cfb8::<P, Encrypting, KEY_LEN, 16>::do_encrypt_init_rng(
                &key,
                &mut FixedSeedRNG::<16>::new(iv),
            )
            .expect("encrypt init");
            assert_eq!(got, iv, "{name}: the pinned RNG should reproduce the IV");
            enc
        };
        let decryptor = || {
            Cfb8::<P, Decrypting, KEY_LEN, 16>::do_decrypt_init(&key, &iv).expect("decrypt init")
        };

        // The reference: the whole message in one call.
        let mut reference = plaintext.clone();
        encryptor().do_encrypt(&mut reference).expect("one-call encryption");
        assert_ne!(reference, plaintext, "{name}: the data must actually be encrypted");

        // ...and the round trip of that, also in one call.
        let mut back = reference.clone();
        decryptor().do_decrypt(&mut back).expect("one-call decryption");
        assert_eq!(back, plaintext, "{name}: one-call round trip");

        for &enc_chunk in &CHUNKINGS {
            let mut ct = plaintext.clone();
            let mut e = encryptor();
            for piece in ct.chunks_mut(enc_chunk) {
                e.do_encrypt(piece).expect("chunked encryption");
            }
            assert_eq!(ct, reference, "{name}: encrypting in {enc_chunk}-byte calls");

            for &dec_chunk in &CHUNKINGS {
                let mut pt = ct.clone();
                let mut d = decryptor();
                for piece in pt.chunks_mut(dec_chunk) {
                    d.do_decrypt(piece).expect("chunked decryption");
                }
                assert_eq!(
                    pt, plaintext,
                    "{name}: encrypted in {enc_chunk}-byte calls, decrypted in {dec_chunk}-byte calls"
                );
            }
        }
    }

    check::<AES_128, 16>("AES-128");
    check::<AES_192, 24>("AES-192");
    check::<AES_256, 32>("AES-256");
}

/// The pair path in `do_decrypt` must actually be taken.
///
/// [`SwappedPairToy`] returns its two pair results in the wrong order while its single-block method
/// is correct. CFB8 decryption batches through `encrypt_blocks2`, so with this permutation six
/// bytes handed over together come out wrong while the same bytes one at a time come out right.
///
/// Six, not eight: the trait's default `encrypt_blocks8` is four `encrypt_blocks2` calls, so eight
/// bytes would also be wrong and would not distinguish the two paths.
#[test]
fn the_pair_path_is_really_used() {
    let key = toy_key();
    let iv = pinned_iv();
    let plaintext = message(6);

    // The correct toy round-trips.
    let ct = enc(&mut pinned_encryptor(iv), &plaintext);
    assert_eq!(dec(&mut pinned_decryptor(iv), &ct), plaintext);

    // The swapped-pair toy encrypts identically -- CFB8 encryption is serial and never batches.
    let (mut e, _) =
        SwappedCfb8::<Encrypting>::do_encrypt_init_rng(&key, &mut pinned_rng(iv)).unwrap();
    assert_eq!(enc(&mut e, &plaintext), ct, "CFB8 encryption must not use the pair path");

    // ...but decrypting six bytes together must now be wrong, because the pair path is used.
    let mut d = SwappedCfb8::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    assert_ne!(dec(&mut d, &ct), plaintext, "three pairs must go through encrypt_blocks2");

    // One byte at a time avoids the pair path, so it is correct even for this toy.
    let mut d = SwappedCfb8::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    assert_eq!(dec_chunked(&mut d, &ct, 1), plaintext, "the single-byte path must not pair");
}

/// The eight-byte batch path in `do_decrypt` must actually be taken, and only for full eights.
///
/// [`SwappedEightToy`] returns its eight `encrypt_blocks8` results rotated while its pair and
/// single-block methods are correct. So nine bytes handed over together decrypt wrongly (eight
/// batched, then one), while six bytes (pairs) or one at a time decrypt correctly.
#[test]
fn the_eight_byte_path_is_really_used() {
    let key = toy_key();
    let iv = pinned_iv();
    let plaintext = message(9);

    let ct = enc(&mut pinned_encryptor(iv), &plaintext);
    assert_eq!(dec(&mut pinned_decryptor(iv), &ct), plaintext);

    // The rotated-eight toy encrypts identically: CFB8 encryption is serial and never batches.
    let (mut e, _) =
        SwappedEightCfb8::<Encrypting>::do_encrypt_init_rng(&key, &mut pinned_rng(iv)).unwrap();
    assert_eq!(enc(&mut e, &plaintext), ct, "CFB8 encryption must not use the eight path");

    // ...but nine bytes together must now be wrong, because the first eight go through
    // encrypt_blocks8.
    let mut d = SwappedEightCfb8::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    assert_ne!(dec(&mut d, &ct), plaintext, "nine bytes must go through encrypt_blocks8");

    // Six bytes use the pair path only, so they are correct even for this toy...
    let six = &ct[..6];
    let mut d = SwappedEightCfb8::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    assert_eq!(dec(&mut d, six), plaintext[..6], "pairs must not use the eight path");

    // ...and so is one byte at a time.
    let mut d = SwappedEightCfb8::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    assert_eq!(dec_chunked(&mut d, &ct, 1), plaintext, "the single-byte path must not batch");
}

/// The one-shots must produce exactly what the streaming API produces.
#[test]
fn one_shots_agree_with_the_streaming_api() {
    let key = toy_key();
    let iv = pinned_iv();

    for len in [1, 9, 2 * TOY_LEN + 3] {
        let plaintext = message(len);
        let streamed = enc(&mut pinned_encryptor(iv), &plaintext);

        let mut buf = plaintext.clone();
        let iv_b = ToyCfb8::<Encrypting>::encrypt_rng(&key, &mut pinned_rng(iv), &mut buf).unwrap();
        assert_eq!(iv_b, iv);
        assert_eq!(buf, streamed, "len {len}: one-shot must equal streaming");
        ToyCfb8::<Decrypting>::decrypt(&key, &iv, &mut buf).unwrap();
        assert_eq!(buf, plaintext);

        // The OS-RNG variant round-trips too. Whether the ciphertext *differs* from the plaintext
        // is only worth asserting once the message is long enough that coinciding with the
        // keystream by chance is negligible -- see `every_length_round_trips_without_padding`.
        let mut buf = plaintext.clone();
        let iv_fresh = ToyCfb8::<Encrypting>::encrypt(&key, &mut buf).unwrap();
        if len >= 8 {
            assert_ne!(buf, plaintext);
        }
        ToyCfb8::<Decrypting>::decrypt(&key, &iv_fresh, &mut buf).unwrap();
        assert_eq!(buf, plaintext);
    }
}

// ---- SP 800-38A Appendix D error propagation ---------------------------------------------

/// Appendix D, Table D.2 for CFB: a bit error in `Cj` gives "SBE in the decryption of `Cj`" plus
/// "RBE in the decryption of `Cj+1`,...,`Cj+b/s`". With `s = 8` on a 16-byte block, `b/s` is **16**:
/// the flipped bit lands in exactly the byte the attacker aimed at, the next 16 bytes are
/// randomised, and byte 17 onwards is **exactly correct** -- the corrupted byte has been shifted
/// out of the register and decryption has resynchronised.
///
/// That self-synchronisation is the property CFB8 is chosen for, and the exact-equality assertion
/// on the tail is what pins it. Checked with AES-128, because "randomised" is a property of the
/// block cipher's diffusion rather than of the mode, and the byte-local toy cannot show it.
#[test]
fn a_ciphertext_bit_error_damages_exactly_sixteen_following_bytes() {
    type Aes128Cfb8<Dir> = Cfb8<AES_128, Dir, 16, 16>;
    const LEN: usize = 48;

    let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
        .expect("a valid AES-128 key");
    let iv: [u8; 16] = core::array::from_fn(|i| 0x0F ^ (i as u8));
    let plaintext: Vec<u8> = (0..LEN).map(|i| (i * 11 + 3) as u8).collect();

    let mut ct = plaintext.clone();
    let (mut e, got_iv) =
        Aes128Cfb8::<Encrypting>::do_encrypt_init_rng(&key, &mut FixedSeedRNG::<16>::new(iv))
            .unwrap();
    assert_eq!(got_iv, iv);
    e.do_encrypt(&mut ct).unwrap();

    // Byte 8, so there is a clean prefix, a full 16-byte damage window and a clean tail.
    const J: usize = 8;
    for bit in 0..8 {
        let mut corrupt = ct.clone();
        corrupt[J] ^= 1 << bit;

        let mut d = Aes128Cfb8::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
        let mut got = corrupt;
        d.do_decrypt(&mut got).unwrap();

        assert_eq!(&got[..J], &plaintext[..J], "bit {bit}: earlier bytes are unaffected");
        assert_eq!(
            got[J],
            plaintext[J] ^ (1 << bit),
            "bit {bit}: SBE -- exactly the flipped bit, in the targeted byte"
        );
        // The 16 bytes after it are randomised. Asserting each one differs would be a 1-in-256
        // coin flip per byte, so the window is compared as a whole.
        assert_ne!(
            &got[J + 1..J + 1 + 16],
            &plaintext[J + 1..J + 1 + 16],
            "bit {bit}: the next b/s = 16 bytes should be randomised"
        );
        // ...and then it resynchronises, exactly.
        assert_eq!(
            &got[J + 1 + 16..],
            &plaintext[J + 1 + 16..],
            "bit {bit}: byte j + 17 onwards must be exactly right again"
        );
    }
}

/// The same claim in the direction that needs no cipher diffusion, and so holds for *any*
/// permutation: the damage window is bounded by `b/s` segments, and the SBE lands in the targeted
/// byte. With the toy this is exact arithmetic rather than a statistical argument.
#[test]
fn a_ciphertext_bit_error_flips_exactly_that_bit_of_its_own_byte() {
    let iv = pinned_iv();
    let plaintext = message(3 * TOY_LEN);
    let ct = enc(&mut pinned_encryptor(iv), &plaintext);

    for j in [0usize, 1, 5, TOY_LEN, 2 * TOY_LEN] {
        for bit in 0..8 {
            let mut corrupt = ct.clone();
            corrupt[j] ^= 1 << bit;
            let got = dec(&mut pinned_decryptor(iv), &corrupt);

            assert_eq!(&got[..j], &plaintext[..j], "byte {j} bit {bit}: earlier bytes unaffected");
            assert_eq!(
                got[j],
                plaintext[j] ^ (1 << bit),
                "byte {j} bit {bit}: exactly that bit of that byte"
            );
            // Damage cannot reach past b/s = TOY_LEN segments.
            let resync = core::cmp::min(j + 1 + TOY_LEN, plaintext.len());
            assert_eq!(
                &got[resync..],
                &plaintext[resync..],
                "byte {j} bit {bit}: must resynchronise after b/s = {TOY_LEN} segments"
            );
        }
    }
}

// ---- IV handling -------------------------------------------------------------------------

/// Two encryption flows under the same key must not reuse an IV.
#[test]
fn each_encryption_gets_a_fresh_iv() {
    let key = toy_key();
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..64 {
        let (_, iv) = ToyCfb8::<Encrypting>::do_encrypt_init(&key).unwrap();
        assert!(seen.insert(iv), "IV repeated across encryptions: {iv:02x?}");
    }
}

/// Identical plaintext under the same key must give different ciphertext, because the IV differs.
#[test]
fn identical_plaintext_gives_different_ciphertext() {
    let key = toy_key();
    let plaintext = [0x77u8; 2 * TOY_LEN];

    let mut first = plaintext;
    ToyCfb8::<Encrypting>::encrypt(&key, &mut first).unwrap();
    let mut second = plaintext;
    ToyCfb8::<Encrypting>::encrypt(&key, &mut second).unwrap();
    assert_ne!(first, second);

    // ...and, within one message, a run of identical plaintext bytes must not give a run of
    // identical ciphertext bytes: the register changes on every byte. Compared a block at a time
    // rather than byte against byte, because two single bytes coincide once in 256 runs by chance
    // while two 16-byte halves do so once in 2^128.
    assert_ne!(
        first[..TOY_LEN],
        first[TOY_LEN..],
        "the shifting register should break the pattern within a message"
    );
}

// ---- key handling ------------------------------------------------------------------------

#[test]
fn a_key_of_the_wrong_type_is_rejected() {
    let bytes: [u8; TOY_LEN] = core::array::from_fn(|i| (i as u8) + 1);
    let seed = KeyMaterial::<TOY_LEN>::from_bytes_as_type(&bytes, KeyType::Seed).unwrap();
    assert!(ToyCfb8::<Encrypting>::do_encrypt_init(&seed).is_err());
    assert!(ToyCfb8::<Decrypting>::do_decrypt_init(&seed, &[0u8; TOY_LEN]).is_err());
}

// ---- every length, no padding ------------------------------------------------------------

/// CFB8 is a stream cipher with a one-byte segment: every length round-trips, the ciphertext is
/// exactly as long as the plaintext, and no padding layer is involved.
#[test]
fn every_length_round_trips_without_padding() {
    let key = toy_key();
    for len in 0..=(2 * TOY_LEN + 1) {
        let plaintext = message(len);
        let mut data = plaintext.clone();
        let iv = ToyCfb8::<Encrypting>::encrypt(&key, &mut data).expect("encryption");
        assert_eq!(data.len(), len, "len {len}: the ciphertext is as long as the plaintext");
        // Only meaningful once the message is long enough that agreeing with the keystream by
        // chance is negligible: a 1-byte message coincides with its own ciphertext whenever the
        // single keystream byte is zero, which a fresh random IV makes happen about once in 256
        // runs. At 8 bytes the odds are 2^-64. (This is why the assertion is guarded rather than
        // dropped: it is worth making, just not at every length.)
        if len >= 8 {
            assert_ne!(data, plaintext, "len {len}: the data must actually be encrypted");
        }
        ToyCfb8::<Decrypting>::decrypt(&key, &iv, &mut data).expect("decryption");
        assert_eq!(data, plaintext, "len {len}: round trip");
    }
}

// ---- memory ------------------------------------------------------------------------------

/// Pins the "Memory Usage" table in the crate docs, and the claim that CFB8 costs exactly what CBC
/// costs -- one block of shift register and nothing else, since its segment is a single byte and
/// so there is never a partial segment to remember.
#[test]
fn sizes_match_the_documented_memory_table() {
    use core::mem::size_of;

    assert_eq!(size_of::<Cfb8<AES_128, Encrypting, 16, 16>>(), 176 + 16);
    assert_eq!(size_of::<Cfb8<AES_192, Encrypting, 24, 16>>(), 208 + 16);
    assert_eq!(size_of::<Cfb8<AES_256, Encrypting, 32, 16>>(), 240 + 16);

    // The direction marker is free, and does not change the layout.
    assert_eq!(
        size_of::<Cfb8<AES_128, Encrypting, 16, 16>>(),
        size_of::<Cfb8<AES_128, Decrypting, 16, 16>>()
    );

    // ...and the general rule the docs state.
    assert_eq!(size_of::<Cfb8<AES_256, Encrypting, 32, 16>>(), size_of::<AES_256>() + 16);

    // The docs say CFB8 is the same size as CBC, and one `usize` smaller than CFB.
    assert_eq!(
        size_of::<Cfb8<AES_128, Encrypting, 16, 16>>(),
        size_of::<Cbc<AES_128, Encrypting, 16, 16>>()
    );
    assert_eq!(
        size_of::<Cfb8<AES_128, Encrypting, 16, 16>>() + size_of::<usize>(),
        size_of::<Cfb<AES_128, Encrypting, 16, 16>>()
    );
}
