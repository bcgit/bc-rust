//! Structural tests for CTR, driven by a toy permutation.
//!
//! These check the properties of the *mode* -- the counter block construction, the standard
//! incrementing function, the counter limit and its error, call sequencing at arbitrary byte
//! boundaries, the batch paths in both directions, direction typing, and the "forward cipher
//! function only" rule -- independently of any real cipher. The known-answer tests against the NIST
//! ACVP `ACVP-AES-CTR` set are in `acvp_ctr_tests.rs`.
//!
//! The toy's own conformance to [`ElectronicCodeBook`] is pinned once, by
//! `the_toy_permutation_conforms_to_the_trait` in `cbc_tests.rs`; it is the same `Toy` here, so it
//! is not re-run.
//!
//! # Why there is no SP 800-38A Appendix F.5 suite
//!
//! F.5 gives each vector a full 16-byte "Init. Counter" -- `f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff` --
//! whose counter part starts at `0xfcfdfeff`, not at zero. [`Ctr`] takes a *nonce* as its init data
//! and always starts the counter at zero, so those vectors cannot be expressed through its API.
//! What the F.5 counter blocks do confirm is the shape of the split this type uses: across the four
//! blocks they increment only within the last four bytes (`fcfdfeff`, `fcfdff00`, `fcfdff01`,
//! `fcfdff02`), leaving the leading twelve fixed, which is exactly a 12-byte nonce and a 4-byte
//! counter. `the_f5_counter_blocks_have_the_shape_this_type_assumes` pins that reading, and the
//! ACVP suite supplies the actual known-answer coverage.

mod common;

use bouncycastle_aes::{AES_128, AES_192, AES_256};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{ElectronicCodeBook, StreamCipherDecryptor, StreamCipherEncryptor};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_core_test_framework::symmetric_ciphers::TestFrameworkStreamCipher;
use bouncycastle_modes::{Ctr, Decrypting, Encrypting};
use common::{ForwardOnlyToy, SwappedEightToy, SwappedPairToy, TOY_LEN, Toy, toy_key};

/// The default shape under test: a 12-byte nonce, so a 4-byte counter.
const NONCE_LEN: usize = 12;
type ToyCtr<Dir> = Ctr<Toy, Dir, TOY_LEN, TOY_LEN, NONCE_LEN>;
type SwappedCtr<Dir> = Ctr<SwappedPairToy, Dir, TOY_LEN, TOY_LEN, NONCE_LEN>;
type ForwardOnlyCtr<Dir> = Ctr<ForwardOnlyToy, Dir, TOY_LEN, TOY_LEN, NONCE_LEN>;
type SwappedEightCtr<Dir> = Ctr<SwappedEightToy, Dir, TOY_LEN, TOY_LEN, NONCE_LEN>;

/// A 15-byte nonce leaves a **1-byte** counter, so the whole counter space is 256 blocks -- 4 KiB
/// of keystream. That makes the exhaustion behaviour reachable in a test.
const SHORT_CTR_NONCE_LEN: usize = 15;
type TinyCtr<Dir> = Ctr<Toy, Dir, TOY_LEN, TOY_LEN, SHORT_CTR_NONCE_LEN>;
/// Capacity of a 1-byte counter, in bytes.
const TINY_CAPACITY: usize = 256 * TOY_LEN;

fn enc(e: &mut impl StreamCipherEncryptor<TOY_LEN, NONCE_LEN>, plaintext: &[u8]) -> Vec<u8> {
    let mut data = plaintext.to_vec();
    e.do_encrypt(&mut data).unwrap();
    data
}

fn dec(d: &mut impl StreamCipherDecryptor<TOY_LEN, NONCE_LEN>, ciphertext: &[u8]) -> Vec<u8> {
    let mut data = ciphertext.to_vec();
    d.do_decrypt(&mut data).unwrap();
    data
}

fn dec_chunked(
    d: &mut impl StreamCipherDecryptor<TOY_LEN, NONCE_LEN>,
    ciphertext: &[u8],
    chunk: usize,
) -> Vec<u8> {
    let mut data = ciphertext.to_vec();
    for piece in data.chunks_mut(chunk) {
        d.do_decrypt(piece).unwrap();
    }
    data
}

fn pinned_nonce() -> [u8; NONCE_LEN] {
    core::array::from_fn(|i| 0xA0 ^ (i as u8))
}

fn pinned_rng(nonce: [u8; NONCE_LEN]) -> FixedSeedRNG<NONCE_LEN> {
    FixedSeedRNG::<NONCE_LEN>::new(nonce)
}

fn pinned_encryptor(nonce: [u8; NONCE_LEN]) -> ToyCtr<Encrypting> {
    let (e, got) =
        ToyCtr::<Encrypting>::do_encrypt_init_rng(&toy_key(), &mut pinned_rng(nonce)).unwrap();
    assert_eq!(got, nonce, "the pinned RNG should reproduce the nonce");
    e
}

fn pinned_decryptor(nonce: [u8; NONCE_LEN]) -> ToyCtr<Decrypting> {
    ToyCtr::<Decrypting>::do_decrypt_init(&toy_key(), &nonce).unwrap()
}

fn message(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + (i / TOY_LEN) * 31 + 1) as u8).collect()
}

const CHUNKINGS: [usize; 12] = [1, 3, 5, 7, 15, 16, 17, 31, 32, 33, 64, 100];

// ---- the mode against the shared framework ------------------------------------------------

#[test]
fn ctr_conforms_to_the_stream_cipher_framework() {
    TestFrameworkStreamCipher::new()
        .test::<TOY_LEN, NONCE_LEN, ToyCtr<Encrypting>, ToyCtr<Decrypting>>();
}

// ---- the spec equations -------------------------------------------------------------------

/// CTR from SP 800-38A Sec 6.5, written out longhand against the raw permutation:
///
/// ```text
/// Tj = N | [j - 1]m;  Oj = CIPH_K(Tj);  Cj = Pj XOR Oj;  C*_n = P*_n XOR MSB_u(On)
/// ```
///
/// The counter block is built here from scratch on every block, from the nonce and the index, so it
/// is an independent statement of the construction rather than a second call to the same
/// incrementing code the implementation uses.
fn reference_ctr(perm: &Toy, nonce: [u8; NONCE_LEN], input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    for (j, chunk) in input.chunks(TOY_LEN).enumerate() {
        let mut t = [0u8; TOY_LEN];
        t[..NONCE_LEN].copy_from_slice(&nonce);
        t[NONCE_LEN..].copy_from_slice(&(j as u32).to_be_bytes());
        let mut o = t;
        perm.encrypt_block(&mut o); // Oj = CIPH_K(Tj)
        // Cj = Pj XOR Oj, and for a short final block only its leading bytes: MSB_u(On).
        out.extend(chunk.iter().zip(o.iter()).map(|(d, o)| d ^ o));
    }
    out
}

/// The mode must reproduce the Sec 6.5 equations exactly, for whole blocks and for a message ending
/// in a partial block.
///
/// A reference implementation is a weak test on its own, so this also pins the anchors that follow
/// directly from the equations: the first counter block is the nonce with a zero counter, and
/// encrypting zeros reveals the keystream itself.
#[test]
fn the_mode_matches_the_spec_equations() {
    let key = toy_key();
    let nonce = pinned_nonce();
    let perm = <Toy as ElectronicCodeBook<TOY_LEN, TOY_LEN>>::new(&key).unwrap();

    for len in [1, TOY_LEN - 1, TOY_LEN, TOY_LEN + 1, 5 * TOY_LEN, 5 * TOY_LEN + 9] {
        let plaintext = message(len);
        let ct = enc(&mut pinned_encryptor(nonce), &plaintext);
        assert_eq!(
            ct,
            reference_ctr(&perm, nonce, &plaintext),
            "len {len}: encryption must match the Sec 6.5 equations"
        );
        assert_eq!(dec(&mut pinned_decryptor(nonce), &ct), plaintext, "len {len}: round trip");
    }

    // Anchor 1: `T1 = N | 0`, so `O1 = CIPH_K(N | 0)` and encrypting a zero block yields it.
    let mut t1 = [0u8; TOY_LEN];
    t1[..NONCE_LEN].copy_from_slice(&nonce);
    let mut o1 = t1;
    perm.encrypt_block(&mut o1);
    assert_eq!(
        enc(&mut pinned_encryptor(nonce), &[0u8; TOY_LEN]),
        o1.to_vec(),
        "encrypting a zero block yields O1 = CIPH_K(N | 0)"
    );

    // Anchor 2: the cipher never touches the data. The keystream depends only on the key and the
    // counter blocks, so two messages encrypted under the same nonce satisfy
    // `C XOR C' == P XOR P'` -- the defining property of a keystream mode, and the reason a nonce
    // must never repeat. A mode that put the plaintext through the cipher could not satisfy it.
    let p1 = message(3 * TOY_LEN + 4);
    let p2: Vec<u8> = p1.iter().map(|b| b ^ 0x5A).collect();
    let c1 = enc(&mut pinned_encryptor(nonce), &p1);
    let c2 = enc(&mut pinned_encryptor(nonce), &p2);
    let ct_xor: Vec<u8> = c1.iter().zip(c2.iter()).map(|(a, b)| a ^ b).collect();
    let pt_xor: Vec<u8> = p1.iter().zip(p2.iter()).map(|(a, b)| a ^ b).collect();
    assert_eq!(ct_xor, pt_xor, "C XOR C' must equal P XOR P' under a repeated nonce");
}

/// **Encryption and decryption are the same operation** (Sec 6.5): both compute `CIPH_K(Tj)` and
/// XOR it in. Running the encryptor over ciphertext must therefore recover the plaintext, which is
/// the sharpest statement of that property and would fail for every other mode in this crate.
#[test]
fn encryption_and_decryption_are_the_same_operation() {
    let nonce = pinned_nonce();
    let plaintext = message(3 * TOY_LEN + 5);

    let ct = enc(&mut pinned_encryptor(nonce), &plaintext);
    assert_eq!(enc(&mut pinned_encryptor(nonce), &ct), plaintext, "the encryptor decrypts too");
    assert_eq!(dec(&mut pinned_decryptor(nonce), &ct), plaintext, "and so does the decryptor");
}

// ---- the counter ---------------------------------------------------------------------------

/// The counter blocks are the nonce followed by a big-endian counter from zero, incremented by
/// Appendix B.1's standard incrementing function -- **at every permitted counter width**.
///
/// Read out of the keystream rather than out of the mode's private state: encrypting zeros gives
/// `Oj`, and `Oj` must equal `CIPH_K(N | [j]m)` computed independently here from the nonce and the
/// index.
///
/// Running this at all four widths matters more than it looks. The counter occupies the trailing
/// `CTR_LEN` bytes, so writing it involves a width-dependent slice, and getting that wrong is a bug
/// that **round-trip tests cannot see**: encryption and decryption would build the same wrong
/// counter block and still recover the plaintext, while producing ciphertext no other
/// implementation agrees with. Only checking the keystream against an independently built counter
/// block catches it.
///
/// Where the counter is wide enough, the run crosses the 255 -> 256 boundary, which is the carry
/// between counter bytes that a per-byte increment could get wrong.
fn check_counter_blocks<const N: usize>(blocks: usize) {
    const fn ctr_len<const N: usize>() -> usize {
        TOY_LEN - N
    }

    let key = toy_key();
    let perm = <Toy as ElectronicCodeBook<TOY_LEN, TOY_LEN>>::new(&key).unwrap();
    let nonce: [u8; N] = core::array::from_fn(|i| (i as u8).wrapping_mul(13).wrapping_add(5));

    let (mut e, got) = Ctr::<Toy, Encrypting, TOY_LEN, TOY_LEN, N>::do_encrypt_init_rng(
        &key,
        &mut FixedSeedRNG::<N>::new(nonce),
    )
    .unwrap();
    assert_eq!(got, nonce);
    let mut keystream = vec![0u8; blocks * TOY_LEN];
    e.do_encrypt(&mut keystream).expect("the run must fit in the counter space");

    for j in 0..blocks {
        let mut expected = [0u8; TOY_LEN];
        expected[..N].copy_from_slice(&nonce);
        // The counter, big-endian, in the trailing CTR_LEN bytes: the low CTR_LEN bytes of the
        // index written big-endian.
        let be = (j as u64).to_be_bytes();
        expected[N..].copy_from_slice(&be[be.len() - ctr_len::<N>()..]);
        perm.encrypt_block(&mut expected);
        assert_eq!(
            &keystream[j * TOY_LEN..(j + 1) * TOY_LEN],
            &expected[..],
            "counter width {}: block {j} must be CIPH_K(nonce | {j} big-endian)",
            ctr_len::<N>()
        );
    }
}

#[test]
fn counter_blocks_are_the_nonce_then_a_big_endian_counter_from_zero() {
    // A 1-byte counter has exactly 256 blocks, so that is the whole space and there is no internal
    // carry to cross. The wider ones run past 256 so that the 255 -> 256 carry is exercised.
    check_counter_blocks::<15>(256); // 1-byte counter, its entire space
    check_counter_blocks::<14>(258); // 2-byte counter, across the carry
    check_counter_blocks::<13>(258); // 3-byte counter, across the carry
    check_counter_blocks::<12>(258); // 4-byte counter, across the carry
}

/// SP 800-38A Appendix F.5's counter blocks increment only within their last four bytes
/// (`fcfdfeff`, `fcfdff00`, `fcfdff01`, `fcfdff02`), leaving the leading twelve fixed.
///
/// That is the nonce-and-counter split this type is built on, so the spec's own example vectors
/// corroborate the shape even though their non-zero starting counter puts them out of reach of this
/// API. See the module docs.
#[test]
fn the_f5_counter_blocks_have_the_shape_this_type_assumes() {
    /// F.5.1 CTR-AES128.Encrypt, the four tabulated "Input Block" values.
    const F5_COUNTER_BLOCKS: [[u8; 16]; 4] = [
        [
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
            0xfe, 0xff,
        ],
        [
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
            0xff, 0x00,
        ],
        [
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
            0xff, 0x01,
        ],
        [
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
            0xff, 0x02,
        ],
    ];

    // The leading 12 bytes are identical in all four: that is the nonce.
    for (i, block) in F5_COUNTER_BLOCKS.iter().enumerate() {
        assert_eq!(
            &block[..12],
            &F5_COUNTER_BLOCKS[0][..12],
            "F.5 block {i}: the leading 12 bytes must be fixed, i.e. a nonce"
        );
    }

    // ...and the trailing 4 are a big-endian counter incremented by one each time, carrying.
    for (i, block) in F5_COUNTER_BLOCKS.iter().enumerate() {
        let counter = u32::from_be_bytes(block[12..].try_into().unwrap());
        let first = u32::from_be_bytes(F5_COUNTER_BLOCKS[0][12..].try_into().unwrap());
        assert_eq!(
            counter,
            first.wrapping_add(i as u32),
            "F.5 block {i}: the trailing 4 bytes must be the counter, incremented by one"
        );
    }
}

/// The mode must **error** rather than let the counter repeat, and it must do so without consuming
/// anything.
///
/// Appendix B.1: counter blocks satisfy the uniqueness requirement "provided that `n <= 2^m`". With
/// a 1-byte counter that is 256 blocks, so exactly 4 KiB of keystream is available; the byte after
/// that would reuse `T1` and hence `O1`, which is keystream reuse within one message.
///
/// `the_counter_limit_is_enforced_at_two_bytes_too` repeats the boundary one width up, where the
/// limit is 65536 blocks rather than 256, so the check is not tied to the one width whose counter
/// happens to be a single byte.
#[test]
fn the_counter_limit_is_enforced() {
    let key = toy_key();
    let nonce: [u8; SHORT_CTR_NONCE_LEN] = core::array::from_fn(|i| 0x5A ^ (i as u8));

    let encryptor = || {
        let (e, got) = TinyCtr::<Encrypting>::do_encrypt_init_rng(
            &key,
            &mut FixedSeedRNG::<SHORT_CTR_NONCE_LEN>::new(nonce),
        )
        .unwrap();
        assert_eq!(got, nonce);
        e
    };

    // Exactly the capacity is allowed, in one call.
    let mut data = vec![0u8; TINY_CAPACITY];
    encryptor().do_encrypt(&mut data).expect("the full counter space must be usable");

    // One byte more is refused.
    let mut data = vec![0u8; TINY_CAPACITY + 1];
    match encryptor().do_encrypt(&mut data) {
        Err(SymmetricCipherError::StateError(msg)) => {
            assert!(msg.contains("counter"), "the error should name the counter: {msg}");
        }
        other => panic!("expected a StateError past the counter limit, got {other:?}"),
    }
    assert_eq!(data, vec![0u8; TINY_CAPACITY + 1], "a refused call must not touch the data");

    // The same limit reached across many calls, not just one.
    let mut e = encryptor();
    let mut sixteenth = vec![0u8; TINY_CAPACITY / 16];
    for i in 0..16 {
        e.do_encrypt(&mut sixteenth).unwrap_or_else(|err| panic!("call {i} should fit: {err:?}"));
    }
    let mut one = [0u8; 1];
    assert!(e.do_encrypt(&mut one).is_err(), "the next byte must be refused");
    assert_eq!(one, [0u8; 1], "a refused call must not touch the data");

    // ...and a refused call must not disturb the state either: the mode is exhausted, so it stays
    // exhausted, and a smaller call is refused too rather than silently wrapping.
    let mut one = [0u8; 1];
    assert!(e.do_encrypt(&mut one).is_err(), "still exhausted on a second attempt");

    // A call refused part-way through the counter space leaves the state untouched, so the bytes
    // that *do* fit are unchanged by the attempt.
    let mut e = encryptor();
    let mut half = vec![0u8; TINY_CAPACITY / 2];
    e.do_encrypt(&mut half).unwrap();
    let mut too_big = vec![0u8; TINY_CAPACITY]; // more than the half that is left
    assert!(e.do_encrypt(&mut too_big).is_err(), "must refuse what does not fit");
    assert_eq!(too_big, vec![0u8; TINY_CAPACITY], "refused call must not touch the data");
    // The remaining half still encrypts, and to exactly what an uninterrupted run would give.
    let mut rest = vec![0u8; TINY_CAPACITY / 2];
    e.do_encrypt(&mut rest).expect("the untouched remainder must still be usable");
    let mut whole = vec![0u8; TINY_CAPACITY];
    encryptor().do_encrypt(&mut whole).unwrap();
    assert_eq!(
        &rest[..],
        &whole[TINY_CAPACITY / 2..],
        "the refused call must not have advanced the counter"
    );
}

/// The same boundary with a **2-byte** counter: 65536 blocks, so 1 MiB exactly.
///
/// Cheap enough to run, and it shows the limit tracks the counter width rather than being a
/// property of the one-byte case. Three and four byte counters put the boundary at 256 MiB and
/// 64 GiB, which is why they are not tested here; the width-generic capacity arithmetic is shared,
/// and `check_counter_blocks` pins the counter construction at all four widths.
#[test]
fn the_counter_limit_is_enforced_at_two_bytes_too() {
    const NONCE: usize = 14;
    const CAPACITY: usize = 65536 * TOY_LEN;
    let key = toy_key();
    let nonce: [u8; NONCE] = core::array::from_fn(|i| 0x3C ^ (i as u8));

    let encryptor = || {
        let (e, got) = Ctr::<Toy, Encrypting, TOY_LEN, TOY_LEN, NONCE>::do_encrypt_init_rng(
            &key,
            &mut FixedSeedRNG::<NONCE>::new(nonce),
        )
        .unwrap();
        assert_eq!(got, nonce);
        e
    };

    let mut data = vec![0u8; CAPACITY];
    encryptor().do_encrypt(&mut data).expect("the full 2-byte counter space must be usable");

    let mut data = vec![0u8; CAPACITY + 1];
    assert!(encryptor().do_encrypt(&mut data).is_err(), "one byte past the limit must be refused");
    assert_eq!(data, vec![0u8; CAPACITY + 1], "a refused call must not touch the data");
}

/// The decryptor enforces the same limit: a ciphertext longer than the counter can cover is refused
/// rather than decrypted with repeated keystream.
#[test]
fn the_counter_limit_is_enforced_when_decrypting_too() {
    let key = toy_key();
    let nonce: [u8; SHORT_CTR_NONCE_LEN] = core::array::from_fn(|i| 0x5A ^ (i as u8));
    let mut d = TinyCtr::<Decrypting>::do_decrypt_init(&key, &nonce).unwrap();
    let mut data = vec![0u8; TINY_CAPACITY + 1];
    assert!(d.do_decrypt(&mut data).is_err(), "decryption must refuse past the counter limit");
    assert_eq!(data, vec![0u8; TINY_CAPACITY + 1], "a refused call must not touch the data");
}

// ---- the forward-cipher-only rule ---------------------------------------------------------

/// CTR applies `CIPH_K` to counter blocks in both directions and never inverts anything, so neither
/// direction may reach the inverse cipher. [`ForwardOnlyToy`] panics from every inverse entry point.
#[test]
fn neither_direction_uses_the_inverse_cipher() {
    let key = toy_key();
    let nonce = pinned_nonce();
    let plaintext = message(11 * TOY_LEN + 5);

    let (mut e, _) = ForwardOnlyCtr::<Encrypting>::do_encrypt_init_rng(
        &key,
        &mut FixedSeedRNG::<NONCE_LEN>::new(nonce),
    )
    .unwrap();
    let mut ct = plaintext.clone();
    e.do_encrypt(&mut ct).unwrap();

    let mut d = ForwardOnlyCtr::<Decrypting>::do_decrypt_init(&key, &nonce).unwrap();
    let mut back = ct.clone();
    d.do_decrypt(&mut back).unwrap();
    assert_eq!(back, plaintext, "all paths, forward cipher only");

    // Byte by byte, so the single-block path runs too.
    let mut d = ForwardOnlyCtr::<Decrypting>::do_decrypt_init(&key, &nonce).unwrap();
    let mut back = ct.clone();
    for piece in back.chunks_mut(1) {
        d.do_decrypt(piece).unwrap();
    }
    assert_eq!(back, plaintext, "byte path, forward cipher only");

    // The forward-only toy must agree with the real one, or the above proves nothing.
    assert_eq!(enc(&mut pinned_encryptor(nonce), &plaintext), ct, "the two toys must agree");
}

// ---- call sequencing -----------------------------------------------------------------------

/// Chunking must not change the result, in either direction, at byte granularity -- and every
/// encrypt chunking must decrypt under every decrypt chunking.
#[test]
fn call_chunking_does_not_change_the_result() {
    let nonce = pinned_nonce();
    let plaintext = message(10 * TOY_LEN + 11);

    let reference = enc(&mut pinned_encryptor(nonce), &plaintext);
    assert_eq!(dec(&mut pinned_decryptor(nonce), &reference), plaintext);

    for &enc_chunk in &CHUNKINGS {
        let mut ct = plaintext.clone();
        let mut e = pinned_encryptor(nonce);
        for piece in ct.chunks_mut(enc_chunk) {
            e.do_encrypt(piece).unwrap();
        }
        assert_eq!(ct, reference, "encrypting in {enc_chunk}-byte calls");

        for &dec_chunk in &CHUNKINGS {
            assert_eq!(
                dec_chunked(&mut pinned_decryptor(nonce), &ct, dec_chunk),
                plaintext,
                "encrypted in {enc_chunk}-byte calls, decrypted in {dec_chunk}-byte calls"
            );
        }
    }

    // Empty calls anywhere are no-ops, including mid-block.
    let mut e = pinned_encryptor(nonce);
    e.do_encrypt(&mut []).unwrap();
    let mut ct = plaintext.clone();
    e.do_encrypt(&mut ct[..5]).unwrap();
    e.do_encrypt(&mut []).unwrap();
    e.do_encrypt(&mut ct[5..]).unwrap();
    assert_eq!(ct, reference, "empty calls must not disturb the state");
}

/// The same equivalence with **real AES**, at all three key lengths, as for the other stream modes.
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
        let nonce: [u8; 12] = core::array::from_fn(|i| 0xC3 ^ (i as u8));
        let plaintext: Vec<u8> = (0..171).map(|i| (i * 7 + i / 16) as u8).collect();

        let encryptor = || {
            let (e, got) = Ctr::<P, Encrypting, KEY_LEN, 16, 12>::do_encrypt_init_rng(
                &key,
                &mut FixedSeedRNG::<12>::new(nonce),
            )
            .expect("encrypt init");
            assert_eq!(got, nonce, "{name}: the pinned RNG should reproduce the nonce");
            e
        };
        let decryptor = || {
            Ctr::<P, Decrypting, KEY_LEN, 16, 12>::do_decrypt_init(&key, &nonce)
                .expect("decrypt init")
        };

        let mut reference = plaintext.clone();
        encryptor().do_encrypt(&mut reference).expect("one-call encryption");
        assert_ne!(reference, plaintext, "{name}: the data must actually be encrypted");

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
                    "{name}: encrypted in {enc_chunk}-byte, decrypted in {dec_chunk}-byte calls"
                );
            }
        }
    }

    check::<AES_128, 16>("AES-128");
    check::<AES_192, 24>("AES-192");
    check::<AES_256, 32>("AES-256");
}

/// The pair path must be taken, **in both directions** -- unlike CBC and CFB, CTR encryption
/// batches too, because counter blocks do not depend on cipher output (Sec 6.5).
#[test]
fn the_pair_path_is_really_used_in_both_directions() {
    let key = toy_key();
    let nonce = pinned_nonce();
    let plaintext = message(2 * TOY_LEN);

    let ct = enc(&mut pinned_encryptor(nonce), &plaintext);
    assert_eq!(dec(&mut pinned_decryptor(nonce), &ct), plaintext);

    // Encryption: two blocks together must go through encrypt_2blocks, so the swapped toy differs.
    let (mut e, _) =
        SwappedCtr::<Encrypting>::do_encrypt_init_rng(&key, &mut pinned_rng(nonce)).unwrap();
    let mut swapped = plaintext.clone();
    e.do_encrypt(&mut swapped).unwrap();
    assert_ne!(swapped, ct, "CTR encryption must use the pair path");

    // ...but one block at a time avoids it, and then it agrees with the correct toy.
    let (mut e, _) =
        SwappedCtr::<Encrypting>::do_encrypt_init_rng(&key, &mut pinned_rng(nonce)).unwrap();
    let mut single = plaintext.clone();
    for piece in single.chunks_mut(TOY_LEN) {
        e.do_encrypt(piece).unwrap();
    }
    assert_eq!(single, ct, "the single-block path must not pair");

    // Decryption: the same, on the correct ciphertext.
    let mut d = SwappedCtr::<Decrypting>::do_decrypt_init(&key, &nonce).unwrap();
    let mut back = ct.clone();
    d.do_decrypt(&mut back).unwrap();
    assert_ne!(back, plaintext, "CTR decryption must use the pair path");
}

/// The eight-block path must be taken, in both directions, and only for full eights.
#[test]
fn the_eight_block_path_is_really_used_in_both_directions() {
    let key = toy_key();
    let nonce = pinned_nonce();
    let plaintext = message(9 * TOY_LEN);

    let ct = enc(&mut pinned_encryptor(nonce), &plaintext);

    let (mut e, _) =
        SwappedEightCtr::<Encrypting>::do_encrypt_init_rng(&key, &mut pinned_rng(nonce)).unwrap();
    let mut swapped = plaintext.clone();
    e.do_encrypt(&mut swapped).unwrap();
    assert_ne!(swapped, ct, "nine blocks must go through encrypt_blocks8");

    // Four blocks at a time uses pairs only, so the rotated-eight toy is correct there.
    let (mut e, _) =
        SwappedEightCtr::<Encrypting>::do_encrypt_init_rng(&key, &mut pinned_rng(nonce)).unwrap();
    let mut fours = plaintext.clone();
    for piece in fours.chunks_mut(4 * TOY_LEN) {
        e.do_encrypt(piece).unwrap();
    }
    assert_eq!(fours, ct, "fours must not use the eight path");

    let mut d = SwappedEightCtr::<Decrypting>::do_decrypt_init(&key, &nonce).unwrap();
    let mut back = ct.clone();
    d.do_decrypt(&mut back).unwrap();
    assert_ne!(back, plaintext, "decryption must batch eights too");
}

// ---- nonce handling ------------------------------------------------------------------------

/// Two encryption flows under the same key must not reuse a nonce. For CTR this is the whole
/// security argument: a repeated nonce repeats the counter blocks and so the keystream.
#[test]
fn each_encryption_gets_a_fresh_nonce() {
    let key = toy_key();
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..64 {
        let (_, nonce) = ToyCtr::<Encrypting>::do_encrypt_init(&key).unwrap();
        assert!(seen.insert(nonce), "nonce repeated across encryptions: {nonce:02x?}");
    }
}

#[test]
fn identical_plaintext_gives_different_ciphertext() {
    let key = toy_key();
    let plaintext = [0x77u8; 2 * TOY_LEN];

    let mut first = plaintext;
    ToyCtr::<Encrypting>::encrypt(&key, &mut first).unwrap();
    let mut second = plaintext;
    ToyCtr::<Encrypting>::encrypt(&key, &mut second).unwrap();
    assert_ne!(first, second);

    // ...and two identical plaintext blocks within one message differ, because the counter moves.
    assert_ne!(first[..TOY_LEN], first[TOY_LEN..], "the counter should change the keystream");
}

// ---- key handling --------------------------------------------------------------------------

#[test]
fn a_key_of_the_wrong_type_is_rejected() {
    let bytes: [u8; TOY_LEN] = core::array::from_fn(|i| (i as u8) + 1);
    let seed = KeyMaterial::<TOY_LEN>::from_bytes_as_type(&bytes, KeyType::Seed).unwrap();
    assert!(ToyCtr::<Encrypting>::do_encrypt_init(&seed).is_err());
    assert!(ToyCtr::<Decrypting>::do_decrypt_init(&seed, &[0u8; NONCE_LEN]).is_err());
}

// ---- every length --------------------------------------------------------------------------

/// CTR is a stream cipher: every length round-trips and the ciphertext is exactly as long as the
/// plaintext.
#[test]
fn every_length_round_trips_without_padding() {
    let key = toy_key();
    for len in 0..=(3 * TOY_LEN + 1) {
        let plaintext = message(len);
        let mut data = plaintext.clone();
        let nonce = ToyCtr::<Encrypting>::encrypt(&key, &mut data).expect("encryption");
        assert_eq!(data.len(), len, "len {len}: the ciphertext is as long as the plaintext");
        if len >= 8 {
            assert_ne!(data, plaintext, "len {len}: the data must actually be encrypted");
        }
        ToyCtr::<Decrypting>::decrypt(&key, &nonce, &mut data).expect("decryption");
        assert_eq!(data, plaintext, "len {len}: round trip");
    }
}

// ---- nonce lengths -------------------------------------------------------------------------

/// Every permitted nonce length works and gives a different counter width. 12, 13, 14 and 15 bytes
/// on a 16-byte block are counters of 4, 3, 2 and 1 bytes; a 16-byte nonce (no counter) and an
/// 11-byte one (a 5-byte counter) are compile errors, so they cannot be tested here.
#[test]
fn every_permitted_nonce_length_works() {
    fn round_trip<const N: usize>() {
        let key = toy_key();
        let nonce: [u8; N] = core::array::from_fn(|i| (i as u8).wrapping_mul(11).wrapping_add(3));
        let plaintext = (0..100u8).collect::<Vec<u8>>();

        let (mut e, got) = Ctr::<Toy, Encrypting, TOY_LEN, TOY_LEN, N>::do_encrypt_init_rng(
            &key,
            &mut FixedSeedRNG::<N>::new(nonce),
        )
        .unwrap();
        assert_eq!(got, nonce);
        let mut ct = plaintext.clone();
        e.do_encrypt(&mut ct).unwrap();
        assert_ne!(ct, plaintext, "nonce length {N}: must actually encrypt");

        Ctr::<Toy, Decrypting, TOY_LEN, TOY_LEN, N>::decrypt(&key, &nonce, &mut ct).unwrap();
        assert_eq!(ct, plaintext, "nonce length {N}: round trip");
    }

    round_trip::<12>();
    round_trip::<13>();
    round_trip::<14>();
    round_trip::<15>();
}

// ---- memory ---------------------------------------------------------------------------------

/// Pins the "Memory Usage" table in the crate docs.
#[test]
fn sizes_match_the_documented_memory_table() {
    use core::mem::size_of;

    // permutation + nonce + counter (u64) + keystream block + the used offset, rounded up to the
    // u64's alignment. For a 12-byte nonce on AES that is 176/208/240 + 12 + 8 + 16 + 8 = 220/252/284,
    // padded to 224/256/288.
    assert_eq!(size_of::<Ctr<AES_128, Encrypting, 16, 16, 12>>(), 224);
    assert_eq!(size_of::<Ctr<AES_192, Encrypting, 24, 16, 12>>(), 256);
    assert_eq!(size_of::<Ctr<AES_256, Encrypting, 32, 16, 12>>(), 288);

    // The direction marker is free, and the nonce length does not change the layout: the counter
    // block is always a whole block.
    assert_eq!(
        size_of::<Ctr<AES_128, Encrypting, 16, 16, 12>>(),
        size_of::<Ctr<AES_128, Decrypting, 16, 16, 12>>()
    );
    // A longer nonce fits in the same padding, so the total is unchanged.
    assert_eq!(
        size_of::<Ctr<AES_128, Encrypting, 16, 16, 12>>(),
        size_of::<Ctr<AES_128, Encrypting, 16, 16, 15>>()
    );
}
