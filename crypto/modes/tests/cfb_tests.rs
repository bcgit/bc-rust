//! Structural tests for CFB, driven by a toy permutation.
//!
//! These check the properties of the *mode* -- the keystream construction, chaining, call
//! sequencing at arbitrary byte boundaries, the short final segment, the pair/eight-block split on
//! the decrypt side, direction typing, SP 800-38A Appendix D error propagation, and the "forward
//! cipher function only" rule of Sec 6.3 -- independently of any real cipher. The known-answer
//! tests against SP 800-38A Appendix F.3.13-F.3.18 are in `sp800_38a_cfb_tests.rs`, and the ACVP
//! CFB128 set is in `acvp_cfb_tests.rs`.
//!
//! The toy's own conformance to [`ElectronicCodeBook`] is pinned once, by
//! `the_toy_permutation_conforms_to_the_trait` in `cbc_tests.rs`; it is the same `Toy` here, so it
//! is not re-run.

mod common;

use bouncycastle_aes::{AES_128, AES_192, AES_256};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{
    BlockCipherEncryptor, ElectronicCodeBook, StreamCipherDecryptor, StreamCipherEncryptor,
};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_core_test_framework::symmetric_ciphers::TestFrameworkStreamCipher;
use bouncycastle_modes::{Cbc, Cfb, Decrypting, Encrypting};
use common::{ForwardOnlyToy, SwappedEightToy, SwappedPairToy, TOY_LEN, Toy, toy_key};

type ToyCfb<Dir> = Cfb<Toy, Dir, TOY_LEN, TOY_LEN>;
type SwappedCfb<Dir> = Cfb<SwappedPairToy, Dir, TOY_LEN, TOY_LEN>;
type ForwardOnlyCfb<Dir> = Cfb<ForwardOnlyToy, Dir, TOY_LEN, TOY_LEN>;
type SwappedEightCfb<Dir> = Cfb<SwappedEightToy, Dir, TOY_LEN, TOY_LEN>;

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

/// `do_encrypt` in `chunk`-byte calls, by value. The last call may be shorter.
fn enc_chunked(
    e: &mut impl StreamCipherEncryptor<TOY_LEN, TOY_LEN>,
    plaintext: &[u8],
    chunk: usize,
) -> Vec<u8> {
    let mut data = plaintext.to_vec();
    for piece in data.chunks_mut(chunk) {
        e.do_encrypt(piece).unwrap();
    }
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

fn pinned_encryptor(iv: [u8; TOY_LEN]) -> ToyCfb<Encrypting> {
    let (enc, got) = ToyCfb::<Encrypting>::do_encrypt_init_rng(&toy_key(), &mut pinned_rng(iv))
        .expect("encrypt init");
    assert_eq!(got, iv, "the pinned RNG should reproduce the IV");
    enc
}

fn pinned_decryptor(iv: [u8; TOY_LEN]) -> ToyCfb<Decrypting> {
    ToyCfb::<Decrypting>::do_decrypt_init(&toy_key(), &iv).expect("decrypt init")
}

/// A test message of `len` bytes with no repeating structure at the block size.
fn message(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + (i / TOY_LEN) * 31 + 1) as u8).collect()
}

/// The chunk sizes every "chunking must not matter" test uses: below, at, just either side of, and
/// well above the block, plus primes that never line up with it.
const CHUNKINGS: [usize; 12] = [1, 3, 5, 7, 15, 16, 17, 31, 32, 33, 64, 100];

// ---- the mode against the shared framework ------------------------------------------------

#[test]
fn cfb_conforms_to_the_stream_cipher_framework() {
    TestFrameworkStreamCipher::new()
        .test::<TOY_LEN, TOY_LEN, ToyCfb<Encrypting>, ToyCfb<Decrypting>>();
}

// ---- the spec equations -------------------------------------------------------------------

/// CFB with `s = b` from SP 800-38A Sec 6.3, written out longhand against the raw permutation:
///
/// ```text
/// I1 = IV;  Ij = C_{j-1} (j >= 2);  Oj = CIPH_K(Ij);  Cj = Pj XOR Oj
/// ```
///
/// extended to a message that is not a whole number of blocks by the rule in the [`Cfb`] docs: the
/// last `r` bytes are a short segment, `C#_n = P#_n XOR MSB_{8r}(On)`, and no input block is formed
/// after it.
///
/// This is the independent reference the mode is checked against below. It uses only
/// [`ElectronicCodeBook::encrypt_block`], because that is all the spec calls for.
fn reference_cfb(perm: &Toy, iv: [u8; TOY_LEN], input: &[u8], encrypt: bool) -> Vec<u8> {
    let mut chain = iv; // I1 = IV
    let mut out = Vec::with_capacity(input.len());
    for segment in input.chunks(TOY_LEN) {
        let mut o = chain;
        perm.encrypt_block(&mut o); // Oj = CIPH_K(Ij)
        // C#_j = P#_j XOR MSB_s(Oj): a whole block, or the leading bytes of Oj for a short segment.
        let result: Vec<u8> = segment.iter().zip(o.iter()).map(|(d, o)| d ^ o).collect();
        if segment.len() == TOY_LEN {
            // I_{j+1} is always the *ciphertext* block, whichever direction we are going.
            let cj = if encrypt { &result[..] } else { segment };
            chain.copy_from_slice(cj);
        }
        out.extend_from_slice(&result);
    }
    out
}

/// The mode must reproduce the Sec 6.3 equations exactly, in both directions, for whole blocks and
/// for a message ending in a short segment.
///
/// A reference implementation is a weak test on its own -- both could be wrong the same way -- so
/// this also pins the two anchors that follow directly from the equations and that no plausible
/// mistake preserves: `C1 = P1 XOR CIPH_K(IV)`, and encrypting an all-zero block reveals the
/// keystream block itself.
#[test]
fn the_mode_matches_the_spec_equations() {
    let key = toy_key();
    let iv = pinned_iv();
    let perm = <Toy as ElectronicCodeBook<TOY_LEN, TOY_LEN>>::new(&key).unwrap();

    for len in [5 * TOY_LEN, 5 * TOY_LEN + 9, TOY_LEN - 1, 1] {
        let plaintext = message(len);

        let ct = enc(&mut pinned_encryptor(iv), &plaintext);
        assert_eq!(
            ct,
            reference_cfb(&perm, iv, &plaintext, true),
            "len {len}: encryption must match the Sec 6.3 equations"
        );

        let recovered = dec(&mut pinned_decryptor(iv), &ct);
        assert_eq!(recovered, plaintext, "len {len}: round trip");
        assert_eq!(
            recovered,
            reference_cfb(&perm, iv, &ct, false),
            "len {len}: decryption must match the Sec 6.3 equations"
        );
    }

    let plaintext = message(3 * TOY_LEN);
    let ct = enc(&mut pinned_encryptor(iv), &plaintext);

    // Anchor 1: `O1 = CIPH_K(IV)` and `C1 = P1 XOR O1`.
    let mut o1 = iv;
    perm.encrypt_block(&mut o1);
    let expected_c1: Vec<u8> =
        plaintext[..TOY_LEN].iter().zip(o1.iter()).map(|(p, o)| p ^ o).collect();
    assert_eq!(&ct[..TOY_LEN], &expected_c1[..], "C1 = P1 XOR CIPH_K(IV)");

    // Anchor 2: with `P1 = 0`, `C1 = O1`. CFB is a keystream mode, and this is what that means.
    assert_eq!(
        enc(&mut pinned_encryptor(iv), &[0u8; TOY_LEN]),
        &o1[..],
        "encrypting zero yields the keystream"
    );

    // ...and CFB is not CBC: CBC computes `CIPH_K(P1 XOR IV)`, CFB computes `P1 XOR CIPH_K(IV)`.
    let (mut cbc, _) =
        Cbc::<Toy, Encrypting, TOY_LEN, TOY_LEN>::do_encrypt_init_rng(&key, &mut pinned_rng(iv))
            .unwrap();
    let mut cbc_c1: [u8; TOY_LEN] = plaintext[..TOY_LEN].try_into().unwrap();
    cbc.do_encrypt(&mut cbc_c1).unwrap();
    assert_ne!(&cbc_c1[..], &ct[..TOY_LEN], "CFB must not agree with CBC");
}

// ---- the short final segment --------------------------------------------------------------

/// A message that is not a whole number of blocks ends in a short segment, and its ciphertext is
/// the plaintext XOR the *leading* bytes of the output block -- `MSB_{8r}(On)` -- for every `r`.
///
/// Checked at the first segment (against `CIPH_K(IV)`) and after two whole blocks (against
/// `CIPH_K(C2)`), so both the "only segment" and "final segment" cases are covered.
#[test]
fn the_final_short_segment_is_xored_with_the_leading_keystream_bytes() {
    let key = toy_key();
    let iv = pinned_iv();
    let perm = <Toy as ElectronicCodeBook<TOY_LEN, TOY_LEN>>::new(&key).unwrap();

    let mut o1 = iv;
    perm.encrypt_block(&mut o1);

    let two_blocks = message(2 * TOY_LEN);
    let two_blocks_ct = enc(&mut pinned_encryptor(iv), &two_blocks);
    let mut o3: [u8; TOY_LEN] = two_blocks_ct[TOY_LEN..].try_into().unwrap();
    perm.encrypt_block(&mut o3);

    for r in 1..TOY_LEN {
        // The only segment.
        let short = message(r);
        let ct = enc(&mut pinned_encryptor(iv), &short);
        let expected: Vec<u8> = short.iter().zip(o1.iter()).map(|(p, o)| p ^ o).collect();
        assert_eq!(ct, expected, "r = {r}: C#_1 = P#_1 XOR MSB(O1)");
        assert_eq!(dec(&mut pinned_decryptor(iv), &ct), short, "r = {r}: round trip");

        // The final segment after two whole blocks.
        let mut long = two_blocks.clone();
        long.extend_from_slice(&message(2 * TOY_LEN + r)[2 * TOY_LEN..]);
        let ct = enc(&mut pinned_encryptor(iv), &long);
        assert_eq!(
            &ct[..2 * TOY_LEN],
            &two_blocks_ct[..],
            "r = {r}: the whole blocks are unchanged"
        );
        let expected: Vec<u8> =
            long[2 * TOY_LEN..].iter().zip(o3.iter()).map(|(p, o)| p ^ o).collect();
        assert_eq!(&ct[2 * TOY_LEN..], &expected[..], "r = {r}: C#_3 = P#_3 XOR MSB(O3)");
        assert_eq!(dec(&mut pinned_decryptor(iv), &ct), long, "r = {r}: round trip");
    }
}

/// A stream cipher's ciphertext for a prefix of the message is the prefix of the ciphertext: the
/// bytes after position `k` cannot influence the bytes before it. For CFB that follows from the
/// equations -- `Oj` depends only on `C_{j-1}` -- and it is what makes the short final segment
/// well defined: truncating the message truncates the ciphertext, nothing more.
#[test]
fn the_ciphertext_of_a_prefix_is_a_prefix_of_the_ciphertext() {
    let iv = pinned_iv();
    let plaintext = message(4 * TOY_LEN + 3);
    let full = enc(&mut pinned_encryptor(iv), &plaintext);

    for k in 0..=plaintext.len() {
        let ct = enc(&mut pinned_encryptor(iv), &plaintext[..k]);
        assert_eq!(&ct[..], &full[..k], "encrypting the first {k} bytes");
        let pt = dec(&mut pinned_decryptor(iv), &full[..k]);
        assert_eq!(&pt[..], &plaintext[..k], "decrypting the first {k} bytes");
    }
}

// ---- the forward-cipher-only rule ---------------------------------------------------------

/// SP 800-38A Sec 6.3: "The *forward cipher* function is applied to each input block to produce the
/// output blocks" -- in CFB *decryption* as well as encryption.
///
/// [`ForwardOnlyToy`] panics from `decrypt_block`, `decrypt_blocks2` and `decrypt_blocks8`, so this
/// test fails loudly if either direction of the mode ever reaches the inverse cipher. Every
/// decrypt path is exercised -- the eight-block, pair, single-block and byte paths -- and the result
/// is required to agree with the plain [`Toy`], otherwise the test could pass by not really
/// encrypting anything.
#[test]
fn neither_direction_uses_the_inverse_cipher() {
    let key = toy_key();
    let iv = pinned_iv();
    let plaintext = message(11 * TOY_LEN + 5);

    let (mut e, _) =
        ForwardOnlyCfb::<Encrypting>::do_encrypt_init_rng(&key, &mut pinned_rng(iv)).unwrap();
    let ct = enc(&mut e, &plaintext);

    // One call: eight blocks, then a pair, then a single, then the short segment.
    let mut d = ForwardOnlyCfb::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    assert_eq!(dec(&mut d, &ct), plaintext, "all paths, forward cipher only");

    // Byte by byte: the byte path only.
    let mut d = ForwardOnlyCfb::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    assert_eq!(dec_chunked(&mut d, &ct, 1), plaintext, "byte path, forward cipher only");

    // The forward-only toy must agree with the real one, or the above proves nothing.
    assert_eq!(
        enc(&mut pinned_encryptor(iv), &plaintext),
        ct,
        "the two toys must agree going forward"
    );
}

/// The decryptor must feed the **ciphertext** back, not the plaintext it just recovered.
///
/// Getting this wrong is invisible in the first block -- `O1 = CIPH_K(IV)` either way -- and wrong
/// from the second onwards. An encryptor run over ciphertext is exactly that mistake: it XORs the
/// right keystream into block 1 and then chains on its own output. So block 1 agreeing while
/// block 2 disagrees is the signature of the bug, and is what this asserts -- once for whole-block
/// calls and once byte by byte, since the two paths feed back separately.
#[test]
fn the_decryptor_chains_on_ciphertext_not_plaintext() {
    let iv = pinned_iv();
    let plaintext = message(3 * TOY_LEN);
    let ct = enc(&mut pinned_encryptor(iv), &plaintext);
    assert_ne!(
        &ct[..TOY_LEN],
        &plaintext[..TOY_LEN],
        "the two feedback choices must actually differ here"
    );

    for chunk in [3 * TOY_LEN, 1] {
        let wrong = enc_chunked(&mut pinned_encryptor(iv), &ct, chunk);
        assert_eq!(
            &wrong[..TOY_LEN],
            &plaintext[..TOY_LEN],
            "chunk {chunk}: block 1 cannot tell the two apart"
        );
        assert_ne!(
            &wrong[TOY_LEN..2 * TOY_LEN],
            &plaintext[TOY_LEN..2 * TOY_LEN],
            "chunk {chunk}: block 2 must, so the feedback source is pinned"
        );
    }
}

// ---- chaining and call sequencing --------------------------------------------------------

/// Encrypting a message must not depend on how the calls are chunked, and likewise for decryption,
/// at *byte* granularity. This is the "a sequence of calls is equivalent to one call over the
/// concatenation" contract of the trait, and for CFB it is about the input block surviving across
/// calls and, when a call ends mid-segment, the unused keystream surviving too.
///
/// Every chunking in [`CHUNKINGS`] is checked against the one-call reference in both directions,
/// and every encrypt chunking against every decrypt chunking. Chunk sizes that are not multiples
/// of the block put every call through the head-blocks-tail split with all three parts non-empty at
/// some point; 1 never reaches the block path at all; 16 and 32 never leave it.
#[test]
fn call_chunking_does_not_change_the_result() {
    let iv = pinned_iv();
    let plaintext = message(10 * TOY_LEN + 11);

    let reference = enc(&mut pinned_encryptor(iv), &plaintext);
    assert_eq!(dec(&mut pinned_decryptor(iv), &reference), plaintext);

    for &enc_chunk in &CHUNKINGS {
        let ct = enc_chunked(&mut pinned_encryptor(iv), &plaintext, enc_chunk);
        assert_eq!(ct, reference, "encrypting in {enc_chunk}-byte calls");

        for &dec_chunk in &CHUNKINGS {
            let pt = dec_chunked(&mut pinned_decryptor(iv), &ct, dec_chunk);
            assert_eq!(
                pt, plaintext,
                "encrypted in {enc_chunk}-byte calls, decrypted in {dec_chunk}-byte calls"
            );
        }
    }

    // Empty calls anywhere are no-ops, including mid-segment.
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
/// `call_chunking_does_not_change_the_result` proves the property over the toy permutation, where
/// the mode's own bookkeeping is the only thing that can be wrong. This repeats it with the cipher
/// the mode is actually used with, so a chunking bug that only shows up for a 16-byte block under
/// a real key schedule -- rather than for the toy -- cannot hide. The AES coverage elsewhere
/// (`sp800_38a_cfb_tests.rs`, `acvp_cfb_tests.rs`) chunks against *published* ciphertext; this is
/// the direct single-call-versus-chunked comparison.
///
/// The message is 171 bytes: not a whole number of blocks, so every chunking ends on a short final
/// segment, and long enough to run the decryptor's eight-block batch ten times over.
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
            let (enc, got) = Cfb::<P, Encrypting, KEY_LEN, 16>::do_encrypt_init_rng(
                &key,
                &mut FixedSeedRNG::<16>::new(iv),
            )
            .expect("encrypt init");
            assert_eq!(got, iv, "{name}: the pinned RNG should reproduce the IV");
            enc
        };
        let decryptor =
            || Cfb::<P, Decrypting, KEY_LEN, 16>::do_decrypt_init(&key, &iv).expect("decrypt init");

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

/// The pair path in `do_decrypt` must actually be taken, and only where a pair of whole blocks sits
/// at a segment boundary.
///
/// [`SwappedPairToy`] returns its two pair results in the wrong order while its single-block methods
/// are correct. CFB decryption pairs through `encrypt_blocks2`, so with this permutation two blocks
/// handed over together come out wrong, while the same bytes handed over one block at a time, or
/// offset by a partial segment so that no two whole blocks line up, come out right. If everything
/// came out right, the pair path would be dead code and every claim about it would be untested.
#[test]
fn the_pair_path_is_really_used() {
    let key = toy_key();
    let iv = pinned_iv();
    let plaintext = message(2 * TOY_LEN);

    // The correct toy round-trips.
    let ct = enc(&mut pinned_encryptor(iv), &plaintext);
    assert_eq!(dec(&mut pinned_decryptor(iv), &ct), plaintext);

    // The swapped-pair toy encrypts identically -- CFB encryption is serial and never pairs, so its
    // `encrypt_blocks2` override is not reached from the encryptor at all.
    let (mut e, _) =
        SwappedCfb::<Encrypting>::do_encrypt_init_rng(&key, &mut pinned_rng(iv)).unwrap();
    assert_eq!(enc(&mut e, &plaintext), ct, "CFB encryption must not use the pair path");

    // ...but decrypting the pair together must now be wrong, because the pair path is used.
    let mut d = SwappedCfb::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    assert_ne!(dec(&mut d, &ct), plaintext, "decrypting a pair must go through encrypt_blocks2");

    // Decrypting one block at a time avoids the pair path, so it is correct even for this toy.
    let mut d = SwappedCfb::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    assert_eq!(dec_chunked(&mut d, &ct, TOY_LEN), plaintext, "the single-block path must not pair");

    // So does splitting the pair across a segment boundary: 5 bytes, then 27. The second call has
    // an 11-byte head, one whole block and no tail, so there is no pair to form.
    let mut d = SwappedCfb::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    let mut got = ct.clone();
    d.do_decrypt(&mut got[..5]).unwrap();
    d.do_decrypt(&mut got[5..]).unwrap();
    assert_eq!(got, plaintext, "a pair not at a segment boundary is not a pair");
}

/// The eight-block path in `do_decrypt` must actually be taken, and only for full eights.
///
/// [`SwappedEightToy`] returns its eight `encrypt_blocks8` results rotated while its pair and
/// single-block methods are correct. CFB decryption batches eights through the *forward*
/// `encrypt_blocks8`, so with this permutation nine blocks handed over together decrypt wrongly
/// (eight rotated, then one), while the same blocks handed over as two fours (pairs) or one at a
/// time decrypt correctly. Encryption is serial and never batches, so it is unaffected.
#[test]
fn the_eight_block_path_is_really_used() {
    let key = toy_key();
    let iv = pinned_iv();
    let plaintext = message(9 * TOY_LEN);

    // The correct toy round-trips nine blocks.
    let ct = enc(&mut pinned_encryptor(iv), &plaintext);
    assert_eq!(dec(&mut pinned_decryptor(iv), &ct), plaintext);

    // The rotated-eight toy encrypts identically: CFB encryption is serial and never batches.
    let (mut e, _) =
        SwappedEightCfb::<Encrypting>::do_encrypt_init_rng(&key, &mut pinned_rng(iv)).unwrap();
    assert_eq!(enc(&mut e, &plaintext), ct, "CFB encryption must not use the eight path");

    // ...but nine blocks together must now be wrong, because the first eight go through
    // encrypt_blocks8.
    let mut d = SwappedEightCfb::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    assert_ne!(dec(&mut d, &ct), plaintext, "nine blocks must go through encrypt_blocks8");

    // Two fours use the pair path only, so they are correct even for this toy...
    let mut d = SwappedEightCfb::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    assert_eq!(
        dec_chunked(&mut d, &ct, 4 * TOY_LEN),
        plaintext,
        "fours must not use the eight path"
    );

    // ...and so is one block at a time.
    let mut d = SwappedEightCfb::<Decrypting>::do_decrypt_init(&key, &iv).unwrap();
    assert_eq!(
        dec_chunked(&mut d, &ct, TOY_LEN),
        plaintext,
        "the single-block path must not batch"
    );
}

/// The one-shots (`encrypt` / `decrypt`, in place) must produce exactly what the streaming API
/// produces, for a message ending in a short segment and one that does not, in both directions.
#[test]
fn one_shots_agree_with_the_streaming_api() {
    let key = toy_key();
    let iv = pinned_iv();

    for len in [3 * TOY_LEN + 7, 4 * TOY_LEN] {
        let plaintext = message(len);
        let streamed = enc(&mut pinned_encryptor(iv), &plaintext);

        let mut buf = plaintext.clone();
        let iv_b = ToyCfb::<Encrypting>::encrypt_rng(&key, &mut pinned_rng(iv), &mut buf).unwrap();
        assert_eq!(iv_b, iv);
        assert_eq!(buf, streamed, "len {len}: one-shot must equal streaming");
        ToyCfb::<Decrypting>::decrypt(&key, &iv, &mut buf).unwrap();
        assert_eq!(buf, plaintext);

        // The OS-RNG variant round-trips too.
        let mut buf = plaintext.clone();
        let iv_fresh = ToyCfb::<Encrypting>::encrypt(&key, &mut buf).unwrap();
        assert_ne!(buf, plaintext);
        ToyCfb::<Decrypting>::decrypt(&key, &iv_fresh, &mut buf).unwrap();
        assert_eq!(buf, plaintext);
    }
}

// ---- SP 800-38A Appendix D error propagation ---------------------------------------------

/// The parts of Appendix D that follow from the equations and hold for *any* permutation.
///
/// Table D.2 for CFB: a bit error in `Cj` gives "SBE in the decryption of `Cj`" -- specific bit
/// errors, i.e. the same bit positions -- because `Pj = Cj XOR Oj` and `Oj = CIPH_K(C_{j-1})` does
/// not depend on `Cj` at all. Earlier blocks are untouched, and with `s = b` the damage reaches
/// exactly one block further (`Cj+1`, since `b/s = 1`). A bit error in the short final segment is
/// the same story with nothing after it: the same bit of the same segment, and nothing else.
#[test]
fn a_ciphertext_bit_error_flips_exactly_that_bit_of_its_own_block() {
    let iv = pinned_iv();
    let plaintext = message(4 * TOY_LEN + 5);
    let ct = enc(&mut pinned_encryptor(iv), &plaintext);

    // Every bit of C2, so the SBE claim is checked exhaustively rather than at one position.
    for byte in TOY_LEN..2 * TOY_LEN {
        for bit in 0..8 {
            let mut corrupt = ct.clone();
            corrupt[byte] ^= 1 << bit;
            let got = dec(&mut pinned_decryptor(iv), &corrupt);

            assert_eq!(&got[..TOY_LEN], &plaintext[..TOY_LEN], "P1 depends only on the IV and C1");

            let mut expected_p2 = plaintext[TOY_LEN..2 * TOY_LEN].to_vec();
            expected_p2[byte - TOY_LEN] ^= 1 << bit;
            assert_eq!(
                &got[TOY_LEN..2 * TOY_LEN],
                &expected_p2[..],
                "C2 byte {byte} bit {bit}: exactly that bit of P2 should change"
            );

            assert_ne!(
                &got[2 * TOY_LEN..3 * TOY_LEN],
                &plaintext[2 * TOY_LEN..3 * TOY_LEN],
                "P3 comes from CIPH_K of the corrupted C2"
            );
            assert_eq!(
                &got[3 * TOY_LEN..],
                &plaintext[3 * TOY_LEN..],
                "P4 and the final segment are unaffected: b/s = 1, so damage stops at P3"
            );
        }
    }

    // Every bit of the short final segment.
    for byte in 4 * TOY_LEN..plaintext.len() {
        for bit in 0..8 {
            let mut corrupt = ct.clone();
            corrupt[byte] ^= 1 << bit;
            let got = dec(&mut pinned_decryptor(iv), &corrupt);
            let mut expected = plaintext.clone();
            expected[byte] ^= 1 << bit;
            assert_eq!(
                got, expected,
                "final segment byte {byte} bit {bit}: exactly that bit, and nothing else"
            );
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
    type Aes128Cfb<Dir> = Cfb<AES_128, Dir, 16, 16>;
    const LEN: usize = 16;

    let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
        .expect("a valid AES-128 key");
    let iv: [u8; LEN] = core::array::from_fn(|i| 0x0F ^ (i as u8));
    let plaintext = [[0x00u8; LEN], [0x11u8; LEN], [0x22u8; LEN]];

    let (mut e, got_iv) =
        Aes128Cfb::<Encrypting>::do_encrypt_init_rng(&key, &mut FixedSeedRNG::<LEN>::new(iv))
            .unwrap();
    assert_eq!(got_iv, iv);
    let mut ct = plaintext;
    e.do_encrypt(ct.as_flattened_mut()).unwrap();

    let mut first_blocks = std::collections::BTreeSet::new();

    for byte in 0..LEN {
        for bit in 0..8 {
            let mut corrupt_iv = iv;
            corrupt_iv[byte] ^= 1 << bit;

            let mut d = Aes128Cfb::<Decrypting>::do_decrypt_init(&key, &corrupt_iv).unwrap();
            let mut got = ct;
            d.do_decrypt(got.as_flattened_mut()).unwrap();

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

// ---- every length, no padding ------------------------------------------------------------

/// CFB is a stream cipher: every length round-trips, the ciphertext is exactly as long as the
/// plaintext, and no padding layer is involved. Every length from empty to just past three blocks
/// covers the empty message, a lone short segment, exact multiples and every partial final segment.
#[test]
fn every_length_round_trips_without_padding() {
    let key = toy_key();
    for len in 0..=(3 * TOY_LEN + 1) {
        let plaintext = message(len);
        let mut data = plaintext.clone();
        let iv = ToyCfb::<Encrypting>::encrypt(&key, &mut data).expect("encryption");
        assert_eq!(data.len(), len, "len {len}: the ciphertext is as long as the plaintext");
        // Only meaningful once the message is long enough that agreeing with the keystream by
        // chance is negligible: a 1-byte message coincides with its own ciphertext whenever the
        // single keystream byte is zero, which a fresh random IV makes happen about once in 256
        // runs. At 8 bytes the odds are 2^-64. (This is why the assertion is guarded rather than
        // dropped: it is worth making, just not at every length.)
        if len >= 8 {
            assert_ne!(data, plaintext, "len {len}: the data must actually be encrypted");
        }
        ToyCfb::<Decrypting>::decrypt(&key, &iv, &mut data).expect("decryption");
        assert_eq!(data, plaintext, "len {len}: round trip");
    }
}

// ---- memory ------------------------------------------------------------------------------

/// Pins the "Memory Usage" table in the crate docs, and the claim that CFB costs one `usize` more
/// than CBC: the block that is `Ij`, `Oj` and `I_{j+1}` in turn, plus the count of how much of it
/// has been used.
#[test]
fn sizes_match_the_documented_memory_table() {
    use core::mem::size_of;

    assert_eq!(size_of::<Cfb<AES_128, Encrypting, 16, 16>>(), 176 + 16 + 8);
    assert_eq!(size_of::<Cfb<AES_192, Encrypting, 24, 16>>(), 208 + 16 + 8);
    assert_eq!(size_of::<Cfb<AES_256, Encrypting, 32, 16>>(), 240 + 16 + 8);

    // The direction marker is free, and does not change the layout.
    assert_eq!(
        size_of::<Cfb<AES_128, Encrypting, 16, 16>>(),
        size_of::<Cfb<AES_128, Decrypting, 16, 16>>()
    );

    // ...and the general rule the docs state.
    assert_eq!(
        size_of::<Cfb<AES_256, Encrypting, 32, 16>>(),
        size_of::<AES_256>() + 16 + size_of::<usize>()
    );

    // The docs say CFB is one `usize` bigger than CBC.
    assert_eq!(
        size_of::<Cfb<AES_128, Encrypting, 16, 16>>(),
        size_of::<Cbc<AES_128, Encrypting, 16, 16>>() + size_of::<usize>()
    );
}
