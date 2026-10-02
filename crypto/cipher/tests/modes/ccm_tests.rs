//! Structural tests for CCM, driven by toy permutations.
//!
//! These check the properties of the *mode* -- that only the forward cipher function is ever
//! used, that the counter half batches while the CBC-MAC stays serial, that call chunking is
//! invisible in both directions, what `TAG_LEN` and `NONCE_LEN` do and do not change, that the
//! decryptor holds to the declared length, and which entry points release unauthenticated
//! plaintext -- independently of the known-answer vectors in the `aes` crate's `sp800_38c_tests.rs`,
//! `acvp_ccm_tests.rs` and `wycheproof_ccm_tests.rs`. The Appendix C file also carries the
//! buffering `CcmEncryptor` / `CcmDecryptor` pair's contract, the shared framework run and the
//! memory table, so none of those is repeated here.
//!
//! Spec references are to NIST SP 800-38C (May 2004, errata update 07-20-2007).

mod common;

use bouncycastle_cipher::modes::{Ccm, CcmDecryptor};
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::hazmat::ElectronicCodeBook;
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::traits::{AEADCipherDecryptor, SymmetricCipherDecryptor};
use common::{ForwardOnlyToy, SwappedFourToy, SwappedPairToy, TOY_LEN, Toy, toy_key};

/// The default shape under test: a 12-byte nonce, so `q = 3`, and a full 16-byte tag.
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

type ToyCcm<Dir> = Ccm<Toy, Dir, TOY_LEN, TOY_LEN, NONCE_LEN, TAG_LEN>;
type SwappedCcm<Dir> = Ccm<SwappedPairToy, Dir, TOY_LEN, TOY_LEN, NONCE_LEN, TAG_LEN>;
type SwappedFourCcm<Dir> = Ccm<SwappedFourToy, Dir, TOY_LEN, TOY_LEN, NONCE_LEN, TAG_LEN>;
type ForwardOnlyCcm<Dir> = Ccm<ForwardOnlyToy, Dir, TOY_LEN, TOY_LEN, NONCE_LEN, TAG_LEN>;

fn pinned_nonce() -> [u8; NONCE_LEN] {
    core::array::from_fn(|i| 0xA0 ^ (i as u8))
}

fn message(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(3).wrapping_add(1)).collect()
}

/// One-shot Sec 6.1 over the toy permutation `P`, detached: the ciphertext and the tag.
fn encrypt<P: ElectronicCodeBook<TOY_LEN, TOY_LEN>>(
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; TAG_LEN]) {
    let mut ct = vec![0u8; plaintext.len()];
    let (written, tag) =
        Ccm::<P, Encrypting, TOY_LEN, TOY_LEN, NONCE_LEN, TAG_LEN>::encrypt_out_detached(
            &toy_key(),
            nonce,
            aad,
            plaintext,
            &mut ct,
        )
        .unwrap();
    assert_eq!(written, plaintext.len(), "CCM never expands the payload");
    (ct, tag)
}

/// Sec 6.1 through the streaming API over `P`, `chunk` bytes per `do_encrypt_update`.
fn stream_encrypt<P: ElectronicCodeBook<TOY_LEN, TOY_LEN>>(
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
    chunk: usize,
) -> (Vec<u8>, [u8; TAG_LEN]) {
    let mut ccm = Ccm::<P, Encrypting, TOY_LEN, TOY_LEN, NONCE_LEN, TAG_LEN>::new(
        &toy_key(),
        nonce,
        aad,
        plaintext.len(),
    )
    .unwrap();
    let mut data = plaintext.to_vec();
    for piece in data.chunks_mut(chunk) {
        ccm.do_encrypt(piece).unwrap();
    }
    let tag = ccm.do_encrypt_final().unwrap();
    (data, tag)
}

/// Sec 6.2 through the streaming API over `P`, `chunk` bytes per `do_decrypt_update`.
fn stream_decrypt<P: ElectronicCodeBook<TOY_LEN, TOY_LEN>>(
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_LEN],
    chunk: usize,
) -> Result<Vec<u8>, SymmetricCipherError> {
    let mut ccm = Ccm::<P, Decrypting, TOY_LEN, TOY_LEN, NONCE_LEN, TAG_LEN>::new(
        &toy_key(),
        nonce,
        aad,
        ciphertext.len(),
    )?;
    let mut data = ciphertext.to_vec();
    for piece in data.chunks_mut(chunk) {
        ccm.do_decrypt_update(piece)?;
    }
    ccm.do_decrypt_final(tag)?;
    Ok(data)
}

// ---- the forward-cipher-only rule ---------------------------------------------------------

/// Sec 3: "Only the forward cipher function of the block cipher algorithm is used within these
/// primitives", and Sec 5.1: "the CCM mode does not require the inverse cipher function". So
/// neither direction may reach the inverse cipher: decryption is CTR against the same keystream
/// (Sec 6.2 steps 3 and 5) and a CBC-MAC over the recovered plaintext (step 9), all forward.
/// `ForwardOnlyToy` panics from every inverse entry point, and the message is long enough that
/// the four-block, pair, single-block and partial-block keystream paths all run.
#[test]
fn neither_direction_uses_the_inverse_cipher() {
    let nonce = pinned_nonce();
    // Long enough to span two MAC blocks, so the AAD's own zero pad (A.2.2) runs as well.
    let aad = b"a header long enough to run over into a second CBC-MAC block";
    let plaintext = message(11 * TOY_LEN + 5);

    let (ct, tag) = encrypt::<ForwardOnlyToy>(&nonce, aad, &plaintext);
    let mut back = vec![0u8; plaintext.len()];
    ForwardOnlyCcm::<Decrypting>::decrypt_out_detached(
        &toy_key(),
        &nonce,
        aad,
        &ct,
        &tag,
        &mut back,
    )
    .unwrap();
    assert_eq!(back, plaintext, "all paths, forward cipher only");

    // Byte by byte, so the partial-block keystream path runs in both directions too.
    assert_eq!(
        stream_encrypt::<ForwardOnlyToy>(&nonce, aad, &plaintext, 1),
        (ct.clone(), tag),
        "byte path, forward cipher only"
    );
    assert_eq!(stream_decrypt::<ForwardOnlyToy>(&nonce, aad, &ct, &tag, 1).unwrap(), plaintext);

    // The forward-only toy must agree with the real one, or the above proves nothing.
    assert_eq!(encrypt::<Toy>(&nonce, aad, &plaintext), (ct, tag), "the two toys must agree");
}

// ---- the batched keystream paths ----------------------------------------------------------

/// The counter half batches, in both directions, and the CBC-MAC half does not.
///
/// Sec 6.1 steps 5 and 6 encipher the counter blocks `Ctr_j`, which A.3 forms from `j` alone, so
/// they are independent of each other and may go through `encrypt_2blocks`; step 3's
/// `Yi = CIPH_K(Bi XOR Yi-1)` depends on the previous output and cannot. `SwappedPairToy`
/// returns its two pair results in the wrong order while its single-block method is correct, so
/// with it: the ciphertext of two whole blocks differs from `Toy`'s (the pair path is taken), the
/// tag is *identical* (the MAC never batches, and `S0` is one block), and one block per call
/// avoids the pair path and agrees with `Toy` entirely.
#[test]
fn the_pair_path_is_really_used_in_both_directions_and_the_mac_never_batches() {
    let nonce = pinned_nonce();
    let plaintext = message(2 * TOY_LEN);
    let (ct, tag) = encrypt::<Toy>(&nonce, b"aad", &plaintext);

    let (swapped_ct, swapped_tag) = encrypt::<SwappedPairToy>(&nonce, b"aad", &plaintext);
    assert_ne!(swapped_ct, ct, "CCM encryption must use the pair path");
    assert_eq!(swapped_tag, tag, "the CBC-MAC and S0 are single-block, so the tag must not change");

    let (single_ct, single_tag) =
        stream_encrypt::<SwappedPairToy>(&nonce, b"aad", &plaintext, TOY_LEN);
    assert_eq!(single_ct, ct, "the single-block path must not pair");
    assert_eq!(single_tag, tag);

    // Decryption: the swapped keystream recovers the wrong plaintext (Sec 6.2 step 5), which is
    // what the MAC then absorbs (step 9), so the tag check fails.
    let mut dec = SwappedCcm::<Decrypting>::new(&toy_key(), &nonce, b"aad", ct.len()).unwrap();
    let mut back = ct.clone();
    dec.do_decrypt_update(&mut back).unwrap();
    assert_ne!(back, plaintext, "CCM decryption must use the pair path");
    assert!(matches!(dec.do_decrypt_final(&tag), Err(SymmetricCipherError::AEADTagCheckFailed)));
}

/// The four-block path must be taken, in both directions, and only for full fours.
/// `SwappedFourToy` rotates its four `encrypt_4blocks` results while its pair and single-block
/// methods are correct.
#[test]
fn the_four_block_path_is_really_used_in_both_directions() {
    let nonce = pinned_nonce();
    let plaintext = message(5 * TOY_LEN);
    let (ct, tag) = encrypt::<Toy>(&nonce, b"aad", &plaintext);

    let (swapped_ct, swapped_tag) = encrypt::<SwappedFourToy>(&nonce, b"aad", &plaintext);
    assert_ne!(swapped_ct, ct, "five blocks must go through encrypt_4blocks");
    assert_eq!(swapped_tag, tag, "the CBC-MAC and S0 are single-block, so the tag must not change");

    // Two blocks per call uses pairs only, so the rotated-four toy is correct there.
    let (pairs_ct, pairs_tag) =
        stream_encrypt::<SwappedFourToy>(&nonce, b"aad", &plaintext, 2 * TOY_LEN);
    assert_eq!(pairs_ct, ct, "pairs must not use the four path");
    assert_eq!(pairs_tag, tag);

    let mut dec = SwappedFourCcm::<Decrypting>::new(&toy_key(), &nonce, b"aad", ct.len()).unwrap();
    let mut back = ct.clone();
    dec.do_decrypt_update(&mut back).unwrap();
    assert_ne!(back, plaintext, "decryption must batch fours too");
    assert!(matches!(dec.do_decrypt_final(&tag), Err(SymmetricCipherError::AEADTagCheckFailed)));
}

// ---- call sequencing ----------------------------------------------------------------------

/// Call chunking must be invisible in both directions: every two-call split of a 101-byte
/// message, so that the second call resumes a keystream block and a CBC-MAC block left open at
/// every possible offset, gives the one-shot's ciphertext, tag and plaintext.
///
/// 101 bytes is six blocks and a tail, so a small opening call leaves the second one at least a
/// four-block batch, a pair batch and a remainder: the batched blocks must line up with the
/// keystream the small call left partway through, not silently skip over it. None of the Appendix
/// C vectors is long enough for that -- the largest, C.4, is two blocks -- and every chunking
/// `sp800_38c_tests.rs` sweeps is uniform, so a call that resumes an open block there is always a
/// short final remainder, never one big enough to batch.
#[test]
fn every_split_agrees_with_the_one_shot_in_both_directions() {
    let nonce = pinned_nonce();
    let aad = b"header";
    let plaintext = message(6 * TOY_LEN + 5);
    let (ct, tag) = encrypt::<Toy>(&nonce, aad, &plaintext);

    for split in 0..=plaintext.len() {
        let mut enc = ToyCcm::<Encrypting>::new(&toy_key(), &nonce, aad, plaintext.len()).unwrap();
        let mut streamed = plaintext.clone();
        let (head, rest) = streamed.split_at_mut(split);
        enc.do_encrypt(head).unwrap();
        enc.do_encrypt(rest).unwrap();
        assert_eq!(enc.do_encrypt_final().unwrap(), tag, "tag, split at {split}");
        assert_eq!(streamed, ct, "ciphertext, split at {split}");

        let mut dec = ToyCcm::<Decrypting>::new(&toy_key(), &nonce, aad, ct.len()).unwrap();
        let mut back = ct.clone();
        let (head, rest) = back.split_at_mut(split);
        dec.do_decrypt_update(head).unwrap();
        dec.do_decrypt_update(rest).unwrap();
        dec.do_decrypt_final(&tag).unwrap_or_else(|e| panic!("tag check, split at {split}: {e:?}"));
        assert_eq!(back, plaintext, "plaintext, split at {split}");
    }
}

/// The payload length declared to `new` is inside `B0` (A.2.1 Table 2's `Q`), so neither
/// direction may be given more data than declared, nor finalized with less: either would produce
/// or verify a tag against a `B0` no counterpart could reproduce. A refused update consumes
/// nothing, so the flow is still usable.
#[test]
fn both_directions_hold_to_the_declared_length() {
    let nonce = pinned_nonce();
    let plaintext = message(8);
    let (ct, tag) = encrypt::<Toy>(&nonce, &[], &plaintext);

    // Encrypting: too much is refused, and finalizing short is refused.
    let mut enc = ToyCcm::<Encrypting>::new(&toy_key(), &nonce, &[], 8).unwrap();
    let mut too_much = [0x77u8; 9];
    assert!(
        matches!(enc.do_encrypt(&mut too_much), Err(SymmetricCipherError::StateError(_))),
        "9 bytes against a declared 8"
    );
    assert_eq!(too_much, [0x77u8; 9], "a refused update must not touch the data");
    let mut some = plaintext[..4].to_vec();
    enc.do_encrypt(&mut some).expect("4 of the 8 declared bytes");
    assert!(
        matches!(enc.do_encrypt_final(), Err(SymmetricCipherError::StateError(_))),
        "finalizing 4 bytes short"
    );

    // Decrypting: the same two refusals.
    let mut dec = ToyCcm::<Decrypting>::new(&toy_key(), &nonce, &[], 8).unwrap();
    let mut too_much = [0x77u8; 9];
    assert!(
        matches!(dec.do_decrypt_update(&mut too_much), Err(SymmetricCipherError::StateError(_))),
        "9 bytes against a declared 8"
    );
    assert_eq!(too_much, [0x77u8; 9], "a refused update must not touch the data");
    // ...and must not have debited the declared length either: the 8 genuine bytes still verify.
    let mut back = ct.clone();
    dec.do_decrypt_update(&mut back).unwrap();
    dec.do_decrypt_final(&tag).unwrap();
    assert_eq!(back, plaintext);

    let mut dec = ToyCcm::<Decrypting>::new(&toy_key(), &nonce, &[], 8).unwrap();
    let mut some = ct[..4].to_vec();
    dec.do_decrypt_update(&mut some).unwrap();
    assert!(
        matches!(dec.do_decrypt_final(&tag), Err(SymmetricCipherError::StateError(_))),
        "finalizing 4 bytes short"
    );
}

// ---- the parameters -----------------------------------------------------------------------

/// `TAG_LEN` changes the tag and nothing else -- and, unlike GCM's `MSB_t` truncation, a shorter
/// CCM tag is **not** a prefix of a longer one.
///
/// A.3 Table 4 keeps `t` out of the counter blocks (bits 3, 4 and 5 "shall also be set to 0"),
/// so the ciphertext is the same for every `t`. A.2.1 Table 1 puts `[(t-2)/2]_3` in `B0`'s flags
/// octet, so `Y0` and every `Yi` after it change with `t` (Sec 6.1 steps 2 and 3), and with them
/// the whole of `T = MSB_Tlen(Yr)`. With `Toy`, which permutes each byte independently, the
/// differing flags octet is guaranteed to propagate to byte 0 of every `Yi`, so the "not a
/// prefix" assertion holds by construction rather than by luck. All seven of A.1's `t` values
/// round-trip.
#[test]
fn tag_length_changes_the_tag_but_not_the_ciphertext_and_tags_do_not_nest() {
    let nonce = pinned_nonce();
    let aad = b"associated";
    let plaintext = message(23);
    let (ct16, tag16) = encrypt::<Toy>(&nonce, aad, &plaintext);

    macro_rules! check_tag_len {
        ($t:literal) => {{
            type Enc = Ccm<Toy, Encrypting, TOY_LEN, TOY_LEN, NONCE_LEN, $t>;
            type Dec = Ccm<Toy, Decrypting, TOY_LEN, TOY_LEN, NONCE_LEN, $t>;
            let mut ct = vec![0u8; plaintext.len()];
            let (_, tag) =
                Enc::encrypt_out_detached(&toy_key(), &nonce, aad, &plaintext, &mut ct).unwrap();
            assert_eq!(ct, ct16, "ciphertext must not depend on TAG_LEN ({})", $t);
            let mut pt = vec![0u8; plaintext.len()];
            Dec::decrypt_out_detached(&toy_key(), &nonce, aad, &ct, &tag, &mut pt).unwrap();
            assert_eq!(pt, plaintext, "TAG_LEN={} round trip", $t);
            tag.to_vec()
        }};
    }
    let shorter = [
        check_tag_len!(4),
        check_tag_len!(6),
        check_tag_len!(8),
        check_tag_len!(10),
        check_tag_len!(12),
        check_tag_len!(14),
    ];
    assert_eq!(check_tag_len!(16), tag16.to_vec(), "the reference is TAG_LEN=16 itself");
    for tag in &shorter {
        assert_ne!(
            &tag[..],
            &tag16[..tag.len()],
            "a {}-byte tag must not be a prefix of the 16-byte tag: t is inside B0",
            tag.len()
        );
    }
}

/// Every nonce length A.1 permits, `n` in `7..=13`, works, and each one implies its own payload
/// limit: `q = 15 - n` and "by definition, p < 2^8q", which `Ccm::MAX_PAYLOAD_LEN` exposes.
/// `sp800_38c_tests.rs` reaches `n` of 7, 8, 12 and 13 through Appendix C; 9, 10 and 11 are
/// reached only here. Over the toy alone, since where the nonce goes (A.2.1 Table 2, A.3 Table 3)
/// is the mode's business and not the permutation's.
#[test]
fn every_permitted_nonce_length_works() {
    fn round_trip<P, const KEY_LEN: usize, const N: usize>(
        key: &KeyMaterial<KEY_LEN>,
        expected_max_payload: u64,
    ) where
        P: ElectronicCodeBook<KEY_LEN, 16>,
    {
        // The full 16-byte tag, deliberately. `Toy` permutes each byte independently, so under
        // it the CBC-MAC is sixteen independent byte-chains and a `t`-byte tag witnesses only the
        // first `t` of them; the last nonce octet flipped below sits at block octet `N`, which an
        // 8-byte tag would never see once `N >= 8`. Real AES mixes every byte into every other,
        // so this is a limit of the toy, not of the mode.
        type Enc<P, const K: usize, const N: usize> = Ccm<P, Encrypting, K, 16, N, 16>;
        type Dec<P, const K: usize, const N: usize> = Ccm<P, Decrypting, K, 16, N, 16>;
        assert_eq!(
            Enc::<P, KEY_LEN, N>::MAX_PAYLOAD_LEN,
            expected_max_payload,
            "n = {N}: the payload limit 2^8q - 1 that q = 15 - n implies"
        );

        let nonce: [u8; N] = core::array::from_fn(|i| (i as u8).wrapping_mul(11).wrapping_add(3));
        let plaintext = message(100);
        let mut ct = vec![0u8; plaintext.len()];
        let (_, tag) =
            Enc::<P, KEY_LEN, N>::encrypt_out_detached(key, &nonce, b"aad", &plaintext, &mut ct)
                .unwrap();
        assert_ne!(ct, plaintext, "nonce length {N}: must actually encrypt");

        let mut back = vec![0u8; plaintext.len()];
        Dec::<P, KEY_LEN, N>::decrypt_out_detached(key, &nonce, b"aad", &ct, &tag, &mut back)
            .unwrap();
        assert_eq!(back, plaintext, "nonce length {N}: round trip");

        // The last nonce octet sits right before `Q` in B0 (Table 2) and before the counter in
        // every `Ctr_i` (Table 3); flipping it must change both and so fail the check.
        let mut wrong = nonce;
        wrong[N - 1] ^= 0x01;
        assert!(
            matches!(
                Dec::<P, KEY_LEN, N>::decrypt_out_detached(
                    key, &wrong, b"aad", &ct, &tag, &mut back
                ),
                Err(SymmetricCipherError::AEADTagCheckFailed)
            ),
            "nonce length {N}: the nonce is authenticated"
        );
    }

    // `q = 8` makes `2^8q` exactly `2^64`, which does not fit a `u64`, so the bound is `u64::MAX`.
    let toy = toy_key();
    round_trip::<Toy, TOY_LEN, 7>(&toy, u64::MAX);
    round_trip::<Toy, TOY_LEN, 8>(&toy, (1 << 56) - 1);
    round_trip::<Toy, TOY_LEN, 9>(&toy, (1 << 48) - 1);
    round_trip::<Toy, TOY_LEN, 10>(&toy, (1 << 40) - 1);
    round_trip::<Toy, TOY_LEN, 11>(&toy, (1 << 32) - 1);
    round_trip::<Toy, TOY_LEN, 12>(&toy, (1 << 24) - 1);
    round_trip::<Toy, TOY_LEN, 13>(&toy, (1 << 16) - 1);
}

/// Which entry points release unauthenticated plaintext on a forgery, pinned side by side.
///
/// Sec 6.2: "When the error message INVALID is returned, the payload P and the MAC T shall not
/// be revealed." The one-shots and the buffering `CcmDecryptor` honour that -- the caller's
/// buffer comes back zeroized -- because they have the whole ciphertext before they start. The
/// inherent streaming `do_decrypt_update` cannot: Sec 6.2 recovers `P` (step 5) before it can
/// verify it (step 10), so by the time `do_decrypt_final` rejects the tag the plaintext is
/// already in the caller's buffer, as that method's docs warn. Pinning the difference makes it
/// a documented property rather than an accident.
#[test]
fn one_shots_release_nothing_on_forgery_but_the_inherent_stream_does() {
    let nonce = pinned_nonce();
    let plaintext = *b"do not trust me yet";
    let (ct, mut tag) = encrypt::<Toy>(&nonce, b"aad", &plaintext);
    tag[0] ^= 0xFF; // forge it

    // The inherent one-shot: verify-then-return, so a forged tag leaves nothing but zeros.
    let mut one_shot = [0xEEu8; 19];
    assert!(matches!(
        ToyCcm::<Decrypting>::decrypt_out_detached(
            &toy_key(),
            &nonce,
            b"aad",
            &ct,
            &tag,
            &mut one_shot
        ),
        Err(SymmetricCipherError::AEADTagCheckFailed)
    ));
    assert_eq!(one_shot, [0u8; 19], "the one-shot must zeroize its buffer on a forged tag");

    // The inherent stream: the plaintext is in the buffer before the tag is ever looked at, and
    // rejecting the tag cannot take it back.
    let mut dec = ToyCcm::<Decrypting>::new(&toy_key(), &nonce, b"aad", ct.len()).unwrap();
    let mut streamed = ct.clone();
    dec.do_decrypt_update(&mut streamed).unwrap();
    assert_eq!(&streamed[..], &plaintext[..], "the stream already produced plaintext");
    assert!(matches!(dec.do_decrypt_final(&tag), Err(SymmetricCipherError::AEADTagCheckFailed)));
    assert_eq!(&streamed[..], &plaintext[..], "...and a rejected tag cannot take it back");

    // The buffering decryptor holds everything until the final call, so it can and does behave
    // like the one-shot: `do_final` returns no buffer at all on failure, and
    // `do_final_detached_out` zeroizes the one it was given.
    type Dec = CcmDecryptor<Toy, TOY_LEN, TOY_LEN, NONCE_LEN, TAG_LEN, 48, 48, 64>;
    let mut nothing = [0u8; 0];

    let mut dec = Dec::do_decrypt_init(&toy_key(), &nonce).unwrap();
    dec.do_update_aad(b"aad").unwrap();
    assert_eq!(dec.do_decrypt_out(&ct, &mut nothing).unwrap(), 0, "nothing is released mid-stream");
    let mut detached = [0xEEu8; 64];
    assert!(matches!(
        dec.do_final_detached_out(&tag, &mut detached),
        Err(SymmetricCipherError::AEADTagCheckFailed)
    ));
    assert_eq!(detached[..19], [0u8; 19], "do_final_detached_out must zeroize on a forged tag");

    let mut inline = ct.clone();
    inline.extend_from_slice(&tag);
    let mut dec = Dec::do_decrypt_init(&toy_key(), &nonce).unwrap();
    dec.do_update_aad(b"aad").unwrap();
    assert_eq!(dec.do_decrypt_out(&inline, &mut nothing).unwrap(), 0);
    assert!(matches!(dec.do_final(), Err(SymmetricCipherError::AEADTagCheckFailed)));
}

/// Tests a large payload that would blow the Linux stack limit if we try to hard-copy it.
/// Tests the inherent APIs on CCM.
#[test]
fn test_large_payload_inherent() {
    // 5 mb payload
    const LARGE_LEN: usize = 5 * 1024 * 1024;
    let key = toy_key();
    let nonce = pinned_nonce();
    let aad = b"header";
    let plaintext = message(LARGE_LEN);

    // round-tripped though the inherent CCM interface
    let mut ct = vec![0u8; LARGE_LEN];
    let (written, tag) =
        ToyCcm::<Encrypting>::encrypt_out_detached(&key, &nonce, aad, &plaintext, &mut ct).unwrap();
    assert_eq!(written, LARGE_LEN);
    assert_ne!(ct, plaintext, "must actually encrypt");

    let mut back = vec![0u8; LARGE_LEN];
    let n = ToyCcm::<Decrypting>::decrypt_out_detached(&key, &nonce, aad, &ct, &tag, &mut back)
        .unwrap();
    assert_eq!(n, LARGE_LEN);
    assert_eq!(back, plaintext, "inherent round trip");
}
