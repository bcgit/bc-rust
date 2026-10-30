//! Structural tests for CCM, driven by toy permutations.
//!
//! These check the properties of the *mode* -- that only the forward cipher function is ever
//! used, that the counter half batches while the CBC-MAC stays serial, that call chunking is
//! invisible in both directions, what `TAG_LEN` and `NONCE_LEN` do and do not change, that the
//! stream holds to its frame, and which entry points release unauthenticated plaintext --
//! independently of the known-answer vectors in the `aes` crate's `sp800_38c_tests.rs`,
//! `ccm_bc-test-data.rs` and `ccm_wycheproof.rs`. The Appendix C file also carries the
//! fixed-frame `CcmPacketEncryptor` / `CcmPacketDecryptor` pair's contract, the shared framework run and the
//! memory table, so none of those is repeated here.
//!
//! The one-shots are the mode's in-place pair on [`CCM`], which take any length; the streams are
//! the fixed-frame pair, whose frame is the message under test.
//!
//! Spec references are to NIST SP 800-38C (May 2004, errata update 07-20-2007).

mod common;
#[path = "../common/toy_key.rs"]
mod toy_key;

use bouncycastle_cipher::modes::{CCM, CCM_Packet, ModeNames};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::hazmat::ElectronicCodeBook;
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{
    AeadDeclaredDecryptionKey, AeadDeclaredEncryptionKey, AeadDecryptionKey, AeadEncryptionKey,
    FromKeyMaterial,
};
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};
use bouncycastle_core_test_framework::from_key_material::TestFrameworkFromKeyMaterial;
use common::{ForwardOnlyToy, SwappedFourToy, SwappedPairToy, TOY_LEN, Toy, toy_key};
use toy_key::ToyKey;

/// The default shape under test: a 12-byte nonce, so `q = 3`, and a full 16-byte tag.
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// The streams' AAD capacity, above any AAD used here.
const AAD_LEN: usize = 64;

/// The toy key under the in-place pair, which takes any length.
type DeclaredKey<P> = ToyKey<P, CCM<NONCE_LEN, TAG_LEN>>;
/// The toy key under the fixed-frame streams, whose frame is `DATA_LEN`.
type FrameKey<P, const DATA_LEN: usize> =
    ToyKey<P, CCM_Packet<NONCE_LEN, TAG_LEN, AAD_LEN, DATA_LEN>>;

fn pinned_nonce() -> [u8; NONCE_LEN] {
    core::array::from_fn(|i| 0xA0 ^ (i as u8))
}

fn message(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(3).wrapping_add(1)).collect()
}

fn declared_key<P: ElectronicCodeBook<TOY_LEN, TOY_LEN> + ModeNames + Clone>() -> DeclaredKey<P> {
    DeclaredKey::from_key_material(&toy_key()).expect("the toy key")
}

fn frame_key<P: ElectronicCodeBook<TOY_LEN, TOY_LEN> + ModeNames + Clone, const DATA_LEN: usize>()
-> FrameKey<P, DATA_LEN> {
    FrameKey::from_key_material(&toy_key()).expect("the toy key")
}

/// One-shot Sec 6.1 over the toy permutation `P`, in place: the ciphertext and the tag.
fn seal<P: ElectronicCodeBook<TOY_LEN, TOY_LEN> + ModeNames + Clone>(
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; TAG_LEN]) {
    let mut buf = plaintext.to_vec();
    let tag = declared_key::<P>().encrypt_detached_in_place_nonce(nonce, aad, &mut buf).unwrap();
    (buf, tag)
}

/// One-shot Sec 6.2 over `P`, in place.
fn open<P: ElectronicCodeBook<TOY_LEN, TOY_LEN> + ModeNames + Clone>(
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_LEN],
) -> Result<Vec<u8>, SymmetricCipherError> {
    let mut buf = ciphertext.to_vec();
    declared_key::<P>().decrypt_detached_in_place(nonce, aad, &mut buf, tag)?;
    Ok(buf)
}

/// Sec 6.1 through the fixed-frame stream over `P`, `chunk` bytes per update. The frame is
/// `DATA_LEN`, so `plaintext` must be exactly that long.
fn stream_encrypt<
    P: ElectronicCodeBook<TOY_LEN, TOY_LEN> + ModeNames + Clone,
    const DATA_LEN: usize,
>(
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
    chunk: usize,
) -> (Vec<u8>, [u8; TAG_LEN]) {
    let key = frame_key::<P, DATA_LEN>();
    let mut enc = key.create_encryptor_nonce(nonce);
    enc.do_update_aad(aad).unwrap();
    let mut out = vec![0u8; plaintext.len()];
    let mut written = 0;
    for piece in plaintext.chunks(chunk) {
        written += enc.do_encrypt_out(piece, &mut out[written..]).unwrap();
    }
    assert_eq!(written, plaintext.len(), "CCM never holds back payload");
    let (_, _, tag) = enc.do_encrypt_final_detached().unwrap();
    (out, tag)
}

/// Sec 6.2 through the fixed-frame stream over `P`, `chunk` bytes per update, detached tag.
fn stream_decrypt<
    P: ElectronicCodeBook<TOY_LEN, TOY_LEN> + ModeNames + Clone,
    const DATA_LEN: usize,
>(
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_LEN],
    chunk: usize,
) -> Result<Vec<u8>, SymmetricCipherError> {
    let key = frame_key::<P, DATA_LEN>();
    let mut dec = key.create_decryptor(nonce);
    dec.do_update_aad(aad)?;
    let mut out = vec![0u8; ciphertext.len()];
    let mut written = 0;
    for piece in ciphertext.chunks(chunk) {
        written += dec.do_decrypt_out(piece, &mut out[written..])?;
    }
    dec.do_decrypt_final_detached(tag)?;
    out.truncate(written);
    Ok(out)
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
    const LEN: usize = 11 * TOY_LEN + 5;
    let nonce = pinned_nonce();
    // Long enough to span two MAC blocks, so the AAD's own zero pad (A.2.2) runs as well.
    let aad = b"a header long enough to run over into a second CBC-MAC block";
    let plaintext = message(LEN);

    let (ct, tag) = seal::<ForwardOnlyToy>(&nonce, aad, &plaintext);
    assert_eq!(open::<ForwardOnlyToy>(&nonce, aad, &ct, &tag).unwrap(), plaintext);

    // Byte by byte, so the partial-block keystream path runs in both directions too.
    assert_eq!(
        stream_encrypt::<ForwardOnlyToy, LEN>(&nonce, aad, &plaintext, 1),
        (ct.clone(), tag),
        "byte path, forward cipher only"
    );
    assert_eq!(
        stream_decrypt::<ForwardOnlyToy, LEN>(&nonce, aad, &ct, &tag, 1).unwrap(),
        plaintext
    );

    // The forward-only toy must agree with the real one, or the above proves nothing.
    assert_eq!(seal::<Toy>(&nonce, aad, &plaintext), (ct, tag), "the two toys must agree");
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
    const LEN: usize = 2 * TOY_LEN;
    let nonce = pinned_nonce();
    let plaintext = message(LEN);
    let (ct, tag) = seal::<Toy>(&nonce, b"aad", &plaintext);

    let (swapped_ct, swapped_tag) = seal::<SwappedPairToy>(&nonce, b"aad", &plaintext);
    assert_ne!(swapped_ct, ct, "CCM encryption must use the pair path");
    assert_eq!(swapped_tag, tag, "the CBC-MAC and S0 are single-block, so the tag must not change");

    let (single_ct, single_tag) =
        stream_encrypt::<SwappedPairToy, LEN>(&nonce, b"aad", &plaintext, TOY_LEN);
    assert_eq!(single_ct, ct, "the single-block path must not pair");
    assert_eq!(single_tag, tag);

    // Decryption: the swapped keystream recovers the wrong plaintext (Sec 6.2 step 5), which is
    // what the MAC then absorbs (step 9), so the tag check fails. The stream releases the
    // plaintext before the final, so the wrong recovery can be seen.
    let key = frame_key::<SwappedPairToy, LEN>();
    let mut dec = key.create_decryptor(&nonce);
    dec.do_update_aad(b"aad").unwrap();
    let mut back = vec![0u8; LEN];
    dec.do_decrypt_out(&ct, &mut back).unwrap();
    assert_ne!(back, plaintext, "CCM decryption must use the pair path");
    assert!(matches!(
        dec.do_decrypt_final_detached(&tag),
        Err(SymmetricCipherError::AEADTagCheckFailed)
    ));
}

/// The four-block path must be taken, in both directions, and only for full fours.
/// `SwappedFourToy` rotates its four `encrypt_4blocks` results while its pair and single-block
/// methods are correct.
#[test]
fn the_four_block_path_is_really_used_in_both_directions() {
    const LEN: usize = 5 * TOY_LEN;
    let nonce = pinned_nonce();
    let plaintext = message(LEN);
    let (ct, tag) = seal::<Toy>(&nonce, b"aad", &plaintext);

    let (swapped_ct, swapped_tag) = seal::<SwappedFourToy>(&nonce, b"aad", &plaintext);
    assert_ne!(swapped_ct, ct, "five blocks must go through encrypt_4blocks");
    assert_eq!(swapped_tag, tag, "the CBC-MAC and S0 are single-block, so the tag must not change");

    // Two blocks per call uses pairs only, so the rotated-four toy is correct there.
    let (pairs_ct, pairs_tag) =
        stream_encrypt::<SwappedFourToy, LEN>(&nonce, b"aad", &plaintext, 2 * TOY_LEN);
    assert_eq!(pairs_ct, ct, "pairs must not use the four path");
    assert_eq!(pairs_tag, tag);

    let key = frame_key::<SwappedFourToy, LEN>();

    let mut dec = key.create_decryptor(&nonce);
    dec.do_update_aad(b"aad").unwrap();
    let mut back = vec![0u8; LEN];
    dec.do_decrypt_out(&ct, &mut back).unwrap();
    assert_ne!(back, plaintext, "decryption must batch fours too");
    assert!(matches!(
        dec.do_decrypt_final_detached(&tag),
        Err(SymmetricCipherError::AEADTagCheckFailed)
    ));
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
    const LEN: usize = 6 * TOY_LEN + 5;
    let nonce = pinned_nonce();
    let aad = b"header";
    let plaintext = message(LEN);
    let (ct, tag) = seal::<Toy>(&nonce, aad, &plaintext);

    for split in 0..=LEN {
        let key = frame_key::<Toy, LEN>();
        let mut enc = key.create_encryptor_nonce(&nonce);
        enc.do_update_aad(aad).unwrap();
        let mut streamed = vec![0u8; LEN];
        enc.do_encrypt_out(&plaintext[..split], &mut streamed).unwrap();
        enc.do_encrypt_out(&plaintext[split..], &mut streamed[split..]).unwrap();
        let (_, _, streamed_tag) = enc.do_encrypt_final_detached().unwrap();
        assert_eq!(streamed_tag, tag, "tag, split at {split}");
        assert_eq!(streamed, ct, "ciphertext, split at {split}");

        let key = frame_key::<Toy, LEN>();

        let mut dec = key.create_decryptor(&nonce);
        dec.do_update_aad(aad).unwrap();
        let mut back = vec![0u8; LEN];
        dec.do_decrypt_out(&ct[..split], &mut back).unwrap();
        dec.do_decrypt_out(&ct[split..], &mut back[split..]).unwrap();
        dec.do_decrypt_final_detached(&tag)
            .unwrap_or_else(|e| panic!("tag check, split at {split}: {e:?}"));
        assert_eq!(back, plaintext, "plaintext, split at {split}");
    }
}

/// The frame is inside `B0` (A.2.1 Table 2's `Q`), so neither stream may be given more than it,
/// nor finalized with less: either would produce or verify a tag against a `B0` no counterpart
/// could reproduce. A refused update consumes nothing, so the flow is still usable.
#[test]
fn both_streams_hold_to_the_frame() {
    const LEN: usize = 8;
    let nonce = pinned_nonce();
    let plaintext = message(LEN);
    let (ct, tag) = seal::<Toy>(&nonce, &[], &plaintext);

    // Encrypting: too much is refused, and finalizing short is refused.
    let key = frame_key::<Toy, LEN>();
    let mut enc = key.create_encryptor_nonce(&nonce);
    let mut out = [0u8; 9];
    assert!(
        matches!(
            enc.do_encrypt_out(&[0x77u8; 9], &mut out),
            Err(SymmetricCipherError::StateError(_))
        ),
        "9 bytes against a frame of 8"
    );
    enc.do_encrypt_out(&plaintext[..4], &mut out).expect("4 of the 8 bytes");
    assert!(
        matches!(enc.do_encrypt_final_detached(), Err(SymmetricCipherError::StateError(_))),
        "finalizing 4 bytes short"
    );

    // Decrypting: the stream's bound is the frame plus an inline tag, and a final that has not
    // seen the frame reports a malformed ciphertext.
    let key = frame_key::<Toy, LEN>();
    let mut dec = key.create_decryptor(&nonce);
    let mut out = [0u8; LEN];
    assert!(
        matches!(
            dec.do_decrypt_out(&[0x77u8; LEN + TAG_LEN + 1], &mut out),
            Err(SymmetricCipherError::StateError(_))
        ),
        "more than the frame and a tag"
    );
    // ...and must not have debited the frame either: the 8 genuine bytes still verify.
    dec.do_decrypt_out(&ct, &mut out).unwrap();
    dec.do_decrypt_final_detached(&tag).unwrap();
    assert_eq!(out, plaintext[..]);

    let key = frame_key::<Toy, LEN>();

    let mut dec = key.create_decryptor(&nonce);
    dec.do_decrypt_out(&ct[..4], &mut out).unwrap();
    assert!(
        matches!(dec.do_decrypt_final_detached(&tag), Err(SymmetricCipherError::DecryptionFailed)),
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
    let (ct16, tag16) = seal::<Toy>(&nonce, aad, &plaintext);

    macro_rules! check_tag_len {
        ($t:literal) => {{
            let key = ToyKey::<Toy, CCM<NONCE_LEN, $t>>::from_key_material(&toy_key()).unwrap();
            let mut buf = plaintext.clone();
            let tag = key.encrypt_detached_in_place_nonce(&nonce, aad, &mut buf).unwrap();
            assert_eq!(buf, ct16, "ciphertext must not depend on TAG_LEN ({})", $t);
            key.decrypt_detached_in_place(&nonce, aad, &mut buf, &tag).unwrap();
            assert_eq!(buf, plaintext, "TAG_LEN={} round trip", $t);
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
/// limit: `q = 15 - n` and "by definition, p < 2^8q", which `CCM::MAX_PAYLOAD_LEN` exposes.
/// `sp800_38c_tests.rs` reaches `n` of 7, 8, 12 and 13 through Appendix C; 9, 10 and 11 are
/// reached only here. Over the toy alone, since where the nonce goes (A.2.1 Table 2, A.3 Table 3)
/// is the mode's business and not the permutation's.
#[test]
fn every_permitted_nonce_length_works() {
    fn round_trip<P, const KEY_LEN: usize, const N: usize>(
        key: &KeyMaterial<KEY_LEN>,
        expected_max_payload: u64,
    ) where
        P: ElectronicCodeBook<KEY_LEN, 16> + ModeNames + Clone,
    {
        // The full 16-byte tag, deliberately. `Toy` permutes each byte independently, so under
        // it the CBC-MAC is sixteen independent byte-chains and a `t`-byte tag witnesses only the
        // first `t` of them; the last nonce octet flipped below sits at block octet `N`, which an
        // 8-byte tag would never see once `N >= 8`. Real AES mixes every byte into every other,
        // so this is a limit of the toy, not of the mode.
        type Mode<const N: usize> = CCM<N, 16>;
        assert_eq!(
            Mode::<N>::MAX_PAYLOAD_LEN,
            expected_max_payload,
            "n = {N}: the payload limit 2^8q - 1 that q = 15 - n implies"
        );
        let key = ToyKey::<P, Mode<N>>::from_perm(P::new(key).unwrap());

        let nonce: [u8; N] = core::array::from_fn(|i| (i as u8).wrapping_mul(11).wrapping_add(3));
        let plaintext = message(100);
        let mut buf = plaintext.clone();
        let tag = key.encrypt_detached_in_place_nonce(&nonce, b"aad", &mut buf).unwrap();
        assert_ne!(buf, plaintext, "nonce length {N}: must actually encrypt");
        let ct = buf.clone();

        key.decrypt_detached_in_place(&nonce, b"aad", &mut buf, &tag).unwrap();
        assert_eq!(buf, plaintext, "nonce length {N}: round trip");

        // The last nonce octet sits right before `Q` in B0 (Table 2) and before the counter in
        // every `Ctr_i` (Table 3); flipping it must change both and so fail the check.
        let mut wrong = nonce;
        wrong[N - 1] ^= 0x01;
        let mut buf = ct;
        assert!(
            matches!(
                key.decrypt_detached_in_place(&wrong, b"aad", &mut buf, &tag),
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
/// be revealed." The in-place one-shot honours that -- the caller's buffer comes back zeroized --
/// because it has the whole ciphertext before it starts. The stream cannot: Sec 6.2 recovers `P`
/// (step 5) before it can verify it (step 10), and the fixed-frame `CcmPacketDecryptor` releases `P`
/// as it is recovered rather than hold the frame back, so by the time the final rejects the tag
/// the plaintext is already in the caller's buffer, as its docs warn. Pinning the difference
/// makes it a documented property rather than an accident.
#[test]
fn the_one_shot_releases_nothing_on_forgery_but_the_stream_does() {
    const LEN: usize = 19;
    let nonce = pinned_nonce();
    let plaintext = *b"do not trust me yet";
    let (ct, mut tag) = seal::<Toy>(&nonce, b"aad", &plaintext);
    tag[0] ^= 0xFF; // forge it

    // The one-shot: verify-then-return, so a forged tag leaves nothing but zeros.
    let mut buf = ct.clone();
    assert!(matches!(
        declared_key::<Toy>().decrypt_detached_in_place(&nonce, b"aad", &mut buf, &tag),
        Err(SymmetricCipherError::AEADTagCheckFailed)
    ));
    assert_eq!(buf, [0u8; LEN], "the one-shot must zeroize its buffer on a forged tag");

    // The stream: the payload is released by the update that brings it, the finals release
    // nothing, and a rejected tag cannot take it back. The detached final leaves its (unused)
    // buffer alone rather than zeroizing it, since there is nothing of the plaintext in it.
    let key = frame_key::<Toy, LEN>();
    let mut dec = key.create_decryptor(&nonce);
    dec.do_update_aad(b"aad").unwrap();
    let mut streamed = [0u8; LEN];
    assert_eq!(dec.do_decrypt_out(&ct, &mut streamed).unwrap(), LEN, "released mid-stream");
    assert_eq!(&streamed[..], &plaintext[..], "the stream already produced plaintext");
    let mut detached = [0xEEu8; 16];
    assert!(matches!(
        dec.do_decrypt_final_detached_out(&tag, &mut detached),
        Err(SymmetricCipherError::AEADTagCheckFailed)
    ));
    assert_eq!(&streamed[..], &plaintext[..], "...and a rejected tag cannot take it back");
    assert_eq!(detached, [0u8; 16], "the detached final only zeroes its buffer");

    let mut inline = ct.clone();
    inline.extend_from_slice(&tag);
    let key = frame_key::<Toy, LEN>();
    let mut dec = key.create_decryptor(&nonce);
    dec.do_update_aad(b"aad").unwrap();
    let mut streamed = [0u8; LEN];
    assert_eq!(dec.do_decrypt_out(&inline, &mut streamed).unwrap(), LEN);
    assert_eq!(&streamed[..], &plaintext[..]);
    assert!(matches!(dec.do_decrypt_final(), Err(SymmetricCipherError::AEADTagCheckFailed)));
}

/// A payload large enough to blow the stack if it were copied there, through the in-place
/// one-shots, which hold nothing but the caller's one buffer.
#[test]
fn a_large_payload_round_trips_in_place() {
    const LARGE_LEN: usize = 5 * 1024 * 1024;
    let nonce = pinned_nonce();
    let aad = b"header";
    let plaintext = message(LARGE_LEN);

    let (ct, tag) = seal::<Toy>(&nonce, aad, &plaintext);
    assert_ne!(ct, plaintext, "must actually encrypt");
    assert_eq!(open::<Toy>(&nonce, aad, &ct, &tag).unwrap(), plaintext, "in-place round trip");
}

/// The construction suite for both keys: the type, binding and strength policy of
/// `from_key_material`.
#[test]
fn the_keys_enforce_the_material_policy() {
    let framework = TestFrameworkFromKeyMaterial::new();
    framework.test::<TOY_LEN, DeclaredKey<Toy>>(Toy::CCM_ALG_NAME, SecurityStrength::_128bit);
    framework.test::<TOY_LEN, FrameKey<Toy, 32>>(Toy::CCM_ALG_NAME, SecurityStrength::_128bit);
}

/// A refused `do_encrypt_out` / `do_decrypt_out` on the any-length workers leaves nothing of the
/// input in the caller's buffer, and zeroes the buffer first as every `_out` method must: payload
/// offered while declared AAD is still owed, and payload past the declared length, on both sides.
/// The refusal must come before the copy; the inner `Ccm` refuses the same calls, but only after
/// the bytes have been copied.
#[test]
fn a_refused_update_leaves_no_payload_in_the_output_buffer() {
    let key = declared_key::<Toy>();
    let nonce = pinned_nonce();
    let payload = [0x5Au8; 16];

    // AAD still owed: the four bytes declared have not been supplied. An empty update is still
    // a no-op, not a refusal.
    let mut enc = key.create_encryptor_nonce(&nonce, 4, 16).unwrap();
    let mut out = [0xEEu8; 32];
    assert_eq!(enc.do_encrypt_out(&[], &mut out).unwrap(), 0, "an empty update is accepted");
    let mut out = [0xEEu8; 32];
    assert!(matches!(
        enc.do_encrypt_out(&payload, &mut out),
        Err(SymmetricCipherError::StateError(_))
    ));
    assert_eq!(out, [0u8; 32], "a refused encrypt must leave only zeros behind");

    // Past the declared payload length.
    let mut enc = key.create_encryptor_nonce(&nonce, 0, 8).unwrap();
    let mut out = [0xEEu8; 32];
    assert!(matches!(
        enc.do_encrypt_out(&payload, &mut out),
        Err(SymmetricCipherError::StateError(_))
    ));
    assert_eq!(out, [0u8; 32], "an over-length encrypt must leave only zeros behind");

    // The decryptor, with AAD still owed: the sixteen bytes are within the declared payload, so
    // they are not held back as a tag, and must not be copied either.
    let mut dec = key.create_decryptor(&nonce, 4, 16).unwrap();
    let mut out = [0xEEu8; 32];
    assert!(matches!(
        dec.do_decrypt_out(&payload, &mut out),
        Err(SymmetricCipherError::StateError(_))
    ));
    assert_eq!(out, [0u8; 32], "a refused decrypt must leave only zeros behind");

    // An accepted update still zeroes the buffer past what it wrote.
    let mut enc = key.create_encryptor_nonce(&nonce, 0, 16).unwrap();
    let mut out = [0xEEu8; 32];
    assert_eq!(enc.do_encrypt_out(&payload, &mut out).unwrap(), 16);
    assert_eq!(out[16..], [0u8; 16], "the bytes past the ciphertext must be zeroed");
}
