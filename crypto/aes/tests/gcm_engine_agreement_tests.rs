//! GCM over `Bitsliced`, the portable reference, against GCM over the default engine on this
//! target (see `arm_agreement_tests.rs`), on the same keys, nonces, AAD and plaintext, demanding
//! byte-identical ciphertext and tags and the same tag-check verdicts.
//!
//! What this pins is the AES half of GCM: the counter-mode keystream and the hash subkey
//! `H = CIPH_K(0^128)` come from the engine under test, and the plaintext and AAD lengths 0..=200
//! cross the one-block, four-block and 64-byte boundaries where the engines take their 1-, 2- and
//! 4-block paths and GHASH its four-block grouping. What it does not pin is GHASH itself: the
//! multiplier is chosen in `bouncycastle-cipher` independently of the AES engine, so on these
//! builds both sides multiply on PMULL. The GHASH kernel is pinned against the portable multiplier
//! by the `mul`-level test in `bouncycastle-cipher` and end to end by the ACVP, Wycheproof and BC
//! Java suites here.
//!
//! The engine is named through the permutation, `AESInternal<P, Bitsliced<P>>`, and the GCM key
//! state and workers are made through the hazmat mode traits, since a key object such as
//! `AES128Key<GCM>` always runs the default engine. Every key, nonce, AAD, plaintext, chunking,
//! split and corrupted bit comes from a seeded xorshift generator, and each failure message
//! carries the seed and the lengths, so a failure reproduces from the source alone.

// What this proves depends on the build:
// * `aes` declared: `Arm` against `Bitsliced`.
// * `-aes` with `std`: `Detected` against `Bitsliced`. On a CPU with FEAT_AES that is `Arm`
//   again; on one without, `Detected` runs `Bitsliced`, so the test compares `Bitsliced` with
//   itself and proves nothing about the fallback beyond that it runs.
// * `-aes` without `std`: the gate is false and the file compiles to nothing.
#![cfg(all(
    target_arch = "aarch64",
    target_endian = "little",
    target_feature = "neon",
    any(target_feature = "aes", feature = "std")
))]

use bouncycastle_aes::hazmat::AESInternal;
use bouncycastle_aes::hazmat::engine::{Bitsliced, DefaultEngine};
use bouncycastle_aes::{AES128Params, AES192Params, AES256Params};
use bouncycastle_cipher::modes::{GCM, GCM_NONCE_LEN};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::hazmat::{AeadDecryptMode, AeadEncryptMode, ElectronicCodeBook, Mode};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};

const TAG_LEN: usize = 16;
type Tag = [u8; TAG_LEN];

/// The xorshift64 generator the GHASH tests in `bouncycastle-cipher` use: deterministic from its
/// seed, which must be nonzero.
struct Lcg(u64);

impl Lcg {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next_u64() as u8).collect()
    }

    /// A draw from `0..bound`; `bound` is small, so the modulo bias is irrelevant here.
    fn below(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }
}

/// How a message is handed to a streaming worker.
#[derive(Clone, Copy, Debug)]
enum Feed {
    Whole,
    Bytewise,
    RandomChunks,
}

/// Splits `data` into the pieces `feed` calls for. Random chunks are 1 to 40 bytes, so a chunk
/// can end inside a block, on a block boundary, or past a four-block run.
fn pieces<'a>(rng: &mut Lcg, data: &'a [u8], feed: Feed) -> Vec<&'a [u8]> {
    match feed {
        Feed::Whole => vec![data],
        Feed::Bytewise => data.chunks(1).collect(),
        Feed::RandomChunks => {
            let mut out = Vec::new();
            let mut rest = data;
            while !rest.is_empty() {
                let take = (1 + rng.below(40)).min(rest.len());
                let (head, tail) = rest.split_at(take);
                out.push(head);
                rest = tail;
            }
            out
        }
    }
}

/// Encrypts `pt` under `state` and `nonce`, giving `aad` and `pt` to the encryptor in the pieces
/// `feed` calls for, and returns the ciphertext and the detached tag.
fn encrypt<const K: usize, P>(
    rng: &mut Lcg,
    state: &<GCM as Mode<P>>::KeyState,
    nonce: &[u8; GCM_NONCE_LEN],
    aad: &[u8],
    pt: &[u8],
    feed: Feed,
) -> (Vec<u8>, Tag)
where
    GCM: AeadEncryptMode<P, K, GCM_NONCE_LEN, TAG_LEN, TAG_LEN>,
{
    let mut enc =
        <GCM as AeadEncryptMode<P, K, GCM_NONCE_LEN, TAG_LEN, TAG_LEN>>::encrypt_init_nonce(
            state, nonce,
        );
    for piece in pieces(rng, aad, feed) {
        enc.do_update_aad(piece).unwrap();
    }
    let mut ct = Vec::with_capacity(pt.len());
    for piece in pieces(rng, pt, feed) {
        let mut out = vec![0u8; enc.do_encrypt_out_len(piece.len())];
        let written = enc.do_encrypt_out(piece, &mut out).unwrap();
        ct.extend_from_slice(&out[..written]);
    }
    let (last, last_len, tag) = enc.do_encrypt_final_detached().unwrap();
    ct.extend_from_slice(&last[..last_len]);
    (ct, tag)
}

/// Decrypts `ct` under `state`, `nonce` and the detached `tag`, giving the ciphertext to the
/// decryptor split at `splits` (sorted offsets into `ct`). Returns the plaintext, or the error
/// from the final tag check.
fn decrypt<const K: usize, P>(
    state: &<GCM as Mode<P>>::KeyState,
    nonce: &[u8; GCM_NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
    tag: &Tag,
    splits: &[usize],
) -> Result<Vec<u8>, SymmetricCipherError>
where
    GCM: AeadDecryptMode<P, K, GCM_NONCE_LEN, TAG_LEN, TAG_LEN>,
{
    let mut dec =
        <GCM as AeadDecryptMode<P, K, GCM_NONCE_LEN, TAG_LEN, TAG_LEN>>::decrypt_init(state, nonce);
    dec.do_update_aad(aad).unwrap();
    let mut pt = Vec::with_capacity(ct.len());
    let mut start = 0;
    for &end in splits.iter().chain(core::iter::once(&ct.len())) {
        let piece = &ct[start..end];
        let mut out = vec![0u8; dec.do_decrypt_out_len(piece.len())];
        let written = dec.do_decrypt_out(piece, &mut out).unwrap();
        pt.extend_from_slice(&out[..written]);
        start = end;
    }
    let (last, last_len) = dec.do_decrypt_final_detached(tag)?;
    pt.extend_from_slice(&last[..last_len]);
    Ok(pt)
}

/// Up to three sorted split points in `0..=len`, so a decrypt can be split anywhere, including at
/// the ends.
fn random_splits(rng: &mut Lcg, len: usize) -> Vec<usize> {
    let mut splits: Vec<usize> = (0..rng.below(4)).map(|_| rng.below(len + 1)).collect();
    splits.sort_unstable();
    splits
}

/// For every plaintext length in 0..=200, with an AAD length that walks all of 0..=200 over the
/// sweep (7 and 201 are coprime), runs GCM over engine `A` and engine `B` on one key, nonce, AAD
/// and plaintext drawn from `Lcg(seed)`, through every feeding, and demands identical output,
/// agreeing decryption, and that a one-bit change to the ciphertext or the tag fails on both.
fn agree<const K: usize, A, B>(seed: u64)
where
    A: ElectronicCodeBook<K, 16>,
    B: ElectronicCodeBook<K, 16>,
    GCM: AeadEncryptMode<A, K, GCM_NONCE_LEN, TAG_LEN, TAG_LEN>
        + AeadDecryptMode<A, K, GCM_NONCE_LEN, TAG_LEN, TAG_LEN>
        + AeadEncryptMode<B, K, GCM_NONCE_LEN, TAG_LEN, TAG_LEN>
        + AeadDecryptMode<B, K, GCM_NONCE_LEN, TAG_LEN, TAG_LEN>,
{
    let rng = &mut Lcg(seed);
    for pt_len in 0..=200usize {
        let aad_len = (pt_len * 7) % 201;
        let key_bytes = rng.bytes(K);
        let key =
            KeyMaterial::<K>::from_bytes_as_type(&key_bytes, KeyType::SymmetricCipherKey).unwrap();
        let state_a = <GCM as Mode<A>>::key_state(A::new(&key).unwrap());
        let state_b = <GCM as Mode<B>>::key_state(B::new(&key).unwrap());
        let nonce: [u8; GCM_NONCE_LEN] = rng.bytes(GCM_NONCE_LEN).try_into().unwrap();
        let aad = rng.bytes(aad_len);
        let pt = rng.bytes(pt_len);
        let ctx = format!("seed={seed:#018x} K={K} pt_len={pt_len} aad_len={aad_len}");

        let (ct, tag) = encrypt::<K, A>(rng, &state_a, &nonce, &aad, &pt, Feed::Whole);
        assert_eq!(ct.len(), pt_len, "{ctx}: ciphertext length");
        for feed in [Feed::Whole, Feed::Bytewise, Feed::RandomChunks] {
            let (ct_b, tag_b) = encrypt::<K, B>(rng, &state_b, &nonce, &aad, &pt, feed);
            assert_eq!(ct_b, ct, "{ctx} {feed:?}: ciphertext differs between engines");
            assert_eq!(tag_b, tag, "{ctx} {feed:?}: tag differs between engines");
        }

        let splits = random_splits(rng, ct.len());
        let pt_a = decrypt::<K, A>(&state_a, &nonce, &aad, &ct, &tag, &splits);
        let pt_b = decrypt::<K, B>(&state_b, &nonce, &aad, &ct, &tag, &splits);
        assert_eq!(pt_a.as_deref(), Ok(&pt[..]), "{ctx} splits={splits:?}: engine A decrypt");
        assert_eq!(pt_b.as_deref(), Ok(&pt[..]), "{ctx} splits={splits:?}: engine B decrypt");

        let mut bad_tag = tag;
        bad_tag[rng.below(TAG_LEN)] ^= 1 << rng.below(8);
        let mut bad = vec![
            decrypt::<K, A>(&state_a, &nonce, &aad, &ct, &bad_tag, &splits),
            decrypt::<K, B>(&state_b, &nonce, &aad, &ct, &bad_tag, &splits),
        ];
        if !ct.is_empty() {
            let mut bad_ct = ct.clone();
            bad_ct[rng.below(ct.len())] ^= 1 << rng.below(8);
            bad.push(decrypt::<K, A>(&state_a, &nonce, &aad, &bad_ct, &tag, &splits));
            bad.push(decrypt::<K, B>(&state_b, &nonce, &aad, &bad_ct, &tag, &splits));
        }
        for result in bad {
            assert_eq!(
                result,
                Err(SymmetricCipherError::AEADTagCheckFailed),
                "{ctx}: a one-bit change must fail the tag check on both engines"
            );
        }
    }
}

#[test]
fn gcm_agrees_across_engines_for_aes128() {
    agree::<
        16,
        AESInternal<AES128Params, Bitsliced<AES128Params>>,
        AESInternal<AES128Params, DefaultEngine<AES128Params>>,
    >(0x6a09_e667_f3bc_c908);
}

#[test]
fn gcm_agrees_across_engines_for_aes192() {
    agree::<
        24,
        AESInternal<AES192Params, Bitsliced<AES192Params>>,
        AESInternal<AES192Params, DefaultEngine<AES192Params>>,
    >(0xbb67_ae85_84ca_a73b);
}

#[test]
fn gcm_agrees_across_engines_for_aes256() {
    agree::<
        32,
        AESInternal<AES256Params, Bitsliced<AES256Params>>,
        AESInternal<AES256Params, DefaultEngine<AES256Params>>,
    >(0x3c6e_f372_fe94_f82b);
}
