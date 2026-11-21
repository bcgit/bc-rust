//! Structural tests for XTS, driven by a toy permutation: the key constructor's refusals,
//! ciphertext stealing as SP 800-38E Sec 5 describes it, which ciphertext blocks a change to each
//! plaintext block reaches, and that the pair and four-block paths are really taken. The known
//! answers -- NIST ACVP, Wycheproof and OpenSSL -- and the 64-byte key are in the `aes` crate,
//! `crypto/aes/tests/xts_*.rs`.

mod common;

use bouncycastle_cipher::modes::XTSKey;
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::FromKeyMaterial;
use bouncycastle_core_test_framework::from_key_material::TestFrameworkFromKeyMaterial;
use common::{SwappedFourToy, SwappedPairToy, Toy};

const TWEAK: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

/// `Key_1 | Key_2` for the toy, with distinct halves.
fn key_bytes() -> [u8; 32] {
    core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3))
}

fn material(bytes: &[u8]) -> KeyMaterial<32> {
    KeyMaterial::<32>::from_bytes_as_type(bytes, KeyType::SymmetricCipherKey).unwrap()
}

fn toy_xts<P, const N: usize>() -> XTSKey<P, N>
where
    XTSKey<P, N>: FromKeyMaterial<32>,
{
    XTSKey::<P, N>::from_key_material(&material(&key_bytes())).expect("a valid XTS key")
}

fn pattern<const N: usize>() -> [u8; N] {
    core::array::from_fn(|k| (k as u8).wrapping_mul(13).wrapping_add(5))
}

fn encrypt<const N: usize>(pt: &[u8; N]) -> [u8; N] {
    let mut data_unit = *pt;
    toy_xts::<Toy, N>().encrypt_inplace(&TWEAK, &mut data_unit);
    data_unit
}

// ---- the key -----------------------------------------------------------------------------------

/// The construction suite: key type, strength and `generate`.
#[test]
fn the_key_enforces_the_material_policy() {
    TestFrameworkFromKeyMaterial::new()
        .test::<32, XTSKey<Toy, 512>>("XTS over the toy", SecurityStrength::_128bit);
}

fn refusal(key: &KeyMaterial<32>) -> KeyMaterialError {
    match XTSKey::<Toy, 16>::from_key_material(key) {
        Err(SymmetricCipherError::KeyMaterialError(e)) => e,
        Err(e) => panic!("refused, but not as a KeyMaterialError: {e:?}"),
        Ok(_) => panic!("accepted"),
    }
}

/// FIPS 140-3 IG C.I: Key_1 = Key_2 is refused. Halves that differ only in their last byte, or
/// only in their first, are not.
#[test]
fn equal_halves_are_refused() {
    let half: [u8; 16] = core::array::from_fn(|i| i as u8 + 0x40);
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&half);
    bytes[16..].copy_from_slice(&half);
    assert!(matches!(refusal(&material(&bytes)), KeyMaterialError::GenericError(_)));

    for differing in [16, 31] {
        let mut close = bytes;
        close[differing] ^= 0x01;
        XTSKey::<Toy, 16>::from_key_material(&material(&close))
            .expect("halves that differ in one byte are accepted");
    }
}

/// A half of all zeros is refused, as the permutation refuses an all-zero key; so is a key of
/// all zeros, which `KeyMaterial` tags as zeroized.
#[test]
fn zero_halves_are_refused() {
    let mut low_zero = key_bytes();
    low_zero[..16].fill(0);
    let mut high_zero = key_bytes();
    high_zero[16..].fill(0);
    for bytes in [low_zero, high_zero, [0u8; 32]] {
        assert!(matches!(refusal(&material(&bytes)), KeyMaterialError::InvalidKeyType(_)));
    }
}

/// A `KeyMaterial<32>` holding fewer than 32 bytes is refused rather than split short.
#[test]
fn a_short_key_is_refused() {
    for len in [1, 16, 31] {
        let short = material(&key_bytes()[..len]);
        assert_eq!(short.key_len(), len);
        assert_eq!(refusal(&short), KeyMaterialError::InvalidLength);
    }
}

// ---- ciphertext stealing -----------------------------------------------------------------------

/// Ciphertext stealing (IEEE 1619-2007 Sec 5.3.2 step 4) for a data unit of `LEN` = 16m + b
/// bytes, against the encryption of whole blocks. `ALIGNED` is 16m, and `NEXT` 16(m + 1).
/// SP 800-38E Sec 5: "Cm is the truncation of a block that is derived from Pm-1, and Cm-1 is
/// derived from Pm, concatenated with the discarded bits from the truncation."
fn stealing<const ALIGNED: usize, const LEN: usize, const NEXT: usize>() {
    assert!(ALIGNED.is_multiple_of(16) && ALIGNED < LEN && LEN < NEXT && NEXT == ALIGNED + 16);
    let b = LEN - ALIGNED;
    let last = ALIGNED - 16; // where block m - 1 starts

    let pt: [u8; LEN] = pattern();
    let ct = encrypt(&pt);

    // The whole blocks P_0 .. P_{m-1}, encrypted on their own: CC, the encryption of P_{m-1} under
    // index m - 1, is the last of them.
    let aligned = encrypt::<ALIGNED>(pt[..ALIGNED].try_into().unwrap());
    let cc = &aligned[last..];

    // Nothing before C_{m-1} is touched.
    assert_eq!(ct[..last], aligned[..last], "{LEN} bytes: the leading blocks");
    // C_m is CC truncated to b bytes, and is the tail of the ciphertext.
    assert_eq!(ct[ALIGNED..], cc[..b], "{LEN} bytes: C_m");
    // C_{m-1} is P_m || CC[b..] encrypted under index m: block m of a data unit one block longer.
    let mut q: [u8; NEXT] = [0; NEXT];
    q[..ALIGNED].copy_from_slice(&pt[..ALIGNED]);
    q[ALIGNED..ALIGNED + b].copy_from_slice(&pt[ALIGNED..]);
    q[ALIGNED + b..].copy_from_slice(&cc[b..]);
    assert_eq!(ct[last..ALIGNED], encrypt(&q)[ALIGNED..], "{LEN} bytes: C_m-1");

    // And decryption undoes it.
    let mut back = ct;
    toy_xts::<Toy, LEN>().decrypt_inplace(&TWEAK, &mut back);
    assert_eq!(back, pt, "{LEN} bytes: decryption");
}

#[test]
fn ciphertext_stealing_is_as_sp_800_38e_describes_it() {
    stealing::<16, 17, 32>(); // m = 1, b = 1
    stealing::<16, 31, 32>(); // m = 1, b = 15
    stealing::<32, 39, 48>(); // m = 2, b = 7
    stealing::<80, 83, 96>(); // m = 5, b = 3: the four path, then one block, before stealing
    stealing::<128, 137, 144>(); // m = 8, b = 9
}

// ---- which blocks a change reaches -------------------------------------------------------------

/// The ciphertext blocks (16-byte chunks, the last one short) that differ between `a` and `b`.
fn changed_blocks<const N: usize>(a: &[u8; N], b: &[u8; N]) -> Vec<usize> {
    a.chunks(16)
        .zip(b.chunks(16))
        .enumerate()
        .filter(|(_, (x, y))| x != y)
        .map(|(j, _)| j)
        .collect()
}

/// Each block is encrypted on its own under its position's mask, so a change to plaintext block
/// j reaches ciphertext block j only. With a partial block, P_{m-1} reaches both stolen blocks and
/// P_m only C_{m-1}.
#[test]
fn a_change_reaches_only_its_own_blocks() {
    let pt: [u8; 64] = pattern();
    let ct = encrypt(&pt);
    for j in 0..4 {
        let mut changed = pt;
        changed[16 * j..16 * (j + 1)].iter_mut().for_each(|b| *b = !*b);
        assert_eq!(changed_blocks(&ct, &encrypt(&changed)), [j], "aligned, block {j}");
    }

    // m = 2, b = 8: P_0, P_1 = P_{m-1}, and the tail P_2 = P_m.
    let pt: [u8; 40] = pattern();
    let ct = encrypt(&pt);
    for (range, reached) in [(0..16, &[0][..]), (16..32, &[1, 2][..]), (32..40, &[1][..])] {
        let mut changed = pt;
        changed[range.clone()].iter_mut().for_each(|b| *b = !*b);
        assert_eq!(changed_blocks(&ct, &encrypt(&changed)), reached, "stealing, bytes {range:?}");
    }
}

// ---- the batched paths -------------------------------------------------------------------------

/// The pair path must be taken. [`SwappedPairToy`] returns its two pair results in the wrong
/// order and is otherwise [`Toy`], so a data unit of two whole blocks comes out differently over
/// it in either direction, while a single block, which takes the one-block path, does not.
#[test]
fn the_pair_path_is_really_used() {
    let pt = [0x3Cu8; 32];
    let ct = encrypt(&pt);
    let mut swapped = pt;
    toy_xts::<SwappedPairToy, 32>().encrypt_inplace(&TWEAK, &mut swapped);
    assert_ne!(swapped, ct, "two blocks must go through encrypt_2blocks");
    let mut back = ct;
    toy_xts::<SwappedPairToy, 32>().decrypt_inplace(&TWEAK, &mut back);
    assert_ne!(back, pt, "two blocks must go through decrypt_2blocks");

    let one = [0x3Cu8; 16];
    let mut swapped = one;
    toy_xts::<SwappedPairToy, 16>().encrypt_inplace(&TWEAK, &mut swapped);
    assert_eq!(swapped, encrypt(&one), "one block must not pair");
}

/// The four-block path must be taken, for whole fours only. [`SwappedFourToy`] rotates its four
/// results and is otherwise [`Toy`], so four blocks come out differently over it in either
/// direction, while three, a pair and one, do not.
#[test]
fn the_four_block_path_is_really_used() {
    let pt = [0xC3u8; 64];
    let ct = encrypt(&pt);
    let mut swapped = pt;
    toy_xts::<SwappedFourToy, 64>().encrypt_inplace(&TWEAK, &mut swapped);
    assert_ne!(swapped, ct, "four blocks must go through encrypt_4blocks");
    let mut back = ct;
    toy_xts::<SwappedFourToy, 64>().decrypt_inplace(&TWEAK, &mut back);
    assert_ne!(back, pt, "four blocks must go through decrypt_4blocks");

    let three = [0xC3u8; 48];
    let mut swapped = three;
    toy_xts::<SwappedFourToy, 48>().encrypt_inplace(&TWEAK, &mut swapped);
    assert_eq!(swapped, encrypt(&three), "three blocks must not batch in four");
    let mut back = swapped;
    toy_xts::<SwappedFourToy, 48>().decrypt_inplace(&TWEAK, &mut back);
    assert_eq!(back, three);
}
