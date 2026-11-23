//! Structural tests for XTS, driven by a toy permutation: the key constructor's refusals, the
//! bounds on a data unit's length, ciphertext stealing as SP 800-38E Sec 5 describes it, which
//! ciphertext blocks a change to each plaintext block reaches, and that the pair and four-block
//! paths are really taken. The known answers -- NIST ACVP, Wycheproof and OpenSSL -- and the
//! 64-byte key are in the `aes` module, `crypto/symmetric/tests/aes_xts_*.rs`.

mod common;

use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::FromKeyMaterial;
use bouncycastle_core_test_framework::from_key_material::TestFrameworkFromKeyMaterial;
use bouncycastle_symmetric::modes::{XTS_MAX_DATA_UNIT_LEN, XTS_MIN_DATA_UNIT_LEN, XTSKey};
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

fn toy_xts<P>() -> XTSKey<P>
where
    XTSKey<P>: FromKeyMaterial<32>,
{
    XTSKey::<P>::from_key_material(&material(&key_bytes())).expect("a valid XTS key")
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|k| (k as u8).wrapping_mul(13).wrapping_add(5)).collect()
}

fn encrypt(pt: &[u8]) -> Vec<u8> {
    let mut data_unit = pt.to_vec();
    assert_eq!(toy_xts::<Toy>().encrypt_inplace(&TWEAK, &mut data_unit), Ok(pt.len()));
    data_unit
}

// ---- the key -----------------------------------------------------------------------------------

/// The construction suite: key type, strength and `generate`.
#[test]
fn the_key_enforces_the_material_policy() {
    TestFrameworkFromKeyMaterial::new()
        .test::<32, XTSKey<Toy>>("XTS over the toy", SecurityStrength::_128bit);
}

fn refusal(key: &KeyMaterial<32>) -> KeyMaterialError {
    match XTSKey::<Toy>::from_key_material(key) {
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
        XTSKey::<Toy>::from_key_material(&material(&close))
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

// ---- the length of a data unit -----------------------------------------------------------------

/// A data unit shorter than one block, an empty one included, is refused as an invalid length,
/// and one longer than 2^20 blocks as over the data limit, in both directions and before anything
/// is written: the buffer comes back as it went in.
#[test]
fn data_units_outside_the_bounds_are_refused_unchanged() {
    let key = toy_xts::<Toy>();
    for len in [0, 1, XTS_MIN_DATA_UNIT_LEN - 1, XTS_MAX_DATA_UNIT_LEN + 1] {
        let original = pattern(len);
        let mut data_unit = original.clone();
        let encrypted = key.encrypt_inplace(&TWEAK, &mut data_unit);
        assert!(data_unit == original, "encrypt, {len} bytes: the refused data unit was changed");
        let decrypted = key.decrypt_inplace(&TWEAK, &mut data_unit);
        assert!(data_unit == original, "decrypt, {len} bytes: the refused data unit was changed");

        for (direction, result) in [("encrypt", encrypted), ("decrypt", decrypted)] {
            if len < XTS_MIN_DATA_UNIT_LEN {
                assert!(
                    matches!(result, Err(SymmetricCipherError::InvalidInputLength(_))),
                    "{direction}, {len} bytes: {result:?}"
                );
            } else {
                assert_eq!(result, Err(SymmetricCipherError::DataLimitExceeded), "{direction}");
            }
        }
    }
}

/// The bounds themselves are data units: one block, and 2^20 blocks, each through a round trip
/// that reports the whole length in both directions.
#[test]
fn the_shortest_and_the_longest_data_units_are_accepted() {
    let key = toy_xts::<Toy>();
    for len in [XTS_MIN_DATA_UNIT_LEN, XTS_MAX_DATA_UNIT_LEN] {
        let pt = pattern(len);
        let mut data_unit = pt.clone();
        assert_eq!(key.encrypt_inplace(&TWEAK, &mut data_unit), Ok(len), "{len} bytes: encrypt");
        assert!(data_unit != pt, "{len} bytes: encryption changed nothing");
        assert_eq!(key.decrypt_inplace(&TWEAK, &mut data_unit), Ok(len), "{len} bytes: decrypt");
        assert!(data_unit == pt, "{len} bytes: the round trip");
    }
}

/// One key takes data units of different lengths, each in its own call: the length is the
/// caller's to keep to.
#[test]
fn one_key_takes_any_valid_length() {
    let key = toy_xts::<Toy>();
    for len in [16, 17, 512, 4095] {
        let pt = pattern(len);
        let mut data_unit = pt.clone();
        assert_eq!(key.encrypt_inplace(&TWEAK, &mut data_unit), Ok(len));
        assert_eq!(key.decrypt_inplace(&TWEAK, &mut data_unit), Ok(len));
        assert_eq!(data_unit, pt);
    }
}

// ---- ciphertext stealing -----------------------------------------------------------------------

/// Ciphertext stealing (IEEE 1619-2007 Sec 5.3.2 step 4) for a data unit of 16m + b bytes, against
/// the encryption of whole blocks. SP 800-38E Sec 5: "Cm is the truncation of a block that is
/// derived from Pm-1, and Cm-1 is derived from Pm, concatenated with the discarded bits from the
/// truncation."
fn stealing(m: usize, b: usize) {
    assert!(m >= 1 && (1..16).contains(&b));
    let aligned = 16 * m; // where P_m starts
    let len = aligned + b;
    let last = aligned - 16; // where block m - 1 starts

    let pt = pattern(len);
    let ct = encrypt(&pt);

    // The whole blocks P_0 .. P_{m-1}, encrypted on their own: CC, the encryption of P_{m-1} under
    // index m - 1, is the last of them.
    let whole = encrypt(&pt[..aligned]);
    let cc = &whole[last..];

    // Nothing before C_{m-1} is touched.
    assert_eq!(ct[..last], whole[..last], "{len} bytes: the leading blocks");
    // C_m is CC truncated to b bytes, and is the tail of the ciphertext.
    assert_eq!(ct[aligned..], cc[..b], "{len} bytes: C_m");
    // C_{m-1} is P_m || CC[b..] encrypted under index m: block m of a data unit one block longer.
    let mut q = Vec::with_capacity(aligned + 16);
    q.extend_from_slice(&pt[..aligned]);
    q.extend_from_slice(&pt[aligned..]);
    q.extend_from_slice(&cc[b..]);
    assert_eq!(ct[last..aligned], encrypt(&q)[aligned..], "{len} bytes: C_m-1");

    // And decryption undoes it.
    let mut back = ct;
    assert_eq!(toy_xts::<Toy>().decrypt_inplace(&TWEAK, &mut back), Ok(len));
    assert_eq!(back, pt, "{len} bytes: decryption");
}

#[test]
fn ciphertext_stealing_is_as_sp_800_38e_describes_it() {
    stealing(1, 1);
    stealing(1, 15);
    stealing(2, 7);
    stealing(5, 3); // the four path, then one block, before stealing
    stealing(8, 9);
}

// ---- which blocks a change reaches -------------------------------------------------------------

/// The ciphertext blocks (16-byte chunks, the last one short) that differ between `a` and `b`.
fn changed_blocks(a: &[u8], b: &[u8]) -> Vec<usize> {
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
    let pt = pattern(64);
    let ct = encrypt(&pt);
    for j in 0..4 {
        let mut changed = pt.clone();
        changed[16 * j..16 * (j + 1)].iter_mut().for_each(|b| *b = !*b);
        assert_eq!(changed_blocks(&ct, &encrypt(&changed)), [j], "aligned, block {j}");
    }

    // m = 2, b = 8: P_0, P_1 = P_{m-1}, and the tail P_2 = P_m.
    let pt = pattern(40);
    let ct = encrypt(&pt);
    for (range, reached) in [(0..16, &[0][..]), (16..32, &[1, 2][..]), (32..40, &[1][..])] {
        let mut changed = pt.clone();
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
    toy_xts::<SwappedPairToy>().encrypt_inplace(&TWEAK, &mut swapped).unwrap();
    assert_ne!(swapped[..], ct, "two blocks must go through encrypt_2blocks");
    let mut back = ct;
    toy_xts::<SwappedPairToy>().decrypt_inplace(&TWEAK, &mut back).unwrap();
    assert_ne!(back, pt, "two blocks must go through decrypt_2blocks");

    let one = [0x3Cu8; 16];
    let mut swapped = one;
    toy_xts::<SwappedPairToy>().encrypt_inplace(&TWEAK, &mut swapped).unwrap();
    assert_eq!(swapped[..], encrypt(&one), "one block must not pair");
}

/// The four-block path must be taken, for whole fours only. [`SwappedFourToy`] rotates its four
/// results and is otherwise [`Toy`], so four blocks come out differently over it in either
/// direction, while three, a pair and one, do not.
#[test]
fn the_four_block_path_is_really_used() {
    let pt = [0xC3u8; 64];
    let ct = encrypt(&pt);
    let mut swapped = pt;
    toy_xts::<SwappedFourToy>().encrypt_inplace(&TWEAK, &mut swapped).unwrap();
    assert_ne!(swapped[..], ct, "four blocks must go through encrypt_4blocks");
    let mut back = ct;
    toy_xts::<SwappedFourToy>().decrypt_inplace(&TWEAK, &mut back).unwrap();
    assert_ne!(back, pt, "four blocks must go through decrypt_4blocks");

    let three = [0xC3u8; 48];
    let mut swapped = three;
    toy_xts::<SwappedFourToy>().encrypt_inplace(&TWEAK, &mut swapped).unwrap();
    assert_eq!(swapped[..], encrypt(&three), "three blocks must not batch in four");
    let mut back = swapped;
    toy_xts::<SwappedFourToy>().decrypt_inplace(&TWEAK, &mut back).unwrap();
    assert_eq!(back, three);
}
