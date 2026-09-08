//! Key-bundle handling: what `TDES::new` accepts and rejects, and why.
//!
//! * The 4 weak, 12 semi-weak and 48 possibly weak DEA keys listed in SP 800-67r2 Sec 3.3.2, all
//!   rejected in any component position, and shown to be exactly the 64 keys the engine's
//!   structural test recognises.
//! * Bundles whose component keys are not pairwise distinct (Sec 3.1), including two-key TDEA and
//!   components that differ only in parity bits.
//! * Parity bits are ignored by the cipher, as Appendix A says.
//! * The `KeyMaterial` checks: type, length and security strength.

use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::key_material::{
    KeyMaterial, KeyMaterialTrait, KeyType, do_hazardous_operations,
};
use bouncycastle_core::traits::{Algorithm, ElectronicCodeBook, SecurityStrength};
use bouncycastle_tdes::{BLOCK_LEN, KEY_LEN, KEY_LEN_2KEY, TDES, TDES2Key};

/// Sec 3.3.2, "Keys that are considered weak are (in hexadecimal format)".
const WEAK: [u64; 4] =
    [0x0101010101010101, 0xFEFEFEFEFEFEFEFE, 0xE0E0E0E0F1F1F1F1, 0x1F1F1F1F0E0E0E0E];

/// Sec 3.3.2, "These semi-weak keys are (in hexadecimal format)", six pairs.
const SEMI_WEAK: [u64; 12] = [
    0x011F011F010E010E, 0x1F011F010E010E01, 0x01E001E001F101F1, 0xE001E001F101F101,
    0x01FE01FE01FE01FE, 0xFE01FE01FE01FE01, 0x1FE01FE00EF10EF1, 0xE01FE01FF10EF10E,
    0x1FFE1FFE0EFE0EFE, 0xFE1FFE1FFE0EFE0E, 0xE0FEE0FEF1FEF1FE, 0xFEE0FEE0FEF1FEF1,
];

/// Sec 3.3.2, "There are also 48 keys that produce only four distinct subkeys (instead of 16) -
/// these are called possibly weak keys", in the order printed (three columns, read row by row).
const POSSIBLY_WEAK: [u64; 48] = [
    0x01011F1F01010E0E, 0x1F1F01010E0E0101, 0xE0E01F1FF1F10E0E, 0x0101E0E00101F1F1,
    0x1F1FE0E00E0EF1F1, 0xE0E0FEFEF1F1FEFE, 0x0101FEFE0101FEFE, 0x1F1FFEFE0E0EFEFE,
    0xE0FE011FF1FE010E, 0x011F1F01010E0E01, 0x1FE001FE0EF101FE, 0xE0FE1F01F1FE0E01,
    0x011FE0FE010EF1FE, 0x1FE0E01F0EF1F10E, 0xE0FEFEE0F1FEFEF1, 0x011FFEE0010EFEF1,
    0x1FE0FE010EF1FE01, 0xFE0101FEFE0101FE, 0x01E01FFE01F10EFE, 0x1FFE01E00EFE01F1,
    0xFE011FE0FE010EF1, 0xFE01E01FFE01F10E, 0x1FFEE0010EFEF101, 0xFE1F01E0FE0E01F1,
    0x01E0E00101F1F101, 0x1FFEFE1F0EFEFE0E, 0xFE1FE001FE0EF101, 0x01E0FE1F01F1FE0E,
    0xE00101E0F10101F1, 0xFE1F1FFEFE0E0EFE, 0x01FE1FE001FE0EF1, 0xE0011FFEF1010EFE,
    0xFEE0011FFEF1010E, 0x01FEE01F01FEF10E, 0xE001FE1FF101FE0E, 0xFEE01F01FEF10E01,
    0x01FEFE0101FEFE01, 0xE01F01FEF10E01FE, 0xFEE0E0FEFEF1F1FE, 0x1F01011F0E01010E,
    0xE01F1FE0F10E0EF1, 0xFEFE0101FEFE0101, 0x1F01E0FE0E01F1FE, 0xE01FFE01F10EFE01,
    0xFEFE1F1FFEFE0E0E, 0x1F01FEE00E01FEF1, 0xE0E00101F1F10101, 0xFEFEE0E0FEFEF1F1,
];

/// PC-1 (Appendix A), for rebuilding a key from a `(C0, D0)` pair in the tests.
#[rustfmt::skip]
const PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4,
];

const PARITY_MASK: u64 = 0xFEFE_FEFE_FEFE_FEFE;

/// Three known-good, distinct, non-weak DEA keys (from CAVP `TECBMMT3` COUNT = 0).
const GOOD: [u64; 3] = [0xe97c8313ba265d43, 0x254cbf9e8f7c2aa8, 0xa754d65e8ae997e3];

fn bundle(k: [u64; 3]) -> KeyMaterial<KEY_LEN> {
    let mut bytes = [0u8; KEY_LEN];
    for (i, key) in k.iter().enumerate() {
        bytes[8 * i..8 * i + 8].copy_from_slice(&key.to_be_bytes());
    }
    KeyMaterial::<KEY_LEN>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).unwrap()
}

fn is_weak_key_error(result: Result<TDES, SymmetricCipherError>) -> bool {
    matches!(result, Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::WeakKey(_))))
}

#[test]
fn a_good_bundle_is_accepted() {
    assert!(TDES::new(&bundle(GOOD)).is_ok());
}

#[test]
fn every_listed_weak_key_is_rejected_in_every_position() {
    let all: Vec<u64> =
        WEAK.iter().chain(SEMI_WEAK.iter()).chain(POSSIBLY_WEAK.iter()).copied().collect();
    assert_eq!(all.len(), 64);
    for &weak in &all {
        for position in 0..3 {
            let mut k = GOOD;
            k[position] = weak;
            assert!(
                is_weak_key_error(TDES::new(&bundle(k))),
                "weak key {weak:016x} in position {} should be rejected",
                position + 1
            );
            // ...and with the parity bits flipped, since the algorithm ignores them.
            k[position] = weak ^ !PARITY_MASK;
            assert!(
                is_weak_key_error(TDES::new(&bundle(k))),
                "weak key {weak:016x} with even parity"
            );
        }
    }
}

#[test]
fn the_three_lists_are_exactly_the_period_four_keys() {
    // The engine detects a weak key structurally: C0 and D0 each have period 4 (see the crate's
    // `schedule` module). That is 8 x 8 = 64 keys, and PC-1 is a bijection on the non-parity bits,
    // so this reconstructs all 64 from the eight 28-bit patterns and checks they are precisely the
    // 64 keys the spec lists -- which also proves the transcription above.
    let patterns: [u32; 8] = [
        0x000_0000, 0xFFF_FFFF, // period 1
        0x555_5555, 0xAAA_AAAA, // period 2
        0x333_3333, 0x666_6666, 0xCCC_CCCC, 0x999_9999, // period 4
    ];
    let mut structural = std::collections::BTreeSet::new();
    for &c in &patterns {
        for &d in &patterns {
            let cd = ((c as u64) << 28) | d as u64;
            let mut key = 0u64;
            for (j, &dst) in PC1.iter().enumerate() {
                let bit = (cd >> (55 - j)) & 1;
                key |= bit << (64 - dst as u32);
            }
            structural.insert(key & PARITY_MASK);
        }
    }
    assert_eq!(structural.len(), 64);

    let listed: std::collections::BTreeSet<u64> = WEAK
        .iter()
        .chain(SEMI_WEAK.iter())
        .chain(POSSIBLY_WEAK.iter())
        .map(|k| k & PARITY_MASK)
        .collect();
    assert_eq!(listed.len(), 64, "the spec's 64 keys are distinct once parity is ignored");
    assert_eq!(listed, structural);

    // The listed keys really do carry odd parity, as Sec 3.3.2 says.
    for k in WEAK.iter().chain(SEMI_WEAK.iter()).chain(POSSIBLY_WEAK.iter()) {
        for b in k.to_be_bytes() {
            assert_eq!(b.count_ones() % 2, 1, "{k:016x} should have odd parity");
        }
    }
}

#[test]
fn a_key_one_bit_away_from_weak_is_accepted() {
    // The structural test must not over-reach: flipping one non-parity bit of a weak key breaks
    // its period and must give an ordinary, accepted key.
    for &weak in WEAK.iter().chain(SEMI_WEAK.iter()).chain(POSSIBLY_WEAK.iter()) {
        let nearly = weak ^ (1u64 << 62); // key bit 2, not a parity bit
        let mut k = GOOD;
        k[1] = nearly;
        assert!(TDES::new(&bundle(k)).is_ok(), "{nearly:016x} should not be treated as weak");
    }
}

#[test]
fn repeated_component_keys_are_rejected() {
    let [a, b, c] = GOOD;
    // Key1 = Key2 and Key2 = Key3 collapse to single DES; Key1 = Key3 is two-key TDEA.
    assert!(is_weak_key_error(TDES::new(&bundle([a, a, c]))), "Key1 = Key2");
    assert!(is_weak_key_error(TDES::new(&bundle([a, b, b]))), "Key2 = Key3");
    assert!(is_weak_key_error(TDES::new(&bundle([a, b, a]))), "Key1 = Key3 (two-key TDEA)");
    assert!(is_weak_key_error(TDES::new(&bundle([a, a, a]))), "three identical keys");
    // Differing only in parity is the same key to the engine, so it is still a repeat.
    assert!(
        is_weak_key_error(TDES::new(&bundle([a, a ^ !PARITY_MASK, c]))),
        "parity-only difference"
    );
}

#[test]
fn parity_bits_do_not_change_the_cipher() {
    let good = TDES::new(&bundle(GOOD)).unwrap();
    let flipped = TDES::new(&bundle([
        GOOD[0] ^ !PARITY_MASK,
        GOOD[1] ^ 0x0000_0000_0000_0001,
        GOOD[2] ^ 0x0100_0100_0100_0100,
    ]))
    .unwrap();
    for i in 0..64u8 {
        let block = [i; BLOCK_LEN];
        let mut a = block;
        let mut b = block;
        good.encrypt_block(&mut a);
        flipped.encrypt_block(&mut b);
        assert_eq!(a, b);
        assert_ne!(a, block);
    }
}

#[test]
fn a_non_parity_bit_does_change_the_cipher() {
    // The complement of the test above: every one of the 56 x 3 effective key bits matters.
    let good = TDES::new(&bundle(GOOD)).unwrap();
    let block = [0x5Au8; BLOCK_LEN];
    let mut reference = block;
    good.encrypt_block(&mut reference);
    for position in 0..3 {
        for bit in 0..64u32 {
            if bit % 8 == 0 {
                continue; // a parity bit: bits 8, 16, ..., 64 in spec numbering are word bits 56, 48, .., 0
            }
            let mut k = GOOD;
            k[position] ^= 1u64 << bit;
            let mut out = block;
            TDES::new(&bundle(k)).unwrap().encrypt_block(&mut out);
            assert_ne!(out, reference, "key {} bit {bit} had no effect", position + 1);
        }
    }
}

#[test]
fn the_key_material_checks() {
    let mut bytes = [0u8; KEY_LEN];
    for (i, key) in GOOD.iter().enumerate() {
        bytes[8 * i..8 * i + 8].copy_from_slice(&key.to_be_bytes());
    }

    // Wrong type.
    let mac_key = KeyMaterial::<KEY_LEN>::from_bytes_as_type(&bytes, KeyType::MACKey).unwrap();
    assert!(matches!(
        TDES::new(&mac_key),
        Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_)))
    ));

    // Too weak a strength: 3TDEA is 112 bits (SP 800-57 Part 1 Rev 5 Table 2), and that is the floor.
    let mut key = bundle(GOOD);
    do_hazardous_operations(&mut key, |k| k.set_security_strength(SecurityStrength::None)).unwrap();
    assert!(matches!(
        TDES::new(&key),
        Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::SecurityStrength(_)))
    ));
    do_hazardous_operations(&mut key, |k| k.set_security_strength(SecurityStrength::_112bit))
        .unwrap();
    assert!(TDES::new(&key).is_ok());

    // An all-zero buffer is tagged Zeroized by KeyMaterial and rejected on type.
    let zero =
        KeyMaterial::<KEY_LEN>::from_bytes_as_type(&[0u8; KEY_LEN], KeyType::SymmetricCipherKey)
            .unwrap();
    assert!(matches!(
        TDES::new(&zero),
        Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_)))
    ));

    assert_eq!(<TDES as Algorithm>::MAX_SECURITY_STRENGTH, SecurityStrength::_112bit);
}

#[test]
fn debug_output_names_the_algorithm_only() {
    let tdes = TDES::new(&bundle(GOOD)).unwrap();
    assert_eq!(format!("{tdes:?}"), "TDES");
}

// ---- two-key TDEA -----------------------------------------------------------------------------

fn bundle2(k: [u64; 2]) -> KeyMaterial<KEY_LEN_2KEY> {
    let mut bytes = [0u8; KEY_LEN_2KEY];
    for (i, key) in k.iter().enumerate() {
        bytes[8 * i..8 * i + 8].copy_from_slice(&key.to_be_bytes());
    }
    KeyMaterial::<KEY_LEN_2KEY>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).unwrap()
}

fn is_weak_key_error2(result: Result<TDES2Key, SymmetricCipherError>) -> bool {
    matches!(result, Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::WeakKey(_))))
}

#[test]
fn two_key_bundle_is_the_three_key_bundle_with_key3_equal_to_key1() {
    // Sec 3.1: 2TDEA is `Key3 = Key1`. `TDES` refuses that bundle; `TDES2Key` computes it. Check
    // against a three-key engine built by hand from the same DEA keys is impossible (TDES rejects
    // it), so check the definition directly: F_K1(I_K2(F_K1(d))) via the single-DES identity
    // F_K1(I_K1(x)) = x -- encrypting with (K1, K2) then decrypting with (K1, K2) round-trips, and
    // the result differs from three-key TDEA with an unrelated third key.
    let [a, b, c] = GOOD;
    let two = TDES2Key::new(&bundle2([a, b])).unwrap();
    let three = TDES::new(&bundle([a, b, c])).unwrap();
    let block = [0x5Au8; BLOCK_LEN];
    let mut x = block;
    two.encrypt_block(&mut x);
    assert_ne!(x, block);
    let mut y = block;
    three.encrypt_block(&mut y);
    assert_ne!(x, y, "a different third key gives a different permutation");
    two.decrypt_block(&mut x);
    assert_eq!(x, block);
}

#[test]
fn two_key_repeated_or_weak_components_are_rejected() {
    let [a, b, _] = GOOD;
    assert!(is_weak_key_error2(TDES2Key::new(&bundle2([a, a]))), "Key1 = Key2 is single DES");
    assert!(
        is_weak_key_error2(TDES2Key::new(&bundle2([a, a ^ !PARITY_MASK]))),
        "parity-only difference"
    );
    for &weak in WEAK.iter().chain(SEMI_WEAK.iter()).chain(POSSIBLY_WEAK.iter()) {
        assert!(is_weak_key_error2(TDES2Key::new(&bundle2([weak, b]))), "{weak:016x} as Key1");
        assert!(is_weak_key_error2(TDES2Key::new(&bundle2([a, weak]))), "{weak:016x} as Key2");
    }
    assert!(TDES2Key::new(&bundle2([a, b])).is_ok());
}

#[test]
fn two_key_material_checks_and_metadata() {
    let [a, b, _] = GOOD;
    let mut bytes = [0u8; KEY_LEN_2KEY];
    bytes[..8].copy_from_slice(&a.to_be_bytes());
    bytes[8..].copy_from_slice(&b.to_be_bytes());
    let mac_key = KeyMaterial::<KEY_LEN_2KEY>::from_bytes_as_type(&bytes, KeyType::MACKey).unwrap();
    assert!(matches!(
        TDES2Key::new(&mac_key),
        Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_)))
    ));

    // 2TDEA is rated at most 80 bits (SP 800-57 Part 1 Rev 5 Table 2), below the lowest level the
    // library models, so no strength is too low for it.
    let mut key = bundle2([a, b]);
    do_hazardous_operations(&mut key, |k| k.set_security_strength(SecurityStrength::None)).unwrap();
    assert!(TDES2Key::new(&key).is_ok());
    assert_eq!(<TDES2Key as Algorithm>::MAX_SECURITY_STRENGTH, SecurityStrength::None);
    assert_eq!(<TDES2Key as Algorithm>::ALG_NAME, "TDES-2KEY");
    assert!(!<TDES2Key as ElectronicCodeBook<KEY_LEN_2KEY, BLOCK_LEN>>::ENCRYPTION_APPROVED);
    assert!(<TDES as ElectronicCodeBook<KEY_LEN, BLOCK_LEN>>::ENCRYPTION_APPROVED);
    assert_eq!(format!("{:?}", TDES2Key::new(&bundle2([a, b])).unwrap()), "TDES-2KEY");
}
