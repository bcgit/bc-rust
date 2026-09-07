//! Known-answer tests from RFC 5794 Appendix A, "Example Data of ARIA": one vector per key length,
//! checked in both directions, through every lane of the four-block path (which is also the
//! trait's batch) and both slots of the pair path. (The round keys and intermediate round values
//! of A.1 are pinned inside the crate, where they are visible: `schedule::tests` and
//! `aria::tests`.)
//!
//! All values are transcribed from the downloaded text of the RFC.

mod common;

use bouncycastle_aria::{ARIA, ARIA_128, ARIA_192, ARIA_256, ARIAParams, BLOCK_LEN, LANES};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::ElectronicCodeBook;
use common::bytes;

/// The plaintext shared by all three examples.
const PLAINTEXT: &str = "00112233445566778899aabbccddeeff";

/// A.1, "128-Bit Key".
const KEY_128: &str = "000102030405060708090a0b0c0d0e0f";
const CT_128: &str = "d718fbd6ab644c739da95f3be6451778";

/// A.2, "192-Bit Key".
const KEY_192: &str = "000102030405060708090a0b0c0d0e0f1011121314151617";
const CT_192: &str = "26449c1805dbe7aa25a468ce263a9e79";

/// A.3, "256-Bit Key".
const KEY_256: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const CT_256: &str = "f92bd7c79fb72e2f2b8f80c1972d24fc";

fn key<const N: usize>(hex_str: &str) -> KeyMaterial<N> {
    KeyMaterial::<N>::from_bytes_as_type(&bytes::<N>(hex_str), KeyType::SymmetricCipherKey)
        .expect("a valid symmetric cipher key")
}

/// Every entry point, both directions, for one vector.
fn check<const KEY_LEN: usize, P: ARIAParams>(
    name: &str,
    perm: &ARIA<P>,
    plaintext: &[u8; BLOCK_LEN],
    ciphertext: &[u8; BLOCK_LEN],
) where
    ARIA<P>: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    // Single block.
    let mut b = *plaintext;
    perm.encrypt_block(&mut b);
    assert_eq!(&b, ciphertext, "{name}: encrypt_block");
    perm.decrypt_block(&mut b);
    assert_eq!(&b, plaintext, "{name}: decrypt_block");

    // Four lanes: the vector in each lane in turn, with unrelated blocks in the others, which
    // must come out as they do on their own.
    let others: [[u8; BLOCK_LEN]; LANES] = core::array::from_fn(|i| [i as u8 * 17 + 1; 16]);
    let mut alone = others;
    for b in alone.iter_mut() {
        perm.encrypt_block(b);
    }
    for lane in 0..LANES {
        let mut mixed = others;
        mixed[lane] = *plaintext;
        perm.encrypt_4blocks(&mut mixed);
        assert_eq!(&mixed[lane], ciphertext, "{name}: encrypt_4blocks lane {lane}");
        for other in (0..LANES).filter(|&o| o != lane) {
            assert_eq!(mixed[other], alone[other], "{name}: lane {lane} disturbed lane {other}");
        }
        perm.decrypt_4blocks(&mut mixed);
        assert_eq!(&mixed[lane], plaintext, "{name}: decrypt_4blocks lane {lane}");
        assert_eq!(&mixed[..lane], &others[..lane]);
        assert_eq!(&mixed[lane + 1..], &others[lane + 1..]);
    }

    // The pair path, in both slots.
    let mut pair = [*plaintext, others[3]];
    perm.encrypt_2blocks(&mut pair);
    assert_eq!(&pair[0], ciphertext, "{name}: encrypt_2blocks slot 0");
    assert_eq!(pair[1], alone[3]);
    perm.decrypt_2blocks(&mut pair);
    assert_eq!(pair, [*plaintext, others[3]], "{name}: decrypt_2blocks");
    let mut pair = [others[2], *plaintext];
    perm.encrypt_2blocks(&mut pair);
    assert_eq!(&pair[1], ciphertext, "{name}: encrypt_2blocks slot 1");
}

#[test]
fn appendix_a_1_128_bit_key() {
    let perm = ARIA_128::new(&key::<16>(KEY_128)).unwrap();
    check::<16, _>("Appendix A.1", &perm, &bytes(PLAINTEXT), &bytes(CT_128));
}

#[test]
fn appendix_a_2_192_bit_key() {
    let perm = ARIA_192::new(&key::<24>(KEY_192)).unwrap();
    check::<24, _>("Appendix A.2", &perm, &bytes(PLAINTEXT), &bytes(CT_192));
}

#[test]
fn appendix_a_3_256_bit_key() {
    let perm = ARIA_256::new(&key::<32>(KEY_256)).unwrap();
    check::<32, _>("Appendix A.3", &perm, &bytes(PLAINTEXT), &bytes(CT_256));
}

/// The three key lengths are different ciphers: the same 16 key bytes extended to 24 or 32 must
/// not produce the 128-bit answer (a schedule that ignored `KR` or the `CK` order would).
#[test]
fn key_lengths_are_distinct_ciphers() {
    let mut a = bytes::<16>(PLAINTEXT);
    let mut b = a;
    let mut c = a;
    ARIA_128::new(&key::<16>(KEY_128)).unwrap().encrypt_block(&mut a);
    ARIA_192::new(&key::<24>(KEY_192)).unwrap().encrypt_block(&mut b);
    ARIA_256::new(&key::<32>(KEY_256)).unwrap().encrypt_block(&mut c);
    assert_ne!(a, b);
    assert_ne!(b, c);
    assert_ne!(a, c);
}

/// `Debug` prints the algorithm name only, never the round keys.
#[test]
fn debug_prints_only_the_name() {
    assert_eq!(format!("{:?}", ARIA_128::new(&key::<16>(KEY_128)).unwrap()), "ARIA-128");
    assert_eq!(format!("{:?}", ARIA_192::new(&key::<24>(KEY_192)).unwrap()), "ARIA-192");
    assert_eq!(format!("{:?}", ARIA_256::new(&key::<32>(KEY_256)).unwrap()), "ARIA-256");
}
