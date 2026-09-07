//! Known-answer tests from RFC 3713 Appendix A, "Example Data of Camellia": one vector per key
//! length, checked in both directions, through every lane of the four-block path (which is also
//! the trait's batch) and through the pair path.
//!
//! All values are transcribed from the downloaded text of the RFC.

mod common;

use bouncycastle_camellia::{BLOCK_LEN, Camellia, Camellia_128, Camellia_192, Camellia_256, LANES};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::ElectronicCodeBook;
use common::bytes;

/// The plaintext shared by all three examples.
const PLAINTEXT: &str = "0123456789abcdeffedcba9876543210";

/// "128-bit key".
const KEY_128: &str = "0123456789abcdeffedcba9876543210";
const CT_128: &str = "67673138549669730857065648eabe43";

/// "192-bit key".
const KEY_192: &str = "0123456789abcdeffedcba98765432100011223344556677";
const CT_192: &str = "b4993401b3e996f84ee5cee7d79b09b9";

/// "256-bit key".
const KEY_256: &str = "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff";
const CT_256: &str = "9acc237dff16d76c20ef7c919e3a7509";

fn key<const N: usize>(hex_str: &str) -> KeyMaterial<N> {
    KeyMaterial::<N>::from_bytes_as_type(&bytes::<N>(hex_str), KeyType::SymmetricCipherKey)
        .expect("a valid symmetric cipher key")
}

/// Every entry point, both directions, for one vector.
fn check<const KEY_LEN: usize, P: bouncycastle_camellia::CamelliaParams>(
    name: &str,
    perm: &Camellia<P>,
    plaintext: &[u8; BLOCK_LEN],
    ciphertext: &[u8; BLOCK_LEN],
) where
    Camellia<P>: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
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
fn appendix_a_128_bit_key() {
    let perm = Camellia_128::new(&key::<16>(KEY_128)).unwrap();
    check::<16, _>("Appendix A, 128-bit key", &perm, &bytes(PLAINTEXT), &bytes(CT_128));
}

#[test]
fn appendix_a_192_bit_key() {
    let perm = Camellia_192::new(&key::<24>(KEY_192)).unwrap();
    check::<24, _>("Appendix A, 192-bit key", &perm, &bytes(PLAINTEXT), &bytes(CT_192));
}

#[test]
fn appendix_a_256_bit_key() {
    let perm = Camellia_256::new(&key::<32>(KEY_256)).unwrap();
    check::<32, _>("Appendix A, 256-bit key", &perm, &bytes(PLAINTEXT), &bytes(CT_256));
}

/// The three key lengths are different ciphers: the same 16 key bytes extended to 24 or 32 must
/// not produce the 128-bit answer (a schedule that ignored `KR` would).
#[test]
fn key_lengths_are_distinct_ciphers() {
    let mut a = bytes::<16>(PLAINTEXT);
    let mut b = a;
    let mut c = a;
    Camellia_128::new(&key::<16>(KEY_128)).unwrap().encrypt_block(&mut a);
    Camellia_192::new(&key::<24>(KEY_192)).unwrap().encrypt_block(&mut b);
    Camellia_256::new(&key::<32>(KEY_256)).unwrap().encrypt_block(&mut c);
    assert_ne!(a, b);
    assert_ne!(b, c);
    assert_ne!(a, c);
}

/// `Debug` prints the algorithm name only, never the subkeys.
#[test]
fn debug_prints_only_the_name() {
    assert_eq!(format!("{:?}", Camellia_128::new(&key::<16>(KEY_128)).unwrap()), "Camellia-128");
    assert_eq!(format!("{:?}", Camellia_192::new(&key::<24>(KEY_192)).unwrap()), "Camellia-192");
    assert_eq!(format!("{:?}", Camellia_256::new(&key::<32>(KEY_256)).unwrap()), "Camellia-256");
}
