//! TKW against SP 800-38F Algorithm 7 written out over the raw TDEA permutation, for both key
//! bundles. The CAVP sample files pin the three-key answers in `tkw_cavp_tests.rs`; this file
//! pins the loop itself, with the 32-bit step counter and ICV3, against a direct transcription,
//! and is the only known answer for two-key unwrapping, since no wrapper exists for a two-key
//! bundle and CAVP tests TKW with three keys only.

use bouncycastle_cipher::modes::TKW;
use bouncycastle_core::hazmat::{BlockPermutation, ElectronicCodeBook};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{FromKeyMaterial, KeyUnwrappingKey, KeyWrappingKey};
use bouncycastle_tdes::hazmat::{TDES2Internal, TDESInternal};
use bouncycastle_tdes::{KEY_LEN, KEY_LEN_2KEY, TDES2Key, TDES3Key};

fn material<const N: usize>() -> KeyMaterial<N> {
    let bytes: [u8; N] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).expect("a valid key")
}

/// TKW-AE (Algorithm 9) as written: `S = ICV3 || P`, then TW (Algorithm 7) with its shift
/// register, `A^t = MSB32(CIPH_K(A^{t-1} || R2^{t-1})) xor [t]32`, `R_i^t = R_{i+1}^{t-1}`,
/// `R_n^t = LSB32(CIPH_K(A^{t-1} || R2^{t-1}))`, for `t = 1 .. 6(n-1)`.
fn tkw_ae_as_written<P: BlockPermutation<8>>(perm: &P, plaintext: &[u8]) -> Vec<u8> {
    let mut a = [0xA6u8; 4];
    let mut r: Vec<[u8; 4]> = plaintext.chunks(4).map(|c| c.try_into().unwrap()).collect();
    let n = r.len() + 1;
    for t in 1..=(6 * (n - 1)) as u32 {
        let mut block = [0u8; 8];
        block[..4].copy_from_slice(&a);
        block[4..].copy_from_slice(&r[0]);
        perm.encrypt_block(&mut block);
        a.copy_from_slice(&block[..4]);
        for (x, y) in a.iter_mut().zip(t.to_be_bytes()) {
            *x ^= y;
        }
        r.rotate_left(1);
        r[n - 2].copy_from_slice(&block[4..]);
    }
    let mut out = a.to_vec();
    out.extend(r.iter().flatten());
    out
}

#[test]
fn three_key_tkw_matches_algorithm_9_as_written() {
    let perm = TDESInternal::new(&material::<KEY_LEN>()).unwrap();
    let kek = TDES3Key::<TKW>::from_key_material(&material::<KEY_LEN>()).unwrap();
    for len in [8usize, 12, 16, 20, 24, 256] {
        let plaintext: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(0x9D)).collect();
        let expected = tkw_ae_as_written(&perm, &plaintext);
        assert_eq!(kek.wrap(&plaintext).unwrap(), expected, "{len} bytes");
        assert_eq!(kek.unwrap(&expected).unwrap(), plaintext, "{len} bytes");
    }
}

/// The two-key engine's forward function is not gated (only the key's wrapper is), so a
/// ciphertext can be made from it here and the key's unwrapper must recover the plaintext.
#[test]
fn two_key_tkw_unwraps_what_algorithm_9_wrapped() {
    let perm = TDES2Internal::new(&material::<KEY_LEN_2KEY>()).unwrap();
    let kek = TDES2Key::<TKW>::from_key_material(&material::<KEY_LEN_2KEY>()).unwrap();
    for len in [8usize, 16, 20, 256] {
        let plaintext: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(0x9D)).collect();
        let mut ciphertext = tkw_ae_as_written(&perm, &plaintext);
        assert_eq!(kek.unwrap(&ciphertext).unwrap(), plaintext, "{len} bytes");
        ciphertext[len / 2] ^= 0x01;
        assert!(kek.unwrap(&ciphertext).is_err(), "{len} bytes, modified");
    }
}

/// SP 800-38F Table 1: TKW-AD is defined on three or more semiblocks and TKW-AE on two or more.
/// The shared suite's bad lengths (0, one semiblock, one byte short) never reach the 8-byte
/// ciphertext or the 4-byte plaintext, which must be `InvalidInputLength`, not a run of the
/// algorithm ending in `DecryptionFailed`.
#[test]
fn tkw_refuses_a_two_semiblock_ciphertext_and_a_one_semiblock_plaintext() {
    use bouncycastle_core::errors::SymmetricCipherError;
    use bouncycastle_core::traits::{KeyUnwrapper, KeyWrapper};
    let kek = TDES3Key::<TKW>::from_key_material(&material::<KEY_LEN>()).unwrap();
    let mut out = [0u8; 16];
    assert!(matches!(
        kek.create_unwrapper().unwrap_out(&[0u8; 8], &mut out),
        Err(SymmetricCipherError::InvalidInputLength(_))
    ));
    assert!(matches!(
        kek.create_wrapper().wrap_out(&[0u8; 4], &mut out),
        Err(SymmetricCipherError::InvalidInputLength(_))
    ));
    let kek2 = TDES2Key::<TKW>::from_key_material(&material::<KEY_LEN_2KEY>()).unwrap();
    assert!(matches!(
        kek2.create_unwrapper().unwrap_out(&[0u8; 8], &mut out),
        Err(SymmetricCipherError::InvalidInputLength(_))
    ));
}
