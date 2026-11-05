//! SM4-KW and SM4-KWP against RFC 3394 Sec 2.2.1 and RFC 5649 Sec 4.1 written out over the raw
//! SM4 permutation. No key-wrap vectors are published for SM4, so this is the known answer: the
//! index-based wrapping loop of RFC 3394, which is also SP 800-38F Algorithm 1, transcribed here
//! and composed with `SM4Internal` directly, must agree with what `SM4Key<KW>` and `SM4Key<KWP>`
//! produce. The algorithm's own answers under AES are pinned in `bouncycastle-aes`.

use bouncycastle_cipher::modes::{KW, KWP};
use bouncycastle_core::hazmat::{BlockPermutation, ElectronicCodeBook};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{FromKeyMaterial, KeyUnwrappingKey, KeyWrappingKey};
use bouncycastle_sm4::hazmat::SM4Internal;
use bouncycastle_sm4::{KEY_LEN, SM4Key};

fn material() -> KeyMaterial<KEY_LEN> {
    let bytes: [u8; KEY_LEN] = core::array::from_fn(|i| (i as u8).wrapping_mul(0x33) ^ 0x5A);
    KeyMaterial::<KEY_LEN>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).unwrap()
}

/// RFC 3394 Sec 2.2.1, the index-based form, over `perm`: `a` is the IV and `r` the n 64-bit
/// registers, returned as `A || R[1] || ... || R[n]`.
fn rfc3394_wrap(perm: &SM4Internal, a: [u8; 8], r: &[[u8; 8]]) -> Vec<u8> {
    let n = r.len();
    let mut a = a;
    let mut r = r.to_vec();
    // For j = 0 to 5
    for j in 0..6 {
        // For i = 1 to n
        for i in 1..=n {
            // B = AES(K, A | R[i])
            let mut b = [0u8; 16];
            b[..8].copy_from_slice(&a);
            b[8..].copy_from_slice(&r[i - 1]);
            perm.encrypt_block(&mut b);
            // A = MSB(64, B) ^ t where t = (n*j)+i
            let t = ((n * j) + i) as u64;
            a.copy_from_slice(&b[..8]);
            for (x, y) in a.iter_mut().zip(t.to_be_bytes()) {
                *x ^= y;
            }
            // R[i] = LSB(64, B)
            r[i - 1].copy_from_slice(&b[8..]);
        }
    }
    let mut out = a.to_vec();
    for reg in r {
        out.extend_from_slice(&reg);
    }
    out
}

fn registers(data: &[u8]) -> Vec<[u8; 8]> {
    data.chunks(8).map(|c| c.try_into().unwrap()).collect()
}

/// KW: RFC 3394 with the default IV `A6A6A6A6A6A6A6A6` (Sec 2.2.3.1).
#[test]
fn sm4_kw_matches_rfc3394_over_the_raw_permutation() {
    let perm = SM4Internal::new(&material()).unwrap();
    let kek = SM4Key::<KW>::from_key_material(&material()).unwrap();
    for len in [16usize, 24, 32, 64] {
        let plaintext: Vec<u8> = (0..len as u8).map(|i| i.wrapping_mul(0x9D)).collect();
        let expected = rfc3394_wrap(&perm, [0xA6; 8], &registers(&plaintext));
        assert_eq!(kek.wrap(&plaintext).unwrap(), expected, "{len} bytes");
        assert_eq!(kek.unwrap(&expected).unwrap(), plaintext, "{len} bytes");
    }
}

/// KWP: RFC 5649 Sec 4.1 -- the alternative IV `A65959A6 || MLI`, the plaintext padded with
/// zeros to a multiple of 8, a single block encryption when the padded plaintext is one register
/// and the RFC 3394 loop otherwise.
#[test]
fn sm4_kwp_matches_rfc5649_over_the_raw_permutation() {
    let perm = SM4Internal::new(&material()).unwrap();
    let kek = SM4Key::<KWP>::from_key_material(&material()).unwrap();
    for len in [1usize, 7, 8, 9, 20, 64] {
        let plaintext: Vec<u8> = (0..len as u8).map(|i| i.wrapping_mul(0x9D)).collect();
        let mut aiv = [0xA6, 0x59, 0x59, 0xA6, 0, 0, 0, 0];
        aiv[4..].copy_from_slice(&(len as u32).to_be_bytes());
        let mut padded = plaintext.clone();
        padded.resize(len.div_ceil(8) * 8, 0);
        let expected = if padded.len() == 8 {
            let mut b = [0u8; 16];
            b[..8].copy_from_slice(&aiv);
            b[8..].copy_from_slice(&padded);
            perm.encrypt_block(&mut b);
            b.to_vec()
        } else {
            rfc3394_wrap(&perm, aiv, &registers(&padded))
        };
        assert_eq!(kek.wrap(&plaintext).unwrap(), expected, "{len} bytes");
        assert_eq!(kek.unwrap(&expected).unwrap(), plaintext, "{len} bytes");
    }
}
