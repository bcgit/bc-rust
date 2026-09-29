use bouncycastle_core::errors::{KeyMaterialError, MACError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::MAC;
use bouncycastle_poly1305::Poly1305;

fn key() -> KeyMaterial<32> {
    KeyMaterial::from_bytes_as_type(&[0x42; 32], KeyType::MACKey).unwrap()
}

#[test]
fn empty_message_returns_the_additive_key_half() {
    let key = key();
    assert_eq!(Poly1305::new(&key).unwrap().finalize(), key.ref_to_bytes()[16..]);
}

#[test]
fn streaming_and_output_buffer_contract() {
    let key = key();
    for len in [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 1025] {
        let msg: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(7)).collect();
        let expected = Poly1305::new(&key).unwrap().mac(&msg);
        for chunk in [1, 3, 15, 16, 17, 64, 129] {
            let mut mac = Poly1305::new(&key).unwrap();
            assert_eq!(mac.output_len(), 16);
            mac.do_update(&[]);
            for bytes in msg.chunks(chunk) {
                mac.do_update(bytes);
                mac.do_update(&[]);
            }
            let mut out = [0xa5; 32];
            assert_eq!(mac.do_final_out(&mut out).unwrap(), 16);
            assert_eq!(&out[..16], expected);
            assert_eq!(&out[16..], &[0; 16]);
        }
        assert!(Poly1305::new(&key).unwrap().verify(&msg, &expected));
        for bit in 0..128 {
            let mut bad = expected.clone();
            bad[bit / 8] ^= 1 << (bit % 8);
            assert!(!Poly1305::new(&key).unwrap().verify(&msg, &bad));
        }
        assert!(!Poly1305::new(&key).unwrap().verify(&msg, &expected[..15]));
        assert!(!Poly1305::new(&key).unwrap().verify(&msg, &[0; 17]));
    }
}

#[test]
fn full_tags_are_required() {
    let key = key();
    for len in 0..16 {
        let mut out = vec![0xa5; len];
        assert!(matches!(
            Poly1305::new(&key).unwrap().mac_out(b"message", &mut out),
            Err(MACError::InvalidLength(_))
        ));
        assert!(out.iter().all(|&b| b == 0));
    }
}

#[test]
fn key_length_type_and_strength_policy() {
    for len in 0..=64 {
        let key = KeyMaterial::<64>::from_bytes_as_type(&vec![1; len], KeyType::MACKey).unwrap();
        assert_eq!(Poly1305::new_allow_weak_key(&key).is_ok(), len == 32);
    }
    for kind in
        [KeyType::SymmetricCipherKey, KeyType::Seed, KeyType::Unknown, KeyType::CryptographicRandom]
    {
        let key = KeyMaterial::<32>::from_bytes_as_type(&[1; 32], kind).unwrap();
        assert!(matches!(
            Poly1305::new(&key),
            Err(MACError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_)))
        ));
        assert!(Poly1305::new_allow_weak_key(&key).is_err());
    }
    let mut key = key();
    key.set_security_strength(SecurityStrength::_112bit).unwrap();
    assert!(matches!(
        Poly1305::new(&key),
        Err(MACError::KeyMaterialError(KeyMaterialError::SecurityStrength(_)))
    ));
    assert!(Poly1305::new_allow_weak_key(&key).is_ok());
    let zero = KeyMaterial::<32>::from_bytes(&[0; 32]).unwrap();
    assert!(Poly1305::new(&zero).is_err());
    assert_eq!(Poly1305::new_allow_weak_key(&zero).unwrap().mac(b"zero-key test"), [0; 16]);
}
