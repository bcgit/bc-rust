use bouncycastle_chacha20_poly1305_aead::ChaCha20_Poly1305;
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};
use bouncycastle_core_test_framework::test_data_loaders::Value;

type Enc = ChaCha20_Poly1305<Encrypting>;
type Dec = ChaCha20_Poly1305<Decrypting>;

pub fn decode(case: &Value, field: &str) -> Vec<u8> {
    bouncycastle_hex::decode(case[field].as_str().expect(field)).unwrap()
}

pub fn key(bytes: &[u8]) -> KeyMaterial<32> {
    assert_eq!(bytes.len(), 32);
    let mut key = KeyMaterial::new();
    do_hazardous_operations(&mut key, |key| {
        key.set_bytes_as_type(bytes, KeyType::SymmetricCipherKey)?;
        key.set_security_strength(SecurityStrength::_256bit)
    })
    .unwrap();
    key
}

#[allow(clippy::too_many_arguments)]
pub fn check_valid(
    key: &KeyMaterial<32>,
    nonce: &[u8; 12],
    aad: &[u8],
    msg: &[u8],
    ct: &[u8],
    tag: &[u8; 16],
    chunks: &[usize],
) {
    let mut inline = ct.to_vec();
    inline.extend_from_slice(tag);
    let mut plaintext = vec![0xa5; msg.len() + 8];
    let n = Dec::decrypt_detached_out(key, nonce, aad, ct, tag, &mut plaintext).unwrap();
    assert_eq!(n, msg.len());
    assert_eq!(&plaintext[..n], msg);
    assert_eq!(&plaintext[n..], &[0; 8], "bytes past the plaintext are zeroized");
    assert_eq!(
        Dec::decrypt_with_aad_out(key, nonce, aad, &inline, &mut plaintext).unwrap(),
        msg.len()
    );
    assert_eq!(&plaintext[..msg.len()], msg);

    for &chunk in chunks {
        let mut enc = Enc::do_encrypt_init_nonce(key, nonce).unwrap();
        for bytes in aad.chunks(chunk) {
            enc.do_update_aad(bytes).unwrap();
        }
        let mut ciphertext = vec![0xa5; msg.len()];
        let mut offset = 0;
        enc.do_encrypt_out(&[], &mut []).unwrap();
        for bytes in msg.chunks(chunk) {
            offset += enc.do_encrypt_out(bytes, &mut ciphertext[offset..]).unwrap();
        }
        let mut last = [0xa5; 16];
        let (n, actual_tag) = enc.do_encrypt_final_detached_out(&mut last).unwrap();
        assert_eq!(n, 0);
        assert_eq!(last, [0; 16], "the unused final buffer is zeroized");
        assert_eq!(offset, msg.len());
        assert_eq!(ciphertext, ct);
        assert_eq!(&actual_tag, tag);

        for detached in [false, true] {
            let mut dec = Dec::do_decrypt_init(key, nonce).unwrap();
            for bytes in aad.chunks(chunk) {
                dec.do_update_aad(bytes).unwrap();
            }
            let mut recovered = vec![0u8; msg.len()];
            let mut written = 0;
            let input = if detached { ct } else { &inline };
            for bytes in input.chunks(chunk) {
                let expected = dec.do_decrypt_out_len(bytes.len());
                let n = dec.do_decrypt_out(bytes, &mut recovered[written..]).unwrap();
                assert_eq!(n, expected);
                written += n;
            }
            let (last, n) = if detached {
                dec.do_decrypt_final_detached(tag).unwrap()
            } else {
                dec.do_decrypt_final().unwrap()
            };
            recovered[written..written + n].copy_from_slice(&last[..n]);
            assert_eq!(written + n, msg.len());
            assert_eq!(recovered, msg);
        }
    }
}
