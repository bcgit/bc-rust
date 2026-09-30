use bouncycastle_chacha20_poly1305_aead::{
    ChaCha20Poly1305Decryptor as Dec, ChaCha20Poly1305Encryptor as Enc,
};
use bouncycastle_core::key_material::{
    KeyMaterial, KeyMaterialTrait, KeyType, do_hazardous_operations,
};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};
use serde_json::Value;
use std::{fs, path::PathBuf};

pub fn load(variable: &str, sibling: &str, relative: &str) -> Option<Value> {
    let override_root = std::env::var_os(variable);
    let root = override_root.as_ref().map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").join(sibling)
    });
    let path = root.join(relative);
    if !path.exists() && override_root.is_none() {
        eprintln!("WARNING: {} not found; external vectors skipped", path.display());
        return None;
    }
    Some(
        serde_json::from_str(&fs::read_to_string(&path).expect("external test vector file"))
            .unwrap(),
    )
}

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
    let n = Dec::decrypt_out_detached(key, nonce, aad, ct, tag, &mut plaintext).unwrap();
    assert_eq!(n, msg.len());
    assert_eq!(&plaintext[..n], msg);
    assert_eq!(&plaintext[n..], &[0xa5; 8]);
    assert_eq!(
        Dec::decrypt_out_with_aad(key, nonce, aad, &inline, &mut plaintext).unwrap(),
        msg.len()
    );
    assert_eq!(&plaintext[..msg.len()], msg);

    for &chunk in chunks {
        let mut enc = Enc::new_with_nonce(key, nonce).unwrap();
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
        let (n, actual_tag) = enc.do_final_out_detached(&mut last).unwrap();
        assert_eq!(n, 0);
        assert_eq!(last, [0xa5; 16]);
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
                dec.do_final_detached(tag).unwrap()
            } else {
                dec.do_final().unwrap()
            };
            recovered[written..written + n].copy_from_slice(&last[..n]);
            assert_eq!(written + n, msg.len());
            assert_eq!(recovered, msg);
        }
    }
}
