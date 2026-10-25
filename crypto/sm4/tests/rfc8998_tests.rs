//! The SM4-GCM and SM4-CCM test vectors of RFC 8998 Appendix A, through `SM4Key<GCM>` and
//! `SM4Key<CCM<12, 16>>`.
//!
//! RFC 8998 Sec 3.5 defines `AEAD_SM4_GCM` and `AEAD_SM4_CCM` for TLS 1.3 as GCM and CCM over
//! SM4 with a 12-byte nonce and a 16-byte tag; its Appendix A gives one vector for each, the same
//! key, nonce, plaintext and associated data. The key objects reach both modes by naming them, so
//! these are the published answers for the two AEAD roles the key carries. All values are
//! transcribed from the downloaded text of the RFC.

use bouncycastle_cipher::modes::{CCM, GCM};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{
    AeadDeclaredDecryptionKey, AeadDeclaredEncryptionKey, AeadDecryptionKey, AeadEncryptionKey,
    FromKeyMaterial,
};
use bouncycastle_hex as hex;
use bouncycastle_sm4::{KEY_LEN, SM4Key};

const NONCE: &str = "00001234567800000000ABCD";
const KEY: &str = "0123456789ABCDEFFEDCBA9876543210";
const PLAINTEXT: &str = concat!(
    "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB",
    "CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD",
    "EEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFF",
    "EEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA",
);
const AAD: &str = "FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2";

/// A.1 SM4-GCM.
const GCM_CT: &str = concat!(
    "17F399F08C67D5EE19D0DC9969C4BB7D",
    "5FD46FD3756489069157B282BB200735",
    "D82710CA5C22F0CCFA7CBF93D496AC15",
    "A56834CBCF98C397B4024A2691233B8D",
);
const GCM_TAG: &str = "83DE3541E4C2B58177E065A9BF7B62EC";

/// A.2 SM4-CCM.
const CCM_CT: &str = concat!(
    "48AF93501FA62ADBCD414CCE6034D895",
    "DDA1BF8F132F042098661572E7483094",
    "FD12E518CE062C98ACEE28D95DF4416B",
    "ED31A2F04476C18BB40C84A74B97DC5B",
);
const CCM_TAG: &str = "16842D4FA186F56AB33256971FA110F4";

fn bytes<const N: usize>(hex_str: &str) -> [u8; N] {
    hex::decode(hex_str).expect("valid hex").try_into().expect("expected length")
}

fn material() -> KeyMaterial<KEY_LEN> {
    KeyMaterial::<KEY_LEN>::from_bytes_as_type(&bytes::<KEY_LEN>(KEY), KeyType::SymmetricCipherKey)
        .expect("a valid symmetric cipher key")
}

#[test]
fn a_1_sm4_gcm() {
    let key = SM4Key::<GCM>::from_key_material(&material()).unwrap();
    let nonce: [u8; 12] = bytes(NONCE);
    let aad: [u8; 20] = bytes(AAD);

    let mut buf: [u8; 64] = bytes(PLAINTEXT);
    let tag = key.encrypt_detached_in_place_nonce(&nonce, &aad, &mut buf).expect("encryption");
    assert_eq!(buf, bytes::<64>(GCM_CT), "A.1 ciphertext");
    assert_eq!(tag, bytes::<16>(GCM_TAG), "A.1 tag");

    key.decrypt_detached_in_place(&nonce, &aad, &mut buf, &tag).expect("decryption");
    assert_eq!(buf, bytes::<64>(PLAINTEXT), "A.1 plaintext back");

    let mut tampered = tag;
    tampered[0] ^= 1;
    assert!(key.decrypt_detached_in_place(&nonce, &aad, &mut buf, &tampered).is_err());
}

#[test]
fn a_2_sm4_ccm() {
    let key = SM4Key::<CCM<12, 16>>::from_key_material(&material()).unwrap();
    let nonce: [u8; 12] = bytes(NONCE);
    let aad: [u8; 20] = bytes(AAD);

    let mut buf: [u8; 64] = bytes(PLAINTEXT);
    let tag = key.encrypt_detached_in_place_nonce(&nonce, &aad, &mut buf).expect("encryption");
    assert_eq!(buf, bytes::<64>(CCM_CT), "A.2 ciphertext");
    assert_eq!(tag, bytes::<16>(CCM_TAG), "A.2 tag");

    key.decrypt_detached_in_place(&nonce, &aad, &mut buf, &tag).expect("decryption");
    assert_eq!(buf, bytes::<64>(PLAINTEXT), "A.2 plaintext back");

    let mut tampered = tag;
    tampered[0] ^= 1;
    assert!(key.decrypt_detached_in_place(&nonce, &aad, &mut buf, &tampered).is_err());
}
