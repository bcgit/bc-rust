//! The SM4-GCM and SM4-CCM test vectors of RFC 8998 Appendix A, through the `GCM` and
//! `CCM<12, 16>` modes over `SM4Internal`.
//!
//! RFC 8998 Sec 3.5 defines `AEAD_SM4_GCM` and `AEAD_SM4_CCM` for TLS 1.3 as GCM and CCM over
//! SM4 with a 12-byte nonce and a 16-byte tag; its Appendix A gives one vector for each, the same
//! key, nonce, plaintext and associated data. `SM4Key` carries no AEAD role, since this crate
//! aliases no AEAD mode, so the vectors run through the `hazmat` mode traits over the
//! permutation's key state, which is what a key under those modes would forward to. All values
//! are transcribed from the downloaded text of the RFC.

use bouncycastle_cipher::modes::{CCM, GCM};
use bouncycastle_core::hazmat::{
    AeadDeclaredDecryptMode, AeadDeclaredEncryptMode, AeadDecryptMode, AeadEncryptMode,
    ElectronicCodeBook, Mode,
};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_hex as hex;
use bouncycastle_sm4::KEY_LEN;
use bouncycastle_sm4::hazmat::SM4Internal;

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

type Sm4Ccm = CCM<12, 16>;

fn bytes<const N: usize>(hex_str: &str) -> [u8; N] {
    hex::decode(hex_str).expect("valid hex").try_into().expect("expected length")
}

fn permutation() -> SM4Internal {
    let material = KeyMaterial::<KEY_LEN>::from_bytes_as_type(
        &bytes::<KEY_LEN>(KEY),
        KeyType::SymmetricCipherKey,
    )
    .expect("a valid symmetric cipher key");
    SM4Internal::new(&material).expect("a valid SM4 key")
}

#[test]
fn a_1_sm4_gcm() {
    let state = <GCM as Mode<SM4Internal>>::key_state(permutation());
    let nonce: [u8; 12] = bytes(NONCE);
    let aad: [u8; 20] = bytes(AAD);

    let mut buf: [u8; 64] = bytes(PLAINTEXT);
    let tag = <GCM as AeadEncryptMode<SM4Internal, KEY_LEN, 12, 16, 16>>::encrypt_detached_in_place_nonce(
        &state, &nonce, &aad, &mut buf,
    )
    .expect("encryption");
    assert_eq!(buf, bytes::<64>(GCM_CT), "A.1 ciphertext");
    assert_eq!(tag, bytes::<16>(GCM_TAG), "A.1 tag");

    let decrypt =
        <GCM as AeadDecryptMode<SM4Internal, KEY_LEN, 12, 16, 16>>::decrypt_detached_in_place;
    decrypt(&state, &nonce, &aad, &mut buf, &tag).expect("decryption");
    assert_eq!(buf, bytes::<64>(PLAINTEXT), "A.1 plaintext back");

    let mut tampered = tag;
    tampered[0] ^= 1;
    assert!(decrypt(&state, &nonce, &aad, &mut buf, &tampered).is_err());
}

#[test]
fn a_2_sm4_ccm() {
    let state = <Sm4Ccm as Mode<SM4Internal>>::key_state(permutation());
    let nonce: [u8; 12] = bytes(NONCE);
    let aad: [u8; 20] = bytes(AAD);

    let mut buf: [u8; 64] = bytes(PLAINTEXT);
    let tag = <Sm4Ccm as AeadDeclaredEncryptMode<SM4Internal, KEY_LEN, 12, 16, 16>>::encrypt_detached_in_place_nonce(
        &state, &nonce, &aad, &mut buf,
    )
    .expect("encryption");
    assert_eq!(buf, bytes::<64>(CCM_CT), "A.2 ciphertext");
    assert_eq!(tag, bytes::<16>(CCM_TAG), "A.2 tag");

    let decrypt =
        <Sm4Ccm as AeadDeclaredDecryptMode<SM4Internal, KEY_LEN, 12, 16, 16>>::decrypt_detached_in_place;
    decrypt(&state, &nonce, &aad, &mut buf, &tag).expect("decryption");
    assert_eq!(buf, bytes::<64>(PLAINTEXT), "A.2 plaintext back");

    let mut tampered = tag;
    tampered[0] ^= 1;
    assert!(decrypt(&state, &nonce, &aad, &mut buf, &tampered).is_err());
}
