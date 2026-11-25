//! Known answers for CTS from RFC 3962 (AES Encryption for Kerberos 5), Appendix B: six AES-128
//! messages of 17 to 64 bytes under an all-zero IV, carried here as the RFC prints them.
//!
//! RFC 3962 Sec 5 takes its ciphertext stealing from RFC 2040 Sec 8, and the Addendum to NIST SP
//! 800-38A names it: "CBC-CS3 is the variant specified for Kerberos 5 in Ref. [2]", Ref. [2] being
//! RFC 3962. So these are the known answers of `CTS` and of `CBC_CS3`, one type, which must
//! reproduce them through the one-shots and streamed. CBC-CS2 differs from CBC-CS3 only when the
//! last block is whole, so it must reproduce exactly the vectors with a partial last block (17, 31
//! and 47 bytes), and CBC-CS1, which never swaps, none of them; both are pinned here too.
//!
//! The vectors' "Next IV" lines are Kerberos's cipher state, carried from one message to the next,
//! which this API does not carry; they are not checked.

use bouncycastle_core::hex;
use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
use bouncycastle_core::symmetric_key::{
    FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};
use bouncycastle_symmetric::aes::AES128Key;
use bouncycastle_symmetric::modes::{CBC_CS1, CBC_CS2, CTS};

/// The AES-128 key of every vector, `63 68 69 63 6b 65 6e 20 74 65 72 69 79 61 6b 69`.
const KEY: &[u8; 16] = b"chicken teriyaki";

/// The IV of every vector.
const IV: [u8; 16] = [0; 16];

/// (Input, Output), RFC 3962 Appendix B, in its order.
const VECTORS: [(&str, &str); 6] = [
    ("4920776f756c64206c696b652074686520", "c6353568f2bf8cb4d8a580362da7ff7f97"),
    (
        "4920776f756c64206c696b65207468652047656e6572616c20476175277320",
        "fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5",
    ),
    (
        "4920776f756c64206c696b65207468652047656e6572616c2047617527732043",
        "39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584",
    ),
    (
        "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c",
        "97687268d6ecccc0c07b25e25ecfe584b3fffd940c16a18c1b5549d2f838029e39312523a78662d5be7fcbcc98ebf5",
    ),
    (
        "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20",
        "97687268d6ecccc0c07b25e25ecfe5849dad8bbb96c4cdc03bc103e1a194bbd839312523a78662d5be7fcbcc98ebf5a8",
    ),
    (
        "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20616e6420776f6e746f6e20736f75702e",
        "97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a84807efe836ee89a526730dbc2f7bc8409dad8bbb96c4cdc03bc103e1a194bbd8",
    ),
];

fn key<K: FromKeyMaterial<16>>() -> K {
    let material = KeyMaterial128::from_bytes_as_type(KEY, KeyType::SymmetricCipherKey)
        .expect("the vectors' 16-byte key");
    K::from_key_material(&material).expect("a valid AES-128 key")
}

fn vectors() -> impl Iterator<Item = (Vec<u8>, Vec<u8>)> {
    VECTORS.iter().map(|(pt, ct)| (hex::decode(pt).unwrap(), hex::decode(ct).unwrap()))
}

#[test]
fn cts_reproduces_rfc_3962_appendix_b() {
    let cts = key::<AES128Key<CTS>>();
    for (pt, ct) in vectors() {
        let len = pt.len();
        assert_eq!(cts.encrypt_nonce(&IV, &pt).expect("encryption"), ct, "{len} bytes");
        assert_eq!(cts.decrypt(&IV, &ct).expect("decryption"), pt, "{len} bytes");

        // Streamed in 5-byte pieces, which cross every block boundary at a different offset.
        let mut enc = cts.create_encryptor_nonce(&IV);
        let mut streamed = Vec::new();
        for piece in pt.chunks(5) {
            let mut out = vec![0u8; enc.do_encrypt_out_len(piece.len())];
            enc.do_encrypt_out(piece, &mut out).expect("streaming encryption");
            streamed.extend_from_slice(&out);
        }
        let (last, last_len) = enc.do_encrypt_final().expect("final");
        streamed.extend_from_slice(&last[..last_len]);
        assert_eq!(streamed, ct, "{len} bytes, streamed");

        let mut dec = cts.create_decryptor(&IV);
        let mut recovered = Vec::new();
        for piece in ct.chunks(5) {
            let mut out = vec![0u8; dec.do_decrypt_out_len(piece.len())];
            dec.do_decrypt_out(piece, &mut out).expect("streaming decryption");
            recovered.extend_from_slice(&out);
        }
        let (last, last_len) = dec.do_decrypt_final().expect("final");
        recovered.extend_from_slice(&last[..last_len]);
        assert_eq!(recovered, pt, "{len} bytes, streamed");
    }
}

#[test]
fn cbc_cs2_reproduces_exactly_the_vectors_with_a_partial_last_block() {
    let cs2 = key::<AES128Key<CBC_CS2>>();
    for (pt, ct) in vectors() {
        let partial = pt.len() % 16 != 0;
        assert_eq!(
            cs2.encrypt_nonce(&IV, &pt).expect("encryption") == ct,
            partial,
            "{} bytes: CBC-CS2 is CBC-CS3 exactly when the last block is partial",
            pt.len()
        );
    }
}

#[test]
fn cbc_cs1_reproduces_none_of_them() {
    let cs1 = key::<AES128Key<CBC_CS1>>();
    for (pt, ct) in vectors() {
        assert_ne!(cs1.encrypt_nonce(&IV, &pt).expect("encryption"), ct, "{} bytes", pt.len());
    }
}
