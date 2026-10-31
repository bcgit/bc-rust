//! Type alias for SM4 in GCM (NIST SP 800-38D over the SM4 permutation; RFC 8998 Sec 3.5.1's
//! `AEAD_SM4_GCM`).
//!
//! See `bouncycastle_cipher::modes::gcm` for the construction. The alias is an authenticated
//! cipher: encryption produces a tag as well as a ciphertext, and decryption either returns the
//! plaintext or fails the tag check. Both directions implement [`AEADCipherEncryptor`] /
//! [`AEADCipherDecryptor`], which keep the tag detached, and [`SymmetricCipherEncryptor`] /
//! [`SymmetricCipherDecryptor`], which carry it inline as `ciphertext || tag`. They come from a
//! key, [`SM4Key<GCM>`](crate::SM4Key), through the [`AeadEncryptionKey`] /
//! [`AeadDecryptionKey`] pair, which draws the nonce from the caller's RNG and returns it, or
//! takes the caller's through its `_nonce` forms. `Dir` is [`Encrypting`] or [`Decrypting`]; the
//! wrong direction is a compile error, not a runtime check.
//!
//! The nonce is [`GCM_NONCE_LEN`] (12 bytes) and the tag 16, which is what RFC 8998 Sec 3.5.1
//! fixes for `AEAD_SM4_GCM`: "The nonce length is 12 octets. The authentication tag length is 16
//! octets." For a shorter tag, name the key's mode as `GCM<12>` and so on, within the `12..=16`
//! bytes `Gcm` accepts. The RFC's Appendix A.1 vector is pinned in `tests/rfc8998_tests.rs`.
//!
//! # Usage Examples
//!
//! The detached one-shots return the tag separately from the ciphertext:
//!
//! ```
//! use bouncycastle_sm4::SM4Key;
//! use bouncycastle_cipher::modes::GCM;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey, FromKeyMaterial};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();   // one RNG, held across messages
//! let material = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let key = SM4Key::<GCM>::from_key_material(&material).expect("a valid SM4 key");
//!
//! // The associated data is authenticated but not encrypted; the message is both.
//! let aad = b"header, sent in the clear";
//! let message = b"a message of no particular length";
//!
//! // The nonce is drawn from `rng` and returned.
//! let (nonce, ciphertext, tag) = key.encrypt_detached(&mut rng, aad, message).expect("encryption");
//! assert_eq!(ciphertext.len(), message.len(), "GCM never expands the payload");
//!
//! let recovered = key.decrypt_detached(&nonce, aad, &ciphertext, &tag).expect("decryption");
//! assert_eq!(recovered, message);
//!
//! // Tampering with the ciphertext, the tag or the associated data fails the tag check.
//! let mut tampered = ciphertext.clone();
//! tampered[0] ^= 1;
//! assert!(key.decrypt_detached(&nonce, aad, &tampered, &tag).is_err());
//! assert!(key.decrypt_detached(&nonce, b"other header", &ciphertext, &tag).is_err());
//! ```
//!
//! Through the `_with_aad` one-shots the tag is appended to the ciphertext, and the streaming
//! methods take the data in pieces; `bouncycastle_aes::gcm` shows both, and they are the same
//! calls on this key.
//!
//! # 🚨 Security Considerations 🚨
//!
//! All security considerations from `bouncycastle_cipher::modes::gcm` apply, above all that a
//! nonce repeated under one key lets an attacker recover the hash subkey and forge tags, which
//! RFC 8998 Sec 3.5.1 restates for `AEAD_SM4_GCM`: "Using the same nonce for two different
//! messages encrypted with the same key destroys the security properties of GCM mode."

use crate::hazmat::SM4Internal;
use bouncycastle_cipher::modes::Gcm;

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_cipher::modes::GCM_NONCE_LEN;
#[allow(unused_imports)]
use bouncycastle_cipher::{Decrypting, Encrypting};
#[allow(unused_imports)]
use bouncycastle_core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey};
#[allow(unused_imports)]
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};
// end of imports needed for docs

/// SM4 in GCM with a 128-bit tag.
#[allow(non_camel_case_types)]
pub type SM4_GCM<'k, Dir> = Gcm<'k, SM4Internal, Dir, 16>;
