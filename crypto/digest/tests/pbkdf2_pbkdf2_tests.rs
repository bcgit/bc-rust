//! PBKDF2 against RFC 7914 Section 11's PBKDF2-HMAC-SHA-256 vectors and RFC 8018 Section 5.2's
//! steps by hand, with the limits, the typing of the output and the [`KDF`] trait's rules.

use bouncycastle_core::errors::KDFError;
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::hex::decode as hex_decode;
use bouncycastle_core::kdf_params::KdfDescription;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey};
use bouncycastle_core::traits::{Algorithm, HashOneShot, KDF};
use bouncycastle_digest::pbkdf2::{
    PBKDF2, PBKDF2_HMAC_SHA3_256, PBKDF2_HMAC_SHA224, PBKDF2_HMAC_SHA256, PBKDF2_HMAC_SHA384,
    PBKDF2_HMAC_SHA512,
};
use bouncycastle_hmac::HmacKey;
use bouncycastle_sha2::SHA256;
use core::num::NonZeroU32;

/// RFC 7914 Section 11: (P, S, c, DK), with dkLen = 64.
const RFC_7914: [(&[u8], &[u8], u32, &str); 2] = [
    (
        b"passwd",
        b"salt",
        1,
        "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
    ),
    (
        b"Password",
        b"NaCl",
        80000,
        "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d",
    ),
];

fn c(n: u32) -> NonZeroU32 {
    NonZeroU32::new(n).unwrap()
}

/// A password: bytes of unknown entropy.
fn password(bytes: &[u8]) -> KeyMaterial<256> {
    KeyMaterial::<256>::from_bytes_as_type(bytes, KeyType::Unknown).unwrap()
}

/// HMAC-SHA256 under `key` over `parts`, through the key object.
fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let key = KeyMaterial::<144>::from_bytes_as_type(key, KeyType::MACKey).unwrap();
    HmacKey::<SHA256>::from_key_material_allow_weak(&key).unwrap().mac(&parts.concat())
}

#[test]
fn rfc_7914_section_11() {
    for (p, s, count, dk) in RFC_7914 {
        let expected = hex_decode(dk).unwrap();
        let mut out = KeyMaterial::<64>::new();
        let written =
            PBKDF2_HMAC_SHA256::derive_out(&password(p), s, c(count), 64, &mut out).unwrap();
        assert_eq!(written, 64);
        assert_eq!(out.ref_to_bytes(), &expected[..], "c = {count}");

        // The same through the trait, on an instance.
        let kdf = PBKDF2_HMAC_SHA256::new(s, c(count));
        assert_eq!(kdf.derive_key(&password(p), &[], 64).unwrap().ref_to_bytes(), &expected[..]);
    }
}

/// Section 5.2 steps 3 and 4 by hand: T_i = U_1 xor ... xor U_c with U_1 = PRF(P, S || INT(i))
/// and U_j = PRF(P, U_{j-1}), the PRF being HMAC keyed with the password.
#[test]
fn matches_the_xor_of_the_prf_iterates() {
    let (p, s) = (b"a password".as_slice(), b"a salt of some length".as_slice());
    for count in [1u32, 2, 3, 7] {
        let mut expected = Vec::new();
        for i in 1..=3u32 {
            let mut u = hmac_sha256(p, &[s, &i.to_be_bytes()]);
            let mut t = u;
            for _ in 1..count {
                u = hmac_sha256(p, &[&u]);
                t.iter_mut().zip(u.iter()).for_each(|(t, u)| *t ^= u);
            }
            expected.extend_from_slice(&t);
        }
        // 80 bytes: two whole blocks and half of a third.
        let mut out = KeyMaterial::<128>::new();
        assert_eq!(PBKDF2_HMAC_SHA256::derive_out(&password(p), s, c(count), 80, &mut out), Ok(80));
        assert_eq!(out.ref_to_bytes(), &expected[..80], "c = {count}");
        // Nothing of the last block is left past dkLen.
        let mut capacity = Vec::new();
        do_hazardous_operations(&mut out, |k| {
            capacity = k.ref_to_bytes_mut()?.to_vec();
            Ok(())
        })
        .unwrap();
        assert_eq!(&capacity[80..], &[0u8; 48]);
        // A buffer of exactly dkLen bytes.
        let mut exact = KeyMaterial::<80>::new();
        assert_eq!(
            PBKDF2_HMAC_SHA256::derive_out(&password(p), s, c(count), 80, &mut exact),
            Ok(80)
        );
        assert_eq!(exact.ref_to_bytes(), &expected[..80]);
    }
    // An empty salt and an empty password are both octet strings like any other.
    let u = hmac_sha256(b"", &[&1u32.to_be_bytes()]);
    let mut out = KeyMaterial::<32>::new();
    assert_eq!(
        PBKDF2_HMAC_SHA256::derive_out(&KeyMaterial::<32>::new(), b"", c(1), 32, &mut out),
        Ok(32)
    );
    assert_eq!(out.ref_to_bytes(), &u[..]);
}

/// RFC 8018 Appendix B.1.1 through the function: a password longer than the hash's block keys
/// HMAC as its hash does, whether it arrives as one key or several; one of exactly a block
/// does not.
#[test]
fn a_long_password_is_hashed_as_hmac_does() {
    let kdf = PBKDF2_HMAC_SHA256::new(b"salt", c(3));
    let long = [0x42u8; 65];
    let expected = kdf.derive_key(&password(&SHA256::hash(&long)), &[], 48).unwrap();
    assert_eq!(
        kdf.derive_key(&password(&long), &[], 48).unwrap().ref_to_bytes(),
        expected.ref_to_bytes()
    );
    let (a, b) = (password(&long[..40]), password(&long[40..]));
    assert_eq!(
        kdf.derive_key_from_multiple(&[&a, &b], &[], 48).unwrap().ref_to_bytes(),
        expected.ref_to_bytes()
    );

    let block = [0x42u8; 64];
    let whole = kdf.derive_key(&password(&block), &[], 48).unwrap();
    assert_ne!(
        whole.ref_to_bytes(),
        kdf.derive_key(&password(&SHA256::hash(&block)), &[], 48).unwrap().ref_to_bytes()
    );
    let (a, b) = (password(&block[..1]), password(&block[1..]));
    assert_eq!(
        kdf.derive_key_from_multiple(&[&a, &b], &[], 48).unwrap().ref_to_bytes(),
        whole.ref_to_bytes()
    );
}

#[test]
fn bad_requests_are_refused_with_the_buffer_zeroized() {
    let p = password(b"password");
    let kdf = PBKDF2_HMAC_SHA256::new(b"salt", c(2));
    let stale = || {
        let mut out = KeyMaterial::<32>::new();
        out.set_bytes_as_type(&[0xAA; 32], KeyType::CryptographicRandom).unwrap();
        out
    };
    let refused = |r: Result<usize, KDFError>, out: &KeyMaterial<32>, what: &str| {
        assert!(matches!(r, Err(KDFError::InvalidLength(_))), "{what}");
        assert_eq!((out.key_type(), out.key_len()), (KeyType::Zeroized, 0), "{what}");
    };

    let mut out = stale();
    refused(kdf.derive_key_out(&p, &[], 0, &mut out), &out, "a zero length");
    let mut out = stale();
    refused(kdf.derive_key_out(&p, &[], 33, &mut out), &out, "more than the buffer holds");
    let mut out = stale();
    refused(kdf.derive_key_from_multiple_out(&[], &[], 16, &mut out), &out, "no keys");
    // PBKDF2 has no fixed info, and says so through both forms.
    let mut out = stale();
    refused(kdf.derive_key_out(&p, b"info", 16, &mut out), &out, "fixed info");
    let mut out = stale();
    refused(kdf.derive_key_from_multiple_out(&[&p], b"i", 16, &mut out), &out, "fixed info");
    // The static form refuses the same lengths.
    let mut out = stale();
    refused(PBKDF2_HMAC_SHA256::derive_out(&p, b"salt", c(2), 0, &mut out), &out, "zero, static");
    let mut out = stale();
    refused(PBKDF2_HMAC_SHA256::derive_out(&p, b"salt", c(2), 33, &mut out), &out, "long, static");

    // The buffer's whole capacity is fine, and the trait object works.
    let mut out = stale();
    assert_eq!(kdf.derive_key_out(&p, &[], 32, &mut out), Ok(32));
    let dyn_kdf: &dyn KDF = &kdf;
    assert_eq!(dyn_kdf.derive_key(&p, &[], 32).unwrap().ref_to_bytes(), out.ref_to_bytes());

    // Step 1's bound: (2^32 - 1) * hLen.
    assert_eq!(PBKDF2_HMAC_SHA256::MAX_LEN as u128, 32 * 0xFFFF_FFFFu128);
    assert_eq!(PBKDF2_HMAC_SHA512::MAX_LEN as u128, 64 * 0xFFFF_FFFFu128);
    // One byte past it is "derived key too long"; the bound itself is only more than this
    // buffer holds.
    let mut out = stale();
    assert_eq!(
        kdf.derive_key_out(&p, &[], PBKDF2_HMAC_SHA256::MAX_LEN + 1, &mut out),
        Err(KDFError::InvalidLength("derived key too long"))
    );
    assert_eq!(
        kdf.derive_key_out(&p, &[], PBKDF2_HMAC_SHA256::MAX_LEN, &mut out),
        Err(KDFError::InvalidLength("the output buffer cannot hold dkLen bytes"))
    );
}

/// A password credits nothing, so its key is `Unknown`; full-entropy keying material of half a
/// hash output or more gives `CryptographicRandom` at the least of its strength, HMAC's and the
/// length's.
#[test]
fn the_output_is_typed_from_the_input() {
    let typed = |len: usize, strength: SecurityStrength| {
        let mut k =
            KeyMaterial::<64>::from_bytes_as_type(&[0x33; 64][..len], KeyType::SharedSecret)
                .unwrap();
        do_hazardous_operations(&mut k, |k| k.set_security_strength(strength)).unwrap();
        k
    };
    let label = |kdf: &dyn KDF, keys: &[&dyn KeyMaterialTrait], len: usize| {
        let out = kdf.derive_key_from_multiple(keys, &[], len).unwrap();
        (out.key_type(), out.security_strength())
    };
    let random = KeyType::CryptographicRandom;
    let unknown = (KeyType::Unknown, SecurityStrength::None);
    let sha256 = PBKDF2_HMAC_SHA256::new(b"salt", c(2));
    let sha512 = PBKDF2_HMAC_SHA512::new(b"salt", c(2));

    assert_eq!(label(&sha256, &[&password(b"correct horse battery staple")], 32), unknown);
    assert_eq!(label(&sha256, &[&KeyMaterial::<32>::new()], 32), unknown);
    let unstated =
        KeyMaterial::<64>::from_bytes_as_type(&[0x33; 64], KeyType::SharedSecret).unwrap();
    assert_eq!(label(&sha512, &[&unstated], 32), unknown);

    let strong = typed(64, SecurityStrength::_256bit);
    assert_eq!(label(&sha256, &[&strong], 64), (random, SecurityStrength::_128bit));
    assert_eq!(label(&sha512, &[&strong], 64), (random, SecurityStrength::_256bit));
    assert_eq!(label(&sha512, &[&strong], 16), (random, SecurityStrength::_128bit));
    assert_eq!(
        label(&sha512, &[&typed(64, SecurityStrength::_112bit)], 64),
        (random, SecurityStrength::_112bit)
    );
    // Half a hash output seeds it; one byte less does not.
    assert_eq!(
        label(&sha256, &[&typed(16, SecurityStrength::_128bit)], 32),
        (random, SecurityStrength::_128bit)
    );
    assert_eq!(label(&sha256, &[&typed(15, SecurityStrength::_112bit)], 32), unknown);
    assert_eq!(label(&sha512, &[&typed(31, SecurityStrength::_192bit)], 32), unknown);
    // Two keys are credited together, at the stronger's strength; a password beside a key
    // adds nothing and takes nothing away.
    let (a, b) = (typed(14, SecurityStrength::_112bit), typed(16, SecurityStrength::_128bit));
    assert_eq!(label(&sha256, &[&a], 32), unknown);
    assert_eq!(label(&sha256, &[&a, &b], 32), (random, SecurityStrength::_128bit));
    assert_eq!(label(&sha256, &[&b, &password(b"pw")], 32), (random, SecurityStrength::_128bit));
}

/// SP 800-132's figures for the key, the salt and the iteration count are the caller's to meet
/// (the crate's Security Considerations): no minimum is enforced, and this pins that so a
/// change is noticed.
#[test]
fn no_minimum_is_enforced() {
    let kdf = PBKDF2_HMAC_SHA256::new(b"", c(1));
    let key = kdf.derive_key(&password(b"p"), &[], 1).unwrap();
    assert_eq!(key.key_len(), 1);
}

#[test]
fn names_parameters_and_description() {
    assert_eq!(PBKDF2_HMAC_SHA224::ALG_NAME, "PBKDF2-HMAC-SHA224");
    assert_eq!(PBKDF2_HMAC_SHA256::ALG_NAME, "PBKDF2-HMAC-SHA256");
    assert_eq!(PBKDF2_HMAC_SHA3_256::ALG_NAME, "PBKDF2-HMAC-SHA3-256");
    assert_eq!(PBKDF2_HMAC_SHA256::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);
    assert_eq!(PBKDF2_HMAC_SHA384::MAX_SECURITY_STRENGTH, SecurityStrength::_192bit);
    assert_eq!(PBKDF2_HMAC_SHA512::MAX_SECURITY_STRENGTH, SecurityStrength::_256bit);

    let kdf = PBKDF2::<SHA256>::new(b"the salt", c(5));
    assert_eq!(kdf.salt(), b"the salt");
    assert_eq!(kdf.iterations().get(), 5);
    #[allow(clippy::clone_on_copy)]
    let copy = kdf.clone();
    assert_eq!((copy.salt(), copy.iterations().get()), (&b"the salt"[..], 5));
    // The description's engine is the KDF it describes.
    let engine = kdf.engine().unwrap();
    assert_eq!((engine.salt(), engine.iterations().get()), (&b"the salt"[..], 5));
    let p = password(b"pw");
    assert_eq!(
        engine.derive_key(&p, &[], 40).unwrap().ref_to_bytes(),
        kdf.derive_key(&p, &[], 40).unwrap().ref_to_bytes()
    );
    // The salt and the count each change the output.
    let base = kdf.derive_key(&p, &[], 32).unwrap();
    assert_ne!(
        PBKDF2::<SHA256>::new(b"the salt", c(6)).derive_key(&p, &[], 32).unwrap().ref_to_bytes(),
        base.ref_to_bytes()
    );
    assert_ne!(
        PBKDF2::<SHA256>::new(b"the salT", c(5)).derive_key(&p, &[], 32).unwrap().ref_to_bytes(),
        base.ref_to_bytes()
    );
}
