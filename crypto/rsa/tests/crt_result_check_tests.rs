//! The result of a private-key operation is checked before it is released (the crate's
//! `# Security Considerations`): a key with one bit wrong in `dP`, `dQ` or `qInv`, which the
//! constructor has no means to notice, or with an `e` that is not its own, signs nothing and
//! decrypts nothing. Each such operation returns its error and leaves the caller's buffer
//! zeroized, under RSASSA-PKCS1-v1_5, RSASSA-PSS, RSASVE (raw and through HKDF) and RSAES-OAEP
//! (as a KEM and as key transport); the sound key does all of them.

use bouncycastle_core::errors::{KEMError, KeyTransportError, SignatureError};
use bouncycastle_core::kdf_params::{KdfParams, KeyLen};
use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::key_transport_key::{KeyTransportDecryptingKey, KeyTransportEncryptingKey};
use bouncycastle_core::signature_key::{
    DeterministicOneShotSigningKey, DeterministicSigningKey, OneShotSigningKey,
    OneShotVerifyingKey, SigningKey,
};
use bouncycastle_core::traits::{PrivateKey, SignatureSigner};
use bouncycastle_hkdf::HkdfDescription;
use bouncycastle_rng::DefaultRNG;
use bouncycastle_rsa::RSA2048;
use bouncycastle_rsa::keys::{RsaPrivateComponents, RsaPublicComponents};
use bouncycastle_rsa::rsa_2048::{
    RSA2048KEMPrivateKey, RSA2048KEMPublicKey, RSASSA_PKCS1_v1_5_SHA256, RSASSA_PSS_SHA256,
};
use bouncycastle_rsa::rsaes_oaep::OaepParams;
use bouncycastle_rsa::rsassa;
use bouncycastle_rsa::size::{RsaSigningSize, RsaSize};
use bouncycastle_sha2::SHA256;

// A genuine RSA-2048 key: the first SHA-256 group of Wycheproof's
// `rsa_pkcs1_2048_sig_gen_test.json` (`tests/rsa_2048_pkcs1_v1_5_tests.rs` has the provenance),
// with e = 65537.
const P: [u64; 16] = [
    0x0ea36cfb3a5b18f1, 0x48a6e65332119129, 0x110ad9e7b48a1c93, 0x569156b90113e2e9,
    0xe79813a575cfad9c, 0x69d659d143ec6f17, 0xe81e6bab5ddaa783, 0xbff1c5b80a69f788,
    0x978f6c35814f50ee, 0xe6a289ad4cfbf78f, 0x34d5681e5809d415, 0xbb028bda42eeb5d2,
    0x41c56e4de086b0d5, 0x58b8d1e24f3b55d0, 0xfb5248247d98cb7d, 0xdc431050f782e894,
];
const Q: [u64; 16] = [
    0x669f140cfbc20f25, 0xb97bb03677207d95, 0xfd4e06f3ed7299d4, 0x160f90536abc9492,
    0xf5b131f39098f7bc, 0xae8d72c57088d7ab, 0x89b94fbde542aba9, 0x3d3f9880ec47d5e0,
    0x1378a6868af3b7a0, 0x5544070beb057c94, 0x16611debc472fac4, 0xe500ffb79f5b8868,
    0x308a5e32196603b2, 0xea5fb19eb4eabc38, 0x122273ae3222b598, 0xbd1a81e7977f9898,
];
const D_P: [u64; 16] = [
    0x209f33f09515d7c1, 0xb4a9b37656917205, 0x276933bb07e4efb9, 0x8c14019808e00414,
    0x289f96da220711e5, 0xfbbd2923d31532fe, 0xc06b414e61c0e1e7, 0x4c23c4588488961d,
    0x4dc48ae34514759c, 0x9c786961ae3e2c35, 0x497e8d9c650688e0, 0x18bf08472612dbe5,
    0x8885fb161870ee12, 0xf21d7c1479d99d47, 0x9121d91952ffd1c7, 0xa94b528b28f29159,
];
const D_Q: [u64; 16] = [
    0xf7597ffb68011d8d, 0x7b3cc538c4bab8c9, 0xa8fa480a81a925af, 0x6d6ede7251a383bf,
    0x8a63f788ce3a0f85, 0x0b920502eb478bc9, 0x7e37e755edfe70d9, 0x9cf9948422a16555,
    0x0d6d9ea1f2ef71fd, 0xf7efa32ea0cb6e00, 0x0629b114ca7f780f, 0xcf51176359654348,
    0x540cdcbd4ad35435, 0x31c02ff1a2bc437c, 0xff2503df78bafed5, 0x3af0e72a933aef09,
];
const Q_INV: [u64; 16] = [
    0x552fe4bfce945f7b, 0x67e50c999c67247b, 0xfb54ef17be3b2853, 0x241f5921b5ad3983,
    0x02de5eccd143cf31, 0x74e45f6fcc60f216, 0xafa5428a74f12708, 0x88d42294b6a2759b,
    0xe923e1097c0c562f, 0xc968b48a91c38b5b, 0x933e85179c0320b0, 0x7993d0445f758d51,
    0x9bfc042ee0924b1b, 0x41f956d90fa8a793, 0xee7a87b6483a66ee, 0x2640fbfbcfefb163,
];

const E: u64 = 65537;
const MSG: &[u8] = b"a message";

/// The sound key and four damaged ones, each named: one bit flipped in `dP`, in `dQ` and in
/// `qInv`, and the sound components under an exponent that is not theirs. The constructor
/// takes all of them: every value is still in range.
fn keys() -> (RsaPrivateComponents<RSA2048>, Vec<(&'static str, RsaPrivateComponents<RSA2048>)>) {
    let key = |d_p: &[u64; 16], d_q: &[u64; 16], q_inv: &[u64; 16], e: u64| {
        RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &Q, d_p, d_q, q_inv, e)
            .expect("in range, so accepted")
    };
    let flipped = |x: &[u64; 16], limb: usize, bit: u32| {
        let mut x = *x;
        x[limb] ^= 1 << bit;
        x
    };
    let damaged = vec![
        ("dP", key(&flipped(&D_P, 0, 1), &D_Q, &Q_INV, E)),
        ("dQ", key(&D_P, &flipped(&D_Q, 7, 40), &Q_INV, E)),
        ("qInv", key(&D_P, &D_Q, &flipped(&Q_INV, 15, 3), E)),
        ("e", key(&D_P, &D_Q, &Q_INV, 65539)),
    ];
    (key(&D_P, &D_Q, &Q_INV, E), damaged)
}

/// The key-establishment key over the same components, by way of their encoding, which the
/// two key types share.
fn kem_key(components: &RsaPrivateComponents<RSA2048>) -> RSA2048KEMPrivateKey {
    let bytes: [u8; RSA2048::SK_LEN] = components.key::<RSASSA_PSS_SHA256>().encode();
    RSA2048KEMPrivateKey::from_bytes(&bytes).expect("the same bytes are a KEM key")
}

/// The size's checked exponentiation itself: a sound key gives the value that `e` takes back
/// to the input, and a damaged one gives FALSE and an output of zero.
#[test]
fn the_checked_exponentiation_releases_only_a_result_that_e_inverts() {
    let (sound, damaged) = keys();
    let mut x = [0u64; 32];
    x[0] = 0x0123_4567_89ab_cdef;
    x[17] = 0xfeed_face_cafe_f00d;

    let mut y = [0xFFFF_FFFF_FFFF_FFFFu64; 32];
    assert!(RSA2048::crt_exp(&sound, &x, &mut y).to_bool());
    assert_eq!(RSA2048::public_exp(sound.n(), E, &y), x);

    for (what, sk) in &damaged {
        let mut y = [0xFFFF_FFFF_FFFF_FFFFu64; 32];
        assert!(!RSA2048::crt_exp(sk, &x, &mut y).to_bool(), "{what}");
        assert_eq!(y, [0u64; 32], "{what}");
    }
}

#[test]
fn a_damaged_key_does_not_sign_pkcs1_v1_5() {
    let (sound, damaged) = keys();
    let pk = RsaPublicComponents::<RSA2048>::new(sound.n(), E).unwrap();
    let sig = sound.key::<RSASSA_PKCS1_v1_5_SHA256>().sign_deterministic(MSG, None).unwrap();
    pk.key::<RSASSA_PKCS1_v1_5_SHA256>().verify(MSG, None, &sig).unwrap();

    for (what, sk) in damaged {
        let sk = sk.into_key::<RSASSA_PKCS1_v1_5_SHA256>();
        assert_eq!(
            sk.sign_deterministic(MSG, None),
            Err(SignatureError::ComputationFault),
            "{what}"
        );
        let mut out = [0xFFu8; 256];
        assert_eq!(
            sk.sign_deterministic_out(MSG, None, &mut out),
            Err(SignatureError::ComputationFault),
            "{what}"
        );
        assert_eq!(out, [0u8; 256], "{what}");
        // Streaming, and from the hash.
        let mut signer = sk.create_signer_deterministic(None).unwrap();
        signer.do_update(MSG);
        let mut out = [0xFFu8; 256];
        assert_eq!(signer.do_final_out(&mut out), Err(SignatureError::ComputationFault), "{what}");
        assert_eq!(out, [0u8; 256], "{what}");
        assert_eq!(
            rsassa::sign_from_hash_deterministic(&sk, &[0x11; 32]),
            Err(SignatureError::ComputationFault),
            "{what}"
        );
    }
}

#[test]
fn a_damaged_key_does_not_sign_pss() {
    let (sound, damaged) = keys();
    let mut rng = DefaultRNG::default();
    let pk = RsaPublicComponents::<RSA2048>::new(sound.n(), E).unwrap();
    let sig = sound.key::<RSASSA_PSS_SHA256>().sign(&mut rng, MSG, None).unwrap();
    pk.key::<RSASSA_PSS_SHA256>().verify(MSG, None, &sig).unwrap();

    for (what, sk) in damaged {
        let sk = sk.into_key::<RSASSA_PSS_SHA256>();
        assert_eq!(sk.sign(&mut rng, MSG, None), Err(SignatureError::ComputationFault), "{what}");
        let mut out = [0xFFu8; 256];
        assert_eq!(
            sk.sign_out(&mut rng, MSG, None, &mut out),
            Err(SignatureError::ComputationFault),
            "{what}"
        );
        assert_eq!(out, [0u8; 256], "{what}");
        // Streaming with the salt given, from the hash with a salt drawn, and with one given.
        let mut signer = sk.create_signer(&mut rng, None).unwrap();
        signer.set_salt([0x42u8; 32]);
        signer.do_update(MSG);
        let mut out = [0xFFu8; 256];
        assert_eq!(signer.do_final_out(&mut out), Err(SignatureError::ComputationFault), "{what}");
        assert_eq!(out, [0u8; 256], "{what}");
        assert_eq!(
            rsassa::sign_from_hash(&sk, &[0x11; 32], &mut rng),
            Err(SignatureError::ComputationFault),
            "{what}"
        );
        assert_eq!(
            rsassa::sign_from_hash_with_salt(&sk, &[0x11; 32], &[0x42; 32]),
            Err(SignatureError::ComputationFault),
            "{what}"
        );
    }
}

/// RSASVE and RSASVE with HKDF: the secret value of a ciphertext made for the sound key is
/// not handed out by a damaged one.
#[test]
fn a_damaged_key_does_not_decapsulate_rsasve() {
    let (sound, damaged) = keys();
    let mut rng = DefaultRNG::default();
    let pk = RSA2048KEMPublicKey::new(sound.n(), E).unwrap();
    let sound = kem_key(&sound);
    let hkdf = HkdfDescription::<SHA256>::new();
    let params = KdfParams::new(&hkdf, b"info", KeyLen::<32>);

    let (z, ct) = pk.encaps(&mut rng, ()).unwrap();
    assert_eq!(sound.decaps(&ct, ()).unwrap(), z);
    let (key, ct_kdf) = pk.encaps(&mut rng, params).unwrap();
    assert_eq!(sound.decaps(&ct_kdf, params).unwrap(), key);

    for (what, sk) in damaged {
        let sk = kem_key(&sk);
        assert!(matches!(sk.decaps(&ct, ()), Err(KEMError::DecapsulationFailed)), "{what}");
        let mut ss = KeyMaterial::<256>::from_bytes(&[0xEE; 256]).unwrap();
        assert_eq!(sk.decaps_out(&ct, (), &mut ss), Err(KEMError::DecapsulationFailed), "{what}");
        assert_eq!(ss.key_type(), KeyType::Zeroized, "{what}");
        assert_eq!(ss.key_len(), 0, "{what}");

        let mut ss = KeyMaterial::<32>::from_bytes(&[0xEE; 32]).unwrap();
        assert_eq!(
            sk.decaps_out(&ct_kdf, params, &mut ss),
            Err(KEMError::DecapsulationFailed),
            "{what}"
        );
        assert_eq!(ss.key_type(), KeyType::Zeroized, "{what}");
    }
}

/// RSAES-OAEP: a failed result check is the one decryption error, as a wrong label is, with
/// the key buffer zeroized, for the KEM and for key transport.
#[test]
fn a_damaged_key_does_not_decrypt_oaep() {
    let (sound, damaged) = keys();
    let mut rng = DefaultRNG::default();
    let pk = RSA2048KEMPublicKey::new(sound.n(), E).unwrap();
    let sound = kem_key(&sound);
    let params = OaepParams::<SHA256>::new(b"label");

    let (ss, ct) = pk.encaps(&mut rng, params).unwrap();
    assert_eq!(sound.decaps(&ct, params).unwrap(), ss);
    let sent = KeyMaterial::<48>::from_bytes_as_type(&[0x42; 48], KeyType::MACKey).unwrap();
    let ct_sent = pk.transport(&mut rng, params, &sent).unwrap();
    let mut recovered = KeyMaterial::<64>::new();
    assert_eq!(sound.recover_out(&ct_sent, params, &mut recovered), Ok(48));
    assert_eq!(recovered.ref_to_bytes(), [0x42; 48]);

    // What any other decryption failure looks like: the sound key under the wrong label.
    let wrong = OaepParams::<SHA256>::new(b"another label");
    let mut out = KeyMaterial::<64>::from_bytes(&[0xEE; 64]).unwrap();
    assert_eq!(
        sound.recover_out(&ct_sent, wrong, &mut out),
        Err(KeyTransportError::DecryptionFailed)
    );
    assert_eq!(out.key_type(), KeyType::Zeroized);

    for (what, sk) in damaged {
        let sk = kem_key(&sk);
        assert!(matches!(sk.decaps(&ct, params), Err(KEMError::DecapsulationFailed)), "{what}");
        let mut ss = KeyMaterial::<32>::from_bytes(&[0xEE; 32]).unwrap();
        assert_eq!(
            sk.decaps_out(&ct, params, &mut ss),
            Err(KEMError::DecapsulationFailed),
            "{what}"
        );
        assert_eq!(ss.key_type(), KeyType::Zeroized, "{what}");

        let mut out = KeyMaterial::<64>::from_bytes(&[0xEE; 64]).unwrap();
        assert_eq!(
            sk.recover_out(&ct_sent, params, &mut out),
            Err(KeyTransportError::DecryptionFailed),
            "{what}"
        );
        assert_eq!(out.key_type(), KeyType::Zeroized, "{what}");
        assert_eq!(out.key_len(), 0, "{what}");
    }
}
