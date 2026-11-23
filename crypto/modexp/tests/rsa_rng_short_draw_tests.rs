//! A draw from the RNG that comes back short is an error everywhere this module draws: the
//! contract of `RNG::next_bytes_out` is that the buffer is zeroized and the count of bytes
//! written returned, so an RNG that writes half and says so must not have its zeros used as
//! half of a prime candidate, a salt, an OAEP seed, a transported key or a secret value.

use bouncycastle_core::errors::{KEMError, KeyTransportError, RNGError, SignatureError};
use bouncycastle_core::kem_key::EncapsulatingKey;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::key_transport_key::KeyTransportEncryptingKey;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::{OneShotSigningKey, SigningKey};
use bouncycastle_core::traits::RNG;
use bouncycastle_digest::sha2::SHA256;
use bouncycastle_modexp::rsa::RSA2048;
use bouncycastle_modexp::rsa::keygen::is_probable_prime;
use bouncycastle_modexp::rsa::keys::RsaPrivateComponents;
use bouncycastle_modexp::rsa::rsa_2048::{RSA2048KEMPublicKey, RSASSA_PSS_SHA256};
use bouncycastle_modexp::rsa::rsaes_oaep::OaepParams;
use bouncycastle_modexp::rsa::rsassa::sign_from_hash;
use bouncycastle_modexp::rsa::size::{KemKeyPair, RsaSigningSize, SignatureKeyPair};
use core::num::NonZeroUsize;

// A genuine RSA-2048 key: the first SHA-256 group of Wycheproof's
// `rsa_pkcs1_2048_sig_gen_test.json` (`tests/rsa_2048_pkcs1_v1_5_tests.rs` has the provenance).
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

/// An RNG that fills the first half of what it is asked for, leaves the rest zero, and returns
/// the count it wrote, as the trait asks. `draws` counts the calls.
struct WritesHalf {
    draws: usize,
}

impl RNG for WritesHalf {
    fn add_seed_keymaterial(&mut self, _: &dyn KeyMaterialTrait) -> Result<(), RNGError> {
        Err(RNGError::GenericError("not seedable"))
    }
    fn next_int(&mut self) -> Result<u32, RNGError> {
        Err(RNGError::GenericError("not used"))
    }
    fn next_bytes_out(&mut self, out: &mut [u8]) -> Result<usize, RNGError> {
        self.draws += 1;
        out.fill(0);
        let half = out.len() / 2;
        out[..half].fill(0xA5);
        Ok(half)
    }
    fn fill_keymaterial_out(&mut self, _: &mut dyn KeyMaterialTrait) -> Result<usize, RNGError> {
        Err(RNGError::GenericError("not used"))
    }
    fn security_strength(&self) -> SecurityStrength {
        SecurityStrength::_256bit
    }
}

const SHORT: RNGError = RNGError::GenericError("the RNG wrote fewer bytes than it was asked for");

/// Key generation stops at the first short draw, through every generator, and the Miller-Rabin
/// test does on its own.
#[test]
fn key_generation_refuses_a_short_draw() {
    let mut rng = WritesHalf { draws: 0 };
    assert_eq!(RSA2048::keygen(&mut rng).unwrap_err(), SignatureError::RNGError(SHORT));
    assert_eq!(rng.draws, 1);
    assert!(matches!(
        RSA2048::generate_pss_signature_key_pair::<SHA256>(&mut WritesHalf { draws: 0 }),
        Err(SignatureError::RNGError(SHORT))
    ));
    assert!(matches!(
        RSA2048::generate_kem_key_pair(&mut WritesHalf { draws: 0 }),
        Err(KEMError::RNGError(SHORT))
    ));
    // 2^127 - 1 is prime and has no factor below the trial-division bound, so the test goes
    // on to draw a base.
    let w = [u64::MAX, u64::MAX >> 1];
    assert_eq!(
        is_probable_prime::<2, 4, 5>(
            &w,
            NonZeroUsize::new(5).unwrap(),
            &mut WritesHalf { draws: 0 }
        ),
        Err(SignatureError::RNGError(SHORT))
    );
}

/// RSASSA-PSS draws its salt when the signer is made: no signer, and no signature from the
/// one-shot or from the hash entry point, whose output buffer stays zero.
#[test]
fn pss_signing_refuses_a_short_salt() {
    let sk =
        RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV, 0x10001)
            .unwrap()
            .into_key::<RSASSA_PSS_SHA256>();
    assert!(matches!(
        sk.create_signer(&mut WritesHalf { draws: 0 }, None),
        Err(SignatureError::RNGError(SHORT))
    ));
    assert_eq!(
        sk.sign(&mut WritesHalf { draws: 0 }, b"message", None),
        Err(SignatureError::RNGError(SHORT))
    );
    let mut sig = [0xFFu8; 256];
    assert_eq!(
        sk.sign_out(&mut WritesHalf { draws: 0 }, b"message", None, &mut sig),
        Err(SignatureError::RNGError(SHORT))
    );
    assert_eq!(sig, [0u8; 256]);
    assert_eq!(
        sign_from_hash(&sk, &[0x11; 32], &mut WritesHalf { draws: 0 }),
        Err(SignatureError::RNGError(SHORT))
    );
}

/// RSAES-OAEP draws the key to transport (as a KEM) and the seed; a short draw of either is the
/// RNG's error, with the ciphertext and the key buffer left zeroized.
#[test]
fn oaep_refuses_a_short_key_and_a_short_seed() {
    let sk =
        RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV, 0x10001)
            .unwrap();
    let pk = RSA2048KEMPublicKey::new(sk.n(), 65537).unwrap();
    let params = OaepParams::<SHA256>::new(b"label");

    // As a KEM the first draw is the key.
    let mut ct = [0xFFu8; 256];
    let mut ss = KeyMaterial::<32>::from_bytes(&[0xEE; 32]).unwrap();
    let mut rng = WritesHalf { draws: 0 };
    assert_eq!(pk.encaps_out(&mut rng, params, &mut ct, &mut ss), Err(KEMError::RNGError(SHORT)));
    assert_eq!(rng.draws, 1);
    assert_eq!(ct, [0u8; 256]);
    assert_eq!(ss.key_type(), KeyType::Zeroized);

    // Transporting a key the caller holds, the only draw is the seed.
    let key = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::MACKey).unwrap();
    let mut ct = [0xFFu8; 256];
    let mut rng = WritesHalf { draws: 0 };
    assert_eq!(
        pk.transport_out(&mut rng, params, &key, &mut ct),
        Err(KeyTransportError::RNGError(SHORT))
    );
    assert_eq!(rng.draws, 1);
    assert_eq!(ct, [0u8; 256]);
    assert_eq!(
        pk.transport(&mut WritesHalf { draws: 0 }, params, &key),
        Err(KeyTransportError::RNGError(SHORT))
    );
}

/// RSASVE draws the secret value: a short draw is the RNG's error at once, not a value to
/// test against the range and redraw, and both buffers are left zeroized.
#[test]
fn rsasve_refuses_a_short_secret_value() {
    let sk =
        RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV, 0x10001)
            .unwrap();
    let pk = RSA2048KEMPublicKey::new(sk.n(), 65537).unwrap();
    let mut ct = [0xFFu8; 256];
    let mut ss = KeyMaterial::<256>::from_bytes(&[0xEE; 256]).unwrap();
    let mut rng = WritesHalf { draws: 0 };
    assert_eq!(pk.encaps_out(&mut rng, (), &mut ct, &mut ss), Err(KEMError::RNGError(SHORT)));
    assert_eq!(rng.draws, 1);
    assert_eq!(ct, [0u8; 256]);
    assert_eq!(ss.key_type(), KeyType::Zeroized);
    assert!(matches!(pk.encaps(&mut WritesHalf { draws: 0 }, ()), Err(KEMError::RNGError(SHORT))));
}
