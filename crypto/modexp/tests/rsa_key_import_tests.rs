//! The constructors that take a key as it is usually held: big-endian integers of any length
//! (`from_be`, `from_be_crt`, `from_be_primes`) and the primes alone (`from_primes`).
//!
//! The known answer is Wycheproof's RSA-2048 key (the first SHA-256 group of
//! `rsa_pkcs1_2048_sig_gen_test.json`; `tests/rsa_rsa_2048_pkcs1_v1_5_tests.rs` has the
//! provenance): built from `p`, `q` and `e` alone it must be the key its published CRT
//! components build.

use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::signature_key::{DeterministicOneShotSigningKey, OneShotVerifyingKey};
use bouncycastle_core::traits::PrivateKey;
use bouncycastle_modexp::rsa::RSA2048;
use bouncycastle_modexp::rsa::keys::{
    RsaPrivateComponents, RsaPrivateKey, RsaPublicComponents, RsaPublicKey,
};
use bouncycastle_modexp::rsa::rsa_2048::{
    RSA2048KEMPrivateKey, RSA2048KEMPublicKey, RSASSA_PKCS1_v1_5_SHA256,
};
use bouncycastle_modexp::rsa::size::{RsaSigningSize, RsaSize};
use bouncycastle_rng::DefaultRNG;

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
const E_BE: [u8; 3] = [0x01, 0x00, 0x01];
const TOO_LONG: SignatureError =
    SignatureError::DecodingError("an RSA key integer is longer than the key size allows");

fn reference() -> RsaPrivateComponents<RSA2048> {
    RsaPrivateComponents::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV, E).unwrap()
}

fn be(limbs: &[u64; 16]) -> [u8; 128] {
    RSA2048::half_be_bytes_from_limbs(limbs)
}

fn n_be() -> [u8; 256] {
    RSA2048::be_bytes_from_limbs(reference().n())
}

/// `bytes` with `zeros` zero bytes in front.
fn padded(bytes: &[u8], zeros: usize) -> Vec<u8> {
    let mut out = vec![0u8; zeros];
    out.extend_from_slice(bytes);
    out
}

/// `(P - 1) mod m`, for a small `m`.
fn p_minus_1_mod(m: u64) -> u64 {
    let mut p_minus_1 = P;
    p_minus_1[0] -= 1;
    p_minus_1
        .iter()
        .rev()
        .fold(0u64, |r, &limb| ((u128::from(r) << 64 | u128::from(limb)) % u128::from(m)) as u64)
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

#[test]
fn from_primes_rebuilds_the_published_crt_components() {
    assert_eq!(RsaPrivateComponents::<RSA2048>::from_primes(&P, &Q, E).unwrap(), reference());
    // The primes the other way round are the same key pair, with its own qInv.
    let swapped = RsaPrivateComponents::<RSA2048>::from_primes(&Q, &P, E).unwrap();
    assert_eq!(swapped.n(), reference().n());
    let msg = b"signed by the key with its primes swapped";
    let sig = swapped.key::<RSASSA_PKCS1_v1_5_SHA256>().sign_deterministic(msg, None).unwrap();
    RsaPublicKey::<RSASSA_PKCS1_v1_5_SHA256>::new(reference().n(), E)
        .unwrap()
        .verify(msg, None, &sig)
        .unwrap();
}

#[test]
fn from_be_crt_and_from_be_primes_take_integers_of_any_length() {
    let (p, q, d_p, d_q, q_inv) = (be(&P), be(&Q), be(&D_P), be(&D_Q), be(&Q_INV));
    let exact =
        RsaPrivateComponents::<RSA2048>::from_be_crt(&p, &q, &d_p, &d_q, &q_inv, &E_BE).unwrap();
    assert_eq!(exact, reference());
    let padded_key = RsaPrivateComponents::<RSA2048>::from_be_crt(
        &padded(&p, 1),
        &padded(&q, 7),
        &padded(&d_p, 129),
        &d_q,
        &q_inv,
        &padded(&E_BE, 20),
    )
    .unwrap();
    assert_eq!(padded_key, reference());
    assert_eq!(
        RsaPrivateComponents::<RSA2048>::from_be_primes(&p, &padded(&q, 3), &E_BE).unwrap(),
        reference()
    );
}

#[test]
fn an_integer_wider_than_its_place_is_refused() {
    let (p, q, d_p, d_q, q_inv) = (be(&P), be(&Q), be(&D_P), be(&D_Q), be(&Q_INV));
    let mut long = vec![0x01u8];
    long.extend_from_slice(&q_inv);
    assert_eq!(
        RsaPrivateComponents::<RSA2048>::from_be_crt(&p, &q, &d_p, &d_q, &long, &E_BE),
        Err(TOO_LONG)
    );
    let mut long_p = vec![0x80u8];
    long_p.extend_from_slice(&p);
    assert_eq!(RsaPrivateComponents::<RSA2048>::from_be_primes(&long_p, &q, &E_BE), Err(TOO_LONG));
    let mut long_n = vec![0x01u8];
    long_n.extend_from_slice(&n_be());
    assert_eq!(RsaPublicComponents::<RSA2048>::from_be(&long_n, &E_BE), Err(TOO_LONG));
    let wide_e = [0x01, 0, 0, 0, 0, 0, 0, 0x01, 0x01];
    assert_eq!(
        RsaPublicComponents::<RSA2048>::from_be(&n_be(), &wide_e),
        Err(SignatureError::DecodingError("RSA public exponent must be below 2^64"))
    );
    assert_eq!(
        RsaPrivateComponents::<RSA2048>::from_be_primes(&p, &q, &wide_e),
        Err(SignatureError::DecodingError("RSA public exponent must be below 2^64"))
    );
}

#[test]
fn from_be_builds_the_public_key_and_checks_it_as_new_does() {
    let n = n_be();
    let pk = RsaPublicComponents::<RSA2048>::from_be(&padded(&n, 2), &E_BE).unwrap();
    assert_eq!(pk, RsaPublicComponents::<RSA2048>::new(reference().n(), E).unwrap());
    // Without its top byte the modulus is short of the size.
    assert_eq!(
        RsaPublicComponents::<RSA2048>::from_be(&n[1..], &E_BE),
        Err(SignatureError::DecodingError("RSA modulus must have its top bit set"))
    );
    assert!(RsaPublicComponents::<RSA2048>::from_be(&n, &[0x01, 0x00, 0x00]).is_err());
}

#[test]
fn from_primes_refuses_what_makes_no_key() {
    type C = RsaPrivateComponents<RSA2048>;
    let mut even = P;
    even[0] ^= 1;
    assert_eq!(C::from_primes(&even, &Q, E), Err(SignatureError::DecodingError("p must be odd")));
    assert_eq!(C::from_primes(&P, &even, E), Err(SignatureError::DecodingError("q must be odd")));
    const BAD_E: SignatureError =
        SignatureError::DecodingError("RSA public exponent must be odd and at least 3");
    assert_eq!(C::from_primes(&P, &Q, 65536), Err(BAD_E));
    assert_eq!(C::from_primes(&P, &Q, 1), Err(BAD_E));
    assert_eq!(
        C::from_primes(&P, &P, E),
        Err(SignatureError::DecodingError("p and q must be distinct"))
    );
    let mut one = [0u64; 16];
    one[0] = 1;
    // A prime of 1 leaves `prime - 1 = 0`, which no e inverts.
    const NO_INVERSE: SignatureError =
        SignatureError::DecodingError("e has no inverse modulo p - 1 or q - 1");
    assert_eq!(C::from_primes(&one, &Q, E), Err(NO_INVERSE));
    assert_eq!(C::from_primes(&P, &one, E), Err(NO_INVERSE));

    // An odd e that divides p - 1, and one that shares a factor with it without dividing it,
    // have no inverse modulo it.
    let odd = || (3..10_000u64).step_by(2);
    let divides = odd().find(|&e| p_minus_1_mod(e) == 0).unwrap();
    let shares = odd().find(|&e| p_minus_1_mod(e) != 0 && gcd(p_minus_1_mod(e), e) != 1).unwrap();
    assert_eq!(C::from_primes(&P, &Q, divides), Err(NO_INVERSE));
    assert_eq!(C::from_primes(&P, &Q, shares), Err(NO_INVERSE));

    // p + 2 is composite (it has the factor 173; `rsa_keygen_tests.rs`), so its Fermat qInv is
    // wrong and the congruence check refuses it.
    let mut composite = P;
    composite[0] += 2;
    assert_eq!(
        C::from_primes(&composite, &Q, E),
        Err(SignatureError::DecodingError("qInv is not the inverse of q modulo p"))
    );

    // A composite q is not caught by construction (dQ's congruence holds whatever q is); the
    // key pair validation refuses it.
    let mut composite_q = Q;
    composite_q[0] += 2;
    let accepted = C::from_primes(&P, &composite_q, E).unwrap();
    assert_eq!(
        accepted.validate(&mut DefaultRNG::default()),
        Err(SignatureError::DecodingError("a prime factor is composite"))
    );
}

#[test]
fn a_generated_key_survives_the_trip_through_its_primes() {
    let (_, sk) = RSA2048::keygen(&mut DefaultRNG::default()).unwrap();
    let encoded = sk.key::<RSASSA_PKCS1_v1_5_SHA256>().encode();
    let (p, rest) = encoded.split_at(128);
    let (q, rest) = rest.split_at(128);
    let e = &rest[3 * 128..];
    assert_eq!(RsaPrivateComponents::<RSA2048>::from_be_primes(p, q, e).unwrap(), sk);
}

#[test]
fn the_key_types_forward_to_the_components() {
    type Sk = RsaPrivateKey<RSASSA_PKCS1_v1_5_SHA256>;
    type Pk = RsaPublicKey<RSASSA_PKCS1_v1_5_SHA256>;
    let (p, q, d_p, d_q, q_inv) = (be(&P), be(&Q), be(&D_P), be(&D_Q), be(&Q_INV));
    let sk = Sk::from_primes(&P, &Q, E).unwrap();
    assert_eq!(sk, Sk::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV, E).unwrap());
    assert_eq!(sk, Sk::from_be_primes(&p, &q, &E_BE).unwrap());
    assert_eq!(sk, Sk::from_be_crt(&p, &q, &d_p, &d_q, &q_inv, &E_BE).unwrap());
    let pk = Pk::from_be(&n_be(), &E_BE).unwrap();
    let msg = b"signed by a key built from its primes";
    pk.verify(msg, None, &sk.sign_deterministic(msg, None).unwrap()).unwrap();

    let kem = RSA2048KEMPrivateKey::from_primes(&P, &Q, E).unwrap();
    assert_eq!(
        kem,
        RSA2048KEMPrivateKey::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV, E).unwrap()
    );
    assert_eq!(kem, RSA2048KEMPrivateKey::from_be_primes(&p, &q, &E_BE).unwrap());
    assert_eq!(kem, RSA2048KEMPrivateKey::from_be_crt(&p, &q, &d_p, &d_q, &q_inv, &E_BE).unwrap());
    assert_eq!(
        RSA2048KEMPublicKey::from_be(&n_be(), &E_BE).unwrap(),
        RSA2048KEMPublicKey::new(reference().n(), E).unwrap()
    );
    // The key-establishment keys keep their floor on e.
    assert!(RSA2048KEMPublicKey::from_be(&n_be(), &[0x03]).is_err());
    assert!(RSA2048KEMPrivateKey::from_be_primes(&p, &q, &[0x03]).is_err());
}
