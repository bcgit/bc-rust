//! The signature workers name their algorithm, the random-salt `sign_from_hash` entry points
//! of the PSS schemes sign what `verify_from_hash` accepts, and a non-empty context is refused.

use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::signature_key::{
    DeterministicOneShotSigningKey, DeterministicSigningKey, OneShotSigningKey,
    OneShotVerifyingKey, SigningKey, VerifyingKey,
};
use bouncycastle_core::traits::{AlgorithmInfo, HashOneShot, SignatureSigner, SignatureVerifier};
use bouncycastle_rng::DefaultRNG;
use bouncycastle_rsa::RSA2048;
use bouncycastle_rsa::keys::{RsaPrivateComponents, RsaPublicComponents};
use bouncycastle_rsa::rsassa;
use bouncycastle_rsa::rsassa_pkcs1_v1_5::RSASSA_PKCS1_v1_5;
use bouncycastle_rsa::rsassa_pss::RSASSA_PSS;
use bouncycastle_sha2::SHA256;
use bouncycastle_sha3::SHAKE128;

// The crate docs' example key (Wycheproof's rsa_pkcs1_2048_sig_gen_test.json first SHA-256 group).
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

fn key_pair() -> (RsaPublicComponents<RSA2048>, RsaPrivateComponents<RSA2048>) {
    let sk =
        RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV, 0x10001)
            .unwrap();
    let pk = RsaPublicComponents::<RSA2048>::new(sk.n(), 0x10001).unwrap();
    (pk, sk)
}

#[test]
fn workers_name_their_algorithm() {
    let (pk, sk) = key_pair();
    let mut rng = DefaultRNG::default();

    let sk_rsassa_pkcs1_v1_5_rsa2048_sha256 = sk.key::<RSASSA_PKCS1_v1_5<RSA2048, SHA256>>();
    let signer = sk_rsassa_pkcs1_v1_5_rsa2048_sha256.create_signer_deterministic(None).unwrap();
    assert_eq!(signer.alg_name(), "RSASSA-PKCS1-v1_5-SHA256");
    let pk_rsassa_pkcs1_v1_5_rsa2048_sha256 = pk.key::<RSASSA_PKCS1_v1_5<RSA2048, SHA256>>();

    let verifier = pk_rsassa_pkcs1_v1_5_rsa2048_sha256.create_verifier(None).unwrap();
    assert_eq!(verifier.alg_name(), "RSASSA-PKCS1-v1_5-SHA256");

    let sk_rsassa_pss_rsa2048_sha256 = sk.key::<RSASSA_PSS<RSA2048, SHA256>>();

    let signer = sk_rsassa_pss_rsa2048_sha256.create_signer(&mut rng, None).unwrap();
    assert_eq!(signer.alg_name(), "RSASSA-PSS-SHA256");
    let pk_rsassa_pss_rsa2048_sha256 = pk.key::<RSASSA_PSS<RSA2048, SHA256>>();

    let verifier = pk_rsassa_pss_rsa2048_sha256.create_verifier(None).unwrap();
    assert_eq!(verifier.alg_name(), "RSASSA-PSS-SHA256");

    let sk_rsassa_pss_rsa2048_shake128 = sk.key::<RSASSA_PSS<RSA2048, SHAKE128>>();

    let signer = sk_rsassa_pss_rsa2048_shake128.create_signer(&mut rng, None).unwrap();
    assert_eq!(signer.alg_name(), "RSASSA-PSS-SHAKE128");
    let pk_rsassa_pss_rsa2048_shake128 = pk.key::<RSASSA_PSS<RSA2048, SHAKE128>>();

    let verifier = pk_rsassa_pss_rsa2048_shake128.create_verifier(None).unwrap();
    assert_eq!(verifier.alg_name(), "RSASSA-PSS-SHAKE128");
}

/// The random-salt `sign_from_hash` draws its salt from the RNG: two signatures of one digest
/// differ, and both verify.
#[test]
fn pss_sign_from_hash_draws_a_fresh_salt_and_verifies() {
    let (pk, sk) = key_pair();
    let mut rng = DefaultRNG::default();
    let mut digest = [0u8; 32];
    SHA256::hash_out(b"the message", &mut digest);

    let a = rsassa::sign_from_hash::<RSASSA_PSS<RSA2048, SHA256>, 256>(
        &sk.key::<RSASSA_PSS<RSA2048, SHA256>>(),
        &digest,
        &mut rng,
    )
    .unwrap();
    let b = rsassa::sign_from_hash::<RSASSA_PSS<RSA2048, SHA256>, 256>(
        &sk.key::<RSASSA_PSS<RSA2048, SHA256>>(),
        &digest,
        &mut rng,
    )
    .unwrap();
    assert_ne!(a, b);
    rsassa::verify_from_hash::<RSASSA_PSS<RSA2048, SHA256>, 256>(
        &pk.key::<RSASSA_PSS<RSA2048, SHA256>>(),
        &digest,
        &a,
    )
    .unwrap();
    rsassa::verify_from_hash::<RSASSA_PSS<RSA2048, SHA256>, 256>(
        &pk.key::<RSASSA_PSS<RSA2048, SHA256>>(),
        &digest,
        &b,
    )
    .unwrap();
    assert!(
        rsassa::verify_from_hash::<RSASSA_PSS<RSA2048, SHA256>, 256>(
            &pk.key::<RSASSA_PSS<RSA2048, SHA256>>(),
            &[0u8; 32],
            &a
        )
        .is_err()
    );

    let mut digest = [0u8; 32];
    SHAKE128::hash_out(b"the message", &mut digest);
    let a = rsassa::sign_from_hash::<RSASSA_PSS<RSA2048, SHAKE128>, 256>(
        &sk.key::<RSASSA_PSS<RSA2048, SHAKE128>>(),
        &digest,
        &mut rng,
    )
    .unwrap();
    let b = rsassa::sign_from_hash::<RSASSA_PSS<RSA2048, SHAKE128>, 256>(
        &sk.key::<RSASSA_PSS<RSA2048, SHAKE128>>(),
        &digest,
        &mut rng,
    )
    .unwrap();
    assert_ne!(a, b);
    rsassa::verify_from_hash::<RSASSA_PSS<RSA2048, SHAKE128>, 256>(
        &pk.key::<RSASSA_PSS<RSA2048, SHAKE128>>(),
        &digest,
        &a,
    )
    .unwrap();
    rsassa::verify_from_hash::<RSASSA_PSS<RSA2048, SHAKE128>, 256>(
        &pk.key::<RSASSA_PSS<RSA2048, SHAKE128>>(),
        &digest,
        &b,
    )
    .unwrap();
}

const NO_CONTEXT: SignatureError = SignatureError::LengthError("RSA takes no context");

/// RSA has no context input (RFC 8017 Section 8: the operations take a key and a message), so
/// the absent and the empty context are the same and a non-empty one is refused, by signing and
/// by verifying, one-shot and where a worker is made: RSASSA-PKCS1-v1_5.
#[test]
fn pkcs1_v1_5_refuses_a_context() {
    type Alg = RSASSA_PKCS1_v1_5<RSA2048, SHA256>;
    let (pk, sk) = key_pair();
    let (pk, sk) = (pk.key::<Alg>(), sk.key::<Alg>());
    let msg = b"no context to bind";

    let sig = sk.sign_deterministic(msg, None).unwrap();
    assert_eq!(sk.sign_deterministic(msg, Some(&[])).unwrap(), sig);
    pk.verify(msg, None, &sig).unwrap();
    pk.verify(msg, Some(&[]), &sig).unwrap();

    for ctx in [&b"c"[..], b"a context"] {
        assert_eq!(sk.sign_deterministic(msg, Some(ctx)), Err(NO_CONTEXT));
        let mut out = [0xFFu8; 256];
        assert_eq!(sk.sign_deterministic_out(msg, Some(ctx), &mut out), Err(NO_CONTEXT));
        assert_eq!(out, [0u8; 256]);
        assert!(matches!(sk.create_signer_deterministic(Some(ctx)), Err(NO_CONTEXT)));
        assert_eq!(pk.verify(msg, Some(ctx), &sig), Err(NO_CONTEXT));
        assert!(matches!(pk.create_verifier(Some(ctx)), Err(NO_CONTEXT)));
    }

    // Streaming under the empty context is streaming under none.
    let mut signer = sk.create_signer_deterministic(Some(&[])).unwrap();
    signer.do_update(msg);
    assert_eq!(signer.do_final().unwrap(), sig);
    let mut verifier = pk.create_verifier(Some(&[])).unwrap();
    verifier.do_update(msg);
    verifier.do_verify_final(&sig).unwrap();
}

/// The same for RSASSA-PSS, salted and unsalted, where a refused context draws no salt.
#[test]
fn pss_refuses_a_context() {
    use bouncycastle_core::hazmat::FixedSeedRNG;
    use bouncycastle_rsa::rsassa_pss::NoSalt;
    type Alg = RSASSA_PSS<RSA2048, SHA256>;
    let (pk, sk) = key_pair();
    let (pk_pss, sk_pss) = (pk.key::<Alg>(), sk.key::<Alg>());
    let msg = b"no context to bind";
    let seed: [u8; 96] = core::array::from_fn(|i| i as u8);

    let sig = sk_pss.sign(&mut FixedSeedRNG::new(seed), msg, None).unwrap();
    // The empty context gives the signature the absent one gives, from the same draw.
    assert_eq!(sk_pss.sign(&mut FixedSeedRNG::new(seed), msg, Some(&[])).unwrap(), sig);
    pk_pss.verify(msg, None, &sig).unwrap();
    pk_pss.verify(msg, Some(&[]), &sig).unwrap();

    for ctx in [&b"c"[..], b"a context"] {
        // Refused before the salt is drawn: the next signature is the one a fresh RNG gives.
        let mut rng = FixedSeedRNG::new(seed);
        assert_eq!(sk_pss.sign(&mut rng, msg, Some(ctx)), Err(NO_CONTEXT));
        let mut out = [0xFFu8; 256];
        assert_eq!(sk_pss.sign_out(&mut rng, msg, Some(ctx), &mut out), Err(NO_CONTEXT));
        assert_eq!(out, [0u8; 256]);
        assert!(matches!(sk_pss.create_signer(&mut rng, Some(ctx)), Err(NO_CONTEXT)));
        assert_eq!(sk_pss.sign(&mut rng, msg, None).unwrap(), sig);
        assert_eq!(pk_pss.verify(msg, Some(ctx), &sig), Err(NO_CONTEXT));
        assert!(matches!(pk_pss.create_verifier(Some(ctx)), Err(NO_CONTEXT)));
    }

    let mut signer = sk_pss.create_signer(&mut FixedSeedRNG::new(seed), Some(&[])).unwrap();
    signer.do_update(msg);
    assert_eq!(signer.do_final().unwrap(), sig);
    let mut verifier = pk_pss.create_verifier(Some(&[])).unwrap();
    verifier.do_update(msg);
    verifier.do_verify_final(&sig).unwrap();

    // Unsalted PSS signs through the deterministic role.
    type Unsalted = RSASSA_PSS<RSA2048, SHA256, NoSalt<SHA256>>;
    let (pk_ns, sk_ns) = (pk.key::<Unsalted>(), sk.key::<Unsalted>());
    let sig = sk_ns.sign_deterministic(msg, None).unwrap();
    assert_eq!(sk_ns.sign_deterministic(msg, Some(&[])).unwrap(), sig);
    pk_ns.verify(msg, Some(&[]), &sig).unwrap();
    assert_eq!(sk_ns.sign_deterministic(msg, Some(b"a context")), Err(NO_CONTEXT));
    assert!(matches!(sk_ns.create_signer_deterministic(Some(b"a context")), Err(NO_CONTEXT)));
    assert_eq!(pk_ns.verify(msg, Some(b"a context"), &sig), Err(NO_CONTEXT));
    assert!(matches!(pk_ns.create_verifier(Some(b"a context")), Err(NO_CONTEXT)));
}
