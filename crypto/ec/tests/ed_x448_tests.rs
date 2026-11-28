use bouncycastle_core::agreement_key::AgreementKey;
use bouncycastle_core::errors::{KeyAgreementError, KeyMaterialError};
use bouncycastle_core::hex;
use bouncycastle_core::kdf_params::{KdfDescription, KdfParams, KeyLen};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterial0, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{KDF, KeyAgreement, PrivateKey, PublicKey};
use bouncycastle_core_test_framework::DUMMY_SEED;
use bouncycastle_core_test_framework::key_agreement::TestFrameworkKeyAgreement;
use bouncycastle_digest::hkdf::HKDF_SHA512;
use bouncycastle_digest::hkdf::HkdfDescription;
use bouncycastle_digest::sha2::SHA512;
use bouncycastle_ec::ed::x448::{
    HKDF_SHA512_MAX_LEN, POINT_LEN, SCALAR_LEN, X448PrivateKey, X448PublicKey, keygen,
    keygen_from_seed,
};
use bouncycastle_rng::DefaultRNG;

// Every known answer below is lifted from the text of RFC 7748 by a script, in the two lines
// of 56 hexadecimal digits the RFC prints, unless it says otherwise.

/// RFC 7748 Section 6.2: Alice's private key a.
const ALICE_SK: &str = concat!(
    "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d",
    "d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
);

fn keygen_default() -> Result<(X448PublicKey, X448PrivateKey), KeyAgreementError> {
    keygen(&mut DefaultRNG::default())
}

/// The framework's agreement suite over the raw primitive and over the HKDF-SHA512 pairing.
#[test]
fn core_framework_tests() {
    TestFrameworkKeyAgreement::new().test_key_agreement(keygen_default, ());
    let hkdf = HkdfDescription::<SHA512>::new();
    TestFrameworkKeyAgreement::new().test_key_agreement(
        keygen_default,
        KdfParams::new(&hkdf, b"X448 framework info", KeyLen::<32>),
    );
}

/// The raw agreement's output is `K` typed for a KDF at X448's strength, and the HKDF-SHA512
/// pairing is HKDF run by hand over that `K` with the same info.
#[test]
fn raw_z_is_a_shared_secret_and_the_pairing_is_hkdf_over_it() {
    let (alice_pk, alice_sk) = keygen_default().unwrap();
    let (bob_pk, bob_sk) = keygen_default().unwrap();

    let z = alice_sk.agree(&bob_pk, ()).unwrap();
    assert_eq!(z.key_type(), KeyType::SharedSecret);
    assert_eq!(z.security_strength(), SecurityStrength::_192bit);
    assert_eq!(z.key_len(), POINT_LEN);

    let mut info = [0u8; 2 * POINT_LEN];
    info[..POINT_LEN].copy_from_slice(&alice_pk.encode());
    info[POINT_LEN..].copy_from_slice(&bob_pk.encode());
    let hkdf = HkdfDescription::<SHA512>::new();
    let derived = bob_sk.agree(&alice_pk, KdfParams::new(&hkdf, &info, KeyLen::<48>)).unwrap();
    let mut by_hand = KeyMaterial::<48>::new();
    hkdf.engine().unwrap().derive_key_out(&z, &info, 48, &mut by_hand).unwrap();
    assert!(derived.equals(&by_hand));
    assert_eq!(derived.key_type(), KeyType::CryptographicRandom);
    assert_eq!(derived.security_strength(), SecurityStrength::_192bit);
}

/// The pairing under a salted description: the framework suite, both sides agree, the key is
/// HKDF-SHA512 extract-and-expand by hand over `K` with that salt, and the absent salt or
/// another info derives a different key.
#[test]
fn the_pairing_takes_the_descriptions_salt() {
    const LEN: usize = 32;
    let salt =
        KeyMaterial::<64>::from_bytes_as_type(&DUMMY_SEED[..64], KeyType::CryptographicRandom)
            .unwrap();
    let hkdf = HkdfDescription::<SHA512>::with_salt(&salt).unwrap();
    let params = KdfParams::new(&hkdf, b"X448 salted info", KeyLen::<LEN>);
    TestFrameworkKeyAgreement::new().test_key_agreement(keygen_default, params);

    let (alice_pk, alice_sk) = keygen_default().unwrap();
    let (bob_pk, bob_sk) = keygen_default().unwrap();
    let key = alice_sk.agree(&bob_pk, params).unwrap();
    assert!(key.equals(&bob_sk.agree(&alice_pk, params).unwrap()));
    assert_eq!(key.key_len(), LEN);
    assert_eq!(key.key_type(), KeyType::CryptographicRandom);
    assert_eq!(key.security_strength(), SecurityStrength::_192bit);

    let z = alice_sk.agree(&bob_pk, ()).unwrap();
    let mut expected = KeyMaterial::<LEN>::new();
    HKDF_SHA512::extract_and_expand_out(&salt, &z, b"X448 salted info", LEN, &mut expected)
        .unwrap();
    assert!(key.equals(&expected));

    let other_info = KdfParams::new(&hkdf, b"another context", KeyLen::<LEN>);
    assert!(!alice_sk.agree(&bob_pk, other_info).unwrap().equals(&key));
    let absent = KeyMaterial0::new();
    let hkdf_absent = HkdfDescription::<SHA512>::with_salt(&absent).unwrap();
    let no_salt = KdfParams::new(&hkdf_absent, b"X448 salted info", KeyLen::<LEN>);
    assert!(!alice_sk.agree(&bob_pk, no_salt).unwrap().equals(&key));
}

/// The pairing derives its longest key, RFC 5869 Section 2.3's 255 * HashLen bytes, in one call,
/// and the constant is that bound: 255 * 64 for SHA-512.
#[test]
fn the_pairing_derives_its_longest_key() {
    assert_eq!(HKDF_SHA512_MAX_LEN, 16320);
    let (alice_pk, alice_sk) = keygen_default().unwrap();
    let (bob_pk, bob_sk) = keygen_default().unwrap();
    let hkdf = HkdfDescription::<SHA512>::new();
    let key_a = alice_sk
        .agree(&bob_pk, KdfParams::new(&hkdf, b"longest", KeyLen::<HKDF_SHA512_MAX_LEN>))
        .unwrap();
    let key_b = bob_sk
        .agree(&alice_pk, KdfParams::new(&hkdf, b"longest", KeyLen::<HKDF_SHA512_MAX_LEN>))
        .unwrap();
    assert_eq!(key_a.key_len(), HKDF_SHA512_MAX_LEN);
    assert!(key_a.equals(&key_b));
}

/// The iterated test of RFC 7748 Section 5.2 after one iteration.
#[test]
fn iterated_once() {
    rfc7748_check_iterated(1);
}

/// The iterated test of RFC 7748 Section 5.2 after 1,000 iterations.
#[test]
fn iterated() {
    rfc7748_check_iterated(1000);
}

/// Ignored because it's quite slow, can be run with
///     cargo test -p bouncycastle-ec --test ed_x448_tests -- --ignored
/// or
///     cargo test -p bouncycastle-ec --test ed_x448_tests -- --include-ignored
#[ignore]
#[test]
fn iterated_full() {
    rfc7748_check_iterated(1000000);
}

/// The first X448 single-call test vector of RFC 7748 Section 5.2.
#[test]
fn vector_1() {
    check_vector(
        concat!(
            "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121",
            "700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3",
        ),
        concat!(
            "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9",
            "814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086",
        ),
        concat!(
            "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239f",
            "e14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f",
        ),
        "Vector #1",
    );
}

/// The second X448 single-call test vector of RFC 7748 Section 5.2.
#[test]
fn vector_2() {
    check_vector(
        concat!(
            "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c5",
            "38345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f",
        ),
        concat!(
            "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b",
            "165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db",
        ),
        concat!(
            "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7",
            "ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d",
        ),
        "Vector #2",
    );
}

/// RFC 7748 Section 6.2: Alice's and Bob's public keys, X448(a, 5) and X448(b, 5), and the
/// shared secret K that each derives from their own private key and the other's public key.
#[test]
fn rfc7748_section_6_2() {
    let alice_sk = sk_from_bytes(&decode_56(ALICE_SK));
    let bob_sk = sk_from_bytes(&decode_56(concat!(
        "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d",
        "6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d",
    )));

    let alice_pk = alice_sk.pub_key().unwrap();
    let bob_pk = bob_sk.pub_key().unwrap();
    check_value(
        alice_pk.as_bytes(),
        "Section 6.2 Alice's public key",
        concat!(
            "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c",
            "22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0",
        ),
    );
    check_value(
        bob_pk.as_bytes(),
        "Section 6.2 Bob's public key",
        concat!(
            "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430",
            "27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
        ),
    );

    let k = concat!(
        "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b",
        "b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d",
    );
    let alice_k = alice_sk.agree(&bob_pk, ()).unwrap();
    let bob_k = bob_sk.agree(&alice_pk, ()).unwrap();
    check_value(alice_k.ref_to_bytes(), "Section 6.2 K (Alice)", k);
    check_value(bob_k.ref_to_bytes(), "Section 6.2 K (Bob)", k);
}

/// Every public key in Wycheproof's `x448_test.json` (testvectors_v1, tcId 32, 33, 63 to 66,
/// 70, 71, 97, 98 and 131) whose shared secret is all zero: u = 0, u = 1 and u = p - 1, the
/// points of order 2 and 4 on the curve and its twist, and the non-canonical u = p and
/// u = p + 1. Kept here, copied by a script, so that the check does not depend on the
/// Wycheproof checkout being present.
const LOW_ORDER_PUBLIC_KEYS: [&str; 5] = [
    concat!(
        "00000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000000000000000000000000000",
    ),
    concat!(
        "01000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000000000000000000000000000",
    ),
    concat!(
        "feffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "feffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ),
    concat!(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "feffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ),
    concat!(
        "00000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ),
];

/// The agreement rejects a public key that gives an all-zero shared secret, however that key
/// is encoded. The caller's buffer is left zeroized.
#[test]
fn key_agreement_rejects_all_zero_shared_secret() {
    for u in LOW_ORDER_PUBLIC_KEYS.map(decode_56) {
        let sk = sk_from_bytes(&decode_56(ALICE_SK));
        let pk = X448PublicKey::from_bytes(&u).unwrap();
        match sk.agree(&pk, ()) {
            Err(KeyAgreementError::AgreementFailed) => { /* good */ }
            Err(e) => panic!("expected AgreementFailed for u = {u:02x?}, got {e:?}"),
            Ok(_) => panic!("expected AgreementFailed for u = {u:02x?}, got Ok"),
        }
        let mut ss =
            KeyMaterial::<POINT_LEN>::from_bytes_as_type(&[0xFF; POINT_LEN], KeyType::Seed)
                .unwrap();
        assert!(matches!(sk.agree_out(&pk, (), &mut ss), Err(KeyAgreementError::AgreementFailed)));
        assert_eq!(ss.key_type(), KeyType::Zeroized);
        assert_eq!(ss.key_len(), 0);
    }
}

fn decode_56(s: &str) -> [u8; 56] {
    hex::decode(s).unwrap().try_into().unwrap()
}

/// RFC 7748 Section 5: "Implementations MUST accept non-canonical values and process them as if
/// they had been reduced modulo the field prime", and X448 masks no bit. So u = p + 3 agrees as
/// u = 3 does, and the largest encoding, 2^448 - 1, as u = 2^224 does.
#[test]
fn non_canonical_u_coordinates_agree_as_their_reduced_value() {
    let sk = sk_from_bytes(&decode_56(ALICE_SK));
    let mut three = [0_u8; POINT_LEN];
    three[0] = 3;
    // p + 3 = 2^448 - 2^224 + 2: the high 224 bits set, over 2.
    let mut p_plus_3 = [0xFF_u8; POINT_LEN];
    p_plus_3[..28].fill(0);
    p_plus_3[0] = 2;
    let mut two_224 = [0_u8; POINT_LEN];
    two_224[28] = 1;

    for (reduced, non_canonical) in [(three, p_plus_3), (two_224, [0xFF_u8; POINT_LEN])] {
        let expected = sk.agree(&X448PublicKey::from_bytes(&reduced).unwrap(), ()).unwrap();
        let k = sk.agree(&X448PublicKey::from_bytes(&non_canonical).unwrap(), ()).unwrap();
        assert_eq!(k.ref_to_bytes(), expected.ref_to_bytes(), "u = {non_canonical:02x?}");
    }
}

/// Four times the order of the base point (RFC 7748 Section 4.2), computed from the RFC's
/// value by the script: a multiple of 4 in `[2^447, 2^448)`, so a clamped scalar.
const FOUR_TIMES_ORDER: &str = concat!(
    "cc1361ad4a0ae38d543d1637ca09b38540da58bb266d3b11a78f28f3",
    "fdffffffffffffffffffffffffffffffffffffffffffffffffffffff",
);

/// `X448(4 * order, 6)`. u = 6 is on the twist (`6^3 + A*6^2 + 6` is not a square mod p),
/// whose order is not the curve's. Not from the RFC: computed by a second implementation of
/// X448.
const FOUR_TIMES_ORDER_TIMES_6: &str = concat!(
    "701189dff14a861cf697a73c3b58bd052bfc325cafd4e2a62d6ef60d",
    "3be8370d985a34e281600f7c17e2499f9273d9f91352a3ce3254555d",
);

/// The scalar `4 * order` is a private key like any other, although it sends every point of
/// the curve, the base point included, to the identity: its public key is all zero, an
/// agreement with a point of the curve is refused for its all-zero `K`, and an agreement with
/// a point of the twist goes through, as RFC 7748 Section 5 computes it.
#[test]
fn the_scalar_four_times_the_order_is_a_key_whose_public_key_is_zero() {
    let bytes = decode_56(FOUR_TIMES_ORDER);
    for sk in [X448PrivateKey::from_bytes(&bytes).unwrap(), sk_from_bytes(&bytes)] {
        assert_eq!(sk.encode(), bytes);
        assert_eq!(sk.pub_key().unwrap().as_bytes(), &[0_u8; POINT_LEN]);

        let (on_curve, other_sk) = keygen_default().unwrap();
        assert!(matches!(sk.agree(&on_curve, ()), Err(KeyAgreementError::AgreementFailed)));

        let mut six = [0_u8; POINT_LEN];
        six[0] = 6;
        let on_twist = X448PublicKey::from_bytes(&six).unwrap();
        let k = sk.agree(&on_twist, ()).unwrap();
        check_value(k.ref_to_bytes(), "X448(4 * order, 6)", FOUR_TIMES_ORDER_TIMES_6);
        // And Diffie-Hellman over the twist commutes with it: X448(a, X448(b, 6)) is
        // X448(b, X448(a, 6)).
        let b_6 = other_sk.agree(&on_twist, ()).unwrap();
        let ab = sk.agree(&X448PublicKey::from_bytes(b_6.ref_to_bytes()).unwrap(), ()).unwrap();
        let ba = other_sk.agree(&X448PublicKey::from_bytes(k.ref_to_bytes()).unwrap(), ()).unwrap();
        assert_eq!(ab.ref_to_bytes(), ba.ref_to_bytes());
    }
}

/// The all-zero key that `keygen_out` writes into is not a key until it is filled: it makes no
/// agreement, raw or through HKDF.
#[test]
fn an_unfilled_key_makes_no_agreement() {
    let unfilled = X448PrivateKey::zeroized();
    let (pk, _) = keygen_default().unwrap();
    assert!(matches!(
        unfilled.agree(&pk, ()),
        Err(KeyAgreementError::KeyMaterialError(KeyMaterialError::ActingOnZeroizedKey))
    ));
    let description = HkdfDescription::<SHA512>::new();
    let params = KdfParams::new(&description, b"info", KeyLen::<32>);
    assert!(matches!(
        unfilled.agree(&pk, params),
        Err(KeyAgreementError::KeyMaterialError(KeyMaterialError::ActingOnZeroizedKey))
    ));

    // A generated key is unaffected, including the one whose bytes are all zero: its scalar
    // clamps to 2^447 and its public key is not zero.
    let zero_bytes = X448PrivateKey::from_bytes(&[0u8; SCALAR_LEN]).unwrap();
    assert_ne!(zero_bytes.pub_key().unwrap().as_bytes(), &[0u8; POINT_LEN]);
    assert!(zero_bytes.agree(&pk, ()).is_ok());
    assert!(zero_bytes.agree(&pk, params).is_ok());
}

/// A private key from its 56 bytes, via [`keygen_from_seed`].
fn sk_from_bytes(bytes: &[u8]) -> X448PrivateKey {
    let seed = KeyMaterial::<SCALAR_LEN>::from_bytes_as_type(bytes, KeyType::Seed).unwrap();
    keygen_from_seed(&seed).unwrap().1
}

/// The iterated test of RFC 7748 Section 5.2: starting from k = u = 5, each iteration sets k to
/// `X448(k, u)` and u to the old k, and k is checked after 1, 1,000 and 1,000,000 iterations.
///
/// Feeding each output back in as the next scalar and u-coordinate exercises the ladder, field
/// arithmetic and encodings on `count` effectively random inputs against a single known answer,
/// and one wrong step corrupts every value after it.
fn rfc7748_check_iterated(count: usize) {
    let mut k = decode_56(concat!(
        "05000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000000000000000000000000000",
    ));
    let mut u = k;
    let mut iterations = 0;
    let mut checked = 0;
    while iterations < count {
        let r = sk_from_bytes(&k).agree(&X448PublicKey::from_bytes(&u).unwrap(), ()).unwrap();

        u = k;
        k.copy_from_slice(r.ref_to_bytes());

        iterations += 1;

        let expected = match iterations {
            1 => concat!(
                "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a",
                "4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113",
            ),
            1000 => concat!(
                "aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4",
                "af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38",
            ),
            1000000 => concat!(
                "077f453681caca3693198420bbe515cae0002472519b3e67661a7e89",
                "cab94695c8f4bcd66e61b9b9c946da8d524de3d69bd9d9d66b997e37",
            ),
            _ => continue,
        };
        check_value(&k, &format!("Iterated @{iterations}"), expected);
        checked += 1;
    }
    assert!(checked > 0, "no known answer at or below {count} iterations");
}

fn check_value(n: &[u8], text: &str, se: &str) {
    let e = hex::decode(se).unwrap();
    assert_eq!(e.as_slice(), n, "{}", text);
}

fn check_vector(sk: &str, su: &str, se: &str, text: &str) {
    let k = sk_from_bytes(&decode_56(sk));
    let u = X448PublicKey::from_bytes(&decode_56(su)).unwrap();

    let r = k.agree(&u, ()).unwrap();
    check_value(r.ref_to_bytes(), text, se);
}

/// The workers called directly, not through the role's provided `agree_out` (which zeroizes the
/// buffer itself): each leaves a stale buffer zeroized when the peer key has small order.
#[test]
fn the_workers_leave_a_stale_buffer_zeroized_on_a_small_order_peer() {
    let (_, sk) = keygen_default().unwrap();
    let zero_pk = X448PublicKey::from_bytes(&[0u8; POINT_LEN]).unwrap();

    let raw = sk.create_agreement(()).unwrap();
    let mut ss =
        KeyMaterial::<POINT_LEN>::from_bytes_as_type(&[0xFF; POINT_LEN], KeyType::Seed).unwrap();
    assert!(matches!(raw.agree_out(&zero_pk, &mut ss), Err(KeyAgreementError::AgreementFailed)));
    assert_eq!(ss.key_type(), KeyType::Zeroized);
    assert_eq!(ss.key_len(), 0);

    let hkdf = HkdfDescription::<SHA512>::new();
    let paired = sk.create_agreement(KdfParams::new(&hkdf, b"info", KeyLen::<32>)).unwrap();
    let mut ss = KeyMaterial::<32>::from_bytes_as_type(&[0xFF; 32], KeyType::Seed).unwrap();
    assert!(matches!(paired.agree_out(&zero_pk, &mut ss), Err(KeyAgreementError::AgreementFailed)));
    assert_eq!(ss.key_type(), KeyType::Zeroized);
    assert_eq!(ss.key_len(), 0);
}

/// The workers write `K` and the derived key over a stale buffer and report the length.
#[test]
fn the_workers_report_the_bytes_they_wrote() {
    let (pk, _) = keygen_default().unwrap();
    let (_, sk) = keygen_default().unwrap();
    let raw = sk.create_agreement(()).unwrap();
    let mut ss =
        KeyMaterial::<POINT_LEN>::from_bytes_as_type(&[0xFF; POINT_LEN], KeyType::Seed).unwrap();
    assert_eq!(raw.agree_out(&pk, &mut ss).unwrap(), POINT_LEN);
    assert!(ss.equals(&sk.agree(&pk, ()).unwrap()));

    let hkdf = HkdfDescription::<SHA512>::new();
    let params = KdfParams::new(&hkdf, b"info", KeyLen::<40>);
    let paired = sk.create_agreement(params).unwrap();
    let mut ss = KeyMaterial::<40>::from_bytes_as_type(&[0xFF; 40], KeyType::Seed).unwrap();
    assert_eq!(paired.agree_out(&pk, &mut ss).unwrap(), 40);
    assert!(ss.equals(&sk.agree(&pk, params).unwrap()));
}
