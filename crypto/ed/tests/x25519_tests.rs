use bouncycastle_core::errors::KeyAgreementError;
use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
use bouncycastle_core::traits::KeyAgreement;
use bouncycastle_ed::x25519::{POINT_SIZE, SCALAR_SIZE, X25519, X25519PrivateKey, X25519PublicKey};
use bouncycastle_hex as hex;

#[test]
fn iterated() {
    rfc7748_check_iterated(1000);
}

#[ignore]
#[test]
fn iterated_full() {
    rfc7748_check_iterated(1000000);
}

/// The first X25519 single-call test vector of RFC 7748 Section 5.2.
#[test]
fn vector_1() {
    check_vector(
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        "Vector #1",
    );
}

/// The second X25519 single-call test vector of RFC 7748 Section 5.2.
#[test]
fn vector_2() {
    check_vector(
        "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
        "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
        "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
        "Vector #2",
    );
}

/// RFC 7748 Section 6.1: Alice's and Bob's public keys, X25519(a, 9) and X25519(b, 9), and the
/// shared secret K that each derives from their own private key and the other's public key.
#[test]
fn rfc7748_section_6_1() {
    let alice_sk = sk_from_bytes(&decode_32(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    ));
    let bob_sk = sk_from_bytes(&decode_32(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    ));

    let alice_pk = alice_sk.pk();
    let bob_pk = bob_sk.pk();
    check_value(
        alice_pk.as_bytes(),
        "Section 6.1 Alice's public key",
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
    );
    check_value(
        bob_pk.as_bytes(),
        "Section 6.1 Bob's public key",
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
    );

    let k = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
    let alice_k = X25519::key_agreement(&bob_pk, alice_sk).unwrap();
    let bob_k = X25519::key_agreement(&alice_pk, bob_sk).unwrap();
    check_value(alice_k.as_bytes(), "Section 6.1 K (Alice)", k);
    check_value(bob_k.as_bytes(), "Section 6.1 K (Bob)", k);
}

/// [`X25519::key_agreement`] rejects a public key that gives an all-zero shared secret, however
/// that key is encoded: u = 0, u = p (non-canonical, reduces to 0), and u = 0 with the ignored
/// bit 255 set.
#[test]
fn key_agreement_rejects_all_zero_shared_secret() {
    let zero = [0_u8; POINT_SIZE];
    let p = decode_32("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    let mut zero_bit_255 = zero;
    zero_bit_255[31] = 0x80;

    for u in [zero, p, zero_bit_255] {
        let sk = sk_from_bytes(&decode_32(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        match X25519::key_agreement(&X25519PublicKey::from_bytes(u), sk) {
            Err(KeyAgreementError::InvalidPublicKey(_)) => { /* good */ }
            other => panic!("expected InvalidPublicKey for u = {u:02x?}, got {other:?}"),
        }
    }
}

fn decode_32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

/// A private key from its 32 bytes, via [`X25519::keygen_from_seed`].
fn sk_from_bytes(bytes: &[u8]) -> X25519PrivateKey {
    let seed = KeyMaterial256::from_bytes_as_type(bytes, KeyType::Seed).unwrap();
    X25519::keygen_from_seed(&seed).unwrap().1
}

/// The iterated test of RFC 7748 Section 5.2: starting from k = u = 9, each iteration sets k to
/// `X25519(k, u)` and u to the old k, and k is checked after 1, 1,000 and 1,000,000 iterations.
///
/// Feeding each output back in as the next scalar and u-coordinate exercises the ladder, field
/// arithmetic and encodings on `count` effectively random inputs against a single known answer,
/// and one wrong step corrupts every value after it. The single-call vectors cover two inputs.
fn rfc7748_check_iterated(count: usize) {
    assert_eq!(POINT_SIZE, SCALAR_SIZE);

    let mut k = [0_u8; POINT_SIZE];
    k[0] = 9;
    let mut u = [0_u8; POINT_SIZE];
    u[0] = 9;
    let mut iterations = 0;
    while iterations < count {
        let r = X25519::key_agreement(&X25519PublicKey::from_bytes(u), sk_from_bytes(&k)).unwrap();

        u = k;
        k = *r.as_bytes();

        iterations += 1;

        match iterations {
            1 => check_value(
                &k,
                "Iterated @1",
                "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
            ),
            1000 => check_value(
                &k,
                "Iterated @1000",
                "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
            ),
            1000000 => check_value(
                &k,
                "Iterated @1000000",
                "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424",
            ),
            _ => {}
        }
    }
}

fn check_value(n: &[u8], text: &str, se: &str) {
    let e = hex::decode(se).unwrap();
    assert_eq!(e.as_slice(), n, "{}", text);
}

fn check_vector(sk: &str, su: &str, se: &str, text: &str) {
    let k = sk_from_bytes(&decode_32(sk));
    let u = X25519PublicKey::from_bytes(decode_32(su));

    let r = X25519::key_agreement(&u, k).unwrap();
    check_value(r.as_bytes(), text, se);
}
