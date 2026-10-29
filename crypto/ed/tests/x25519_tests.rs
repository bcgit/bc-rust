use bouncycastle_core;
use bouncycastle_ed::x25519::*;
use bouncycastle_hex as hex;
use bouncycastle_rng;

// todo -- debug and turn back on
// #[test]
// fn agreement() {
//     // todo ???
//     precompute();
//
//     let mut ka = [0_u8; SCALAR_SIZE];
//     let mut kb = [0_u8; SCALAR_SIZE];
//     let mut qa = [0_u8; POINT_SIZE];
//     let mut qb = [0_u8; POINT_SIZE];
//     let mut sa = [0_u8; POINT_SIZE];
//     let mut sb = [0_u8; POINT_SIZE];
//
//     let mut rng = bouncycastle_rng::DefaultRNG::new();
//
//     for i in 1..=100 {
//         // Each party generates an ephemeral private key, ...
//         generate_private_key_rng(&mut rng, &mut ka);
//         generate_private_key(&mut rng, &mut kb);
//
//         // ... publishes their public key, ...
//         generate_public_key(&ka, &mut qa);
//         generate_public_key(&kb, &mut qb);
//
//         // ... computes the shared secret, ...
//         let ra = calculate_agreement(&ka, &qb, &mut sa);
//         let rb = calculate_agreement(&kb, &qa, &mut sb);
//
//         // ... which is the same for both parties.
//         assert_eq!(ra, rb, "ECDH #{}", i);
//         assert_eq!(sa, sb, "ECDH #{}", i);
//     }
// }

#[test]
fn iterated() {
    check_iterated(1000);
}

#[ignore]
#[test]
fn iterated_full() {
    check_iterated(1000000);
}

// TODO --  this appears to be the vector from RFC7749 s.5.2
//          If so, document that.
#[test]
fn vector_1() {
    check_vector(
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        "Vector #1",
    );
}

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
    let alice_sk = decode_32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let bob_sk = decode_32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");

    let mut alice_pk = [0_u8; POINT_SIZE];
    let mut bob_pk = [0_u8; POINT_SIZE];
    generate_public_key(&alice_sk, &mut alice_pk);
    generate_public_key(&bob_sk, &mut bob_pk);
    check_value(
        &alice_pk,
        "Section 6.1 Alice's public key",
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
    );
    check_value(
        &bob_pk,
        "Section 6.1 Bob's public key",
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
    );

    let k = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
    let mut alice_k = [0_u8; POINT_SIZE];
    let mut bob_k = [0_u8; POINT_SIZE];
    assert!(calculate_agreement(&alice_sk, &bob_pk, &mut alice_k));
    assert!(calculate_agreement(&bob_sk, &alice_pk, &mut bob_k));
    check_value(&alice_k, "Section 6.1 K (Alice)", k);
    check_value(&bob_k, "Section 6.1 K (Bob)", k);
}

fn decode_32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

// TODO --  what on earth is this? We're going to key_agree this with itself 1 million times?
//          Why? What is this testing that's not already covered by the regular KATs?
fn check_iterated(count: usize) {
    assert_eq!(POINT_SIZE, SCALAR_SIZE);

    precompute();

    let mut k = [0_u8; POINT_SIZE];
    k[0] = 9;
    let mut u = [0_u8; POINT_SIZE];
    u[0] = 9;
    let mut r = [0_u8; POINT_SIZE];

    let mut iterations = 0;
    while iterations < count {
        calculate_agreement(&k, &u, &mut r);

        u = k;
        k = r;

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
    let k: [u8; SCALAR_SIZE] = hex::decode(sk).unwrap().try_into().unwrap();
    let u: [u8; POINT_SIZE] = hex::decode(su).unwrap().try_into().unwrap();

    let mut r = [0_u8; POINT_SIZE];
    calculate_agreement(&k, &u, &mut r);
    check_value(&r, text, se);
}

// fn decode_hex<const N: usize>(hex: &str) -> [u8; N] {
//     let mut result = [0; N];
//     hex::decode_to_slice(hex, &mut result).unwrap();
//     result
// }
