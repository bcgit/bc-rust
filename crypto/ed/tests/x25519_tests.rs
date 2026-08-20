use bouncycastle_edcurves::x25519::*;
use bouncycastle_hex as hex;

#[test]
fn agreement() {
    precompute();

    let mut ka = [0_u8; SCALAR_SIZE];
    let mut kb = [0_u8; SCALAR_SIZE];
    let mut qa = [0_u8; POINT_SIZE];
    let mut qb = [0_u8; POINT_SIZE];
    let mut sa = [0_u8; POINT_SIZE];
    let mut sb = [0_u8; POINT_SIZE];

    let mut random = rand::rng();

    for i in 1..=100 {
        // Each party generates an ephemeral private key, ...
        generate_private_key(&mut random, &mut ka);
        generate_private_key(&mut random, &mut kb);

        // ... publishes their public key, ...
        generate_public_key(&ka, &mut qa);
        generate_public_key(&kb, &mut qb);

        // ... computes the shared secret, ...
        let ra = calculate_agreement(&ka, &qb, &mut sa);
        let rb = calculate_agreement(&kb, &qa, &mut sb);

        // ... which is the same for both parties.
        assert_eq!(ra, rb, "ECDH #{}", i);
        assert_eq!(sa, sb, "ECDH #{}", i);
    }
}

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
    let k: [u8; SCALAR_SIZE] = hex::decode(sk).try_into().unwrap();
    let u: [u8; POINT_SIZE] = hex::decode(su).try_into().unwrap();

    let mut r = [0_u8; POINT_SIZE];
    calculate_agreement(&k, &u, &mut r);
    check_value(&r, text, se);
}

// fn decode_hex<const N: usize>(hex: &str) -> [u8; N] {
//     let mut result = [0; N];
//     hex::decode_to_slice(hex, &mut result).unwrap();
//     result
// }
