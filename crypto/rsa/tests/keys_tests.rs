//! Validation tests for [`bouncycastle_rsa::keys`]'s public API, including the
//! `SignaturePrivateKey`/`SignaturePublicKey` impls `rsa_2048` gives its aliases of these types
//! (`RsaPrivateKey<32, 16>` *is* `Rsa2048PrivateKey`, so the traits' methods resolve here once
//! imported). The generic boundary conditions every size shares are covered by
//! `core-test-framework`'s `test_keys` in each size's own test file; these pin the layout itself.

use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{SignaturePrivateKey, SignaturePublicKey};
use bouncycastle_rsa::keys::{RsaPrivateKey, RsaPublicKey};

const P: [u64; 16] = [
    0xfec673c1b07d4997, 0x98c9e3737faecc8b, 0x01369d6bebcfd19b, 0x8aadc1799d493a6e,
    0x958ca74fe2a455a1, 0x686e62c9e375661d, 0xbf73814b7bf6fe14, 0x791ffe2d364719e4,
    0xc82e25af581825a1, 0x716d239de20732c7, 0xdb517e266b0c15bc, 0xe92c721464fa1e50,
    0x683e7fcc3898a002, 0xc7f69cb8c57e630f, 0xc467ab3a006acdf7, 0xe189725eddf8ccb3,
];
const Q: [u64; 16] = [
    0x7b4cf8c928cc535f, 0x59f055409b91aa89, 0xcd0ba689661c56d5, 0xe4659bfb595039f4,
    0x751842ab04e21054, 0xe2c2655760ebb5fc, 0xb2f71094e48dc76b, 0x2efed995e680919d,
    0x83c35ffcfdb9ee9d, 0xfe4a5fdb9f28a01b, 0x0ebf4a61e23c7524, 0x8cc355a69e45d7e6,
    0x9589828fca436940, 0x4cd1bfe875cddd70, 0x203e0d5e8d4d3acb, 0x86278c27281306ec,
];
const D_P: [u64; 16] = [
    0xa7c48ae44e99dd99, 0xa6794425077c6c01, 0x0f7f8dfabf278380, 0xb481c3d6cf359f60,
    0xa5b5efbc5d9f744a, 0x91b95de874b741a1, 0xea3152a3da97ddf5, 0xe180bda330e9eba0,
    0xbcbfcc51e73a7a34, 0x019d0405e258c3c0, 0x0b08c52c187e3667, 0x84a723999981f7c1,
    0x5e50dc3287b126ff, 0xd0204fd4674f4ac6, 0x6e786ef11d0686f6, 0xa82c39200c1c4d67,
];
const D_Q: [u64; 16] = [
    0x0bc1fcecb5c853bf, 0x2000c1caf24e96d2, 0xb423419c07e0736a, 0x90bcb6fb03d68029,
    0xd811d2e24994ff2e, 0x5a89a6b7c7c83737, 0xbdea803dc4157f87, 0xffe93a09240b9b65,
    0xe6f584c8dc80c30a, 0x5e66076e22c91c3c, 0xb41221e6b67af91b, 0x2e3d8c36b1d9d161,
    0x7b1309bb3857cb1f, 0xee8de5186c920235, 0x5e4785a534bec7a3, 0x85883dd007ea907c,
];
const Q_INV: [u64; 16] = [
    0xf1be36246c217ae1, 0x079e038ceb7506d7, 0x2021f982bc5f6713, 0x55fa8fdd926a4d0f,
    0xb927b5edab1a24b8, 0xc2a1d37632cfb70e, 0x9ef39b4a3f144e8a, 0x70efa5974ed43d2f,
    0x6ea50741414ce321, 0x7df35889e34d4f38, 0x859106459f51850b, 0xd59e422a92f4a7a2,
    0x0c1e16e70fcbe362, 0xcf95cadb6a1f450d, 0x106a4e948e405012, 0x95a3415bfb9b5ff6,
];
const N: [u64; 32] = [
    0xbc9607fe59ae4409, 0x33fb0be666401931, 0x29fe66e068d6028b, 0xf4225b99e1483032,
    0x3e05752e447f3448, 0x3621f382f494e49c, 0xb12e1f7bd18e9f62, 0xba911df383b4764d,
    0x206002df096d6863, 0x07e881cdab73cfe3, 0x4e9ca660d04d6b6c, 0xfdd0169786ca06a2,
    0xffc09630c54f5731, 0x79ff3ac5ce73cc72, 0x72dd018024dd28a7, 0x4155291016140929,
    0x21a0943f3500f009, 0xd386df1b9afb0808, 0xd06dca00e14b1311, 0x31ed2137effa6d2a,
    0xb914de4e6361f98f, 0x181ad8797a7574fb, 0x98285be3abda6248, 0xcce5cb7a03c57a7d,
    0x3bdb7daa02c2b084, 0x8bb59db9b76bd95d, 0x95e3a77cea5ff912, 0x841d24a921abd3db,
    0x2895f5b063db401c, 0xe57dc21fc3866988, 0xb88f89afa429e300, 0x7630c947be6e9710,
];

#[test]
fn from_crt_components_accepts_a_genuine_key_and_derives_n() {
    let sk = RsaPrivateKey::<32, 16>::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV)
        .expect("genuine RSA-2048 CRT components must be accepted");
    assert_eq!(*sk.n(), N);
}

#[test]
fn from_crt_components_rejects_mismatched_widths() {
    // L = 31 != 2 * 16.
    assert!(matches!(
        RsaPrivateKey::<31, 16>::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV),
        Err(SignatureError::DecodingError(_))
    ));
}

#[test]
fn from_crt_components_rejects_equal_primes() {
    assert!(matches!(
        RsaPrivateKey::<32, 16>::from_crt_components(&P, &P, &D_P, &D_Q, &Q_INV),
        Err(SignatureError::DecodingError(_))
    ));
}

#[test]
fn from_crt_components_rejects_even_prime() {
    let mut even_p = P;
    even_p[0] &= !1;
    assert!(matches!(
        RsaPrivateKey::<32, 16>::from_crt_components(&even_p, &Q, &D_P, &D_Q, &Q_INV),
        Err(SignatureError::DecodingError(_))
    ));
}

#[test]
fn from_crt_components_rejects_even_q() {
    let mut even_q = Q;
    even_q[0] &= !1;
    assert!(matches!(
        RsaPrivateKey::<32, 16>::from_crt_components(&P, &even_q, &D_P, &D_Q, &Q_INV),
        Err(SignatureError::DecodingError(_))
    ));
}

#[test]
fn from_crt_components_rejects_dp_out_of_range() {
    assert!(matches!(
        RsaPrivateKey::<32, 16>::from_crt_components(&P, &Q, &P, &D_Q, &Q_INV),
        Err(SignatureError::DecodingError(_))
    ));
}

#[test]
fn from_crt_components_rejects_qinv_out_of_range() {
    assert!(matches!(
        RsaPrivateKey::<32, 16>::from_crt_components(&P, &Q, &D_P, &D_Q, &P),
        Err(SignatureError::DecodingError(_))
    ));
}

#[test]
fn public_key_accepts_e_65537() {
    let pk = RsaPublicKey::<32>::new(&N, 0x00010001).expect("e = 65537 is valid");
    assert_eq!(*pk.n(), N);
    assert_eq!(pk.e(), 0x00010001);
}

#[test]
fn public_key_rejects_even_exponent() {
    assert!(matches!(RsaPublicKey::<32>::new(&N, 65536), Err(SignatureError::DecodingError(_))));
}

#[test]
fn public_key_rejects_exponent_below_three() {
    assert!(matches!(RsaPublicKey::<32>::new(&N, 1), Err(SignatureError::DecodingError(_))));
}

#[test]
fn public_key_rejects_even_modulus() {
    let mut even_n = N;
    even_n[0] &= !1;
    assert!(matches!(RsaPublicKey::<32>::new(&even_n, 3), Err(SignatureError::DecodingError(_))));
}

#[test]
fn public_key_encode_round_trips() {
    let pk = RsaPublicKey::<32>::new(&N, 0x10001).unwrap();
    let bytes: [u8; 260] = pk.encode();
    let decoded = RsaPublicKey::<32>::from_bytes(&bytes).expect("must decode");
    assert_eq!(decoded, pk);
}

/// `SignaturePublicKey`'s `n || e` layout, checked field by field rather than only by round
/// trip: `n` big-endian (its most significant limb's top byte first), then `e` big-endian.
#[test]
fn public_key_encode_layout_is_n_then_e_big_endian() {
    let pk = RsaPublicKey::<32>::new(&N, 0x10001).unwrap();
    let bytes = pk.encode();
    assert_eq!(bytes[..8], N[31].to_be_bytes());
    assert_eq!(bytes[248..256], N[0].to_be_bytes());
    assert_eq!(bytes[256..], [0x00, 0x01, 0x00, 0x01]);

    let mut out = [0xaau8; 260];
    assert_eq!(pk.encode_out(&mut out), 260);
    assert_eq!(out, bytes);
}

#[test]
fn public_key_from_bytes_rejects_even_modulus() {
    let pk = RsaPublicKey::<32>::new(&N, 0x10001).unwrap();
    let mut bytes: [u8; 260] = pk.encode();
    bytes[255] &= !1; // clear n's low bit (last byte, big-endian)
    assert!(matches!(
        RsaPublicKey::<32>::from_bytes(&bytes),
        Err(SignatureError::DecodingError(_))
    ));
}

#[test]
fn public_key_from_bytes_rejects_wrong_lengths() {
    let pk = RsaPublicKey::<32>::new(&N, 0x10001).unwrap();
    let bytes = pk.encode();
    assert!(matches!(
        RsaPublicKey::<32>::from_bytes(&bytes[..259]),
        Err(SignatureError::DecodingError(_))
    ));
    let mut too_long = bytes.to_vec();
    too_long.push(0);
    assert!(matches!(
        RsaPublicKey::<32>::from_bytes(&too_long),
        Err(SignatureError::DecodingError(_))
    ));
}

/// `Display` (a `SignaturePublicKey` supertrait) prints `n` as one big-endian hex string and `e`
/// in hex, so a printed key can be matched by eye against a hex dump of its encoding.
#[test]
fn public_key_display_prints_big_endian_hex() {
    let pk = RsaPublicKey::<32>::new(&N, 0x10001).unwrap();
    let shown = format!("{pk}");
    let n_hex: String = pk.encode()[..256].iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(shown, format!("RsaPublicKey<32> {{ n: {n_hex}, e: 10001 }}"));
}

#[test]
fn private_key_encode_round_trips() {
    let sk = RsaPrivateKey::<32, 16>::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV).unwrap();
    let bytes: [u8; 640] = sk.encode();
    let decoded = RsaPrivateKey::<32, 16>::from_bytes(&bytes).expect("must decode");
    assert_eq!(decoded, sk);
}

/// `SignaturePrivateKey`'s `p || q || dP || dQ || qInv` layout, each field 128 bytes big-endian.
#[test]
fn private_key_encode_layout_is_five_big_endian_fields() {
    let sk = RsaPrivateKey::<32, 16>::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV).unwrap();
    let bytes = sk.encode();
    for (i, field) in [P, Q, D_P, D_Q, Q_INV].iter().enumerate() {
        let start = 128 * i;
        assert_eq!(bytes[start..start + 8], field[15].to_be_bytes(), "field {i} MSB");
        assert_eq!(bytes[start + 120..start + 128], field[0].to_be_bytes(), "field {i} LSB");
    }

    let mut out = [0xaau8; 640];
    assert_eq!(sk.encode_out(&mut out), 640);
    assert_eq!(out, bytes);
}

#[test]
fn private_key_from_bytes_rejects_equal_primes() {
    let sk = RsaPrivateKey::<32, 16>::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV).unwrap();
    let mut bytes: [u8; 640] = sk.encode();
    // Overwrite q (the second 128-byte field) with p, making the two primes equal.
    let p_field = bytes[..128].to_vec();
    bytes[128..256].copy_from_slice(&p_field);
    assert!(matches!(
        RsaPrivateKey::<32, 16>::from_bytes(&bytes),
        Err(SignatureError::DecodingError(_))
    ));
}

#[test]
fn private_key_from_bytes_rejects_wrong_lengths() {
    let sk = RsaPrivateKey::<32, 16>::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV).unwrap();
    let bytes = sk.encode();
    assert!(matches!(
        RsaPrivateKey::<32, 16>::from_bytes(&bytes[..639]),
        Err(SignatureError::DecodingError(_))
    ));
    let mut too_long = bytes.to_vec();
    too_long.push(0);
    assert!(matches!(
        RsaPrivateKey::<32, 16>::from_bytes(&too_long),
        Err(SignatureError::DecodingError(_))
    ));
}
