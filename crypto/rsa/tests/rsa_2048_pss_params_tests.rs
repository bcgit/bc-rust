//! RSASSA-PSS under spelled parameters, the forms RFC 8017 allows beyond the conventional
//! pairing: MGF1 over a hash other than the message hash with a shorter salt
//! (`Mgf1<SHA256, 32>` under SHA-512, Wycheproof's `rsa_pss_2048_sha512_mgf1sha256_32_params`),
//! and no salt at all (`NoSalt<SHA256>`, Wycheproof's `rsa_pss_2048_sha256_mgf1_0`), which is
//! deterministic and so signs through `DeterministicSigningKey`. A key is for one set of
//! parameters, so the other set's signatures are invalid under it.

use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::{DeterministicSigningKey, SigningKey, VerifyingKey};
use bouncycastle_core::traits::{Algorithm, AlgorithmInfo, SignatureSigner, XOF};
use bouncycastle_hex::decode as hex_decode;
use bouncycastle_rng::DefaultRNG;
use bouncycastle_rsa::RSA2048;
use bouncycastle_rsa::keys::{RsaPrivateComponents, RsaPublicComponents};
use bouncycastle_rsa::rsa_2048::RSASSA_PSS_SHA256;
use bouncycastle_rsa::rsassa::RsaSignatureAlgorithm;
use bouncycastle_rsa::rsassa_pss::{Conventional, Mgf1, NoSalt, PssHash, RSASSA_PSS};
use bouncycastle_rsa::size::{RsaSize, SignatureKeyPair};
use bouncycastle_rsa::{RSA3072, RSA8192};
use bouncycastle_sha2::{SHA224, SHA256, SHA512};
use bouncycastle_sha3::{SHA3_256, SHAKE128, SHAKE256};
use serde_json::Value;
use std::fs;
use std::path::Path;

const TEST_DATA_PATH_RELATIVE: &str = "../../../wycheproof/testvectors_v1";
const TEST_DATA_PATH: &str = "../wycheproof/testvectors_v1";

fn get_test_data(filename: &str) -> String {
    for dir in [TEST_DATA_PATH_RELATIVE, TEST_DATA_PATH] {
        let path = format!("{dir}/{filename}");
        if Path::new(&path).exists() {
            return fs::read_to_string(path).unwrap();
        }
    }
    panic!(
        "wycheproof not found (looked for {filename} in {TEST_DATA_PATH_RELATIVE:?} and \
         {TEST_DATA_PATH:?}); this suite requires it rather than skipping"
    );
}

fn limbs_from_hex<const L: usize>(hex: &str) -> [u64; L] {
    let bytes_len = 8 * L;
    let mut bytes = hex_decode(hex).expect("valid hex");
    if bytes.len() == bytes_len + 1 && bytes[0] == 0 {
        bytes.remove(0);
    }
    assert_eq!(bytes.len(), bytes_len, "expected a {}-bit value", bytes_len * 8);
    let mut limbs = [0u64; L];
    for i in 0..L {
        let start = bytes_len - (i + 1) * 8;
        limbs[i] = u64::from_be_bytes(bytes[start..start + 8].try_into().unwrap());
    }
    limbs
}

/// The same genuine RSA-2048 keypair `rsa_2048_pkcs1_v1_5_tests.rs` recovers from
/// `rsa_pkcs1_2048_sig_gen_test.json` -- see that file for the full, sourced provenance (p/q
/// recovered from Wycheproof's own `(n, e, d)` via the standard factoring-from-d method).

/// One Wycheproof RSASSA-PSS verify file under the key type `A`, checking every vector's
/// verdict and the counts (valid, invalid).
fn wycheproof<A: RsaSignatureAlgorithm<Size = RSA2048>>(
    file: &str,
    sha: &str,
    mgf_sha: &str,
    s_len: u64,
    expected: (usize, usize, usize),
) {
    let doc: Value = serde_json::from_str(&get_test_data(file)).expect("valid JSON");
    let (mut num_tests, mut num_valid, mut num_invalid) = (0usize, 0usize, 0usize);
    for group in doc["testGroups"].as_array().unwrap() {
        assert_eq!(group["sha"], sha);
        assert_eq!(group["mgfSha"], mgf_sha);
        assert_eq!(group["sLen"], s_len);
        let n: [u64; 32] = limbs_from_hex(group["publicKey"]["modulus"].as_str().unwrap());
        let e = u32::from_str_radix(group["publicKey"]["publicExponent"].as_str().unwrap(), 16)
            .unwrap();
        let pk = RsaPublicComponents::<RSA2048>::new(&n, e).unwrap().into_key::<A>();
        for test in group["tests"].as_array().unwrap() {
            num_tests += 1;
            let tc_id = test["tcId"].as_u64().unwrap();
            let msg = hex_decode(test["msg"].as_str().unwrap()).unwrap();
            let sig = hex_decode(test["sig"].as_str().unwrap()).unwrap();
            let verified = pk.verify(&msg, None, &sig).is_ok();
            match test["result"].as_str().unwrap() {
                "valid" => {
                    assert!(verified, "tcId {tc_id}: expected valid, got invalid");
                    num_valid += 1;
                }
                "invalid" => {
                    assert!(!verified, "tcId {tc_id}: expected invalid, got valid");
                    num_invalid += 1;
                }
                other => panic!("tcId {tc_id}: unknown result {other:?}"),
            }
        }
    }
    assert_eq!((num_tests, num_valid, num_invalid), expected);
}

/// SHA-512 as the message hash, MGF1 over SHA-256 and a 32-byte salt: the parameters the
/// RSASSA-PSS-params structure of RFC 8017 Appendix A.2.3 can carry, which §8.1 allows.
#[test]
fn sha512_with_mgf1_sha256_and_a_32_byte_salt_wycheproof_vectors() {
    wycheproof::<RSASSA_PSS<RSA2048, SHA512, Mgf1<SHA256, 32>>>(
        "rsa_pss_2048_sha512_mgf1sha256_32_params_test.json",
        "SHA-512",
        "SHA-256",
        32,
        (178, 132, 46),
    );
}

/// The zero salt of RFC 8017 §9.1 note 4.
#[test]
fn sha256_with_no_salt_wycheproof_vectors() {
    wycheproof::<RSASSA_PSS<RSA2048, SHA256, NoSalt<SHA256>>>(
        "rsa_pss_2048_sha256_mgf1_0_test.json",
        "SHA-256",
        "SHA-256",
        0,
        (103, 61, 42),
    );
}

#[test]
fn names_and_strengths() {
    assert_eq!(RSASSA_PSS::<RSA2048, SHA256>::ALG_NAME, "RSASSA-PSS-SHA256");
    assert_eq!(RSASSA_PSS::<RSA2048, SHA256, Conventional>::ALG_NAME, "RSASSA-PSS-SHA256");
    assert_eq!(RSASSA_PSS::<RSA2048, SHAKE128>::ALG_NAME, "RSASSA-PSS-SHAKE128");
    assert_eq!(
        RSASSA_PSS::<RSA2048, SHA512, Mgf1<SHA256, 32>>::ALG_NAME,
        "RSASSA-PSS-SHA512-MGF1-SHA256-32"
    );
    assert_eq!(
        RSASSA_PSS::<RSA2048, SHA256, NoSalt<SHA256>>::ALG_NAME,
        "RSASSA-PSS-SHA256-MGF1-SHA256-0"
    );
    // The lesser of the size's and the hash's; the mask's hash does not enter (RFC 8017 §8.1).
    assert_eq!(RSA2048::STRENGTH, SecurityStrength::_112bit);
    assert_eq!(RSASSA_PSS::<RSA2048, SHA256>::MAX_SECURITY_STRENGTH, SecurityStrength::_112bit);
    assert_eq!(RSASSA_PSS::<RSA8192, SHA224>::MAX_SECURITY_STRENGTH, SecurityStrength::_112bit);
    assert_eq!(RSASSA_PSS::<RSA3072, SHA512>::MAX_SECURITY_STRENGTH, RSA3072::STRENGTH);
    assert_eq!(
        RSASSA_PSS::<RSA2048, SHA256, Mgf1<SHA512, 16>>::MAX_SECURITY_STRENGTH,
        RSASSA_PSS::<RSA2048, SHA256>::MAX_SECURITY_STRENGTH
    );
}

/// Each hash family's conventional mask and salt length: MGF1 output for SHA-2 and SHA-3,
/// which differs by hash and is never the seed or zero; the XOF itself for SHAKE.
#[test]
fn pss_hash_conventional_mask_and_salt_length_per_family() {
    let seed = [0x5au8; 32];
    let mut sha256 = [0u8; 48];
    let mut sha512 = [0u8; 48];
    let mut sha3 = [0u8; 48];
    <SHA256 as PssHash>::mask(&seed, &mut sha256);
    <SHA512 as PssHash>::mask(&seed, &mut sha512);
    <SHA3_256 as PssHash>::mask(&seed, &mut sha3);
    assert_ne!(sha256, [0u8; 48]);
    assert_ne!(sha512, [0u8; 48]);
    assert_ne!(sha3, [0u8; 48]);
    assert_ne!(sha256, sha512);
    assert_ne!(sha256, sha3);
    assert_ne!(sha512, sha3);
    assert_ne!(&sha256[..32], &seed);
    assert_eq!(<SHA224 as PssHash>::SALT_LEN, 28);
    assert_eq!(<SHA512 as PssHash>::SALT_LEN, 64);
    assert_eq!(<SHA3_256 as PssHash>::SALT_LEN, 32);

    let mut shake = [0u8; 48];
    let mut xof = [0u8; 48];
    <SHAKE256 as PssHash>::mask(&seed, &mut shake);
    SHAKE256::default().xof_out(&seed, &mut xof);
    assert_ne!(shake, [0u8; 48]);
    assert_eq!(shake, xof);
    assert_eq!(<SHAKE128 as PssHash>::SALT_LEN, 32);
    assert_eq!(<SHAKE256 as PssHash>::SALT_LEN, 64);
}

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

/// No salt signs through the deterministic role and reproduces; a key under other parameters
/// rejects what it did not make; a spelled salt length is drawn and pinned at that length; the
/// generator with spelled parameters gives the spelled type.
#[test]
fn no_salt_is_deterministic_and_parameters_do_not_mix() {
    let sk =
        RsaPrivateComponents::<RSA2048>::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV).unwrap();
    let pk = RsaPublicComponents::<RSA2048>::new(sk.n(), 0x10001).unwrap();
    let msg = b"the message to sign";

    let sk_none = sk.key::<RSASSA_PSS<RSA2048, SHA256, NoSalt<SHA256>>>();
    let pk_none = pk.key::<RSASSA_PSS<RSA2048, SHA256, NoSalt<SHA256>>>();
    let a = sk_none.sign_deterministic(msg, None).unwrap();
    let b = sk_none.sign_deterministic(msg, None).unwrap();
    assert_eq!(a, b, "no salt, no randomness");
    pk_none.verify(msg, None, &a).unwrap();
    let mut signer = sk_none.create_signer_deterministic(None).unwrap();
    assert_eq!(signer.alg_name(), "RSASSA-PSS-SHA256-MGF1-SHA256-0");
    signer.do_update(msg);
    assert_eq!(signer.do_final().unwrap(), a);

    let sk_conv = sk.key::<RSASSA_PSS_SHA256>();
    let pk_conv = pk.key::<RSASSA_PSS_SHA256>();
    let c = sk_conv.sign(&mut DefaultRNG::default(), msg, None).unwrap();
    assert!(pk_conv.verify(msg, None, &a).is_err());
    assert!(pk_none.verify(msg, None, &c).is_err());
    let pk_16 = pk.key::<RSASSA_PSS<RSA2048, SHA256, Mgf1<SHA256, 16>>>();
    assert!(pk_16.verify(msg, None, &a).is_err());
    assert!(pk_16.verify(msg, None, &c).is_err());

    let sk_16 = sk.key::<RSASSA_PSS<RSA2048, SHA256, Mgf1<SHA256, 16>>>();
    let mut signer = sk_16.create_signer(&mut DefaultRNG::default(), None).unwrap();
    signer.set_salt([0x42u8; 16]);
    signer.do_update(msg);
    let d = signer.do_final().unwrap();
    pk_16.verify(msg, None, &d).unwrap();
    let mut signer = sk_16.create_signer(&mut DefaultRNG::default(), None).unwrap();
    signer.set_salt([0x42u8; 16]);
    signer.do_update(msg);
    assert_eq!(signer.do_final().unwrap(), d);
    assert!(pk_conv.verify(msg, None, &d).is_err());

    let (pk_g, sk_g) = RSA2048::generate_pss_signature_key_pair_with::<SHA256, NoSalt<SHA256>>(
        &mut DefaultRNG::default(),
    )
    .unwrap();
    let e = sk_g.sign_deterministic(msg, None).unwrap();
    assert_eq!(e, sk_g.sign_deterministic(msg, None).unwrap());
    pk_g.verify(msg, None, &e).unwrap();
}
