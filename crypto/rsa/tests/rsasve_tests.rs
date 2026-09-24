//! RSASVE (SP 800-56B Rev. 2 §7.2.1) as a KEM, at every modulus size that has one.
//!
//! Known-answer sources, all in `bc-test-data/crypto/rsa/`:
//!
//! * `acvp/KAS-IFC-SSC-Sp800-56Br2.json`: NIST ACVP-Server's sample KAS-IFC-SSC vector set
//!   (`gen-val/json-files/KAS-IFC-SSC-Sp800-56Br2/internalProjection.json`). Its KAS1 (2048-bit) and
//!   KAS2 (3072-bit) groups with CRT keys (`rsakpg1-crt`/`rsakpg2-crt`) carry RSASVE ciphertexts
//!   with their secret values in both directions: `serverZ^iutE = serverC` and `iutZ^serverE =
//!   iutC`. They exercise `decaps` directly, and `encaps_rng` through an RNG that emits the
//!   vector's `Z`, since RSASVE.GENERATE's step 2.b turns the RNG's bytes straight into `z`. The
//!   `failChangedZ` cases carry a `Z` inconsistent with `C`, which must not be recovered.
//! * `acvp/RSA-DecryptionPrimitive-Sp800-56Br2.json`: ACVP-Server's RSADP vector set
//!   (`gen-val/json-files/RSA-DecryptionPrimitive-Sp800-56Br2/internalProjection.json`). Its CRT
//!   groups (2048/3072/4096) are RSASVE.RECOVER's step 3.b, including the out-of-range
//!   ciphertexts (`c <= 1` or `c >= n - 1`) that step 3.c must reject. The basic-format groups
//!   (`keyMode: standard`, no CRT components) are skipped, since this crate has no `(n, d)` key
//!   type.
//! * `openssl/openssl_rsasve_<bits>.json`: produced by `openssl/ossl_rsasve.c` against OpenSSL
//!   3.0.13's `EVP_PKEY_encapsulate` with `EVP_PKEY_CTX_set_kem_op(ctx, "RSASVE")`. Each file has
//!   one freshly generated key (`e = 65537`) and five OpenSSL encapsulations `(C, Z)` under it.
//!   These are the only third-party vectors at 8192 bits, and they are what the trait-conformance
//!   suites below use as their fixed keys.

use bouncycastle_core::errors::{KEMError, RNGError};
use bouncycastle_core::key_material::{KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{KEMDecapsulator, KEMEncapsulator, KEMPrivateKey, KEMPublicKey};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_core_test_framework::kem::{TestFrameworkKEM, TestFrameworkKEMKeys};
use bouncycastle_hex::decode as hex_decode;
use serde_json::Value;
use std::fs;
use std::path::Path;

const TEST_DATA_PATH_RELATIVE: &str = "../../../bc-test-data/crypto/rsa";
const TEST_DATA_PATH: &str = "../bc-test-data/crypto/rsa";

fn get_test_data(filename: &str) -> Value {
    for dir in [TEST_DATA_PATH_RELATIVE, TEST_DATA_PATH] {
        let path = format!("{dir}/{filename}");
        if Path::new(&path).exists() {
            return serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        }
    }
    panic!(
        "bc-test-data not found (looked for {filename} in {TEST_DATA_PATH_RELATIVE:?} and \
         {TEST_DATA_PATH:?}); this suite requires it rather than skipping"
    );
}

/// A big-endian hex integer as exactly `LEN` bytes, left-padded with zeros. ACVP drops leading
/// zero nibbles from some values (its `passLeadingZeroNibble` cases), so the input may be shorter.
fn be_bytes<const LEN: usize>(hex: &str) -> [u8; LEN] {
    let padded = if hex.len() % 2 == 1 { format!("0{hex}") } else { hex.to_string() };
    let bytes = hex_decode(&padded).expect("valid hex");
    assert!(bytes.len() <= LEN, "value wider than {LEN} bytes");
    let mut out = [0u8; LEN];
    out[LEN - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// A big-endian hex integer as `L` little-endian limbs (the key constructors' representation).
fn limbs<const L: usize>(hex: &str) -> [u64; L] {
    let padded = if hex.len() % 2 == 1 { format!("0{hex}") } else { hex.to_string() };
    let bytes = hex_decode(&padded).expect("valid hex");
    assert!(bytes.len() <= 8 * L, "value wider than {L} limbs");
    let mut wide = vec![0u8; 8 * L - bytes.len()];
    wide.extend_from_slice(&bytes);
    let mut out = [0u64; L];
    for i in 0..L {
        let start = 8 * L - (i + 1) * 8;
        out[i] = u64::from_be_bytes(wide[start..start + 8].try_into().unwrap());
    }
    out
}

/// An `RNG` whose stream is `bytes` repeated, reporting `strength`.
fn rng_emitting<const N: usize>(bytes: [u8; N], strength: SecurityStrength) -> FixedSeedRNG<N> {
    let mut rng = FixedSeedRNG::new(bytes);
    rng.set_security_strength(strength);
    rng
}

macro_rules! rsasve_suite {
    ($module:ident, $size:ident, $bits:literal, $L:literal, $HALF:literal, $strength:expr, $weaker:expr) => {
        mod $module {
            use super::*;
            use bouncycastle_rsa::$size::{CT_LEN, PK_LEN, RSASVE, SK_LEN, SS_LEN};

            type PK = bouncycastle_rsa::rsasve::RsaKEMPublicKey<$L>;
            type SK = bouncycastle_rsa::rsasve::RsaKEMPrivateKey<$L, $HALF>;

            fn openssl_vectors() -> Value {
                get_test_data(&format!("openssl/openssl_rsasve_{}.json", $bits))
            }

            fn sk_from(v: &Value, p: &str, q: &str, dp: &str, dq: &str, qinv: &str) -> SK {
                SK::from_crt_components(
                    &limbs::<$HALF>(v[p].as_str().unwrap()),
                    &limbs::<$HALF>(v[q].as_str().unwrap()),
                    &limbs::<$HALF>(v[dp].as_str().unwrap()),
                    &limbs::<$HALF>(v[dq].as_str().unwrap()),
                    &limbs::<$HALF>(v[qinv].as_str().unwrap()),
                )
                .expect("vector CRT key must be accepted")
            }

            fn openssl_keypair() -> Result<(PK, SK), KEMError> {
                let v = openssl_vectors();
                let pk = PK::new(&limbs::<$L>(v["n"].as_str().unwrap()), 65537)?;
                let sk = sk_from(&v, "p", "q", "dP", "dQ", "qInv");
                Ok((pk, sk))
            }

            #[test]
            fn lengths_are_nlen() {
                assert_eq!(CT_LEN, $bits / 8);
                assert_eq!(SS_LEN, $bits / 8);
                assert_eq!(PK_LEN, $bits / 8 + 4);
                assert_eq!(SK_LEN, 5 * $bits / 16);
            }

            #[test]
            fn kem_trait_conformance_suite() {
                // Not deterministic (fresh `Z` per call). "Implicitly rejecting" in the test
                // framework's sense: a corrupted but in-range ciphertext recovers a different `Z`
                // rather than an error, since RSASVE has no redundancy to check.
                TestFrameworkKEM::new(false, true)
                    .test_kem::<PK, SK, RSASVE, PK_LEN, SK_LEN, CT_LEN, SS_LEN>(
                        openssl_keypair, false,
                    );
            }

            #[test]
            fn kem_key_trait_conformance_suite() {
                TestFrameworkKEMKeys::new().test_keys::<PK, SK, PK_LEN, SK_LEN>(openssl_keypair);
            }

            #[test]
            fn keys_round_trip_through_their_encoding() {
                let (pk, sk) = openssl_keypair().unwrap();
                assert_eq!(PK::from_bytes(&pk.encode()).unwrap(), pk);
                assert_eq!(SK::from_bytes(&sk.encode()).unwrap(), sk);
                let mut pk_out = [0xAAu8; PK_LEN];
                assert_eq!(pk.encode_out(&mut pk_out), PK_LEN);
                assert_eq!(pk_out, pk.encode());
                let mut sk_out = [0xAAu8; SK_LEN];
                assert_eq!(sk.encode_out(&mut sk_out), SK_LEN);
                assert_eq!(sk_out, sk.encode());
                assert_eq!(pk.n(), sk.n());
                assert_eq!(pk.e(), 65537);
                // `Display` is the wrapped signature key type's, unchanged.
                let inner = bouncycastle_rsa::keys::RsaPublicKey::<$L>::new(pk.n(), 65537).unwrap();
                assert_eq!(format!("{pk}"), format!("{inner}"));
            }

            /// OpenSSL encapsulated; this crate decapsulates. And the other way round: fed
            /// OpenSSL's `Z` as its RNG output, `encaps_rng` must produce OpenSSL's `C` exactly
            /// (RSAEP is deterministic in `z`).
            #[test]
            fn openssl_rsasve_vectors() {
                let v = openssl_vectors();
                let (pk, sk) = openssl_keypair().unwrap();
                let encs = v["encapsulations"].as_array().unwrap();
                assert_eq!(encs.len(), 5);
                for enc in encs {
                    let c = be_bytes::<CT_LEN>(enc["C"].as_str().unwrap());
                    let z = be_bytes::<SS_LEN>(enc["Z"].as_str().unwrap());

                    let ss = RSASVE::decaps(&sk, &c).unwrap();
                    assert_eq!(ss.ref_to_bytes(), &z[..]);

                    let (ss, ct) =
                        RSASVE::encaps_rng(&pk, &mut rng_emitting(z, SecurityStrength::_256bit))
                            .unwrap();
                    assert_eq!(ct, c);
                    assert_eq!(ss.ref_to_bytes(), &z[..]);
                }
            }

            #[test]
            fn shared_secret_is_labelled_with_the_modulus_strength() {
                let (pk, sk) = openssl_keypair().unwrap();
                let (ss, ct) = RSASVE::encaps(&pk).unwrap();
                assert_eq!(ss.key_len(), SS_LEN);
                assert_eq!(ss.key_type(), KeyType::CryptographicRandom);
                assert_eq!(ss.security_strength(), $strength);
                let ss2 = RSASVE::decaps(&sk, &ct).unwrap();
                assert_eq!(ss2.key_len(), SS_LEN);
                assert_eq!(ss2.key_type(), KeyType::CryptographicRandom);
                assert_eq!(ss2.security_strength(), $strength);
                assert_eq!(ss, ss2);
            }

            #[test]
            fn encaps_rng_accepts_exactly_the_modulus_strength_and_rejects_below_it() {
                let (pk, _) = openssl_keypair().unwrap();
                assert!(
                    RSASVE::encaps_rng(&pk, &mut rng_emitting([0x5Au8; CT_LEN], $strength)).is_ok()
                );
                assert!(matches!(
                    RSASVE::encaps_rng(&pk, &mut rng_emitting([0x5Au8; CT_LEN], $weaker)),
                    Err(KEMError::RNGError(RNGError::SecurityStrengthInsufficientForAlgorithm))
                ));
            }

            /// RSASVE.GENERATE step 2.c's boundaries, one draw at a time: `z` in {0, 1, n - 1,
            /// all-ones} must be redrawn, and `z` in {2, n - 2} kept.
            #[test]
            fn generate_redraws_exactly_outside_one_to_n_minus_one() {
                let (pk, sk) = openssl_keypair().unwrap();
                let n = be_bytes::<CT_LEN>(openssl_vectors()["n"].as_str().unwrap());
                let mut n_minus_1 = n;
                n_minus_1[CT_LEN - 1] -= 1; // n is odd: no borrow
                // Byte-wise `n - 2` needs no borrow only if `n`'s low byte is at least 3.
                assert!(n[CT_LEN - 1] >= 3, "vector key's low byte makes n - 2 need a borrow");
                let mut n_minus_2 = n;
                n_minus_2[CT_LEN - 1] -= 2;
                let mut two = [0u8; CT_LEN];
                two[CT_LEN - 1] = 2;
                let mut one = [0u8; CT_LEN];
                one[CT_LEN - 1] = 1;
                let zero = [0u8; CT_LEN];
                let ones = [0xFFu8; CT_LEN];

                for good in [two, n_minus_2] {
                    for bad in [zero, one, n_minus_1, n, ones] {
                        // The RNG emits `bad` then `good`: one rejected draw, then an accepted one.
                        let mut stream = [0u8; 2 * CT_LEN];
                        stream[..CT_LEN].copy_from_slice(&bad);
                        stream[CT_LEN..].copy_from_slice(&good);
                        let (ss, ct) = RSASVE::encaps_rng(
                            &pk,
                            &mut rng_emitting(stream, SecurityStrength::_256bit),
                        )
                        .unwrap();
                        assert_eq!(ss.ref_to_bytes(), &good[..]);
                        assert_eq!(RSASVE::decaps(&sk, &ct).unwrap().ref_to_bytes(), &good[..]);
                    }
                }
            }

            #[test]
            fn generate_gives_up_on_an_rng_that_never_lands_in_range() {
                let (pk, _) = openssl_keypair().unwrap();
                for stuck in [[0xFFu8; CT_LEN], [0u8; CT_LEN]] {
                    assert!(matches!(
                        RSASVE::encaps_rng(
                            &pk,
                            &mut rng_emitting(stuck, SecurityStrength::_256bit)
                        ),
                        Err(KEMError::GenericError(_))
                    ));
                }
                // One in-range draw after `MAX_GENERATE_ATTEMPTS - 1` rejected ones still succeeds:
                // the cap is exactly `MAX_GENERATE_ATTEMPTS` draws, not one fewer.
                const ATTEMPTS: usize = bouncycastle_rsa::rsasve::MAX_GENERATE_ATTEMPTS;
                let mut stream = vec![0xFFu8; ATTEMPTS * CT_LEN];
                stream[(ATTEMPTS - 1) * CT_LEN..].fill(0x5A);
                let mut rng =
                    FixedSeedRNG::<{ ATTEMPTS * CT_LEN }>::new(stream.try_into().unwrap());
                let (ss, _) = RSASVE::encaps_rng(&pk, &mut rng).unwrap();
                assert_eq!(ss.ref_to_bytes(), &[0x5Au8; CT_LEN][..]);
            }

            /// RSADP's step 1 range (§7.1.2.3): `1 < c < n - 1`.
            #[test]
            fn recover_rejects_exactly_outside_one_to_n_minus_one() {
                let (_, sk) = openssl_keypair().unwrap();
                let n = be_bytes::<CT_LEN>(openssl_vectors()["n"].as_str().unwrap());
                let mut n_minus_1 = n;
                n_minus_1[CT_LEN - 1] -= 1;
                assert!(n[CT_LEN - 1] >= 3, "vector key's low byte makes n - 2 need a borrow");
                let mut n_minus_2 = n;
                n_minus_2[CT_LEN - 1] -= 2;
                let mut two = [0u8; CT_LEN];
                two[CT_LEN - 1] = 2;
                let mut one = [0u8; CT_LEN];
                one[CT_LEN - 1] = 1;

                for bad in [[0u8; CT_LEN], one, n_minus_1, n, [0xFFu8; CT_LEN]] {
                    assert!(matches!(
                        RSASVE::decaps(&sk, &bad),
                        Err(KEMError::DecapsulationFailed)
                    ));
                }
                for good in [two, n_minus_2] {
                    assert!(RSASVE::decaps(&sk, &good).is_ok());
                }
            }

            #[test]
            fn recover_rejects_a_wrong_length_ciphertext() {
                let (_, sk) = openssl_keypair().unwrap();
                for len in [0, CT_LEN - 1, CT_LEN + 1] {
                    assert!(matches!(
                        RSASVE::decaps(&sk, &vec![0x5Au8; len]),
                        Err(KEMError::LengthError(_))
                    ));
                }
            }

            #[test]
            fn public_key_validation() {
                let v = openssl_vectors();
                let n = limbs::<$L>(v["n"].as_str().unwrap());
                // SP 800-56B Rev. 2 §6.2.1: 65,537 <= e.
                assert!(PK::new(&n, 65537).is_ok());
                assert!(PK::new(&n, 65539).is_ok());
                for e in [3u32, 17, 65535] {
                    assert!(matches!(PK::new(&n, e), Err(KEMError::DecodingError(_))));
                }
                // Still rejected for being even (RsaPublicKey's own check).
                assert!(matches!(PK::new(&n, 65538), Err(KEMError::DecodingError(_))));
                let mut even_n = n;
                even_n[0] &= !1;
                assert!(matches!(PK::new(&even_n, 65537), Err(KEMError::DecodingError(_))));
                // n must be exactly $bits bits: its top bit set.
                let mut short_n = n;
                short_n[$L - 1] &= !(1 << 63);
                assert!(matches!(PK::new(&short_n, 65537), Err(KEMError::DecodingError(_))));
                // The same checks apply on decoding.
                let (pk, _) = openssl_keypair().unwrap();
                let mut bytes = pk.encode();
                bytes[0] &= 0x7F;
                assert!(matches!(PK::from_bytes(&bytes), Err(KEMError::DecodingError(_))));
                let mut bytes = pk.encode();
                bytes[PK_LEN - 4..].copy_from_slice(&3u32.to_be_bytes());
                assert!(matches!(PK::from_bytes(&bytes), Err(KEMError::DecodingError(_))));
            }

            #[test]
            fn private_key_validation() {
                let v = openssl_vectors();
                // RsaPrivateKey's own checks come through as DecodingError: p == q.
                assert!(matches!(
                    SK::from_crt_components(
                        &limbs::<$HALF>(v["p"].as_str().unwrap()),
                        &limbs::<$HALF>(v["p"].as_str().unwrap()),
                        &limbs::<$HALF>(v["dP"].as_str().unwrap()),
                        &limbs::<$HALF>(v["dP"].as_str().unwrap()),
                        &limbs::<$HALF>(v["qInv"].as_str().unwrap()),
                    ),
                    Err(KEMError::DecodingError(_))
                ));
                // p = 3, q = 5, dP = dQ = qInv = 1: every RsaPrivateKey check passes, but
                // n = 15 has its top bit clear.
                let mut p = [0u64; $HALF];
                p[0] = 3;
                let mut q = [0u64; $HALF];
                q[0] = 5;
                let mut small = [0u64; $HALF];
                small[0] = 1;
                assert!(matches!(
                    SK::from_crt_components(&p, &q, &small, &small, &small),
                    Err(KEMError::DecodingError(_))
                ));
                let (_, sk) = openssl_keypair().unwrap();
                let mut bytes = sk.encode();
                bytes[..8 * $HALF].fill(0); // p = 0, which is even
                assert!(matches!(SK::from_bytes(&bytes), Err(KEMError::DecodingError(_))));
            }
        }
    };
}

rsasve_suite!(
    rsa_2048_rsasve,
    rsa_2048,
    2048,
    32,
    16,
    SecurityStrength::_112bit,
    SecurityStrength::None
);
rsasve_suite!(
    rsa_3072_rsasve,
    rsa_3072,
    3072,
    48,
    24,
    SecurityStrength::_128bit,
    SecurityStrength::_112bit
);
rsasve_suite!(
    rsa_4096_rsasve,
    rsa_4096,
    4096,
    64,
    32,
    SecurityStrength::_128bit,
    SecurityStrength::_112bit
);
rsasve_suite!(
    rsa_8192_rsasve,
    rsa_8192,
    8192,
    128,
    64,
    SecurityStrength::_192bit,
    SecurityStrength::_128bit
);

/// ACVP KAS-IFC-SSC's KAS1 group (2048-bit, CRT IUT key, IUT as responder): the server
/// encapsulated to the IUT's key. Also checks `encaps_rng` reproduces `serverC` from `serverZ`.
#[test]
fn acvp_kas_ifc_ssc_kas1_2048() {
    use bouncycastle_rsa::rsa_2048::{CT_LEN, RSA2048KEMPrivateKey, RSA2048KEMPublicKey, RSASVE};
    let d = get_test_data("acvp/KAS-IFC-SSC-Sp800-56Br2.json");
    let group = d["testGroups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["scheme"] == "KAS1" && g["keyGenerationMethod"] == "rsakpg1-crt")
        .expect("KAS1 CRT group");
    assert_eq!(group["modulo"], 2048);
    let (mut passed, mut failed) = (0, 0);
    for t in group["tests"].as_array().unwrap() {
        let s = |k: &str| t[k].as_str().unwrap();
        let sk = RSA2048KEMPrivateKey::from_crt_components(
            &limbs(s("iutP")),
            &limbs(s("iutQ")),
            &limbs(s("iutDmp1")),
            &limbs(s("iutDmq1")),
            &limbs(s("iutIqmp")),
        )
        .unwrap();
        let e = u32::from_str_radix(s("iutE"), 16).unwrap();
        let pk = RSA2048KEMPublicKey::new(&limbs(s("iutN")), e).unwrap();
        let c = be_bytes::<CT_LEN>(s("serverC"));
        let z = be_bytes::<CT_LEN>(s("serverZ"));
        let recovered = RSASVE::decaps(&sk, &c).unwrap();
        if t["testPassed"].as_bool().unwrap() {
            assert_eq!(recovered.ref_to_bytes(), &z[..], "tcId {}", t["tcId"]);
            let (_, ct) =
                RSASVE::encaps_rng(&pk, &mut rng_emitting(z, SecurityStrength::_256bit)).unwrap();
            assert_eq!(ct, c, "tcId {}", t["tcId"]);
            passed += 1;
        } else {
            assert_ne!(recovered.ref_to_bytes(), &z[..], "tcId {}", t["tcId"]);
            failed += 1;
        }
    }
    assert_eq!((passed, failed), (4, 1));
}

/// ACVP KAS-IFC-SSC's KAS2 CRT group (3072-bit, both parties' keys CRT): one RSASVE in each
/// direction per case.
#[test]
fn acvp_kas_ifc_ssc_kas2_3072() {
    use bouncycastle_rsa::rsa_3072::{CT_LEN, RSA3072KEMPrivateKey, RSA3072KEMPublicKey, RSASVE};
    let d = get_test_data("acvp/KAS-IFC-SSC-Sp800-56Br2.json");
    let group = d["testGroups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["scheme"] == "KAS2" && g["keyGenerationMethod"] == "rsakpg2-crt")
        .expect("KAS2 CRT group");
    assert_eq!(group["modulo"], 3072);
    let (mut passed, mut failed) = (0, 0);
    for t in group["tests"].as_array().unwrap() {
        let s = |k: &str| t[k].as_str().unwrap();
        let key = |who: &str| {
            let sk = RSA3072KEMPrivateKey::from_crt_components(
                &limbs(s(&format!("{who}P"))),
                &limbs(s(&format!("{who}Q"))),
                &limbs(s(&format!("{who}Dmp1"))),
                &limbs(s(&format!("{who}Dmq1"))),
                &limbs(s(&format!("{who}Iqmp"))),
            )
            .unwrap();
            let e = u32::from_str_radix(s(&format!("{who}E")), 16).unwrap();
            let pk = RSA3072KEMPublicKey::new(&limbs(s(&format!("{who}N"))), e).unwrap();
            (pk, sk)
        };
        let (iut_pk, iut_sk) = key("iut");
        let (server_pk, server_sk) = key("server");
        // (recipient pk, recipient sk, C, Z): serverC was made to the IUT's key, iutC to the
        // server's.
        let directions = [
            (&iut_pk, &iut_sk, s("serverC"), s("serverZ")),
            (&server_pk, &server_sk, s("iutC"), s("iutZ")),
        ];
        let ok = t["testPassed"].as_bool().unwrap();
        for (pk, sk, c, z) in directions {
            let c = be_bytes::<CT_LEN>(c);
            let z = be_bytes::<CT_LEN>(z);
            let recovered = RSASVE::decaps(sk, &c).unwrap();
            if ok {
                assert_eq!(recovered.ref_to_bytes(), &z[..], "tcId {}", t["tcId"]);
                let (_, ct) =
                    RSASVE::encaps_rng(pk, &mut rng_emitting(z, SecurityStrength::_256bit))
                        .unwrap();
                assert_eq!(ct, c, "tcId {}", t["tcId"]);
            } else {
                assert_ne!(recovered.ref_to_bytes(), &z[..], "tcId {}", t["tcId"]);
            }
        }
        if ok {
            passed += 1;
        } else {
            failed += 1;
        }
    }
    assert_eq!((passed, failed), (4, 1));
}

/// ACVP's SP 800-56B Rev. 2 RSADP vectors, CRT groups: RSASVE.RECOVER is RSADP plus I2BS, so
/// `decaps(ct)` must be `pt` at `nLen` bytes, or `DecapsulationFailed` for the out-of-range
/// ciphertexts ACVP marks as failing.
macro_rules! acvp_rsadp {
    ($name:ident, $size:ident, $bits:literal, $L:literal, $HALF:literal) => {
        #[test]
        fn $name() {
            use bouncycastle_rsa::$size::{CT_LEN, RSASVE};
            type SK = bouncycastle_rsa::rsasve::RsaKEMPrivateKey<$L, $HALF>;
            let d = get_test_data("acvp/RSA-DecryptionPrimitive-Sp800-56Br2.json");
            let group = d["testGroups"]
                .as_array()
                .unwrap()
                .iter()
                .find(|g| g["keyMode"] == "crt" && g["modulo"] == $bits)
                .expect("CRT group");
            let (mut passed, mut failed) = (0, 0);
            for t in group["tests"].as_array().unwrap() {
                let s = |k: &str| t[k].as_str().unwrap();
                let sk = SK::from_crt_components(
                    &limbs(s("p")),
                    &limbs(s("q")),
                    &limbs(s("dmp1")),
                    &limbs(s("dmq1")),
                    &limbs(s("iqmp")),
                )
                .unwrap();
                let ct = be_bytes::<CT_LEN>(s("ct"));
                if t["testPassed"].as_bool().unwrap() {
                    let pt = be_bytes::<CT_LEN>(s("pt"));
                    assert_eq!(
                        RSASVE::decaps(&sk, &ct).unwrap().ref_to_bytes(),
                        &pt[..],
                        "tcId {}",
                        t["tcId"]
                    );
                    passed += 1;
                } else {
                    assert!(
                        matches!(RSASVE::decaps(&sk, &ct), Err(KEMError::DecapsulationFailed)),
                        "tcId {}",
                        t["tcId"]
                    );
                    failed += 1;
                }
            }
            assert_eq!(passed + failed, 15);
            assert!(failed > 0, "the group's out-of-range cases must have been exercised");
        }
    };
}

acvp_rsadp!(acvp_rsadp_crt_2048, rsa_2048, 2048, 32, 16);
acvp_rsadp!(acvp_rsadp_crt_3072, rsa_3072, 3072, 48, 24);
acvp_rsadp!(acvp_rsadp_crt_4096, rsa_4096, 4096, 64, 32);

/// `RSASVE::keygen`'s pairs are usable KEM keys (a genuine generation, at the smallest size
/// only: key generation is the slow part), and `keygen_from_rng` enforces the RNG strength.
#[test]
fn keygen_produces_working_kem_keys() {
    use bouncycastle_rsa::rsa_2048::RSASVE;
    let (pk, sk) = RSASVE::keygen().unwrap();
    assert_eq!(pk.e(), 65537);
    assert_eq!(pk.n(), sk.n());
    let (ss, ct) = RSASVE::encaps(&pk).unwrap();
    assert_eq!(RSASVE::decaps(&sk, &ct).unwrap(), ss);

    // A stuck RNG exhausts FIPS 186-5 A.1.3's candidate limit (see `keygen_tests.rs`'s
    // `keygen_from_rng_gives_up_on_a_stuck_rng`), and the KEM keygen passes that error through
    // as `GenericError` with key generation's own message, not a generic one.
    let mut stuck = FixedSeedRNG::new([0x42u8; 64]);
    match RSASVE::keygen_from_rng(&mut stuck) {
        Err(KEMError::GenericError(msg)) => assert!(msg.contains("candidate limit"), "{msg}"),
        other => panic!("expected GenericError, got {other:?}"),
    }

    let mut weak = FixedSeedRNG::new([0x5Au8; 64]);
    weak.set_security_strength(SecurityStrength::None);
    assert!(matches!(
        RSASVE::keygen_from_rng(&mut weak),
        Err(KEMError::RNGError(RNGError::SecurityStrengthInsufficientForAlgorithm))
    ));
}

/// `RSASVE::keygen` at the larger sizes, following `keygen_tests.rs`: 3072 runs by default, and
/// 4096/8192 are `#[ignore]`d for the same reason as there.
macro_rules! kem_keygen_round_trip {
    ($name:ident, $size:ident $(, $ignore:meta)?) => {
        #[test]
        $(#[$ignore])?
        fn $name() {
            use bouncycastle_rsa::$size::RSASVE;
            let (pk, sk) = RSASVE::keygen().unwrap();
            assert_eq!(pk.e(), 65537);
            assert_eq!(pk.n(), sk.n());
            let (ss, ct) = RSASVE::encaps(&pk).unwrap();
            assert_eq!(RSASVE::decaps(&sk, &ct).unwrap(), ss);
        }
    };
}

kem_keygen_round_trip!(kem_keygen_3072_round_trips, rsa_3072);
kem_keygen_round_trip!(
    kem_keygen_4096_round_trips,
    rsa_4096,
    ignore = "tens of minutes in a debug build: run with --release --ignored"
);
kem_keygen_round_trip!(
    kem_keygen_8192_round_trips,
    rsa_8192,
    ignore = "tens of minutes in a debug build: run with --release --ignored"
);
