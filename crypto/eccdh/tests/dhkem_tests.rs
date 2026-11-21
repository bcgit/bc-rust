//! DHKEM over P-256, P-384 and P-521 (RFC 9180 Section 4.1) on the ECC CDH keys.
//!
//! Known answers for P-256 and P-521 are the RFC's own vectors: `bc-test-data/crypto/hpke.txt`
//! is the machine-readable set RFC 9180 Appendix A cites as `[TestVectors]`, 32 entries for each
//! of `kem_id` 16 (P-256) and 18 (P-521); Appendix A.3 to A.6 print a few of them. Every entry
//! gives `DeriveKeyPair` vectors (`ikmR`, `ikmE`, and `ikmS` in the authenticated modes), and
//! `enc` and `shared_secret`: `Encap`'s in modes 0 and 1 (base and PSK), checked through
//! `Decap`, and `AuthEncap`'s in modes 2 and 3, checked through `AuthDecap` with `pkSm`.
//!
//! `Encap` cannot be run against the vectors: its ephemeral key comes from the extra-random-bits
//! key generation of SP 800-56A, not from raw RNG bytes, so no RNG yields the vector's `skEm`.
//! `Decap` of the vector's `enc` covers the same `ExtractAndExpand` over the same `kem_context`.
//!
//! P-521's `DeriveKeyPair` is the two-block `LabeledExpand`: Nsk is 66 and HKDF-SHA512 gives 64
//! bytes a block.
//!
//! One printed vector for each of the two curves (Appendix A.3.1 and A.6.1) is also carried in
//! this file, so that a known answer runs where `bc-test-data` is not checked out.
//!
//! Neither the appendix nor that file has P-384 (`kem_id` 17). Its known answers are in
//! `dhkem_p384_bc_java_tests.rs`.

use bouncycastle_core::errors::{KEMError, RNGError};
use bouncycastle_core::hazmat::FixedSeedRNG;
use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    Algorithm, AlgorithmInfo, KEMEncapsulator, PrivateKey, PublicKey, RNG,
};
use bouncycastle_core_test_framework::kem::{TestFrameworkKEM, TestFrameworkKEMKeys};
use bouncycastle_core_test_framework::test_data_loaders::bc_test_data;
use bouncycastle_dhkem::{AuthDecapsulatingKey, AuthEncapsulatingKey};
use bouncycastle_ec::curve::Curve;
use bouncycastle_ec::{P256, P384, P521};
use bouncycastle_eccdh::dhkem::{
    DHKEM_P256_HKDF_SHA256, DHKEM_P384_HKDF_SHA384, DHKEM_P521_HKDF_SHA512, DhkemCurve,
    derive_key_pair,
};
use bouncycastle_eccdh::keys::{ECCDHPrivateKey, ECCDHPublicKey, keygen};
use bouncycastle_hex as hex;
use bouncycastle_rng::{DefaultRNG, HashDRBG_SHA512};
use std::collections::HashMap;

/// The entries of `hpke.txt`: each starts at a `count = N` line and holds `name = hex` lines
/// (the per-message `encryptions` and `exports` sections reuse names this file does not read, so
/// only the first value of a name is kept).
fn hpke_vectors() -> Option<Vec<HashMap<String, String>>> {
    let text = bc_test_data("crypto", "hpke.txt")?;
    let mut entries = Vec::new();
    for line in text.lines() {
        let Some((name, value)) = line.split_once(" = ") else { continue };
        if name == "count" {
            entries.push(HashMap::new());
        }
        let entry: &mut HashMap<String, String> = entries.last_mut().expect("a count line first");
        entry.entry(name.to_string()).or_insert_with(|| value.trim().to_string());
    }
    Some(entries)
}

fn seed(bytes: &[u8]) -> KeyMaterial<128> {
    KeyMaterial::<128>::from_bytes_as_type(bytes, KeyType::Seed).expect("ikm fits and is a seed")
}

/// Runs every `hpke.txt` entry of `kem_id` through the curve `C`, and returns how many
/// `DeriveKeyPair` and how many `Decap` vectors were checked.
fn run_vectors<C, const N_PK: usize, const N_SK: usize, const N_SECRET: usize>(
    kem_id: &str,
) -> Option<(usize, usize)>
where
    C: DhkemCurve<SharedSecret = KeyMaterial<N_SECRET>>
        + Curve<PkUncompressed = [u8; N_PK], ScalarBytes = [u8; N_SK]>,
{
    let mut derived = 0;
    let mut decapped = 0;
    for entry in hpke_vectors()?.iter().filter(|e| e["kem_id"] == kem_id) {
        let count = &entry["count"];
        let get = |name: &str| hex::decode(&entry[name]).expect("hex");

        // DeriveKeyPair(ikmX) is (skXm, pkXm), for the recipient, the ephemeral key and, in the
        // authenticated modes, the sender.
        for who in ["R", "E", "S"] {
            let Some(ikm) = entry.get(&format!("ikm{who}")) else { continue };
            let (pk, sk) = derive_key_pair::<C>(&seed(&hex::decode(ikm).unwrap())).unwrap();
            assert_eq!(sk.encode().as_slice(), get(&format!("sk{who}m")), "count {count} sk{who}m");
            assert_eq!(pk.encode().as_slice(), get(&format!("pk{who}m")), "count {count} pk{who}m");
            derived += 1;
        }

        // Decap(enc, skR) is shared_secret, where the vector's secret came from Encap.
        if entry["mode"] == "0" || entry["mode"] == "1" {
            let sk_r = ECCDHPrivateKey::<C>::from_bytes(&get("skRm")).unwrap();
            let enc: [u8; N_PK] = get("enc").try_into().expect("enc is Nenc bytes");
            let ss = sk_r.decaps(&enc, ()).unwrap();
            assert_eq!(ss.ref_to_bytes(), get("shared_secret"), "count {count} shared_secret");
            assert_eq!(ss.key_type(), KeyType::CryptographicRandom);
            assert_eq!(ss.security_strength(), C::STRENGTH);
            // The ephemeral public key is the ciphertext (Section 4.1: enc = SerializePublicKey(pkE)).
            assert_eq!(get("enc"), get("pkEm"), "count {count}");
            decapped += 1;
        } else {
            // AuthDecap(enc, skR, pkS) is shared_secret, where the vector's came from AuthEncap.
            let sk_r = ECCDHPrivateKey::<C>::from_bytes(&get("skRm")).unwrap();
            let pk_s = ECCDHPublicKey::<C>::from_bytes(&get("pkSm")).unwrap();
            let enc: [u8; N_PK] = get("enc").try_into().expect("enc is Nenc bytes");
            let mut ss = KeyMaterial::<N_SECRET>::new();
            assert_eq!(sk_r.auth_decaps_out(&enc, &pk_s, &mut ss), Ok(N_SECRET));
            assert_eq!(ss.ref_to_bytes(), get("shared_secret"), "count {count} shared_secret");
            assert_eq!(ss.key_type(), KeyType::CryptographicRandom);
            assert_eq!(ss.security_strength(), C::STRENGTH);
            // The unauthenticated Decap of the same enc, without pkS, is another secret.
            assert_ne!(sk_r.decaps(&enc, ()).unwrap().ref_to_bytes(), get("shared_secret"));
            decapped += 1;
        }
    }
    Some((derived, decapped))
}

#[test]
fn p256_matches_the_rfc_9180_vectors() {
    let Some((derived, decapped)) = run_vectors::<P256, 65, 32, 32>("16") else {
        return;
    };
    // 32 entries: 16 in the unauthenticated modes with two ikm each, 16 authenticated with three.
    assert_eq!((derived, decapped), (80, 32));
}

/// Nsk = 66 against Nh = 64: every `DeriveKeyPair` here runs the two-block `LabeledExpand`.
#[test]
fn p521_matches_the_rfc_9180_vectors() {
    let Some((derived, decapped)) = run_vectors::<P521, 133, 66, 64>("18") else {
        return;
    };
    assert_eq!((derived, decapped), (80, 32));
}

/// One printed vector for a curve, so that a known answer runs when `bc-test-data` is absent.
struct Printed {
    ikm_r: &'static str,
    sk_rm: &'static str,
    pk_rm: &'static str,
    enc: &'static str,
    shared_secret: &'static str,
}

/// RFC 9180 Appendix A.3.1: DHKEM(P-256, HKDF-SHA256), base setup information.
const A_3_1: Printed = Printed {
    ikm_r: "668b37171f1072f3cf12ea8a236a45df23fc13b82af3609ad1e354f6ef817550",
    sk_rm: "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2",
    pk_rm: concat!(
        "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a",
        "826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72e",
        "a0",
    ),
    enc: concat!(
        "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325a",
        "c98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18",
        "c4",
    ),
    shared_secret: "c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8",
};

/// RFC 9180 Appendix A.6.1: DHKEM(P-521, HKDF-SHA512), base setup information.
const A_6_1: Printed = Printed {
    ikm_r: concat!(
        "2ad954bbe39b7122529f7dde780bff626cd97f850d0784a432784e69d86eccaa",
        "de43b6c10a8ffdb94bf943c6da479db137914ec835a7e715e36e45e29b587bab",
        "3bf1",
    ),
    sk_rm: concat!(
        "01462680369ae375e4b3791070a7458ed527842f6a98a79ff5e0d4cbde83c271",
        "96a3916956655523a6a2556a7af62c5cadabe2ef9da3760bb21e005202f7b246",
        "2847",
    ),
    pk_rm: concat!(
        "0401b45498c1714e2dce167d3caf162e45e0642afc7ed435df7902ccae0e84ba",
        "0f7d373f646b7738bbbdca11ed91bdeae3cdcba3301f2457be452f271fa68375",
        "80e661012af49583a62e48d44bed350c7118c0d8dc861c238c72a2bda17f6470",
        "4f464b57338e7f40b60959480c0e58e6559b190d81663ed816e523b6b6a418f6",
        "6d2451ec64",
    ),
    enc: concat!(
        "040138b385ca16bb0d5fa0c0665fbbd7e69e3ee29f63991d3e9b5fa740aab890",
        "0aaeed46ed73a49055758425a0ce36507c54b29cc5b85a5cee6bae0cf1c21f27",
        "31ece2013dc3fb7c8d21654bb161b463962ca19e8c654ff24c94dd2898de1205",
        "1f1ed0692237fb02b2f8d1dc1c73e9b366b529eb436e98a996ee522aef863dd5",
        "739d2f29b0",
    ),
    shared_secret: concat!(
        "776ab421302f6eff7d7cb5cb1adaea0cd50872c71c2d63c30c4f1d5e43653336",
        "fef33b103c67e7a98add2d3b66e2fda95b5b2a667aa9dac7e59cc1d46d30e818",
    ),
};

/// The printed vector through `DeriveKeyPair` and `Decap`.
fn check_printed<C, const N_PK: usize, const N_SK: usize, const N_SECRET: usize>(v: &Printed)
where
    C: DhkemCurve<SharedSecret = KeyMaterial<N_SECRET>>
        + Curve<PkUncompressed = [u8; N_PK], ScalarBytes = [u8; N_SK]>,
{
    let (pk_r, sk_r) = derive_key_pair::<C>(&seed(&hex::decode(v.ikm_r).unwrap())).unwrap();
    assert_eq!(hex::encode(sk_r.encode()), v.sk_rm);
    assert_eq!(hex::encode(pk_r.encode()), v.pk_rm);
    let enc: [u8; N_PK] = hex::decode(v.enc).unwrap().try_into().unwrap();
    assert_eq!(hex::encode(sk_r.decaps(&enc, ()).unwrap().ref_to_bytes()), v.shared_secret);
}

#[test]
fn the_printed_appendix_vectors_pass() {
    check_printed::<P256, 65, 32, 32>(&A_3_1);
    check_printed::<P521, 133, 66, 64>(&A_6_1);
}

fn keygen_kem<C: Curve>() -> Result<(ECCDHPublicKey<C>, ECCDHPrivateKey<C>), KEMError> {
    keygen::<C>(&mut DefaultRNG::default()).map_err(|_| KEMError::KeyGenError("keygen failed"))
}

/// The shared KEM suites. A changed ciphertext is no longer a point on the curve, so the KEM
/// rejects it explicitly.
#[test]
fn the_kem_frameworks_pass_for_the_three_curves() {
    let kem = TestFrameworkKEM::new(false, false);
    kem.test_kem::<(), ECCDHPublicKey<P256>, ECCDHPrivateKey<P256>, 65, 32>(keygen_kem, (), true);
    kem.test_kem::<(), ECCDHPublicKey<P384>, ECCDHPrivateKey<P384>, 97, 48>(keygen_kem, (), true);
    kem.test_kem::<(), ECCDHPublicKey<P521>, ECCDHPrivateKey<P521>, 133, 64>(keygen_kem, (), true);

    let keys = TestFrameworkKEMKeys::new();
    keys.test_keys::<ECCDHPublicKey<P256>, ECCDHPrivateKey<P256>, 65, 32>(keygen_kem);
    keys.test_keys::<ECCDHPublicKey<P384>, ECCDHPrivateKey<P384>, 97, 48>(keygen_kem);
    keys.test_keys::<ECCDHPublicKey<P521>, ECCDHPrivateKey<P521>, 133, 66>(keygen_kem);
}

/// Table 2's names and the curves' strengths, on the markers and on the workers.
#[test]
fn the_kems_are_named_as_rfc_9180_names_them() {
    assert_eq!(DHKEM_P256_HKDF_SHA256::ALG_NAME, "DHKEM(P-256, HKDF-SHA256)");
    assert_eq!(DHKEM_P384_HKDF_SHA384::ALG_NAME, "DHKEM(P-384, HKDF-SHA384)");
    assert_eq!(DHKEM_P521_HKDF_SHA512::ALG_NAME, "DHKEM(P-521, HKDF-SHA512)");
    assert_eq!(DHKEM_P256_HKDF_SHA256::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);
    assert_eq!(DHKEM_P384_HKDF_SHA384::MAX_SECURITY_STRENGTH, SecurityStrength::_192bit);
    assert_eq!(DHKEM_P521_HKDF_SHA512::MAX_SECURITY_STRENGTH, SecurityStrength::_256bit);

    let (pk, sk) = keygen_kem::<P384>().unwrap();
    let encapsulator = EncapsulatingKey::<(), 97, 48>::create_encapsulator(&pk, ()).unwrap();
    let decapsulator = DecapsulatingKey::<(), 97, 48>::create_decapsulator(&sk, ()).unwrap();
    assert_eq!(encapsulator.alg_name(), "DHKEM(P-384, HKDF-SHA384)");
    assert_eq!(decapsulator.alg_name(), "DHKEM(P-384, HKDF-SHA384)");
    assert_eq!(encapsulator.max_security_strength(), SecurityStrength::_192bit);
    assert_eq!(decapsulator.max_security_strength(), SecurityStrength::_192bit);
    assert_eq!((P256::KEM_ID, P384::KEM_ID, P521::KEM_ID), (0x0010, 0x0011, 0x0012));
    assert_eq!((P256::BITMASK, P384::BITMASK, P521::BITMASK), (0xFF, 0xFF, 0x01));
}

/// Section 7.1.1: `enc` is the uncompressed point, and Section 7.1.4: it must be on the curve.
/// A ciphertext of the right length that is the wrong form, or not a point, is refused.
#[test]
fn a_ciphertext_that_is_not_an_uncompressed_point_is_refused() {
    let mut rng = HashDRBG_SHA512::new_from_os();
    let (pk, sk) = keygen::<P256>(&mut rng).unwrap();
    let (_, ct) = pk.encaps(&mut rng, ()).unwrap();
    assert!(sk.decaps(&ct, ()).is_ok());

    // Not a point: y changed by one bit.
    let mut off_curve = ct;
    off_curve[64] ^= 1;
    assert!(matches!(sk.decaps(&off_curve, ()), Err(KEMError::DecapsulationFailed)));

    // The hybrid and compressed lead octets of SEC 1 Section 2.3.3 over the same bytes.
    for lead in [0x00, 0x02, 0x03, 0x06, 0x07] {
        let mut wrong_form = ct;
        wrong_form[0] = lead;
        assert!(
            matches!(sk.decaps(&wrong_form, ()), Err(KEMError::DecapsulationFailed)),
            "lead octet {lead:#04x}"
        );
    }

    // The all-zero string, which no encoding of a point is.
    assert!(matches!(sk.decaps(&[0u8; 65], ()), Err(KEMError::DecapsulationFailed)));
}

/// Section 7.1.3's requirements on the keying material are "SHOULD"s; what is enforced is its
/// type and its strength: keying material of the wrong type or weaker than the curve is refused.
#[test]
fn derive_key_pair_checks_its_keying_material() {
    assert!(derive_key_pair::<P256>(&seed(&[0x5A; 32])).is_ok());

    // The strength is what is required, not Nsk bytes: a 64-byte seed at 256 bits serves P-521,
    // whose Nsk is 66, and the same seed labelled weaker than the curve does not.
    let sixty_four = seed(&[0x5A; 64]);
    assert_eq!(sixty_four.security_strength(), SecurityStrength::_256bit);
    assert!(derive_key_pair::<P521>(&sixty_four).is_ok());
    let mut too_weak = seed(&[0x5A; 64]);
    too_weak.set_security_strength(SecurityStrength::_192bit).unwrap();
    assert!(matches!(derive_key_pair::<P521>(&too_weak), Err(KEMError::KeyGenError(_))));

    let mac_key = KeyMaterial::<128>::from_bytes_as_type(&[0x5A; 48], KeyType::MACKey).unwrap();
    assert!(matches!(derive_key_pair::<P384>(&mac_key), Err(KEMError::KeyGenError(_))));

    let mut weak = seed(&[0x5A; 48]);
    weak.set_security_strength(SecurityStrength::_128bit).unwrap();
    assert!(matches!(derive_key_pair::<P384>(&weak), Err(KEMError::KeyGenError(_))));

    // Deterministic: the same keying material gives the same pair, and different material a
    // different one.
    let (pk1, sk1) = derive_key_pair::<P384>(&seed(&[0x5A; 48])).unwrap();
    let (pk2, sk2) = derive_key_pair::<P384>(&seed(&[0x5A; 48])).unwrap();
    let (pk3, _) = derive_key_pair::<P384>(&seed(&[0xA5; 48])).unwrap();
    assert_eq!((&pk1, &sk1), (&pk2, &sk2));
    assert_ne!(pk1, pk3);
}

/// Each curve round-trips, and the secret is typed as a full-entropy key at the curve's strength.
#[test]
fn encaps_and_decaps_agree_on_every_curve() {
    fn round_trip<C, const N_ENC: usize, const N_SECRET: usize>()
    where
        C: DhkemCurve<SharedSecret = KeyMaterial<N_SECRET>> + Curve<PkUncompressed = [u8; N_ENC]>,
    {
        let mut rng = HashDRBG_SHA512::new_from_os();
        let (pk, sk) = keygen::<C>(&mut rng).unwrap();
        let (ss, ct) = pk.encaps(&mut rng, ()).unwrap();
        let ss2 = sk.decaps(&ct, ()).unwrap();
        assert_eq!(ss.ref_to_bytes(), ss2.ref_to_bytes());
        assert_eq!(ss.key_len(), N_SECRET);
        assert_eq!(ss.key_type(), KeyType::CryptographicRandom);
        assert_eq!(ss.security_strength(), C::STRENGTH);
        // A second encapsulation uses a fresh ephemeral key.
        let (ss3, ct3) = pk.encaps(&mut rng, ()).unwrap();
        assert_ne!(ct, ct3);
        assert_ne!(ss.ref_to_bytes(), ss3.ref_to_bytes());
    }
    round_trip::<P256, 65, 32>();
    round_trip::<P384, 97, 48>();
    round_trip::<P521, 133, 64>();
}

/// An RNG at full strength whose every draw fails, so that the failure comes from the ephemeral
/// key generation and not from the strength check before it.
struct StrongButFailing;

impl RNG for StrongButFailing {
    fn add_seed_keymaterial(&mut self, _: &dyn KeyMaterialTrait) -> Result<(), RNGError> {
        Err(RNGError::GenericError("every draw fails"))
    }
    fn next_int(&mut self) -> Result<u32, RNGError> {
        Err(RNGError::GenericError("every draw fails"))
    }
    fn next_bytes(&mut self, _: usize) -> Result<Vec<u8>, RNGError> {
        Err(RNGError::GenericError("every draw fails"))
    }
    fn next_bytes_out(&mut self, _: &mut [u8]) -> Result<usize, RNGError> {
        Err(RNGError::GenericError("every draw fails"))
    }
    fn fill_keymaterial_out(&mut self, _: &mut dyn KeyMaterialTrait) -> Result<usize, RNGError> {
        Err(RNGError::GenericError("every draw fails"))
    }
    fn security_strength(&self) -> SecurityStrength {
        SecurityStrength::_256bit
    }
}

/// An RNG failure while the ephemeral key is generated reaches the caller as the RNG's error,
/// with the ciphertext and the secret left zeroized.
#[test]
fn an_rng_failure_during_encapsulation_is_reported_as_the_rngs() {
    let (pk, _) = keygen_kem::<P256>().unwrap();
    assert!(matches!(
        pk.encaps(&mut StrongButFailing, ()),
        Err(KEMError::RNGError(RNGError::GenericError(_)))
    ));
    let mut ct = [0xAAu8; 65];
    let mut ss = KeyMaterial::<32>::from_bytes_as_type(&[0xAA; 32], KeyType::Seed).unwrap();
    let encapsulator = EncapsulatingKey::<(), 65, 32>::create_encapsulator(&pk, ()).unwrap();
    assert!(matches!(
        encapsulator.encaps_out(&mut StrongButFailing, &mut ct, &mut ss),
        Err(KEMError::RNGError(_))
    ));
    assert_eq!(ct, [0u8; 65]);
    assert_eq!(ss.key_type(), KeyType::Zeroized);
}

/// `AuthEncap` and `AuthDecap` on the keys of one curve: they agree, the sender's key is bound
/// into the secret, and the outputs are zeroized first and left so on an error.
fn auth_round_trip<C, const N_ENC: usize, const N_SECRET: usize>()
where
    C: DhkemCurve<SharedSecret = KeyMaterial<N_SECRET>> + Curve<PkUncompressed = [u8; N_ENC]>,
{
    let mut rng = HashDRBG_SHA512::new_from_os();
    let (pk_r, sk_r) = keygen::<C>(&mut rng).unwrap();
    let (pk_s, sk_s) = keygen::<C>(&mut rng).unwrap();
    let (pk_other, _) = keygen::<C>(&mut rng).unwrap();

    let mut enc = [0xFFu8; N_ENC];
    let mut ss = KeyMaterial::<N_SECRET>::from_bytes(&[0xFF; 32]).unwrap();
    assert_eq!(pk_r.auth_encaps_out(&mut rng, &sk_s, &mut enc, &mut ss), Ok(N_ENC));
    assert_eq!(enc[0], 0x04, "enc is an uncompressed point");
    assert_eq!(ss.key_len(), N_SECRET);

    let mut got = KeyMaterial::<N_SECRET>::from_bytes(&[0xFF; 32]).unwrap();
    assert_eq!(sk_r.auth_decaps_out(&enc, &pk_s, &mut got), Ok(N_SECRET));
    assert!(got.equals(&ss));
    // Another sender's public key gives another secret, not an error.
    assert_eq!(sk_r.auth_decaps_out(&enc, &pk_other, &mut got), Ok(N_SECRET));
    assert!(!got.equals(&ss));

    // An enc that is not a point, and an RNG below the curve's strength.
    let mut got = KeyMaterial::<N_SECRET>::from_bytes(&[0xFF; 32]).unwrap();
    assert_eq!(
        sk_r.auth_decaps_out(&[0x04; N_ENC], &pk_s, &mut got),
        Err(KEMError::DecapsulationFailed)
    );
    assert_eq!(got.key_type(), KeyType::Zeroized);
    let mut weak = FixedSeedRNG::new([0x5A; 64]);
    weak.set_security_strength(SecurityStrength::_112bit);
    let mut enc = [0xFFu8; N_ENC];
    let mut ss = KeyMaterial::<N_SECRET>::from_bytes(&[0xFF; 32]).unwrap();
    assert!(matches!(
        pk_r.auth_encaps_out(&mut weak, &sk_s, &mut enc, &mut ss),
        Err(KEMError::RNGError(_))
    ));
    assert_eq!(enc, [0u8; N_ENC]);
    assert_eq!(ss.key_type(), KeyType::Zeroized);
}

#[test]
fn auth_encaps_and_auth_decaps_agree_on_every_curve() {
    auth_round_trip::<P256, 65, 32>();
    auth_round_trip::<P384, 97, 48>();
    auth_round_trip::<P521, 133, 64>();
}
