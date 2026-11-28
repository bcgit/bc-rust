//! X448 as a KEM: DHKEM(X448, HKDF-SHA512) of RFC 9180 Section 4.1 (`kem_id` 0x0021).
//!
//! RFC 9180 Appendix A prints no X448 vectors. The known answers are the machine-readable set
//! it cites as `[TestVectors]`, `bc-test-data/crypto/hpke.txt`, which has 32 entries of
//! `kem_id` 33: every one gives `DeriveKeyPair` vectors (`ikmR`, `ikmE`, and `ikmS` in the
//! authenticated modes) and `enc` and `shared_secret`, `Encap`'s in modes 0 and 1 and
//! `AuthEncap`'s in modes 2 and 3. An X448 private key is 56 random bytes, so the vector's
//! `skEm` from the RNG reproduces the sender's side too. If the file is absent that test
//! prints a warning and passes; one entry of each kind is carried in this file, copied by a
//! script, so that a known answer always runs.

use bouncycastle_core::agreement_key::AgreementKey;
use bouncycastle_core::errors::{KEMError, KeyAgreementError, KeyMaterialError, RNGError};
use bouncycastle_core::hazmat::FixedSeedRNG;
use bouncycastle_core::hex;
use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    Algorithm, AlgorithmInfo, KEMDecapsulator, KEMEncapsulator, PrivateKey, PublicKey, RNG,
};
use bouncycastle_core_test_framework::kem::{TestFrameworkKEM, TestFrameworkKEMKeys};
use bouncycastle_core_test_framework::test_data_loaders::bc_test_data;
use bouncycastle_ec::dhkem::{
    AuthDecapsulatingKey, AuthEncapsulatingKey, DHKEM, DHKEMParams, HpkeKem,
};
use bouncycastle_ec::ed::x448::{
    DHKEM_SS_LEN, DHKEM_X448_HKDF_SHA512, POINT_LEN, SCALAR_LEN, X448, X448PrivateKey,
    X448PublicKey, keygen,
};
use bouncycastle_rng::{DefaultRNG, HashDRBG_SHA512};
use bouncycastle_utils::secret::Secret;
use std::collections::HashMap;

type X448DHKEM = DHKEM<X448, POINT_LEN, SCALAR_LEN, POINT_LEN, DHKEM_SS_LEN>;

/// The KEM values of one entry of `hpke.txt`, by the file's names.
type Entry = HashMap<String, String>;

/// The entries of `hpke.txt`: each starts at a `count = N` line and holds `name = hex` lines
/// (the per-message sections reuse names this file does not read, so only the first value of a
/// name is kept).
fn hpke_vectors() -> Option<Vec<Entry>> {
    let text = bc_test_data("crypto", "hpke.txt")?;
    let mut entries = Vec::new();
    for line in text.lines() {
        let Some((name, value)) = line.split_once(" = ") else { continue };
        if name == "count" {
            entries.push(HashMap::new());
        }
        let entry: &mut Entry = entries.last_mut().expect("a count line first");
        entry.entry(name.to_string()).or_insert_with(|| value.trim().to_string());
    }
    Some(entries)
}

/// The `kem_id` 33 entry `count = 32` of `hpke.txt` (mode 0).
fn printed_base() -> Entry {
    [
        ("count", "32"),
        ("mode", "0"),
        (
            "ikmE",
            concat!(
                "6e7c63cb3a0b77cdb1ac289e1ac02749f97f0f18b4f2a6e0e3ca1701",
                "73d0c02d48838081b9c5d98af919e8a79ab93e17fa7093a6af6fda01",
            ),
        ),
        (
            "pkEm",
            concat!(
                "71b965384ed06d5ddf43ae816ca30d8cd61235e98d13fe011cfdba7d",
                "19488134c626f087d3fd9b6aaa4d4115ef80e9074b53f2c0fa3d5ecc",
            ),
        ),
        (
            "skEm",
            concat!(
                "a284fb66158038679a7c1106afe253385ed683e67cdf5c89e9e3e6f0",
                "374190343a1d81ae18626a0f9a75f17a7cd9b14aaf27206a5d2eb6fc",
            ),
        ),
        (
            "ikmR",
            concat!(
                "d45d1652df74920abf94a2883c83050f502ff512ffb56f07b6d833ec",
                "8dda74b6a1c1cc4d42a22641c0963d3c21ed8261f344dc9e0501a81c",
            ),
        ),
        (
            "pkRm",
            concat!(
                "145d083ea7a6379dbb32dcbd8aff4c206ea5d069b75e96c6dd2a3e38",
                "f441471ac97adca641fdad66685a96f32b7c3e064635fab3cc89234e",
            ),
        ),
        (
            "skRm",
            concat!(
                "27a4354608f3bdd38f1f5af305f3e0682efe4e25808249d8fcb55927",
                "f6a9f446b8dc1d0a2c3b8cb133a5673b59a6d55ce754ec0c9a555401",
            ),
        ),
        (
            "enc",
            concat!(
                "71b965384ed06d5ddf43ae816ca30d8cd61235e98d13fe011cfdba7d",
                "19488134c626f087d3fd9b6aaa4d4115ef80e9074b53f2c0fa3d5ecc",
            ),
        ),
        (
            "shared_secret",
            concat!(
                "e0f1ddf832f530335c9aabe5274f61e354d39f32ba4e33556446ee01877db615",
                "0b046748d1f25d0c7f66bdb2632915c8d64e04649d23b4a3f0249c5a835434bf",
            ),
        ),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_string(), value.to_string()))
    .collect()
}

/// The `kem_id` 33 entry `count = 34` of `hpke.txt` (mode 2, Auth).
fn printed_auth() -> Entry {
    [
        ("count", "34"),
        ("mode", "2"),
        (
            "ikmE",
            concat!(
                "57f1c4769946dec8d5f1caef27dd2b97dec19c10873ee486bfe27e4f",
                "2178f9040847b59b08ac740c18bc555fca466964778d117d6031838b",
            ),
        ),
        (
            "pkEm",
            concat!(
                "6bdadccd4639d76f6a75148a173b01ffbbaac0396d39fd5bb76e7ced",
                "a46ea1afd115bd8ce24cfa165b92fae3b29240285fbbc6d4c90705ad",
            ),
        ),
        (
            "skEm",
            concat!(
                "f88037e8f95744954e9112ae595e17182a199d85d34091ef2be5b782",
                "82792d88f4db54a1d4ab5825f71adf7200b908e752b3970881bd689d",
            ),
        ),
        (
            "ikmR",
            concat!(
                "b0f9ddecb790b0866097b119b8252aeb6076d44f95fb5e9bc06c71c6",
                "db0d4f2c59a1bec8e11fc111792155eb0dd46b8de06d0388101016fc",
            ),
        ),
        (
            "pkRm",
            concat!(
                "8aa332975597c3c5185199e63daeb2b3de96b6307d01ec670287354d",
                "7090c9febf19617f18142cfbbec97c710875c6c5d2b728c4132280eb",
            ),
        ),
        (
            "skRm",
            concat!(
                "7bbcb2dcb4b0228718b6f01609feffe7e29ebf11583106df31909141",
                "5e54e82fc6360d7dfa6b482fff6690fadee2c6b85aca4eee0ccddb7d",
            ),
        ),
        (
            "ikmS",
            concat!(
                "2c831dd4d97d2e2de000103cc264411f69e12e96665e249c2c767825",
                "f441ef783a44f9046d2cdca75d27ef80e906a3b72de9400ad945e91b",
            ),
        ),
        (
            "pkSm",
            concat!(
                "51aa49db2c674fa0fba4b1aba7212af16b7b08166330149573680cdc",
                "e0916e6b9a2245666af06ab54203e3e986365384306f677e47a73cbc",
            ),
        ),
        (
            "skSm",
            concat!(
                "435ba58b5b6790935e4b108815e4fe6dc3cc87e296d3717631b1251c",
                "910c516799d6145c05352ead3afd820f5ade1fd07655eeb42d8bc228",
            ),
        ),
        (
            "enc",
            concat!(
                "6bdadccd4639d76f6a75148a173b01ffbbaac0396d39fd5bb76e7ced",
                "a46ea1afd115bd8ce24cfa165b92fae3b29240285fbbc6d4c90705ad",
            ),
        ),
        (
            "shared_secret",
            concat!(
                "1df5567445202c83908136b0c9dcb777ca19b36bb3a901ed75fc5a4d460c90b4",
                "3bbf4a30e67b938c87fe796d9e63caad08715f69ed413490876cf5e0c0be73fb",
            ),
        ),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_string(), value.to_string()))
    .collect()
}

fn decode_56(s: &str) -> [u8; 56] {
    hex::decode(s).unwrap().try_into().unwrap()
}

fn seed(bytes: &[u8]) -> KeyMaterial<56> {
    KeyMaterial::<56>::from_bytes_as_type(bytes, KeyType::Seed).unwrap()
}

/// Clamps as `decodeScalar448` does (RFC 7748 Section 5).
fn clamp(mut k: [u8; 56]) -> [u8; 56] {
    k[0] &= 252;
    k[55] |= 128;
    k
}

fn stale_secret() -> KeyMaterial<DHKEM_SS_LEN> {
    KeyMaterial::<DHKEM_SS_LEN>::from_bytes_as_type(&[0xFF; DHKEM_SS_LEN], KeyType::Seed).unwrap()
}

/// Checks one entry: `DeriveKeyPair` for every ikm it has, then `Encap` and `Decap` (modes 0
/// and 1) or `AuthEncap` and `AuthDecap` (modes 2 and 3), the sender's side with the vector's
/// ephemeral key as the RNG's output. Returns how many key pairs were derived.
fn check_entry(entry: &Entry) -> usize {
    let count = &entry["count"];
    let get = |name: &str| decode_56(&entry[name]);
    let shared_secret = hex::decode(&entry["shared_secret"]).unwrap();

    // DeriveKeyPair(ikmX) is (skXm, pkXm). The file lists the private keys as derived, while
    // RFC 9180 Section 7.1.2 has a serialized private key clamped.
    let mut derived = 0;
    for who in ["R", "E", "S"] {
        let Some(ikm) = entry.get(&format!("ikm{who}")) else { continue };
        let (pk, sk) = X448DHKEM::derive_key_pair(&seed(&hex::decode(ikm).unwrap())).unwrap();
        assert_eq!(pk.encode(), get(&format!("pk{who}m")), "count {count} pk{who}m");
        assert_eq!(sk.encode(), clamp(get(&format!("sk{who}m"))), "count {count} sk{who}m");
        assert_eq!(sk.pub_key().unwrap(), pk, "count {count}");
        derived += 1;
    }

    let pk_r = X448PublicKey::from_bytes(&get("pkRm")).unwrap();
    let sk_r = X448PrivateKey::from_bytes(&get("skRm")).unwrap();
    assert_eq!(sk_r.pub_key().unwrap(), pk_r, "count {count}: pk(skRm)");
    // The ephemeral public key is the ciphertext (Section 4.1: enc = SerializePublicKey(pkE)).
    assert_eq!(entry["enc"], entry["pkEm"], "count {count}");
    let mut rng = FixedSeedRNG::new(get("skEm"));
    let strength = SecurityStrength::_192bit;

    if entry["mode"] == "0" || entry["mode"] == "1" {
        let (ss, enc) = pk_r.encaps(&mut rng, ()).unwrap();
        assert_eq!(enc, get("enc"), "count {count}: enc");
        assert_eq!(ss.ref_to_bytes(), shared_secret, "count {count}: Encap");
        assert_eq!(
            (ss.key_type(), ss.security_strength()),
            (KeyType::CryptographicRandom, strength)
        );

        let ss = sk_r.decaps(&get("enc"), ()).unwrap();
        assert_eq!(ss.ref_to_bytes(), shared_secret, "count {count}: Decap");
        assert_eq!(
            (ss.key_type(), ss.security_strength()),
            (KeyType::CryptographicRandom, strength)
        );
    } else {
        let pk_s = X448PublicKey::from_bytes(&get("pkSm")).unwrap();
        let sk_s = X448PrivateKey::from_bytes(&get("skSm")).unwrap();

        let mut enc = [0xFF_u8; POINT_LEN];
        let mut ss = stale_secret();
        assert_eq!(pk_r.auth_encaps_out(&mut rng, &sk_s, &mut enc, &mut ss), Ok(POINT_LEN));
        assert_eq!(enc, get("enc"), "count {count}: enc");
        assert_eq!(ss.ref_to_bytes(), shared_secret, "count {count}: AuthEncap");

        let mut ss = stale_secret();
        assert_eq!(sk_r.auth_decaps_out(&get("enc"), &pk_s, &mut ss), Ok(DHKEM_SS_LEN));
        assert_eq!(ss.ref_to_bytes(), shared_secret, "count {count}: AuthDecap");
        assert_eq!(
            (ss.key_type(), ss.security_strength()),
            (KeyType::CryptographicRandom, strength)
        );
        // The unauthenticated Decap of the same enc, without pkS, is another secret.
        assert_ne!(sk_r.decaps(&get("enc"), ()).unwrap().ref_to_bytes(), shared_secret);
    }
    derived
}

/// Every `kem_id` 33 entry of `hpke.txt`.
#[test]
fn x448_matches_the_rfc_9180_vectors() {
    let Some(entries) = hpke_vectors() else {
        eprintln!("bc-test-data/crypto/hpke.txt not found; skipping");
        return;
    };
    let (mut base, mut auth, mut derived) = (0, 0, 0);
    for entry in entries.iter().filter(|e| e["kem_id"] == "33") {
        derived += check_entry(entry);
        match entry["mode"].as_str() {
            "0" | "1" => base += 1,
            "2" | "3" => auth += 1,
            mode => panic!("an unexpected mode {mode}"),
        }
    }
    println!(
        "hpke.txt kem_id 33: {} entries: {base} Encap/Decap, {auth} AuthEncap/AuthDecap, \
         {derived} DeriveKeyPair",
        base + auth
    );
    // 32 entries: 16 in the unauthenticated modes with two ikm each, 16 authenticated with three.
    assert_eq!((base, auth, derived), (16, 16, 80));
}

/// The two entries carried in this file: they run without `bc-test-data`.
#[test]
fn x448_matches_the_printed_vectors() {
    assert_eq!(check_entry(&printed_base()), 2);
    assert_eq!(check_entry(&printed_auth()), 3);
}

/// The generic DHKEM over X448 by value and through its `_out` forms, which return Nenc and
/// Nsecret.
#[test]
fn the_generic_dhkem_matches_the_printed_vector() {
    let v = printed_base();
    let get = |name: &str| decode_56(&v[name]);
    let shared_secret = hex::decode(&v["shared_secret"]).unwrap();
    let pk_r = X448PublicKey::from_bytes(&get("pkRm")).unwrap();
    let sk_r = X448PrivateKey::from_bytes(&get("skRm")).unwrap();

    let mut enc = [0xFF_u8; POINT_LEN];
    let mut ss = stale_secret();
    let mut rng = FixedSeedRNG::new(get("skEm"));
    assert_eq!(X448DHKEM::encap_rng_out(&pk_r, &mut rng, &mut enc, &mut ss), Ok(POINT_LEN));
    assert_eq!(enc, get("enc"));
    assert_eq!(ss.ref_to_bytes(), shared_secret);

    let mut ss = stale_secret();
    assert_eq!(X448DHKEM::decap_out(&get("enc"), &sk_r, &mut ss), Ok(DHKEM_SS_LEN));
    assert_eq!(ss.ref_to_bytes(), shared_secret);
    assert_eq!(X448DHKEM::decap(&get("enc"), &sk_r).unwrap().ref_to_bytes(), shared_secret);
}

/// The parameters are RFC 9180 Section 7.1, Table 2's row for DHKEM(X448, HKDF-SHA512): kem_id
/// 0x0021, Nsecret 64, Nenc, Npk and Nsk 56.
#[test]
fn the_parameters_are_table_2s() {
    assert_eq!(<X448 as DHKEMParams<56, 56, 56>>::KEM_ID, 0x0021);
    assert_eq!(<DHKEM_X448_HKDF_SHA512 as HpkeKem>::KEM_ID, 0x0021);
    assert_eq!((DHKEM_SS_LEN, POINT_LEN, SCALAR_LEN), (64, 56, 56));
}

#[test]
fn derive_key_pair_rejects_bad_ikm() {
    let ikm = decode_56(&printed_base()["ikmE"]);

    let mac_key = KeyMaterial::<56>::from_bytes_as_type(&ikm, KeyType::MACKey).unwrap();
    match X448DHKEM::derive_key_pair(&mac_key) {
        Err(KEMError::KeyGenError(_)) => { /* good */ }
        _ => panic!("expected KeyGenError for the wrong key type"),
    }

    let mut weak = seed(&ikm);
    weak.set_security_strength(SecurityStrength::_128bit).unwrap();
    match X448DHKEM::derive_key_pair(&weak) {
        Err(KEMError::KeyGenError(_)) => { /* good */ }
        _ => panic!("expected KeyGenError for a 128-bit ikm"),
    }

    // Exactly the algorithm's strength is enough.
    let mut just_right = seed(&ikm);
    just_right.set_security_strength(SecurityStrength::_192bit).unwrap();
    X448DHKEM::derive_key_pair(&just_right).unwrap();
}

/// `encaps` rejects an RNG below 192 bits and accepts one at exactly 192 bits.
#[test]
fn encaps_rng_security_strength() {
    let (pk, _) = keygen(&mut DefaultRNG::default()).unwrap();

    let mut weak = FixedSeedRNG::new([0x5A; 56]);
    weak.set_security_strength(SecurityStrength::_128bit);
    match pk.encaps(&mut weak, ()) {
        Err(KEMError::RNGError(_)) => { /* good */ }
        _ => panic!("expected RNGError for a 128-bit RNG"),
    }

    let mut just_right = FixedSeedRNG::new([0x5A; 56]);
    just_right.set_security_strength(SecurityStrength::_192bit);
    pk.encaps(&mut just_right, ()).unwrap();
}

/// An RNG at full strength whose every request fails.
struct FailingRNG;

impl RNG for FailingRNG {
    fn add_seed_keymaterial(&mut self, _: &dyn KeyMaterialTrait) -> Result<(), RNGError> {
        Ok(())
    }
    fn next_int(&mut self) -> Result<u32, RNGError> {
        Err(RNGError::GenericError("failing RNG"))
    }
    fn next_bytes_out(&mut self, _: &mut [u8]) -> Result<usize, RNGError> {
        Err(RNGError::GenericError("failing RNG"))
    }
    fn fill_keymaterial_out(&mut self, _: &mut dyn KeyMaterialTrait) -> Result<usize, RNGError> {
        Err(RNGError::GenericError("failing RNG"))
    }
    fn security_strength(&self) -> SecurityStrength {
        SecurityStrength::_256bit
    }
}

/// An RNG failure while generating the ephemeral key pair is passed through as the RNG's error.
#[test]
fn encaps_rng_passes_through_rng_failure() {
    let (pk, _) = keygen(&mut DefaultRNG::default()).unwrap();
    match pk.encaps(&mut FailingRNG, ()) {
        Err(KEMError::RNGError(RNGError::GenericError(_))) => { /* good */ }
        other => panic!("expected the RNG's error, got {other:?}"),
    }
}

/// `keygen` with its error mapped, in the shape the KEM test framework takes.
fn keygen_kem() -> Result<(X448PublicKey, X448PrivateKey), KEMError> {
    keygen(&mut DefaultRNG::default()).map_err(|_| KEMError::KeyGenError("X448 keygen failed"))
}

#[test]
fn kem_framework() {
    // DHKEM is randomized. A modified ciphertext is another public key, so decaps succeeds with a
    // different shared secret, which is the behaviour the framework checks for an implicitly
    // rejecting KEM; enc is in kem_context, so flipping any of its bits changes the secret.
    TestFrameworkKEM::new(false, true)
        .test_kem::<(), X448PublicKey, X448PrivateKey, POINT_LEN, DHKEM_SS_LEN>(
            keygen_kem,
            (),
            true,
        );
}

#[test]
fn kem_keys_framework() {
    TestFrameworkKEMKeys::new()
        .test_keys::<X448PublicKey, X448PrivateKey, POINT_LEN, SCALAR_LEN>(keygen_kem);
}

/// The public keys of Wycheproof's `x448_test.json` whose shared secret is all zero (see
/// `ed_x448_tests.rs`): u = 0, 1, p - 1, p and p + 1.
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

/// Low-order public keys give an all-zero X448 output, which RFC 9180 Section 7.1.4 requires
/// to be rejected: "recipients MUST check whether the Diffie-Hellman shared secret is the
/// all-zero value and abort if so". The sender's side rejects it too.
#[test]
fn rejects_low_order_public_key() {
    let (_, sk) = keygen(&mut DefaultRNG::default()).unwrap();

    for u in LOW_ORDER_PUBLIC_KEYS.map(decode_56) {
        match X448PublicKey::from_bytes(&u).unwrap().encaps(&mut HashDRBG_SHA512::new_from_os(), ())
        {
            Err(KEMError::InvalidPublicKey(_)) => { /* good */ }
            other => panic!("encaps: expected InvalidPublicKey for u = {u:02x?}, got {other:?}"),
        }
        match sk.decaps(&u, ()) {
            Err(KEMError::DecapsulationFailed) => { /* good */ }
            other => panic!("decaps: expected DecapsulationFailed for u = {u:02x?}, got {other:?}"),
        }
    }
}

/// The KEM workers called directly, not through the roles' provided one-shots (which zeroize
/// the buffers themselves): each leaves stale buffers zeroized when the key has small order.
#[test]
fn the_kem_workers_leave_stale_buffers_zeroized_on_a_small_order_key() {
    let (_, sk) = keygen(&mut DefaultRNG::default()).unwrap();
    let zero_pk = X448PublicKey::from_bytes(&[0u8; POINT_LEN]).unwrap();

    let encapsulator = zero_pk.create_encapsulator(()).unwrap();
    let mut ct = [0xFFu8; POINT_LEN];
    let mut ss = stale_secret();
    assert!(matches!(
        encapsulator.encaps_out(&mut HashDRBG_SHA512::new_from_os(), &mut ct, &mut ss),
        Err(KEMError::InvalidPublicKey(_))
    ));
    assert_eq!(ct, [0u8; POINT_LEN]);
    assert_eq!(ss.key_type(), KeyType::Zeroized);
    assert_eq!(ss.key_len(), 0);

    let decapsulator = sk.create_decapsulator(()).unwrap();
    let mut ss = stale_secret();
    assert!(matches!(
        decapsulator.decaps_out(&[0u8; POINT_LEN], &mut ss),
        Err(KEMError::DecapsulationFailed)
    ));
    assert_eq!(ss.key_type(), KeyType::Zeroized);
    assert_eq!(ss.key_len(), 0);
}

/// The workers write over stale buffers and report Nenc and Nsecret.
#[test]
fn the_kem_workers_report_the_bytes_they_wrote() {
    let (pk, sk) = keygen(&mut DefaultRNG::default()).unwrap();
    let mut ct = [0xFFu8; POINT_LEN];
    let mut ss = stale_secret();
    let encapsulator = pk.create_encapsulator(()).unwrap();
    assert_eq!(
        encapsulator.encaps_out(&mut HashDRBG_SHA512::new_from_os(), &mut ct, &mut ss),
        Ok(POINT_LEN)
    );
    let mut ss1 = stale_secret();
    assert_eq!(sk.create_decapsulator(()).unwrap().decaps_out(&ct, &mut ss1), Ok(DHKEM_SS_LEN));
    assert!(ss.equals(&ss1));
    assert_eq!(ss.key_len(), DHKEM_SS_LEN);
}

/// The KEM roles name the KEM, not the function under it, and at X448's strength.
#[test]
fn the_kem_workers_name_dhkem() {
    let (pk, sk) = keygen(&mut DefaultRNG::default()).unwrap();
    let encapsulator = pk.create_encapsulator(()).unwrap();
    let decapsulator = sk.create_decapsulator(()).unwrap();
    assert_eq!(encapsulator.alg_name(), "DHKEM(X448, HKDF-SHA512)");
    assert_eq!(decapsulator.alg_name(), "DHKEM(X448, HKDF-SHA512)");
    assert_eq!(DHKEM_X448_HKDF_SHA512::ALG_NAME, "DHKEM(X448, HKDF-SHA512)");
    assert_eq!(DHKEM_X448_HKDF_SHA512::MAX_SECURITY_STRENGTH, X448::MAX_SECURITY_STRENGTH);
    assert_eq!(encapsulator.max_security_strength(), SecurityStrength::_192bit);
    assert_eq!(decapsulator.max_security_strength(), SecurityStrength::_192bit);
}

/// The all-zero key that `keygen_out` writes into is refused by every DHKEM path, role or
/// generic, with the outputs left zeroized.
#[test]
fn an_unfilled_key_is_not_a_dhkem_key() {
    let unfilled = X448PrivateKey::zeroized();
    let zeroized = || KEMError::KeyMaterialError(KeyMaterialError::ActingOnZeroizedKey);
    check_refused_private_key(&unfilled, zeroized);
    let mut dh = Secret::<[u8; POINT_LEN]>::new();
    *dh = [0xFF; POINT_LEN];
    let peer = X448PublicKey::from_bytes(&[9u8; POINT_LEN]).unwrap();
    assert_eq!(
        <X448 as DHKEMParams<56, 56, 56>>::dh_into(&unfilled, &peer, &mut dh),
        Err(KeyAgreementError::KeyMaterialError(KeyMaterialError::ActingOnZeroizedKey))
    );
    assert_eq!(*dh, [0u8; POINT_LEN]);
}

/// Four times the order of the base point (RFC 7748 Section 4.2), computed from the RFC's
/// value by a script: a clamped scalar, so an X448 private key (see `ed_x448_tests.rs`).
const FOUR_TIMES_ORDER: &str = concat!(
    "cc1361ad4a0ae38d543d1637ca09b38540da58bb266d3b11a78f28f3",
    "fdffffffffffffffffffffffffffffffffffffffffffffffffffffff",
);

/// The private key `4 * order` is 0 mod the group order. RFC 9180 Section 7.1.2 has a DHKEM
/// check for that and says no clamped X448 value needs it; this one does, and the DHKEM
/// refuses the key on every path, as a decoding error, with the outputs left zeroized. That
/// holds against a point of the twist too, where X448 itself gives a non-zero output. The
/// agreement role is unaffected.
#[test]
fn the_key_four_times_the_order_is_not_a_dhkem_key() {
    let bytes = decode_56(FOUR_TIMES_ORDER);
    let sk = X448PrivateKey::from_bytes(&bytes).unwrap();
    assert_eq!(sk.pub_key().unwrap().as_bytes(), &[0u8; POINT_LEN]);
    check_refused_private_key(&sk, || KEMError::DecodingError(""));

    let mut six = [0u8; POINT_LEN];
    six[0] = 6;
    let on_twist = X448PublicKey::from_bytes(&six).unwrap();
    assert!(sk.agree(&on_twist, ()).is_ok(), "X448 itself computes with the key");
    let mut dh = Secret::<[u8; POINT_LEN]>::new();
    *dh = [0xFF; POINT_LEN];
    assert!(matches!(
        <X448 as DHKEMParams<56, 56, 56>>::dh_into(&sk, &on_twist, &mut dh),
        Err(KeyAgreementError::DecodingError(_))
    ));
    assert_eq!(*dh, [0u8; POINT_LEN]);
    assert!(matches!(sk.decaps(&six, ()), Err(KEMError::DecodingError(_))));

    // DeriveKeyPair's hook: the bytes are not a DHKEM private key, clamped or as drawn (the
    // two low bits and the top bit are no part of the key), while their neighbour is.
    assert!(<X448 as DHKEMParams<56, 56, 56>>::private_key_from_bytes(&bytes).is_none());
    let mut unclamped = bytes;
    unclamped[0] |= 3;
    unclamped[55] &= 0x7F;
    assert!(<X448 as DHKEMParams<56, 56, 56>>::private_key_from_bytes(&unclamped).is_none());
    let mut neighbour = bytes;
    neighbour[0] ^= 4;
    let key = <X448 as DHKEMParams<56, 56, 56>>::private_key_from_bytes(&neighbour).unwrap();
    assert!(key == X448PrivateKey::from_bytes(&neighbour).unwrap());
    assert_eq!(<X448 as DHKEMParams<56, 56, 56>>::pk(&key), key.pub_key().unwrap());
    assert!(key.create_decapsulator(()).is_ok());

    // Encapsulating to its all-zero public key is refused as any small-order key is.
    assert!(matches!(
        sk.pub_key().unwrap().encaps(&mut HashDRBG_SHA512::new_from_os(), ()),
        Err(KEMError::InvalidPublicKey(_))
    ));
}

/// `sk` is refused as a DHKEM private key with `expected` on the roles, and by the generic
/// DHKEM functions, which take the key without its role, with the outputs left zeroized.
fn check_refused_private_key(sk: &X448PrivateKey, expected: impl Fn() -> KEMError) {
    let same = |e: &KEMError| core::mem::discriminant(e) == core::mem::discriminant(&expected());
    let v = printed_auth();
    let enc = decode_56(&v["enc"]);
    let filled = X448PrivateKey::from_bytes(&decode_56(&v["skRm"])).unwrap();
    let pk_s = X448PublicKey::from_bytes(&decode_56(&v["pkSm"])).unwrap();

    // The roles.
    assert!(same(&sk.create_decapsulator(()).err().unwrap()));
    assert!(same(&sk.decaps(&enc, ()).unwrap_err()));
    let mut ss = stale_secret();
    assert!(same(&sk.auth_decaps_out(&enc, &pk_s, &mut ss).unwrap_err()));
    assert_eq!(ss.key_type(), KeyType::Zeroized);
    let mut enc_out = [0xFFu8; POINT_LEN];
    let mut ss = stale_secret();
    let mut rng = FixedSeedRNG::new([0x5A; 112]);
    assert!(same(
        &filled
            .pub_key()
            .unwrap()
            .auth_encaps_out(&mut rng, sk, &mut enc_out, &mut ss)
            .unwrap_err()
    ));
    assert_eq!(enc_out, [0u8; POINT_LEN]);
    assert_eq!(ss.key_type(), KeyType::Zeroized);

    // The generic functions, through the group's DH.
    let mut ss = stale_secret();
    assert_eq!(X448DHKEM::decap_out(&enc, sk, &mut ss), Err(KEMError::DecapsulationFailed));
    assert_eq!(ss.key_type(), KeyType::Zeroized);
    let mut ss = stale_secret();
    assert_eq!(
        X448DHKEM::auth_decap_out(&enc, sk, &pk_s, &mut ss),
        Err(KEMError::DecapsulationFailed)
    );
    assert_eq!(ss.key_type(), KeyType::Zeroized);
    let mut enc_out = [0xFFu8; POINT_LEN];
    let mut ss = stale_secret();
    let mut rng = FixedSeedRNG::new([0x5A; 112]);
    assert!(matches!(
        X448DHKEM::auth_encap_rng_out(
            &filled.pub_key().unwrap(),
            sk,
            &mut rng,
            &mut enc_out,
            &mut ss
        ),
        Err(KEMError::InvalidPublicKey(_))
    ));
    assert_eq!(enc_out, [0u8; POINT_LEN]);
    assert_eq!(ss.key_type(), KeyType::Zeroized);
}

/// The authenticated forms refuse a small-order sender key and leave the secret zeroized.
#[test]
fn auth_decaps_refuses_a_small_order_sender_key() {
    let v = printed_auth();
    let sk_r = X448PrivateKey::from_bytes(&decode_56(&v["skRm"])).unwrap();
    let small_order = X448PublicKey::from_bytes(&[0u8; POINT_LEN]).unwrap();
    let mut ss = stale_secret();
    assert!(matches!(
        sk_r.auth_decaps_out(&decode_56(&v["enc"]), &small_order, &mut ss),
        Err(KEMError::InvalidPublicKey(_))
    ));
    assert_eq!(ss.key_type(), KeyType::Zeroized);
}
