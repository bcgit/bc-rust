//! HPKE (RFC 9180 Sections 5 and 6) in its four modes.
//!
//! Known answers are the RFC's own vectors: `bc-test-data/crypto/hpke.txt` is the
//! machine-readable set Appendix A cites as `[TestVectors]`. Every entry for `kem_id` 32
//! (X25519), 33 (X448), 16 (P-256) and 18 (P-521), in all four modes, with `kdf_id` 1 and 3 and every
//! `aead_id`, is run from the recipient's side: the setup from `enc` and `skRm` (and `pkSm` in
//! the authenticated modes), then every encryption in order (257 a suite, so the sequence
//! number carries into its second byte) and the exports. That pins the key schedule, the nonces
//! and the export. The sender cannot be run against a vector, its ephemeral key not being
//! injectable; it is checked against the recipient, which the vectors pin.
//!
//! Appendix A.1.1 and A.1.2 are also carried in this file, so that a known answer runs where
//! `bc-test-data` is not checked out. The RFC has no vectors for P-384 or for HKDF-SHA384; those
//! are in `hpke_bc_java_tests.rs`.

use bouncycastle_core::errors::{KEMError, SymmetricCipherError};
use bouncycastle_core::hex;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{PrivateKey, PublicKey};
use bouncycastle_core_test_framework::test_data_loaders::bc_test_data;
use bouncycastle_dhkem::HpkeKem;
use bouncycastle_digest::sha2::{SHA256, SHA384, SHA512};
use bouncycastle_ec::{P256, P384, P521};
use bouncycastle_eccdh::keys::{ECCDHPrivateKey, ECCDHPublicKey};
use bouncycastle_ed::x448::{X448PrivateKey, X448PublicKey};
use bouncycastle_ed::x25519::{X25519PrivateKey, X25519PublicKey};
use bouncycastle_hybrid::hpke::{
    ExportOnly, HpkeAead, HpkeAuthRecipient, HpkeAuthSender, HpkeCipher, HpkeContext, HpkeError,
    HpkeKdf, HpkeParams, HpkeRecipient, HpkeSender, NN, NT, Psk, Recipient, Sender,
};
use bouncycastle_rng::HashDRBG_SHA512;
use bouncycastle_symmetric::aes::{AES128Key, AES256Key};
use bouncycastle_symmetric::chacha20_poly1305_aead::ChaCha20Poly1305Key;
use bouncycastle_symmetric::modes::GCM;
use std::collections::HashMap;

// RFC 9180 Appendix A.1.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, Base mode.
const A_1_1_SK_RM: &str = "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8";
const A_1_1_ENC: &str = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431";
const A_1_1_INFO: &str = "4f6465206f6e2061204772656369616e2055726e";
const A_1_1_AAD_0: &str = "436f756e742d30";
const A_1_1_PT_0: &str = "4265617574792069732074727574682c20747275746820626561757479";
const A_1_1_CT_0: &str =
    "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a";
const A_1_1_AAD_1: &str = "436f756e742d31";
const A_1_1_PT_1: &str = "4265617574792069732074727574682c20747275746820626561757479";
const A_1_1_CT_1: &str =
    "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84";
const A_1_1_EXPORTER_CONTEXT: &str = "54657374436f6e74657874";
const A_1_1_EXPORTED_VALUE: &str =
    "e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931";

// RFC 9180 Appendix A.1.2: the same suite in PSK mode.
const A_1_2_SK_RM: &str = "c5eb01eb457fe6c6f57577c5413b931550a162c71a03ac8d196babbd4e5ce0fd";
const A_1_2_ENC: &str = "0ad0950d9fb9588e59690b74f1237ecdf1d775cd60be2eca57af5a4b0471c91b";
const A_1_2_INFO: &str = "4f6465206f6e2061204772656369616e2055726e";
const A_1_2_PSK: &str = "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82";
const A_1_2_PSK_ID: &str = "456e6e796e20447572696e206172616e204d6f726961";
const A_1_2_AAD_0: &str = "436f756e742d30";
const A_1_2_PT_0: &str = "4265617574792069732074727574682c20747275746820626561757479";
const A_1_2_CT_0: &str =
    "e52c6fed7f758d0cf7145689f21bc1be6ec9ea097fef4e959440012f4feb73fb611b946199e681f4cfc34db8ea";
const A_1_2_AAD_1: &str = "436f756e742d31";
const A_1_2_PT_1: &str = "4265617574792069732074727574682c20747275746820626561757479";
const A_1_2_CT_1: &str =
    "49f3b19b28a9ea9f43e8c71204c00d4a490ee7f61387b6719db765e948123b45b61633ef059ba22cd62437c8ba";
const A_1_2_EXPORTER_CONTEXT: &str = "54657374436f6e74657874";
const A_1_2_EXPORTED_VALUE: &str =
    "8aff52b45a1be3a734bc7a41e20b4e055ad4c4d22104b0c20285a7c4302401cd";

type Aes128Gcm = AES128Key<GCM>;
type Aes256Gcm = AES256Key<GCM>;

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex")
}

/// A pre-shared key as key material: a MAC key, which 32 bytes credit with 256 bits.
fn psk_material(bytes: &[u8]) -> KeyMaterial<64> {
    KeyMaterial::<64>::from_bytes_as_type(bytes, KeyType::MACKey).expect("a PSK of up to 64 bytes")
}

/// One entry of `hpke.txt`: its `name = hex` lines, and its encryptions and exports.
#[derive(Default)]
struct Entry {
    fields: HashMap<String, String>,
    /// `(aad, ct, pt)`, in sequence.
    encryptions: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>,
    /// `(exporter_context, exported_value)`; `L` is the value's length.
    exports: Vec<(Vec<u8>, Vec<u8>)>,
}

/// The entries of `hpke.txt`: each starts at a `count = N` line; the encryptions and the exports
/// are runs of `name = hex` lines closed by `<`, between `...START` and `...STOP`.
fn hpke_vectors() -> Option<Vec<Entry>> {
    let text = bc_test_data("crypto", "hpke.txt")?;
    let mut entries: Vec<Entry> = Vec::new();
    let mut item: HashMap<&str, Vec<u8>> = HashMap::new();
    let mut in_section = false;
    for line in text.lines() {
        match line {
            "encryptionsSTART" | "exportsSTART" => in_section = true,
            "encryptionsSTOP" | "exportsSTOP" => in_section = false,
            "<" => {
                let entry = entries.last_mut().expect("a count line first");
                if let Some(ct) = item.remove("ct") {
                    entry.encryptions.push((item["aad"].clone(), ct, item["pt"].clone()));
                } else {
                    let value = item.remove("exported_value").expect("an export");
                    entry.exports.push((item["exporter_context"].clone(), value));
                }
                item.clear();
            }
            _ => {
                let Some((name, value)) = line.split_once(" = ") else { continue };
                if name == "count" {
                    entries.push(Entry::default());
                }
                if in_section {
                    // `L` is decimal, and is the exported value's length.
                    if name != "L" {
                        item.insert(name, h(value.trim()));
                    }
                } else {
                    let entry = entries.last_mut().expect("a count line first");
                    entry.fields.insert(name.to_string(), value.trim().to_string());
                }
            }
        }
    }
    Some(entries)
}

/// A recipient's context from `setup` exports the entry's values; returns how many.
fn check_exports<H: HpkeKdf, A: HpkeAead>(
    setup: impl Fn() -> HpkeContext<Recipient, H, A>,
    entry: &Entry,
) -> usize {
    let count = &entry.fields["count"];
    let context = setup();
    for (exporter_context, value) in &entry.exports {
        // Every export of the file has L = 32.
        let mut out = KeyMaterial::<32>::new();
        assert_eq!(context.export_out(exporter_context, &mut out), 32);
        assert_eq!(out.ref_to_bytes(), value.as_slice(), "count {count} export");
    }
    entry.exports.len()
}

/// A recipient's context from `setup` opens the entry's ciphertexts, in order, to its
/// plaintexts; returns how many.
fn check_encryptions<H: HpkeKdf, A: HpkeCipher>(
    setup: impl Fn() -> HpkeContext<Recipient, H, A>,
    entry: &Entry,
) -> usize {
    let count = &entry.fields["count"];
    let mut context = setup();
    for (seq, (aad, ct, pt)) in entry.encryptions.iter().enumerate() {
        let mut out = vec![0u8; ct.len()];
        let written = context.open_out(aad, ct, &mut out).unwrap();
        assert_eq!(&out[..written], pt.as_slice(), "count {count} seq {seq}");
    }
    entry.encryptions.len()
}

/// Runs every entry of `kem_id`, in all four modes, through the private key type `SK` and, for
/// the sender's key of the authenticated modes, the public key type `PK`; returns the number of
/// entries, encryptions and exports checked.
fn run_vectors<SK, PK, const N_SK: usize, const N_ENC: usize, const N_SECRET: usize>(
    kem_id: &str,
) -> Option<(usize, usize, usize)>
where
    SK: PrivateKey<N_SK>
        + HpkeRecipient<N_ENC, N_SECRET>
        + HpkeAuthRecipient<N_ENC, N_SECRET, SenderPublicKey = PK>,
    PK: PublicKey<N_ENC>,
{
    let (mut entries, mut encryptions, mut exports) = (0, 0, 0);
    for entry in hpke_vectors()?.iter().filter(|e| e.fields["kem_id"] == kem_id) {
        let get = |name: &str| h(&entry.fields[name]);
        // Table 1: 0 Base, 1 PSK, 2 Auth, 3 AuthPSK.
        let mode = entry.fields["mode"].as_str();
        let sk = SK::from_bytes(&get("skRm")).unwrap();
        let enc: [u8; N_ENC] = get("enc").try_into().unwrap();
        let info = get("info");
        let psk = matches!(mode, "1" | "3").then(|| (psk_material(&get("psk")), get("psk_id")));
        let psk = psk.as_ref().map(|(psk, id)| Psk::new(psk, id).unwrap());
        let pk_s = matches!(mode, "2" | "3").then(|| PK::from_bytes(&get("pkSm")).unwrap());

        // The suite's two type parameters, and whether it encrypts.
        fn params<'p, H: HpkeKdf, A: HpkeAead>(
            info: &'p [u8],
            psk: Option<Psk<'p>>,
        ) -> HpkeParams<'p, H, A> {
            let params = HpkeParams::new(info);
            match psk {
                Some(psk) => params.with_psk(psk),
                None => params,
            }
        }
        macro_rules! setup {
            ($h:ty, $a:ty) => {
                || match &pk_s {
                    None => sk.setup_recipient(&enc, params::<$h, $a>(&info, psk)).unwrap(),
                    Some(pk_s) => {
                        sk.setup_auth_recipient(&enc, pk_s, params::<$h, $a>(&info, psk)).unwrap()
                    }
                }
            };
        }
        macro_rules! cipher_suite {
            ($h:ty, $a:ty) => {{
                encryptions += check_encryptions(setup!($h, $a), entry);
                exports += check_exports(setup!($h, $a), entry);
            }};
        }
        match (entry.fields["kdf_id"].as_str(), entry.fields["aead_id"].as_str()) {
            ("1", "1") => cipher_suite!(SHA256, Aes128Gcm),
            ("1", "2") => cipher_suite!(SHA256, Aes256Gcm),
            ("1", "3") => cipher_suite!(SHA256, ChaCha20Poly1305Key),
            ("3", "1") => cipher_suite!(SHA512, Aes128Gcm),
            ("3", "2") => cipher_suite!(SHA512, Aes256Gcm),
            ("3", "3") => cipher_suite!(SHA512, ChaCha20Poly1305Key),
            ("1", "65535") => exports += check_exports(setup!(SHA256, ExportOnly), entry),
            ("3", "65535") => exports += check_exports(setup!(SHA512, ExportOnly), entry),
            (kdf, aead) => panic!("an unexpected suite in hpke.txt: kdf {kdf}, aead {aead}"),
        }
        entries += 1;
    }
    Some((entries, encryptions, exports))
}

// Each KEM has 32 entries: four modes, two KDFs, four AEADs. Twenty-four of them encrypt, 257
// messages each, and all export three values.
const EXPECTED: (usize, usize, usize) = (32, 24 * 257, 32 * 3);

#[test]
fn rfc_9180_vectors_x25519() {
    match run_vectors::<X25519PrivateKey, X25519PublicKey, 32, 32, 32>("32") {
        Some(counts) => assert_eq!(counts, EXPECTED),
        None => eprintln!("bc-test-data/crypto/hpke.txt not found; skipping"),
    }
}

#[test]
fn rfc_9180_vectors_x448() {
    match run_vectors::<X448PrivateKey, X448PublicKey, 56, 56, 64>("33") {
        Some(counts) => assert_eq!(counts, EXPECTED),
        None => eprintln!("bc-test-data/crypto/hpke.txt not found; skipping"),
    }
}

#[test]
fn rfc_9180_vectors_p256() {
    match run_vectors::<ECCDHPrivateKey<P256>, ECCDHPublicKey<P256>, 32, 65, 32>("16") {
        Some(counts) => assert_eq!(counts, EXPECTED),
        None => eprintln!("bc-test-data/crypto/hpke.txt not found; skipping"),
    }
}

#[test]
fn rfc_9180_vectors_p521() {
    match run_vectors::<ECCDHPrivateKey<P521>, ECCDHPublicKey<P521>, 66, 133, 64>("18") {
        Some(counts) => assert_eq!(counts, EXPECTED),
        None => eprintln!("bc-test-data/crypto/hpke.txt not found; skipping"),
    }
}

/// RFC 9180 Appendix A.1.1, printed in this file: runs without bc-test-data.
#[test]
fn rfc_9180_appendix_a_1_1_base_mode() {
    let sk = X25519PrivateKey::from_bytes(&h(A_1_1_SK_RM)).unwrap();
    let enc: [u8; 32] = h(A_1_1_ENC).try_into().unwrap();
    let info = h(A_1_1_INFO);
    let params = HpkeParams::<SHA256, Aes128Gcm>::new(&info);
    let mut context = sk.setup_recipient(&enc, params).unwrap();

    let mut pt = [0u8; 64];
    let n = context.open_out(&h(A_1_1_AAD_0), &h(A_1_1_CT_0), &mut pt).unwrap();
    assert_eq!(&pt[..n], h(A_1_1_PT_0));
    let n = context.open_out(&h(A_1_1_AAD_1), &h(A_1_1_CT_1), &mut pt).unwrap();
    assert_eq!(&pt[..n], h(A_1_1_PT_1));

    let mut exported = KeyMaterial::<32>::new();
    context.export_out(&h(A_1_1_EXPORTER_CONTEXT), &mut exported);
    assert_eq!(exported.ref_to_bytes(), h(A_1_1_EXPORTED_VALUE));

    // The single-shot Open is a setup and the first message.
    let n = sk.open_out(&enc, params, &h(A_1_1_AAD_0), &h(A_1_1_CT_0), &mut pt).unwrap();
    assert_eq!(&pt[..n], h(A_1_1_PT_0));
    // ReceiveExport is a setup and an export.
    let mut exported = KeyMaterial::<32>::new();
    let n = sk.receive_export_out(&enc, params, &h(A_1_1_EXPORTER_CONTEXT), &mut exported).unwrap();
    assert_eq!(n, 32);
    assert_eq!(exported.ref_to_bytes(), h(A_1_1_EXPORTED_VALUE));
}

/// RFC 9180 Appendix A.1.2, printed in this file: runs without bc-test-data.
#[test]
fn rfc_9180_appendix_a_1_2_psk_mode() {
    let sk = X25519PrivateKey::from_bytes(&h(A_1_2_SK_RM)).unwrap();
    let enc: [u8; 32] = h(A_1_2_ENC).try_into().unwrap();
    let info = h(A_1_2_INFO);
    let (psk, psk_id) = (psk_material(&h(A_1_2_PSK)), h(A_1_2_PSK_ID));
    let params =
        HpkeParams::<SHA256, Aes128Gcm>::new(&info).with_psk(Psk::new(&psk, &psk_id).unwrap());
    let mut context = sk.setup_recipient(&enc, params).unwrap();

    let mut pt = [0u8; 64];
    let n = context.open_out(&h(A_1_2_AAD_0), &h(A_1_2_CT_0), &mut pt).unwrap();
    assert_eq!(&pt[..n], h(A_1_2_PT_0));
    let n = context.open_out(&h(A_1_2_AAD_1), &h(A_1_2_CT_1), &mut pt).unwrap();
    assert_eq!(&pt[..n], h(A_1_2_PT_1));

    let mut exported = KeyMaterial::<32>::new();
    context.export_out(&h(A_1_2_EXPORTER_CONTEXT), &mut exported);
    assert_eq!(exported.ref_to_bytes(), h(A_1_2_EXPORTED_VALUE));

    // Without the PSK the context is another one: the vector's first message does not open.
    let mut base = sk.setup_recipient(&enc, HpkeParams::<SHA256, Aes128Gcm>::new(&info)).unwrap();
    assert_eq!(
        base.open_out(&h(A_1_2_AAD_0), &h(A_1_2_CT_0), &mut pt),
        Err(HpkeError::AEADError(SymmetricCipherError::AEADTagCheckFailed))
    );
}

/// The identifiers of RFC 9180 Section 7, Tables 2, 3 and 5.
#[test]
fn the_suite_identifiers_are_the_rfcs() {
    use bouncycastle_eccdh::dhkem::{
        DHKEM_P256_HKDF_SHA256, DHKEM_P384_HKDF_SHA384, DHKEM_P521_HKDF_SHA512,
    };
    use bouncycastle_ed::x25519::DHKEM_X25519_HKDF_SHA256;
    assert_eq!(DHKEM_P256_HKDF_SHA256::KEM_ID, 0x0010);
    assert_eq!(DHKEM_P384_HKDF_SHA384::KEM_ID, 0x0011);
    assert_eq!(DHKEM_P521_HKDF_SHA512::KEM_ID, 0x0012);
    assert_eq!(DHKEM_X25519_HKDF_SHA256::KEM_ID, 0x0020);
    assert_eq!(SHA256::KDF_ID, 0x0001);
    assert_eq!(SHA384::KDF_ID, 0x0002);
    assert_eq!(SHA512::KDF_ID, 0x0003);
    assert_eq!((Aes128Gcm::AEAD_ID, Aes128Gcm::NK), (0x0001, 16));
    assert_eq!((Aes256Gcm::AEAD_ID, Aes256Gcm::NK), (0x0002, 32));
    assert_eq!((ChaCha20Poly1305Key::AEAD_ID, ChaCha20Poly1305Key::NK), (0x0003, 32));
    assert_eq!((ExportOnly::AEAD_ID, ExportOnly::NK), (0xFFFF, 0));
    assert_eq!((NN, NT), (12, 16));
}

/// A sender and a recipient over one suite: three messages in order, an export on each side,
/// and the single-shot forms.
fn round_trip<PK, SK, H, A, const N_ENC: usize, const N_SECRET: usize>(pk: &PK, sk: &SK)
where
    PK: HpkeSender<N_ENC, N_SECRET>,
    SK: HpkeRecipient<N_ENC, N_SECRET>,
    H: HpkeKdf,
    A: HpkeCipher,
{
    let mut rng = HashDRBG_SHA512::new_from_os();
    let psk = psk_material(&[0x5A; 32]);
    for params in [
        HpkeParams::<H, A>::new(b"round trip"),
        HpkeParams::<H, A>::new(b"round trip").with_psk(Psk::new(&psk, b"id").unwrap()),
    ] {
        let (enc, mut sender) = pk.setup_sender(&mut rng, params).unwrap();
        let mut recipient = sk.setup_recipient(&enc, params).unwrap();
        for (i, pt) in [&b"first"[..], b"", b"the third message"].iter().enumerate() {
            let aad = [i as u8];
            let mut ct = vec![0u8; HpkeContext::<Sender, H, A>::seal_out_len(pt.len())];
            let n = sender.seal_out(&aad, pt, &mut ct).unwrap();
            assert_eq!(n, pt.len() + NT);
            let mut out = vec![0xFFu8; n];
            let n = recipient.open_out(&aad, &ct, &mut out).unwrap();
            assert_eq!(&out[..n], *pt);
        }
        let (mut a, mut b) = (KeyMaterial::<48>::new(), KeyMaterial::<48>::new());
        sender.export_out(b"ctx", &mut a);
        recipient.export_out(b"ctx", &mut b);
        assert_eq!(a.ref_to_bytes(), b.ref_to_bytes());
        assert_eq!(a.key_len(), 48);

        // Seal and Open, and SendExport and ReceiveExport.
        let mut ct = [0u8; 4 + NT];
        let (enc, n) = pk.seal_out(&mut rng, params, b"aad", b"shot", &mut ct).unwrap();
        assert_eq!(n, 4 + NT);
        let mut out = [0u8; 4 + NT];
        let n = sk.open_out(&enc, params, b"aad", &ct, &mut out).unwrap();
        assert_eq!(&out[..n], b"shot");
        let (mut a, mut b) = (KeyMaterial::<32>::new(), KeyMaterial::<32>::new());
        let (enc, n) = pk.send_export_out(&mut rng, params, b"ctx", &mut a).unwrap();
        assert_eq!(n, 32);
        assert_eq!(sk.receive_export_out(&enc, params, b"ctx", &mut b), Ok(32));
        assert_eq!(a.ref_to_bytes(), b.ref_to_bytes());
        assert_eq!(a.key_type(), KeyType::CryptographicRandom);
    }
}

fn x25519_keys() -> (X25519PublicKey, X25519PrivateKey) {
    bouncycastle_ed::x25519::keygen(&mut HashDRBG_SHA512::new_from_os()).unwrap()
}

#[test]
fn round_trips_on_every_kem_kdf_and_aead() {
    let (pk, sk) = x25519_keys();
    round_trip::<_, _, SHA256, Aes128Gcm, 32, 32>(&pk, &sk);
    round_trip::<_, _, SHA384, Aes256Gcm, 32, 32>(&pk, &sk);
    round_trip::<_, _, SHA512, ChaCha20Poly1305Key, 32, 32>(&pk, &sk);

    let mut rng = HashDRBG_SHA512::new_from_os();
    let (pk, sk) = bouncycastle_eccdh::keys::keygen::<P256>(&mut rng).unwrap();
    round_trip::<_, _, SHA256, ChaCha20Poly1305Key, 65, 32>(&pk, &sk);
    let (pk, sk) = bouncycastle_eccdh::keys::keygen::<P384>(&mut rng).unwrap();
    round_trip::<_, _, SHA384, Aes256Gcm, 97, 48>(&pk, &sk);
    let (pk, sk) = bouncycastle_eccdh::keys::keygen::<P521>(&mut rng).unwrap();
    round_trip::<_, _, SHA512, Aes256Gcm, 133, 64>(&pk, &sk);
}

/// A pair of contexts over X25519, HKDF-SHA256 and AES-128-GCM with `info` on each side.
fn contexts(
    sender_info: &[u8],
    recipient_info: &[u8],
) -> (HpkeContext<Sender, SHA256, Aes128Gcm>, HpkeContext<Recipient, SHA256, Aes128Gcm>) {
    let (pk, sk) = x25519_keys();
    let mut rng = HashDRBG_SHA512::new_from_os();
    let (enc, sender) = pk.setup_sender(&mut rng, HpkeParams::new(sender_info)).unwrap();
    (sender, sk.setup_recipient(&enc, HpkeParams::new(recipient_info)).unwrap())
}

const TAG_FAILED: HpkeError = HpkeError::AEADError(SymmetricCipherError::AEADTagCheckFailed);

#[test]
fn a_failed_open_leaves_zeros_and_does_not_use_up_a_position() {
    let (mut sender, mut recipient) = contexts(b"info", b"info");
    let mut ct = [0u8; 5 + NT];
    sender.seal_out(b"aad", b"hello", &mut ct).unwrap();

    // A flipped ciphertext bit, a flipped tag bit and another aad are each refused, and the
    // plaintext buffer is left zeroized.
    for (bit, aad) in [(0, &b"aad"[..]), (ct.len() - 1, b"aad"), (usize::MAX, b"AAD")] {
        let mut bad = ct;
        if let Some(byte) = bad.get_mut(bit) {
            *byte ^= 1;
        }
        let mut pt = [0xFFu8; 5 + NT];
        assert_eq!(recipient.open_out(aad, &bad, &mut pt), Err(TAG_FAILED));
        assert_eq!(pt, [0u8; 5 + NT]);
    }
    // The position was not used: the message itself still opens as the first.
    let mut pt = [0u8; 5 + NT];
    assert_eq!(recipient.open_out(b"aad", &ct, &mut pt), Ok(5));
    assert_eq!(&pt[..5], b"hello");
    // And now it is: the same ciphertext is not the second message.
    assert_eq!(recipient.open_out(b"aad", &ct, &mut pt), Err(TAG_FAILED));
}

#[test]
fn messages_open_only_in_the_order_they_were_sealed() {
    let (mut sender, mut recipient) = contexts(b"", b"");
    let (mut ct0, mut ct1) = ([0u8; 1 + NT], [0u8; 1 + NT]);
    sender.seal_out(b"", b"0", &mut ct0).unwrap();
    sender.seal_out(b"", b"1", &mut ct1).unwrap();
    // The same plaintext at two positions is two ciphertexts.
    let mut again = [0u8; 1 + NT];
    sender.seal_out(b"", b"0", &mut again).unwrap();
    assert_ne!(ct0, again);

    let mut pt = [0u8; 1 + NT];
    assert_eq!(recipient.open_out(b"", &ct1, &mut pt), Err(TAG_FAILED));
    assert_eq!(recipient.open_out(b"", &ct0, &mut pt), Ok(1));
    assert_eq!(recipient.open_out(b"", &ct1, &mut pt), Ok(1));
    assert_eq!(pt[0], b'1');
}

#[test]
fn a_failed_seal_leaves_zeros_and_does_not_use_up_a_position() {
    let (mut sender, mut recipient) = contexts(b"", b"");
    let mut short = [0xFFu8; 4];
    assert!(matches!(
        sender.seal_out(b"", b"hello", &mut short),
        Err(HpkeError::AEADError(SymmetricCipherError::OutputBufferTooSmall(_)))
    ));
    assert_eq!(short, [0u8; 4]);
    let mut ct = [0u8; 5 + NT];
    sender.seal_out(b"", b"hello", &mut ct).unwrap();
    let mut pt = [0u8; 5 + NT];
    assert_eq!(recipient.open_out(b"", &ct, &mut pt), Ok(5));
}

/// `open_out` needs `open_out_len` bytes and no more; a shorter buffer and a ciphertext shorter
/// than a tag are errors that leave zeros and do not use up a position.
#[test]
fn the_plaintext_buffer_is_the_ciphertext_less_the_tag() {
    type Ctx<Dir> = HpkeContext<Dir, SHA256, Aes128Gcm>;
    assert_eq!(Ctx::<Recipient>::open_out_len(5 + NT), 5);
    assert_eq!(Ctx::<Recipient>::open_out_len(NT), 0);
    assert_eq!(Ctx::<Recipient>::open_out_len(NT - 1), 0);
    assert_eq!(Ctx::<Sender>::seal_out_len(5), 5 + NT);

    let (mut sender, mut recipient) = contexts(b"", b"");
    let mut ct = [0u8; 5 + NT];
    sender.seal_out(b"", b"hello", &mut ct).unwrap();

    let mut short = [0xFFu8; 4];
    assert!(matches!(
        recipient.open_out(b"", &ct, &mut short),
        Err(HpkeError::AEADError(SymmetricCipherError::OutputBufferTooSmall(_)))
    ));
    assert_eq!(short, [0u8; 4]);
    let mut pt = [0xFFu8; 5];
    assert!(recipient.open_out(b"", &ct[..NT - 1], &mut pt).is_err());
    assert_eq!(pt, [0u8; 5]);

    // Neither failure used the position: the message opens, into exactly open_out_len bytes.
    let mut pt = [0xFFu8; 5];
    assert_eq!(recipient.open_out(b"", &ct, &mut pt), Ok(5));
    assert_eq!(&pt, b"hello");
}

/// The longest export Section 5.3 allows, 255*Nh bytes, builds and runs.
#[test]
fn the_longest_export_is_255_blocks() {
    let (sender, recipient) = contexts(b"", b"");
    let (mut a, mut b) = (KeyMaterial::<8160>::new(), KeyMaterial::<8160>::new());
    assert_eq!(sender.export_out(b"long", &mut a), 8160);
    assert_eq!(recipient.export_out(b"long", &mut b), 8160);
    assert_eq!(a.ref_to_bytes(), b.ref_to_bytes());
    assert_ne!(&a.ref_to_bytes()[..32], &a.ref_to_bytes()[32..64]);
}

#[test]
fn the_info_and_the_psk_are_bound_into_the_context() {
    // Another info on the recipient's side.
    let (mut sender, mut recipient) = contexts(b"info", b"other");
    let mut ct = [0u8; NT];
    sender.seal_out(b"", b"", &mut ct).unwrap();
    assert_eq!(recipient.open_out(b"", &ct, &mut [0u8; NT]), Err(TAG_FAILED));
    let (mut a, mut b) = (KeyMaterial::<32>::new(), KeyMaterial::<32>::new());
    sender.export_out(b"", &mut a);
    recipient.export_out(b"", &mut b);
    assert_ne!(a.ref_to_bytes(), b.ref_to_bytes());

    // Another PSK, and another PSK identifier.
    let (pk, sk) = x25519_keys();
    let mut rng = HashDRBG_SHA512::new_from_os();
    let (psk, other) = (psk_material(&[1; 32]), psk_material(&[2; 32]));
    let params =
        |psk, id| HpkeParams::<SHA256, Aes128Gcm>::new(b"").with_psk(Psk::new(psk, id).unwrap());
    let (enc, mut sender) = pk.setup_sender(&mut rng, params(&psk, b"id")).unwrap();
    sender.seal_out(b"", b"", &mut ct).unwrap();
    for wrong in [params(&other, b"id"), params(&psk, b"ID")] {
        let mut recipient = sk.setup_recipient(&enc, wrong).unwrap();
        assert_eq!(recipient.open_out(b"", &ct, &mut [0u8; NT]), Err(TAG_FAILED));
    }
    let mut recipient = sk.setup_recipient(&enc, params(&psk, b"id")).unwrap();
    assert_eq!(recipient.open_out(b"", &ct, &mut [0u8; NT]), Ok(0));
}

#[test]
fn a_psk_needs_an_identifier_and_32_bytes_of_entropy() {
    let good = psk_material(&[7; 32]);
    assert!(Psk::new(&good, b"id").is_ok());
    assert!(matches!(Psk::new(&good, b""), Err(HpkeError::InvalidPsk(_))));
    // 31 bytes.
    let short = psk_material(&[7; 31]);
    assert!(matches!(Psk::new(&short, b"id"), Err(HpkeError::InvalidPsk(_))));
    // 32 bytes of unknown provenance carry no strength.
    let unknown = KeyMaterial::<64>::from_bytes(&[7; 32]).unwrap();
    assert_eq!(unknown.security_strength(), SecurityStrength::None);
    assert!(matches!(Psk::new(&unknown, b"id"), Err(HpkeError::InvalidPsk(_))));
    // 32 bytes credited with less than 256 bits.
    let mut weak = psk_material(&[7; 32]);
    weak.set_security_strength(SecurityStrength::_128bit).unwrap();
    assert!(matches!(Psk::new(&weak, b"id"), Err(HpkeError::InvalidPsk(_))));
}

#[test]
fn exports_depend_on_the_context_string_and_not_on_the_sequence() {
    let (mut sender, recipient) = contexts(b"", b"");
    let export = |context: &HpkeContext<_, _, _>, exporter_context: &[u8]| {
        let mut out = KeyMaterial::<32>::new();
        assert_eq!(HpkeContext::export_out(context, exporter_context, &mut out), 32);
        out.ref_to_bytes().to_vec()
    };
    let before = export(&sender, b"a");
    assert_ne!(before, export(&sender, b"b"));
    assert_ne!(before, [0u8; 32]);
    sender.seal_out(b"", b"", &mut [0u8; NT]).unwrap();
    assert_eq!(before, export(&sender, b"a"));
    let mut out = KeyMaterial::<32>::new();
    recipient.export_out(b"a", &mut out);
    assert_eq!(before, out.ref_to_bytes());

    // A longer export is not an extension of a shorter one: L is an input of LabeledExpand.
    let mut long = KeyMaterial::<64>::new();
    assert_eq!(sender.export_out(b"a", &mut long), 64);
    assert_ne!(&long.ref_to_bytes()[..32], before.as_slice());
    // A stale buffer is replaced, and L = 0 is the empty secret.
    let mut stale = KeyMaterial::<32>::from_bytes(&[9; 32]).unwrap();
    sender.export_out(b"a", &mut stale);
    assert_eq!(stale.ref_to_bytes(), before.as_slice());
    assert_eq!(sender.export_out(b"a", &mut KeyMaterial::<0>::new()), 0);
}

/// An exported secret is a full-entropy key at the lesser of what its length carries and the
/// suite's strength, which is the KEM's capped by the KDF's.
#[test]
fn an_exported_secret_carries_the_suites_strength() {
    fn strength<PK, H, const L: usize, const N_ENC: usize, const N_SECRET: usize>(
        pk: &PK,
    ) -> SecurityStrength
    where
        PK: HpkeSender<N_ENC, N_SECRET>,
        H: HpkeKdf,
    {
        let mut rng = HashDRBG_SHA512::new_from_os();
        let mut out = KeyMaterial::<L>::new();
        pk.send_export_out(&mut rng, HpkeParams::<H, ExportOnly>::new(b""), b"", &mut out).unwrap();
        assert_eq!(out.key_type(), KeyType::CryptographicRandom);
        out.security_strength()
    }
    let (x25519, _) = x25519_keys();
    let mut rng = HashDRBG_SHA512::new_from_os();
    let (p521, _) = bouncycastle_eccdh::keys::keygen::<P521>(&mut rng).unwrap();

    // X25519 is 128 bits whatever the KDF.
    assert_eq!(strength::<_, SHA256, 32, 32, 32>(&x25519), SecurityStrength::_128bit);
    assert_eq!(strength::<_, SHA512, 64, 32, 32>(&x25519), SecurityStrength::_128bit);
    // P-521 is 256 bits, under HKDF-SHA512; HMAC-SHA256 caps it at 128.
    assert_eq!(strength::<_, SHA512, 32, 133, 64>(&p521), SecurityStrength::_256bit);
    assert_eq!(strength::<_, SHA256, 32, 133, 64>(&p521), SecurityStrength::_128bit);
    // A short secret carries what its length does.
    let sixteen = KeyMaterial::<16>::from_bytes_as_type(&[1; 16], KeyType::CryptographicRandom);
    assert_eq!(strength::<_, SHA512, 16, 133, 64>(&p521), sixteen.unwrap().security_strength());
}

#[test]
fn the_kems_errors_are_reported_as_the_kems() {
    // The all-zero X25519 public key is a point of small order.
    let small_order = X25519PublicKey::from_bytes(&[0u8; 32]).unwrap();
    let mut rng = HashDRBG_SHA512::new_from_os();
    let params = HpkeParams::<SHA256, Aes128Gcm>::new(b"");
    assert!(matches!(
        small_order.setup_sender(&mut rng, params),
        Err(HpkeError::KEMError(KEMError::InvalidPublicKey(_)))
    ));
    // The single-shot forms leave their output zeroized.
    let mut ct = [0xFFu8; NT];
    assert!(small_order.seal_out(&mut rng, params, b"", b"", &mut ct).is_err());
    assert_eq!(ct, [0u8; NT]);
    let mut out = KeyMaterial::<32>::from_bytes(&[9; 32]).unwrap();
    assert!(small_order.send_export_out(&mut rng, params, b"", &mut out).is_err());
    assert_eq!(out.key_type(), KeyType::Zeroized);

    // An enc that is not a point of P-256.
    let (_, sk) = bouncycastle_eccdh::keys::keygen::<P256>(&mut rng).unwrap();
    let enc = [0x04u8; 65];
    assert!(matches!(
        sk.setup_recipient(&enc, params),
        Err(HpkeError::KEMError(KEMError::DecapsulationFailed))
    ));
    let mut pt = [0xFFu8; NT];
    assert!(sk.open_out(&enc, params, b"", &[0u8; NT], &mut pt).is_err());
    assert_eq!(pt, [0u8; NT]);
    let mut out = KeyMaterial::<32>::from_bytes(&[9; 32]).unwrap();
    assert!(sk.receive_export_out(&enc, params, b"", &mut out).is_err());
    assert_eq!(out.key_type(), KeyType::Zeroized);
}

/// The authenticated modes over one suite: a sender with its own key pair, three messages, an
/// export, the single-shot forms, and what another sender key does.
fn auth_round_trip<PK, SK, H, A, const N_ENC: usize, const N_SECRET: usize>(
    (pk_r, sk_r): &(PK, SK),
    (pk_s, sk_s): &(PK, SK),
    (pk_other, _): &(PK, SK),
) where
    PK: HpkeSender<N_ENC, N_SECRET> + HpkeAuthSender<N_ENC, N_SECRET, SenderPrivateKey = SK>,
    SK: HpkeRecipient<N_ENC, N_SECRET> + HpkeAuthRecipient<N_ENC, N_SECRET, SenderPublicKey = PK>,
    H: HpkeKdf,
    A: HpkeCipher,
{
    let mut rng = HashDRBG_SHA512::new_from_os();
    let psk = psk_material(&[0x5A; 32]);
    for params in [
        HpkeParams::<H, A>::new(b"auth"),
        HpkeParams::<H, A>::new(b"auth").with_psk(Psk::new(&psk, b"id").unwrap()),
    ] {
        let (enc, mut sender) = pk_r.setup_auth_sender(&mut rng, sk_s, params).unwrap();
        let mut recipient = sk_r.setup_auth_recipient(&enc, pk_s, params).unwrap();
        let mut first = [0u8; 5 + NT];
        for (i, pt) in [&b"first"[..], b"", b"the third message"].iter().enumerate() {
            let mut ct = vec![0u8; pt.len() + NT];
            let n = sender.seal_out(&[i as u8], pt, &mut ct).unwrap();
            if i == 0 {
                first.copy_from_slice(&ct);
            }
            let mut out = vec![0xFFu8; n];
            let n = recipient.open_out(&[i as u8], &ct, &mut out).unwrap();
            assert_eq!(&out[..n], *pt);
        }
        let (mut a, mut b) = (KeyMaterial::<32>::new(), KeyMaterial::<32>::new());
        sender.export_out(b"ctx", &mut a);
        recipient.export_out(b"ctx", &mut b);
        assert_eq!(a.ref_to_bytes(), b.ref_to_bytes());

        // The sender's key is bound in: with another sender's public key, or with none (the
        // unauthenticated mode over the same enc), the first message does not open.
        let mut out = [0xFFu8; 5 + NT];
        let mut wrong = sk_r.setup_auth_recipient(&enc, pk_other, params).unwrap();
        assert_eq!(wrong.open_out(&[0], &first, &mut out), Err(TAG_FAILED));
        let mut unauthenticated = sk_r.setup_recipient(&enc, params).unwrap();
        assert_eq!(unauthenticated.open_out(&[0], &first, &mut out), Err(TAG_FAILED));

        // SealAuth and OpenAuth, and SendExportAuth and ReceiveExportAuth.
        let mut ct = [0u8; 4 + NT];
        let (enc, n) =
            pk_r.auth_seal_out(&mut rng, sk_s, params, b"aad", b"shot", &mut ct).unwrap();
        assert_eq!(n, 4 + NT);
        let mut out = [0u8; 4 + NT];
        assert_eq!(sk_r.auth_open_out(&enc, pk_s, params, b"aad", &ct, &mut out), Ok(4));
        assert_eq!(&out[..4], b"shot");
        assert_eq!(
            sk_r.auth_open_out(&enc, pk_other, params, b"aad", &ct, &mut out),
            Err(TAG_FAILED)
        );
        assert_eq!(out, [0u8; 4 + NT]);
        let (mut a, mut b) = (KeyMaterial::<32>::new(), KeyMaterial::<32>::new());
        let (enc, n) = pk_r.auth_send_export_out(&mut rng, sk_s, params, b"ctx", &mut a).unwrap();
        assert_eq!(n, 32);
        assert_eq!(sk_r.auth_receive_export_out(&enc, pk_s, params, b"ctx", &mut b), Ok(32));
        assert_eq!(a.ref_to_bytes(), b.ref_to_bytes());
        assert_eq!(sk_r.auth_receive_export_out(&enc, pk_other, params, b"ctx", &mut b), Ok(32));
        assert_ne!(a.ref_to_bytes(), b.ref_to_bytes());
    }
}

#[test]
fn the_authenticated_modes_round_trip_and_bind_the_senders_key() {
    let keys = [x25519_keys(), x25519_keys(), x25519_keys()];
    auth_round_trip::<_, _, SHA256, Aes128Gcm, 32, 32>(&keys[0], &keys[1], &keys[2]);
    auth_round_trip::<_, _, SHA512, ChaCha20Poly1305Key, 32, 32>(&keys[0], &keys[1], &keys[2]);

    let mut rng = HashDRBG_SHA512::new_from_os();
    let mut p256 = || bouncycastle_eccdh::keys::keygen::<P256>(&mut rng).unwrap();
    let keys = [p256(), p256(), p256()];
    auth_round_trip::<_, _, SHA256, Aes128Gcm, 65, 32>(&keys[0], &keys[1], &keys[2]);
    let mut rng = HashDRBG_SHA512::new_from_os();
    let mut p384 = || bouncycastle_eccdh::keys::keygen::<P384>(&mut rng).unwrap();
    let keys = [p384(), p384(), p384()];
    auth_round_trip::<_, _, SHA384, Aes256Gcm, 97, 48>(&keys[0], &keys[1], &keys[2]);
    let mut rng = HashDRBG_SHA512::new_from_os();
    let mut p521 = || bouncycastle_eccdh::keys::keygen::<P521>(&mut rng).unwrap();
    let keys = [p521(), p521(), p521()];
    auth_round_trip::<_, _, SHA512, Aes256Gcm, 133, 64>(&keys[0], &keys[1], &keys[2]);
}

#[test]
fn the_authenticated_kems_errors_are_reported_as_the_kems() {
    let (pk_r, sk_r) = x25519_keys();
    let (pk_s, sk_s) = x25519_keys();
    let mut rng = HashDRBG_SHA512::new_from_os();
    let params = HpkeParams::<SHA256, Aes128Gcm>::new(b"");
    let small_order = X25519PublicKey::from_bytes(&[0u8; 32]).unwrap();

    // The recipient's key refused by the sender, with the single-shot outputs left zeroized.
    assert!(matches!(
        small_order.setup_auth_sender(&mut rng, &sk_s, params),
        Err(HpkeError::KEMError(KEMError::InvalidPublicKey(_)))
    ));
    let mut ct = [0xFFu8; NT];
    assert!(small_order.auth_seal_out(&mut rng, &sk_s, params, b"", b"", &mut ct).is_err());
    assert_eq!(ct, [0u8; NT]);
    let mut out = KeyMaterial::<32>::from_bytes(&[9; 32]).unwrap();
    assert!(small_order.auth_send_export_out(&mut rng, &sk_s, params, b"", &mut out).is_err());
    assert_eq!(out.key_type(), KeyType::Zeroized);

    // The sender's key refused by the recipient (RFC 9180 Section 7.1.4: "in authenticated
    // modes, the recipient MUST validate the sender's static public key pkS").
    let (enc, _) = pk_r.setup_auth_sender(&mut rng, &sk_s, params).unwrap();
    assert!(matches!(
        sk_r.setup_auth_recipient(&enc, &small_order, params),
        Err(HpkeError::KEMError(KEMError::InvalidPublicKey(_)))
    ));
    let mut pt = [0xFFu8; NT];
    assert!(sk_r.auth_open_out(&enc, &small_order, params, b"", &[0u8; NT], &mut pt).is_err());
    assert_eq!(pt, [0u8; NT]);
    let mut out = KeyMaterial::<32>::from_bytes(&[9; 32]).unwrap();
    assert!(sk_r.auth_receive_export_out(&enc, &small_order, params, b"", &mut out).is_err());
    assert_eq!(out.key_type(), KeyType::Zeroized);
    // And an enc the KEM refuses.
    assert!(matches!(
        sk_r.setup_auth_recipient(&[0u8; 32], &pk_s, params),
        Err(HpkeError::KEMError(KEMError::DecapsulationFailed))
    ));
}
