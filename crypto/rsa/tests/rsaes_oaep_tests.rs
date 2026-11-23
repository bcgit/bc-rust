//! RSAES-OAEP (RFC 8017 §7.1; SP 800-56B Rev. 2 §7.2.2 and §9.2.3) on the key-establishment
//! keys, as a KEM and as transport of a caller's key.
//!
//! Known answers are Wycheproof's `rsa_oaep_*_test.json` files, which are decryption vectors:
//! a private key, and for each case a ciphertext, a label and either the message or the verdict
//! that it does not decrypt (`InvalidOaepPadding`, `InvalidCiphertext`). Every group at a
//! modulus size this crate has a private key for (2048, 3072, 4096 and 8192 bits) is run, for
//! every pairing of label hash and MGF1 hash, SHA-1 included; `rsa_oaep_misc_test.json` also
//! has groups at 1024, 1536 and other sizes, which are skipped and counted. The messages are
//! recovered through the key-transport role, which takes a message of any length.
//!
//! Encryption is randomized and RFC 8017 prints no vectors, so the encrypt side is checked by
//! round trip against the decrypt side, which the vectors pin.

use bouncycastle_core::errors::{KEMError, KeyTransportError, RNGError};
use bouncycastle_core::hazmat::FixedSeedRNG;
use bouncycastle_core::hex::decode as hex_decode;
use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::key_transport_key::{KeyTransportDecryptingKey, KeyTransportEncryptingKey};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, PrivateKey, RNG};
use bouncycastle_core_test_framework::kem::TestFrameworkKEM;
use bouncycastle_core_test_framework::key_transport::TestFrameworkKeyTransport;
use bouncycastle_core_test_framework::test_data_loaders::wycheproof_json;
use bouncycastle_digest::sha1::SHA1;
use bouncycastle_digest::sha2::{SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256};
use bouncycastle_rng::HashDRBG_SHA512;
use bouncycastle_rsa::rsaes_oaep::{OaepHash, OaepParams, RSAES_OAEP};
use bouncycastle_rsa::rsasve::{RSASVE, RsaKEMPrivateKey, RsaKEMPublicKey};
use bouncycastle_rsa::size::{RsaSigningSize, RsaSize};
use bouncycastle_rsa::{RSA2048, RSA3072, RSA4096, RSA8192};
use serde_json::Value;
use std::sync::OnceLock;

/// The RSA-2048 key of Wycheproof's `rsa_oaep_2048_sha256_mgf1sha256_test.json`, as
/// `p || q || dP || dQ || qInv || e`, hex: printed here so that known answers run where
/// Wycheproof is not checked out.
const KAT_SK_HEX: &str = concat!(
    "dc431050f782e894fb5248247d98cb7d58b8d1e24f3b55d041c56e4de086b0d5",
    "bb028bda42eeb5d234d5681e5809d415e6a289ad4cfbf78f978f6c35814f50ee",
    "bff1c5b80a69f788e81e6bab5ddaa78369d659d143ec6f17e79813a575cfad9c",
    "569156b90113e2e9110ad9e7b48a1c9348a6e653321191290ea36cfb3a5b18f1",
    "bd1a81e7977f9898122273ae3222b598ea5fb19eb4eabc38308a5e32196603b2",
    "e500ffb79f5b886816611debc472fac45544070beb057c941378a6868af3b7a0",
    "3d3f9880ec47d5e089b94fbde542aba9ae8d72c57088d7abf5b131f39098f7bc",
    "160f90536abc9492fd4e06f3ed7299d4b97bb03677207d95669f140cfbc20f25",
    "a94b528b28f291599121d91952ffd1c7f21d7c1479d99d478885fb161870ee12",
    "18bf08472612dbe5497e8d9c650688e09c786961ae3e2c354dc48ae34514759c",
    "4c23c4588488961dc06b414e61c0e1e7fbbd2923d31532fe289f96da220711e5",
    "8c14019808e00414276933bb07e4efb9b4a9b37656917205209f33f09515d7c1",
    "3af0e72a933aef09ff2503df78bafed531c02ff1a2bc437c540cdcbd4ad35435",
    "cf511763596543480629b114ca7f780ff7efa32ea0cb6e000d6d9ea1f2ef71fd",
    "9cf9948422a165557e37e755edfe70d90b920502eb478bc98a63f788ce3a0f85",
    "6d6ede7251a383bfa8fa480a81a925af7b3cc538c4bab8c9f7597ffb68011d8d",
    "2640fbfbcfefb163ee7a87b6483a66ee41f956d90fa8a7939bfc042ee0924b1b",
    "7993d0445f758d51933e85179c0320b0c968b48a91c38b5be923e1097c0c562f",
    "88d42294b6a2759bafa5428a74f1270874e45f6fcc60f21602de5eccd143cf31",
    "241f5921b5ad3983fb54ef17be3b285367e50c999c67247b552fe4bfce945f7b",
    "0000000000010001",
);
/// Its public key, `n || e`.
#[allow(dead_code)]
const KAT_PK_HEX: &str = concat!(
    "a2b451a07d0aa5f96e455671513550514a8a5b462ebef717094fa1fee82224e6",
    "37f9746d3f7cafd31878d80325b6ef5a1700f65903b469429e89d6eac8845097",
    "b5ab393189db92512ed8a7711a1253facd20f79c15e8247f3d3e42e46e48c98e",
    "254a2fe9765313a03eff8f17e1a029397a1fa26a8dce26f490ed81299615d981",
    "4c22da610428e09c7d9658594266f5c021d0fceca08d945a12be82de4d1ece6b",
    "4c03145b5d3495d4ed5411eb878daf05fd7afc3e09ada0f1126422f590975a19",
    "69816f48698bcbba1b4d9cae79d460d8f9f85e7975005d9bc22c4e5ac0f7c1a4",
    "5d12569a62807d3b9a02e5a530e773066f453d1f5b4c2e9cf7820283f742b9d5",
    "0000000000010001",
);
/// tcId 2 of that file: a ciphertext of `MSG_HEX` under the empty label.
const CT_HEX: &str = concat!(
    "207180c340658b5154ae45d2e4e7326a0997c683a26b595e536a29333c4b6614",
    "9af85e029d5419a39e3a147b221516ffd86b6b4b66c3e0c4c49fe8c57a2f5c37",
    "b8704b9b592b80db9cd788a4ed51ab4f0a1cbed63bd18d1f06a22f225866b0c2",
    "c417cb23473b7ba4250b1353bd2e5b4f0f937cd2efe5fa38db3c295f7748b970",
    "088657db4aa9a76e1ee6fbff166ec1861d00d085326c7384bdd1bc2f400d4f74",
    "dbdfadaf3fdc46073e668573e02030b9eb5af58eb540c66677a771194479ec00",
    "98d858a2ea45d0ba1e6b32440dfbac745000554d51a17684ca964b02a74d479f",
    "1d432ef763ef4059715a4348cfe36a215359712f25b6977903be4adb92febbf6",
);
const MSG_HEX: &str = "0000000000000000000000000000000000000000";
/// tcId 8: a ciphertext of `LABELLED_MSG_HEX` under `LABEL_HEX`.
const LABELLED_CT_HEX: &str = concat!(
    "6583e2f176aa7e7f655d2c53497349c156c8851fb23325589e85fb83bfa85734",
    "6caba222cdaa3234e71564154298c24dbb85e18822a1d5e7faa47863a64d7687",
    "4a3cbc70f4d9f137426a344c473fac1dd7008a9973765e9f66c5b492535a647c",
    "273c4f78ceb5aa7ba963a2142f2ce4a81f804c002b9b2eabb3c75e80a3c6ceaf",
    "e5384a544c672a5d28d32bb87115f43eb79775fd9b3f4a2f6e6a89368bdd95ef",
    "1d014877b60afdb1234acd57653a65459f01b2fbe381f22a739504b4897a7e6c",
    "33b6349b276db6083abad9c169405859b800c812237634b503de6ada43013c1d",
    "86697a135be78a9784576d796d62aa7819e2ea0e2d902ffdd9cfdd1ae66212ee",
);
const LABELLED_MSG_HEX: &str = "313233343030";
const LABEL_HEX: &str = "0000000000000000";
/// tcId 12: "first byte of l_hash modified".
const INVALID_CT_HEX: &str = concat!(
    "287d7108a1c6e7a18acb0045b20c57cdf2ac03456b44942764a7a9e9fdf3db48",
    "1d7e202e4c8d733b56b9c1e93d71e791af8325c9363df789b252a5ed0eddc79e",
    "76fa41c2cb0a35618398217a390a5e6d99eed905d5554d19c1cf4e30bdf1c2fc",
    "c5148b641d71b3f1977b63d232648ddd935ec9499a53ac2fbcac55f462e91065",
    "adaa018a39c453ba759bd68b454074153421e2ce75cf149f748b5b84758df8a4",
    "23d1c50c880af863f2a6df3cd465ca36aa2152b5771f3d507f4a4dd9f8006d80",
    "eca23537092287976f218a90df1e16d889fe31e79f7309f3224f613e9b52479f",
    "e73b7aad915319a3b62a5936649f7d015d7b09f7fa9f454f78a7c3dd4bf791e0",
);

/// The printed Wycheproof cases: a message under the empty label, one under a label, and a
/// ciphertext whose lHash was damaged.
#[test]
fn printed_known_answers() {
    let sk = RsaKEMPrivateKey::<RSA2048>::from_bytes(&hex_decode(KAT_SK_HEX).unwrap()).unwrap();
    let ct = |hex: &str| -> [u8; 256] { hex_decode(hex).unwrap().try_into().unwrap() };
    let mut key = KeyMaterial::<64>::new();

    let msg = hex_decode(MSG_HEX).unwrap();
    assert_eq!(
        sk.recover_out(&ct(CT_HEX), OaepParams::<SHA256>::new(b""), &mut key),
        Ok(msg.len())
    );
    assert_eq!(key.ref_to_bytes(), msg.as_slice());
    // tcId 2's message is twenty zero bytes: a value, typed as the zeros it is.
    assert_eq!(key.key_type(), KeyType::Zeroized);

    let (msg, label) = (hex_decode(LABELLED_MSG_HEX).unwrap(), hex_decode(LABEL_HEX).unwrap());
    let labelled = OaepParams::<SHA256>::new(&label);
    assert_eq!(sk.recover_out(&ct(LABELLED_CT_HEX), labelled, &mut key), Ok(msg.len()));
    assert_eq!(key.ref_to_bytes(), msg.as_slice());
    assert_eq!(key.key_type(), KeyType::CryptographicRandom);
    assert_eq!(key.security_strength(), SecurityStrength::None, "six bytes carry no strength");
    assert_eq!(
        sk.recover_out(&ct(LABELLED_CT_HEX), OaepParams::<SHA256>::new(b""), &mut key),
        Err(KeyTransportError::DecryptionFailed)
    );

    assert_eq!(
        sk.recover_out(&ct(INVALID_CT_HEX), OaepParams::<SHA256>::new(b""), &mut key),
        Err(KeyTransportError::DecryptionFailed)
    );
    assert_eq!(key.key_type(), KeyType::Zeroized);
}

/// `(valid recovered, invalid refused, skipped)`.
type Counts = (usize, usize, usize);

/// A big-endian hex integer as exactly `len` bytes: Wycheproof writes some with a leading zero
/// byte and some without their leading zeros.
fn be_bytes(hex: &str, len: usize) -> Vec<u8> {
    let bytes = hex_decode(hex).expect("valid hex");
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    let significant = &bytes[first..];
    assert!(significant.len() <= len, "value wider than {len} bytes");
    let mut out = vec![0u8; len - significant.len()];
    out.extend_from_slice(significant);
    out
}

/// One Wycheproof group through `RSAES_OAEP<K, H, M>`.
fn run_group<K, H, M, const N: usize, const SK_LEN: usize>(group: &Value) -> Counts
where
    K: RsaSigningSize + RsaSize<Modulus = [u8; N], PrivateKeyEncoded = [u8; SK_LEN]>,
    H: OaepHash,
    M: OaepHash,
{
    // The private key's encoding is p || q || dP || dQ || qInv, each half the modulus long,
    // then e in eight bytes.
    let key = &group["privateKey"];
    let e = u64::from_str_radix(key["publicExponent"].as_str().unwrap(), 16).unwrap();
    let mut raw = Vec::with_capacity(SK_LEN);
    for field in ["prime1", "prime2", "exponent1", "exponent2", "coefficient"] {
        raw.extend(be_bytes(key[field].as_str().unwrap(), N / 2));
    }
    raw.extend(e.to_be_bytes());
    let sk = RsaKEMPrivateKey::<K>::from_bytes(&raw).expect("a Wycheproof key decodes");

    let (mut valid, mut invalid) = (0, 0);
    for test in group["tests"].as_array().unwrap() {
        let tc_id = test["tcId"].as_u64().unwrap();
        let msg = hex_decode(test["msg"].as_str().unwrap()).unwrap();
        let label = hex_decode(test["label"].as_str().unwrap()).unwrap();
        let ct = hex_decode(test["ct"].as_str().unwrap()).unwrap();
        let params = OaepParams::<H, M>::new(&label);
        // A ciphertext of the wrong length is not a ciphertext: RFC 8017 §7.1.2 step 1.b.
        let mut recovered = KeyMaterial::<1024>::new();
        let result = <[u8; N]>::try_from(ct.as_slice())
            .map_err(|_| KeyTransportError::DecryptionFailed)
            .and_then(|ct| sk.recover_out(&ct, params, &mut recovered));
        match test["result"].as_str().unwrap() {
            // "acceptable" cases are valid ciphertexts with an unusual shape (a small integer
            // ciphertext), which RFC 8017 gives no reason to refuse.
            "valid" | "acceptable" => {
                assert_eq!(result, Ok(msg.len()), "tcId {tc_id}");
                assert_eq!(recovered.ref_to_bytes(), msg.as_slice(), "tcId {tc_id}");
                // An empty or all-zero message is typed as what it is; any other is a key.
                let expected = if msg.iter().all(|b| *b == 0) {
                    KeyType::Zeroized
                } else {
                    KeyType::CryptographicRandom
                };
                assert_eq!(recovered.key_type(), expected, "tcId {tc_id}");
                valid += 1;
            }
            "invalid" => {
                assert_eq!(result, Err(KeyTransportError::DecryptionFailed), "tcId {tc_id}");
                assert_eq!(recovered.key_type(), KeyType::Zeroized, "tcId {tc_id}");
                invalid += 1;
            }
            other => panic!("tcId {tc_id}: unexpected result {other}"),
        }
    }

    // Encryption under the group's public key, which the vectors do not cover: a key
    // transported with this size and these hashes comes back.
    let pk = RsaKEMPublicKey::<K>::new(sk.n(), e).expect("a Wycheproof key is a KEM key");
    let params = OaepParams::<H, M>::new(b"round trip");
    let sent = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::MACKey).unwrap();
    let ct = pk.transport(&mut HashDRBG_SHA512::new_from_os(), params, &sent).unwrap();
    let mut recovered = KeyMaterial::<32>::new();
    assert_eq!(sk.recover_out(&ct, params, &mut recovered), Ok(32));
    assert_eq!(recovered.ref_to_bytes(), [0x42; 32]);

    (valid, invalid, 0)
}

/// The MGF1 hash by Wycheproof's name.
fn with_mgf<K, H, const N: usize, const SK_LEN: usize>(group: &Value) -> Counts
where
    K: RsaSigningSize + RsaSize<Modulus = [u8; N], PrivateKeyEncoded = [u8; SK_LEN]>,
    H: OaepHash,
{
    match group["mgfSha"].as_str().unwrap() {
        "SHA-1" => run_group::<K, H, SHA1, N, SK_LEN>(group),
        "SHA-224" => run_group::<K, H, SHA224, N, SK_LEN>(group),
        "SHA-256" => run_group::<K, H, SHA256, N, SK_LEN>(group),
        "SHA-384" => run_group::<K, H, SHA384, N, SK_LEN>(group),
        "SHA-512" => run_group::<K, H, SHA512, N, SK_LEN>(group),
        "SHA-512/224" => run_group::<K, H, SHA512_224, N, SK_LEN>(group),
        "SHA-512/256" => run_group::<K, H, SHA512_256, N, SK_LEN>(group),
        other => panic!("unexpected mgfSha {other}"),
    }
}

/// The label hash by Wycheproof's name.
fn with_sha<K, const N: usize, const SK_LEN: usize>(group: &Value) -> Counts
where
    K: RsaSigningSize + RsaSize<Modulus = [u8; N], PrivateKeyEncoded = [u8; SK_LEN]>,
{
    assert_eq!(group["mgf"], "MGF1");
    match group["sha"].as_str().unwrap() {
        "SHA-1" => with_mgf::<K, SHA1, N, SK_LEN>(group),
        "SHA-224" => with_mgf::<K, SHA224, N, SK_LEN>(group),
        "SHA-256" => with_mgf::<K, SHA256, N, SK_LEN>(group),
        "SHA-384" => with_mgf::<K, SHA384, N, SK_LEN>(group),
        "SHA-512" => with_mgf::<K, SHA512, N, SK_LEN>(group),
        "SHA-512/224" => with_mgf::<K, SHA512_224, N, SK_LEN>(group),
        "SHA-512/256" => with_mgf::<K, SHA512_256, N, SK_LEN>(group),
        other => panic!("unexpected sha {other}"),
    }
}

/// Every group of a Wycheproof file, by modulus size; `None` if Wycheproof is not checked out.
fn run_file(filename: &str) -> Option<Counts> {
    let file = wycheproof_json(filename)?;
    let mut total = (0, 0, 0);
    for group in file["testGroups"].as_array().unwrap() {
        let (valid, invalid, skipped) = match group["keySize"].as_u64().unwrap() {
            2048 => with_sha::<RSA2048, 256, 648>(group),
            3072 => with_sha::<RSA3072, 384, 968>(group),
            4096 => with_sha::<RSA4096, 512, 1288>(group),
            8192 => with_sha::<RSA8192, 1024, 2568>(group),
            // No private key type below 2048 bits or at the odd sizes of the misc file.
            _ => (0, 0, group["tests"].as_array().unwrap().len()),
        };
        total = (total.0 + valid, total.1 + invalid, total.2 + skipped);
    }
    Some(total)
}

/// The per-suite files: `(file stem, valid, invalid)`.
const SUITE_FILES: [(&str, usize, usize); 21] = [
    ("2048_sha1_mgf1sha1", 17, 19),
    ("2048_sha224_mgf1sha1", 13, 18),
    ("2048_sha224_mgf1sha224", 17, 18),
    ("2048_sha256_mgf1sha1", 13, 18),
    ("2048_sha256_mgf1sha256", 18, 19),
    ("2048_sha384_mgf1sha1", 13, 18),
    ("2048_sha384_mgf1sha384", 16, 18),
    ("2048_sha512_224_mgf1sha1", 13, 19),
    ("2048_sha512_224_mgf1sha512_224", 16, 19),
    ("2048_sha512_mgf1sha1", 13, 18),
    ("2048_sha512_mgf1sha512", 14, 19),
    ("3072_sha256_mgf1sha1", 13, 19),
    ("3072_sha256_mgf1sha256", 18, 19),
    ("3072_sha512_256_mgf1sha1", 13, 18),
    ("3072_sha512_256_mgf1sha512_256", 18, 19),
    ("3072_sha512_mgf1sha1", 13, 18),
    ("3072_sha512_mgf1sha512", 15, 18),
    ("4096_sha256_mgf1sha1", 13, 19),
    ("4096_sha256_mgf1sha256", 18, 19),
    ("4096_sha512_mgf1sha1", 13, 18),
    ("4096_sha512_mgf1sha512", 17, 19),
];

#[test]
fn wycheproof_suite_files() {
    for (stem, valid, invalid) in SUITE_FILES {
        let filename = format!("rsa_oaep_{stem}_test.json");
        match run_file(&filename) {
            Some(counts) => assert_eq!(counts, (valid, invalid, 0), "{filename}"),
            None => return,
        }
    }
}

/// The misc file: every pairing of the hashes at every size, valid cases only. 140 of its 395
/// cases are at sizes with no private key type here.
#[test]
fn wycheproof_misc_file() {
    if let Some(counts) = run_file("rsa_oaep_misc_test.json") {
        assert_eq!(counts, (255, 0, 140));
    }
}

type Pk = RsaKEMPublicKey<RSA2048>;
type Sk = RsaKEMPrivateKey<RSA2048>;

/// Two RSA-2048 key pairs, generated once for the file.
fn key_pairs() -> &'static [(Pk, Sk); 2] {
    static KEYS: OnceLock<[(Pk, Sk); 2]> = OnceLock::new();
    KEYS.get_or_init(|| {
        let mut rng = HashDRBG_SHA512::new_from_os();
        [RSASVE::<RSA2048>::keygen(&mut rng).unwrap(), RSASVE::<RSA2048>::keygen(&mut rng).unwrap()]
    })
}

#[test]
fn the_kem_framework_passes() {
    fn keygen() -> Result<(Pk, Sk), KEMError> {
        Ok(key_pairs()[0].clone())
    }
    let framework = TestFrameworkKEM::new(false, false);
    framework.test_kem::<_, Pk, Sk, 256, 32>(keygen, OaepParams::<SHA256>::new(b"label"), false);
    framework.test_kem::<_, Pk, Sk, 256, 48>(
        keygen,
        OaepParams::<SHA384, SHA1, 48>::new(b""),
        false,
    );
}

#[test]
fn the_key_transport_framework_passes() {
    let [(pk, sk), (_, other_sk)] = key_pairs();
    let framework = TestFrameworkKeyTransport::new(true);
    framework.test::<_, _, _, 256>(pk, sk, other_sk, OaepParams::<SHA256>::new(b"label"));
    framework.test::<_, _, _, 256>(pk, sk, other_sk, OaepParams::<SHA1, SHA512>::new(b""));
    // The longest key is k - 2hLen - 2.
    assert_eq!(pk.max_key_len(OaepParams::<SHA256>::new(b"")), 256 - 2 * 32 - 2);
    assert_eq!(pk.max_key_len(OaepParams::<SHA512, SHA1>::new(b"")), 256 - 2 * 64 - 2);
    assert_eq!(pk.max_key_len(OaepParams::<SHA1, SHA512>::new(b"")), 256 - 2 * 20 - 2);
}

/// The label, the label hash and the MGF1 hash are each part of what a ciphertext is for: a
/// recipient with another one gets the decryption error, through either role.
#[test]
fn the_label_and_both_hashes_are_bound() {
    let [(pk, sk), _] = key_pairs();
    let mut rng = HashDRBG_SHA512::new_from_os();
    let params = OaepParams::<SHA256>::new(b"label");
    let (ss, ct) = pk.encaps(&mut rng, params).unwrap();
    assert_eq!(sk.decaps(&ct, params).unwrap(), ss);

    assert_eq!(
        sk.decaps(&ct, OaepParams::<SHA256>::new(b"Label")),
        Err(KEMError::DecapsulationFailed)
    );
    assert_eq!(sk.decaps(&ct, OaepParams::<SHA256>::new(b"")), Err(KEMError::DecapsulationFailed));
    assert_eq!(
        sk.decaps(&ct, OaepParams::<SHA384, SHA256>::new(b"label")),
        Err(KEMError::DecapsulationFailed)
    );
    assert_eq!(
        sk.decaps(&ct, OaepParams::<SHA256, SHA384>::new(b"label")),
        Err(KEMError::DecapsulationFailed)
    );
}

/// The two roles are one scheme: a key the KEM transported is recovered by the transport role,
/// and a transported key of the KEM's length decapsulates; a key of another length is the
/// decryption error to the KEM, which wants exactly `LEN` bytes.
#[test]
fn the_kem_and_the_transport_roles_interoperate() {
    let [(pk, sk), _] = key_pairs();
    let mut rng = HashDRBG_SHA512::new_from_os();
    let params = OaepParams::<SHA256>::new(b"");

    let (ss, ct) = pk.encaps(&mut rng, params).unwrap();
    let mut recovered = KeyMaterial::<64>::new();
    assert_eq!(sk.recover_out(&ct, params, &mut recovered), Ok(32));
    assert_eq!(recovered.ref_to_bytes(), ss.ref_to_bytes());

    let key = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::MACKey).unwrap();
    let ct = pk.transport(&mut rng, params, &key).unwrap();
    assert_eq!(sk.decaps(&ct, params).unwrap().ref_to_bytes(), [0x42; 32]);

    for len in [31usize, 33] {
        let key = KeyMaterial::<64>::from_bytes_as_type(&vec![0x42; len], KeyType::MACKey).unwrap();
        let ct = pk.transport(&mut rng, params, &key).unwrap();
        assert_eq!(sk.decaps(&ct, params), Err(KEMError::DecapsulationFailed), "len {len}");
    }
}

/// A ciphertext that is not below the modulus is refused, as is the all-zero one, with the
/// output left zeroized.
#[test]
fn ciphertexts_out_of_range_are_refused() {
    let [(_, sk), _] = key_pairs();
    let params = OaepParams::<SHA256>::new(b"");
    // SP 800-56B Rev. 2 §7.2.2.4 step 2.c: 1 < c < n - 1.
    let mut one = [0u8; 256];
    one[255] = 1;
    for ct in [[0xFFu8; 256], [0u8; 256], one] {
        assert_eq!(sk.decaps(&ct, params), Err(KEMError::DecapsulationFailed));
        let mut recovered = KeyMaterial::<64>::from_bytes(&[0xEE; 64]).unwrap();
        assert_eq!(
            sk.recover_out(&ct, params, &mut recovered),
            Err(KeyTransportError::DecryptionFailed)
        );
        assert_eq!(recovered.key_type(), KeyType::Zeroized);
    }
}

/// The algorithm is named by size and both hashes, and its strength is the modulus's capped by
/// what the shorter hash output can carry: SHA-1's 160 bits cap RSA-8192 at 128, and do not
/// lower RSA-2048's 112.
#[test]
fn names_and_strengths() {
    assert_eq!(RSAES_OAEP::<RSA2048, SHA256>::ALG_NAME, "RSAES-OAEP-2048-SHA256-MGF1-SHA256");
    assert_eq!(RSAES_OAEP::<RSA4096, SHA512, SHA1>::ALG_NAME, "RSAES-OAEP-4096-SHA512-MGF1-SHA1");
    assert_eq!(RSAES_OAEP::<RSA2048, SHA256>::MAX_SECURITY_STRENGTH, SecurityStrength::_112bit);
    assert_eq!(RSAES_OAEP::<RSA2048, SHA1, SHA1>::MAX_SECURITY_STRENGTH, SecurityStrength::_112bit);
    assert_eq!(
        RSAES_OAEP::<RSA8192, SHA512>::MAX_SECURITY_STRENGTH,
        <RSA8192 as RsaSize>::STRENGTH
    );
    assert_eq!(
        RSAES_OAEP::<RSA8192, SHA512, SHA1>::MAX_SECURITY_STRENGTH,
        SecurityStrength::_128bit
    );
    assert_eq!(
        RSAES_OAEP::<RSA8192, SHA1, SHA512>::MAX_SECURITY_STRENGTH,
        SecurityStrength::_128bit
    );
    // A 28-byte output carries 192 bits, which is RSA-8192's own strength.
    assert_eq!(<RSA8192 as RsaSize>::STRENGTH, SecurityStrength::_192bit);
    assert_eq!(RSAES_OAEP::<RSA8192, SHA224>::MAX_SECURITY_STRENGTH, SecurityStrength::_192bit);
    assert_eq!(
        RSAES_OAEP::<RSA8192, SHA512_224, SHA512>::MAX_SECURITY_STRENGTH,
        SecurityStrength::_192bit
    );
}

/// The RNG must offer the algorithm's strength, and exactly that is enough, for both roles; a
/// weaker one is refused, with the outputs left zeroized.
#[test]
fn the_rng_must_offer_the_algorithms_strength() {
    let [(pk, sk), _] = key_pairs();
    let params = OaepParams::<SHA256>::new(b"");
    let key = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::MACKey).unwrap();
    let rng_at = |strength| {
        let mut rng = FixedSeedRNG::new(core::array::from_fn::<u8, 256, _>(|i| i as u8 ^ 0x5A));
        rng.set_security_strength(strength);
        rng
    };

    // RSAES-OAEP-2048 is a 112-bit algorithm.
    let (ss, ct) = pk.encaps(&mut rng_at(SecurityStrength::_112bit), params).unwrap();
    assert_eq!(sk.decaps(&ct, params).unwrap(), ss);
    let ct = pk.transport(&mut rng_at(SecurityStrength::_112bit), params, &key).unwrap();
    assert_eq!(sk.decaps(&ct, params).unwrap().ref_to_bytes(), [0x42; 32]);

    let mut ct = [0xFFu8; 256];
    let mut ss = KeyMaterial::<32>::from_bytes(&[0xEE; 32]).unwrap();
    assert_eq!(
        pk.encaps_out(&mut rng_at(SecurityStrength::None), params, &mut ct, &mut ss),
        Err(KEMError::RNGError(RNGError::SecurityStrengthInsufficientForAlgorithm))
    );
    assert_eq!(ct, [0u8; 256]);
    assert_eq!(ss.key_type(), KeyType::Zeroized);
    let mut ct = [0xFFu8; 256];
    assert_eq!(
        pk.transport_out(&mut rng_at(SecurityStrength::None), params, &key, &mut ct),
        Err(KeyTransportError::RNGError(RNGError::SecurityStrengthInsufficientForAlgorithm))
    );
    assert_eq!(ct, [0u8; 256]);
}

/// An RNG that delivers its first draw and fails the second: the KEM's key is drawn first and
/// the OAEP seed second.
struct FailsOnSecondDraw(usize);

impl RNG for FailsOnSecondDraw {
    fn add_seed_keymaterial(&mut self, _: &dyn KeyMaterialTrait) -> Result<(), RNGError> {
        Err(RNGError::GenericError("not seedable"))
    }
    fn next_int(&mut self) -> Result<u32, RNGError> {
        Err(RNGError::GenericError("not used"))
    }
    fn next_bytes_out(&mut self, out: &mut [u8]) -> Result<usize, RNGError> {
        self.0 += 1;
        if self.0 > 1 {
            return Err(RNGError::GenericError("the second draw fails"));
        }
        out.fill(0xA5);
        Ok(out.len())
    }
    fn fill_keymaterial_out(&mut self, _: &mut dyn KeyMaterialTrait) -> Result<usize, RNGError> {
        Err(RNGError::GenericError("not used"))
    }
    fn security_strength(&self) -> SecurityStrength {
        SecurityStrength::_256bit
    }
}

/// An RNG failure on the seed, after the key was drawn, is the RNG's error, and neither the
/// ciphertext nor the key that was drawn is left in the caller's buffers.
#[test]
fn an_rng_failure_on_the_seed_leaves_the_outputs_zeroized() {
    let [(pk, _), _] = key_pairs();
    let params = OaepParams::<SHA256>::new(b"");
    let mut ct = [0xFFu8; 256];
    let mut ss = KeyMaterial::<32>::from_bytes(&[0xEE; 32]).unwrap();
    assert_eq!(
        pk.encaps_out(&mut FailsOnSecondDraw(0), params, &mut ct, &mut ss),
        Err(KEMError::RNGError(RNGError::GenericError("the second draw fails")))
    );
    assert_eq!(ct, [0u8; 256]);
    assert_eq!(ss.key_type(), KeyType::Zeroized);

    let key = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::MACKey).unwrap();
    let mut ct = [0xFFu8; 256];
    assert_eq!(
        pk.transport_out(&mut FailsOnSecondDraw(1), params, &key, &mut ct),
        Err(KeyTransportError::RNGError(RNGError::GenericError("the second draw fails")))
    );
    assert_eq!(ct, [0u8; 256]);
}

/// The longest key the KEM carries at RSA-2048 with SHA-256, 190 bytes, builds and round
/// trips; `OaepParams`' doc has the 191-byte case that does not build.
#[test]
fn the_kem_carries_its_longest_key() {
    let [(pk, sk), _] = key_pairs();
    let params = OaepParams::<SHA256, SHA256, 190>::new(b"");
    let (ss, ct) = pk.encaps(&mut HashDRBG_SHA512::new_from_os(), params).unwrap();
    assert_eq!(ss.key_len(), 190);
    assert_eq!(sk.decaps(&ct, params).unwrap(), ss);
}
