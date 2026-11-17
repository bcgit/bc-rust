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
use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::key_transport_key::{KeyTransportDecryptingKey, KeyTransportEncryptingKey};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, HashAlgParams, HashOneShot, PrivateKey};
use bouncycastle_core_test_framework::kem::TestFrameworkKEM;
use bouncycastle_core_test_framework::key_transport::TestFrameworkKeyTransport;
use bouncycastle_core_test_framework::test_data_loaders::wycheproof_json;
use bouncycastle_hex::decode as hex_decode;
use bouncycastle_rng::{FixedSeedRNG, HashDRBG_SHA512};
use bouncycastle_rsa::rsaes_oaep::{OaepParams, RSAES_OAEP};
use bouncycastle_rsa::rsasve::{RSASVE, RsaKEMPrivateKey, RsaKEMPublicKey};
use bouncycastle_rsa::size::{RsaSigningSize, RsaSize};
use bouncycastle_rsa::{RSA2048, RSA3072, RSA4096, RSA8192};
use bouncycastle_sha1::SHA1;
use bouncycastle_sha2::{SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256};
use serde_json::Value;
use std::sync::OnceLock;

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
    H: HashOneShot + HashAlgParams,
    M: HashOneShot + HashAlgParams,
{
    // The private key's encoding is p || q || dP || dQ || qInv, each half the modulus long.
    let key = &group["privateKey"];
    let mut raw = Vec::with_capacity(SK_LEN);
    for field in ["prime1", "prime2", "exponent1", "exponent2", "coefficient"] {
        raw.extend(be_bytes(key[field].as_str().unwrap(), N / 2));
    }
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
    (valid, invalid, 0)
}

/// The MGF1 hash by Wycheproof's name.
fn with_mgf<K, H, const N: usize, const SK_LEN: usize>(group: &Value) -> Counts
where
    K: RsaSigningSize + RsaSize<Modulus = [u8; N], PrivateKeyEncoded = [u8; SK_LEN]>,
    H: HashOneShot + HashAlgParams,
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
            2048 => with_sha::<RSA2048, 256, 640>(group),
            3072 => with_sha::<RSA3072, 384, 960>(group),
            4096 => with_sha::<RSA4096, 512, 1280>(group),
            8192 => with_sha::<RSA8192, 1024, 2560>(group),
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
    for ct in [[0xFFu8; 256], [0u8; 256]] {
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
/// weaker one is refused before anything is drawn, with the outputs left zeroized.
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
