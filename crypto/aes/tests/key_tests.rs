//! The mode-bound AES key objects: validation at construction, and `key.create_encryptor(rng)`
//! producing exactly what the mode's own `do_encrypt_init_rng` produces from the same material
//! and RNG.

use bouncycastle_aes::hazmat::AES128Internal;
use bouncycastle_aes::{AES_GCM_128, AES_GCM_192, AES_GCM_256, AES128Key, AES192Key, AES256Key};
use bouncycastle_cipher::modes::{CCM, CMAC, GCM, GMAC};
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::hazmat::Mode;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey, FromKeyMaterial};
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, Algorithm, SymmetricCipherDecryptor,
    SymmetricCipherEncryptor,
};
use bouncycastle_core_test_framework::FixedSeedRNG;

/// The worker traits, kept out of scope: a GCM worker implements both them and the cipher
/// traits under the same method names, so the generic helpers name them by path.
mod w {
    pub use bouncycastle_core::symmetric_key::{AeadDecryptWorker, AeadEncryptWorker};
}

fn material<const N: usize>() -> KeyMaterial<N> {
    let bytes: [u8; N] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).expect("a valid key")
}

fn rng() -> FixedSeedRNG<12> {
    FixedSeedRNG::<12>::new([0x24u8; 12])
}

const AAD: &[u8] = b"header, sent in the clear";
const MSG: &[u8] = b"a message of no particular length, long enough to span a few blocks anyway";

/// Streams `MSG` through a key-side GCM encryptor for a key of `N` bytes.
fn encrypt_via_key<const N: usize, K>(key: &K) -> ([u8; 12], Vec<u8>, [u8; 16])
where
    K: AeadEncryptionKey<N, 12, 16, 16>,
{
    let (mut enc, nonce) = key.create_encryptor(&mut rng()).expect("nonce draw");
    w::AeadEncryptWorker::do_update_aad(&mut enc, AAD).unwrap();
    let mut ct = vec![0u8; MSG.len()];
    w::AeadEncryptWorker::do_encrypt_out(&mut enc, MSG, &mut ct).unwrap();
    let (_, tag) =
        w::AeadEncryptWorker::do_encrypt_final_detached_out(enc, &mut [0u8; 16]).unwrap();
    (nonce, ct, tag)
}

/// Streams a ciphertext through a key-side GCM decryptor, returning the plaintext once the tag
/// has been checked.
fn decrypt_via_key<const N: usize, K>(
    key: &K,
    nonce: &[u8; 12],
    ct: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, SymmetricCipherError>
where
    K: AeadDecryptionKey<N, 12, 16, 16>,
{
    // Decryption setup is infallible: no Result to unwrap.
    let mut dec = key.create_decryptor(nonce);
    w::AeadDecryptWorker::do_update_aad(&mut dec, AAD)?;
    let mut pt = vec![0u8; ct.len() + 16];
    let n = w::AeadDecryptWorker::do_decrypt_out(&mut dec, ct, &mut pt)?;
    let mut last = [0u8; 16];
    let m = w::AeadDecryptWorker::do_decrypt_final_detached_out(dec, tag, &mut last)?;
    Ok([&pt[..n], &last[..m]].concat())
}

#[test]
fn a_key_of_the_wrong_type_is_refused_at_construction() {
    let seed = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::Seed).expect("a seed");
    match AES256Key::<GCM>::from_key_material(&seed) {
        Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_))) => {}
        other => panic!("expected InvalidKeyType, got {:?}", other.err()),
    }
}

#[test]
fn a_key_below_its_own_strength_is_refused_at_construction() {
    let mut weak = material::<32>();
    weak.set_security_strength(SecurityStrength::_128bit).expect("downgrading is allowed");
    match AES256Key::<GCM>::from_key_material(&weak) {
        Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::SecurityStrength(_))) => {}
        other => panic!("expected SecurityStrength, got {:?}", other.err()),
    }
}

/// The material's algorithm binding is checked at construction against the mode's name over
/// this permutation: a key bound to another mode, or to the same mode at another key length, is
/// refused; one bound to this mode's name or unbound is accepted. Both key types.
#[test]
fn a_key_bound_to_another_algorithm_is_refused_at_construction() {
    fn bound<const N: usize>(key_type: KeyType, alg: &'static str) -> KeyMaterial<N> {
        let bytes: [u8; N] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
        let mut key = KeyMaterial::<N>::from_bytes_as_type(&bytes, key_type).unwrap();
        key.set_algorithm(Some(alg)).unwrap();
        key
    }
    fn refused<K>(result: Result<K, SymmetricCipherError>) -> bool {
        matches!(
            result,
            Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_)))
        )
    }
    let cipher = KeyType::SymmetricCipherKey;

    assert!(refused(AES128Key::<GCM>::from_key_material(&bound(cipher, "AES_CBC_128"))));
    assert!(refused(AES128Key::<CCM<12, 16>>::from_key_material(&bound(cipher, "AES_GCM_128"))));
    assert!(refused(AES256Key::<GCM>::from_key_material(&bound(cipher, "AES_GCM_128"))));
    assert!(AES128Key::<GCM>::from_key_material(&bound(cipher, "AES_GCM_128")).is_ok());
    assert!(AES128Key::<CCM<12, 16>>::from_key_material(&bound(cipher, "AES_CCM_128")).is_ok());
    assert!(AES128Key::<GCM>::from_key_material(&material::<16>()).is_ok());

    let mac = KeyType::MACKey;
    assert!(refused(AES128Key::<GMAC>::from_key_material(&bound(mac, "AES_CMAC_128"))));
    assert!(refused(AES128Key::<CMAC>::from_key_material(&bound(mac, "AES_GMAC_128"))));
    assert!(AES128Key::<CMAC>::from_key_material(&bound(mac, "AES_CMAC_128")).is_ok());
    assert!(AES128Key::<GMAC>::from_key_material(&bound(mac, "AES_GMAC_128")).is_ok());

    // The name checked is the one the mode's workers report.
    assert_eq!(<GCM as Mode<AES128Internal>>::ALG_NAME, AES_GCM_128::<Encrypting>::ALG_NAME);
}

#[test]
fn the_key_type_a_mode_requires_is_the_constructor_constant() {
    assert_eq!(<AES128Key<GCM> as FromKeyMaterial<16>>::KEY_TYPE, KeyType::SymmetricCipherKey);
    assert_eq!(<AES256Key<GCM<12>> as FromKeyMaterial<32>>::KEY_TYPE, KeyType::SymmetricCipherKey);
}

/// The key-side encryptor is the mode's own type built from the same material, so with the same
/// RNG it must produce the same nonce, ciphertext and tag as the static constructor.
#[test]
fn create_encryptor_matches_do_encrypt_init_rng() {
    let km = material::<32>();
    let key = AES256Key::<GCM>::from_key_material(&km).expect("a valid key");

    let (mut enc_static, nonce_static) =
        AES_GCM_256::<Encrypting>::do_encrypt_init_rng(&km, &mut rng()).expect("static init");
    let (mut enc_key, nonce_key) = key.create_encryptor(&mut rng()).expect("key-side init");
    assert_eq!(nonce_static, nonce_key);

    let mut ct_static = vec![0u8; MSG.len()];
    let mut ct_key = vec![0u8; MSG.len()];
    enc_static.do_update_aad(AAD).unwrap();
    enc_key.do_update_aad(AAD).unwrap();
    enc_static.do_encrypt_out(MSG, &mut ct_static).unwrap();
    enc_key.do_encrypt_out(MSG, &mut ct_key).unwrap();
    let (_, _, tag_static) = enc_static.do_encrypt_final_detached().unwrap();
    let (_, _, tag_key) = enc_key.do_encrypt_final_detached().unwrap();

    assert_eq!(ct_static, ct_key);
    assert_eq!(tag_static, tag_key);
}

#[test]
fn create_decryptor_round_trips_and_detects_tampering() {
    let key = AES256Key::<GCM>::from_key_material(&material::<32>()).expect("a valid key");
    let (nonce, ct, tag) = encrypt_via_key::<32, _>(&key);

    let pt = decrypt_via_key::<32, _>(&key, &nonce, &ct, &tag).expect("a valid tag");
    assert_eq!(pt, MSG);

    let mut bad_tag = tag;
    bad_tag[0] ^= 1;
    assert!(matches!(
        decrypt_via_key::<32, _>(&key, &nonce, &ct, &bad_tag),
        Err(SymmetricCipherError::AEADTagCheckFailed)
    ));
}

/// The one-shots on the role traits are written over `create_encryptor` and the streaming
/// methods, so they must match the cipher traits' key-taking one-shots byte for byte.
#[test]
fn key_one_shots_match_the_static_one_shots() {
    let km = material::<16>();
    let key = AES128Key::<GCM>::from_key_material(&km).expect("a valid key");
    type E = AES_GCM_128<Encrypting>;
    type D = AES_GCM_128<Decrypting>;

    // Inline tag.
    let mut ct_static = vec![0u8; E::encrypt_out_len(MSG.len())];
    let (nonce_s, n_s) =
        E::encrypt_with_aad_rng_out(&km, &mut rng(), AAD, MSG, &mut ct_static).unwrap();
    let mut ct_key = vec![0u8; E::encrypt_out_len(MSG.len())];
    let (n_k, nonce_k) = key.encrypt_with_aad_out(&mut rng(), AAD, MSG, &mut ct_key).unwrap();
    assert_eq!((nonce_s, n_s), (nonce_k, n_k));
    assert_eq!(ct_static, ct_key);

    let mut pt = vec![0u8; D::decrypt_out_len(ct_key.len())];
    let m = key.decrypt_with_aad_out(&nonce_k, AAD, &ct_key, &mut pt).unwrap();
    assert_eq!(&pt[..m], MSG);
    assert_eq!(D::decrypt_with_aad(&km, &nonce_k, AAD, &ct_key).unwrap(), MSG);
    assert_eq!(key.decrypt_with_aad(&nonce_k, AAD, &ct_key).unwrap(), MSG);

    // Detached tag.
    let mut ct_s = vec![0u8; E::encrypt_detached_out_len(MSG.len())];
    let (nonce_s, n_s, tag_s) =
        E::encrypt_detached_rng_out(&km, &mut rng(), AAD, MSG, &mut ct_s).unwrap();
    let (nonce_k, ct_k, tag_k) = key.encrypt_detached(&mut rng(), AAD, MSG).unwrap();
    assert_eq!((nonce_s, n_s), (nonce_k, ct_k.len()));
    assert_eq!((ct_s, tag_s), (ct_k.clone(), tag_k));

    let mut pt = vec![0u8; D::decrypt_detached_out_len(ct_k.len())];
    let m = key.decrypt_detached_out(&nonce_k, AAD, &ct_k, &tag_k, &mut pt).unwrap();
    assert_eq!(&pt[..m], MSG);
    assert_eq!(key.decrypt_detached(&nonce_k, AAD, &ct_k, &tag_k).unwrap(), MSG);

    // A failed check leaves zeros, not plaintext, in the caller's buffer.
    let mut bad_tag = tag_k;
    bad_tag[3] ^= 0x80;
    let mut pt = vec![0xEEu8; ct_k.len()];
    assert!(matches!(
        key.decrypt_detached_out(&nonce_k, AAD, &ct_k, &bad_tag, &mut pt),
        Err(SymmetricCipherError::AEADTagCheckFailed)
    ));
    assert!(pt.iter().all(|&b| b == 0));

    // Too small an output buffer is reported before anything is drawn or encrypted.
    let mut small = [0u8; 4];
    assert!(matches!(
        key.encrypt_with_aad_out(&mut rng(), AAD, MSG, &mut small),
        Err(SymmetricCipherError::OutputBufferTooSmall(_))
    ));
}

/// The decryptor built from the key accepts what the static encryptor produced, and vice versa,
/// at every key length: one more check that the two paths are the same cipher.
#[test]
fn key_side_and_static_paths_interoperate_at_every_key_length() {
    fn check<const N: usize, K, E, D>(key: &K)
    where
        K: AeadEncryptionKey<N, 12, 16, 16> + AeadDecryptionKey<N, 12, 16, 16>,
        E: AEADCipherEncryptor<N, 12, 16, 16>,
        D: AEADCipherDecryptor<N, 12, 16, 16>,
    {
        let km = material::<N>();

        let (nonce, ct, tag) = E::encrypt_detached(&km, AAD, MSG).expect("static one-shot");
        let pt = decrypt_via_key::<N, K>(key, &nonce, &ct, &tag).expect("a valid tag");
        assert_eq!(pt, MSG);

        let (nonce, ct, tag) = encrypt_via_key::<N, K>(key);
        let pt = D::decrypt_detached(&km, &nonce, AAD, &ct, &tag).expect("static one-shot");
        assert_eq!(pt, MSG);
    }

    check::<16, _, AES_GCM_128<Encrypting>, AES_GCM_128<Decrypting>>(
        &AES128Key::<GCM>::from_key_material(&material::<16>()).unwrap(),
    );
    check::<24, _, AES_GCM_192<Encrypting>, AES_GCM_192<Decrypting>>(
        &AES192Key::<GCM>::from_key_material(&material::<24>()).unwrap(),
    );
    check::<32, _, AES_GCM_256<Encrypting>, AES_GCM_256<Decrypting>>(
        &AES256Key::<GCM>::from_key_material(&material::<32>()).unwrap(),
    );
}

/// The tag length is in the key type: `AES128Key<GCM<12>>` is a different key type over the same
/// material, and its tag is the truncation of the full one (SP 800-38D step 6, MSB_t).
#[test]
fn a_shorter_tag_is_a_different_key_type_over_the_same_material() {
    let km = material::<16>();
    let key12 = AES128Key::<GCM<12>>::from_key_material(&km).expect("a valid key");
    let key16 = AES128Key::<GCM>::from_key_material(&km).expect("a valid key");

    let (mut enc, nonce) = key12.create_encryptor(&mut rng()).unwrap();
    let mut ct = vec![0u8; MSG.len()];
    enc.do_encrypt_out(MSG, &mut ct).unwrap();
    let (_, _, tag): (_, _, [u8; 12]) = enc.do_encrypt_final_detached().unwrap();

    let (mut enc16, _) = key16.create_encryptor(&mut rng()).unwrap();
    let mut ct16 = vec![0u8; MSG.len()];
    enc16.do_encrypt_out(MSG, &mut ct16).unwrap();
    let (_, _, tag16) = enc16.do_encrypt_final_detached().unwrap();
    assert_eq!(ct, ct16);
    assert_eq!(tag, tag16[..12]);

    let mut dec = key12.create_decryptor(&nonce);
    let mut pt = vec![0u8; ct.len() + 12];
    let n = dec.do_decrypt_out(&ct, &mut pt).unwrap();
    let mut last = [0u8; 12];
    let m = dec.do_decrypt_final_detached_out(&tag, &mut last).expect("a valid 96-bit tag");
    assert_eq!([&pt[..n], &last[..m]].concat(), MSG);
}

#[test]
fn generate_draws_a_usable_key_at_every_length() {
    let mut r = FixedSeedRNG::<32>::new([0x5Au8; 32]);
    let k128 = AES128Key::<GCM>::generate(&mut r).expect("128");
    let k192 = AES192Key::<GCM>::generate(&mut r).expect("192");
    let k256 = AES256Key::<GCM>::generate(&mut r).expect("256");

    let (nonce, ct, tag) = encrypt_via_key::<16, _>(&k128);
    assert_ne!(ct, MSG);
    assert_eq!(decrypt_via_key::<16, _>(&k128, &nonce, &ct, &tag).unwrap(), MSG);

    let (nonce, ct, tag) = encrypt_via_key::<24, _>(&k192);
    assert_eq!(decrypt_via_key::<24, _>(&k192, &nonce, &ct, &tag).unwrap(), MSG);

    let (nonce, ct, tag) = encrypt_via_key::<32, _>(&k256);
    assert_eq!(decrypt_via_key::<32, _>(&k256, &nonce, &ct, &tag).unwrap(), MSG);

    // A generated key is a different key from the fixed material's: the fixed key's decryptor
    // rejects the generated key's ciphertext.
    let fixed = AES256Key::<GCM>::from_key_material(&material::<32>()).unwrap();
    assert!(matches!(
        decrypt_via_key::<32, _>(&fixed, &nonce, &ct, &tag),
        Err(SymmetricCipherError::AEADTagCheckFailed)
    ));
}

/// The generated material carries the RNG's strength, so an RNG below the key's strength is
/// refused by the same check `from_key_material` applies to supplied material.
#[test]
fn generate_refuses_an_rng_below_the_key_strength() {
    let mut weak = FixedSeedRNG::<32>::new([0x5Au8; 32]);
    weak.set_security_strength(SecurityStrength::_128bit);
    assert!(AES128Key::<GCM>::generate(&mut weak).is_ok());
    assert!(matches!(
        AES256Key::<GCM>::generate(&mut weak),
        Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::SecurityStrength(_)))
    ));
}

/// A key may be cloned (to hand to another thread, say); the clone is the same key.
#[test]
fn a_cloned_key_is_the_same_key() {
    let key = AES128Key::<GCM>::from_key_material(&material::<16>()).unwrap();
    let copy = key.clone();
    let (nonce, ct, tag) = encrypt_via_key::<16, _>(&key);
    assert_eq!(decrypt_via_key::<16, _>(&copy, &nonce, &ct, &tag).unwrap(), MSG);
    assert_eq!(encrypt_via_key::<16, _>(&copy), (nonce, ct, tag));
}

/// Lengths either side of the 64-byte chunk the provided in-place bodies copy through, plus the
/// empty message and a long one.
const IN_PLACE_LENS: [usize; 9] = [0, 1, 15, 16, 63, 64, 65, 200, 1000];

fn message(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 % 251) as u8).collect()
}

/// The provided in-place one-shots, through GCM: the same nonce, ciphertext and tag as the
/// `_out` forms from the same RNG, at every length, and a round trip back.
#[test]
fn gcm_in_place_one_shots_match_the_out_forms_at_every_length() {
    let key = AES128Key::<GCM>::from_key_material(&material::<16>()).unwrap();
    for len in IN_PLACE_LENS {
        let msg = message(len);
        let (nonce_o, ct_o, tag_o) = key.encrypt_detached(&mut rng(), AAD, &msg).unwrap();

        let mut buf = msg.clone();
        let (nonce, tag) = key.encrypt_detached_in_place(&mut rng(), AAD, &mut buf).unwrap();
        assert_eq!((nonce, &buf, tag), (nonce_o, &ct_o, tag_o), "len {len}");

        key.decrypt_detached_in_place(&nonce, AAD, &mut buf, &tag).unwrap();
        assert_eq!(buf, msg, "len {len}");
    }
}

/// A failed tag check leaves zeros in the caller's buffer, since the plaintext was written there
/// before the tag could be checked.
#[test]
fn in_place_decryption_zeroizes_the_buffer_on_a_bad_tag() {
    let msg = message(200);

    let gcm = AES256Key::<GCM>::from_key_material(&material::<32>()).unwrap();
    let mut buf = msg.clone();
    let (nonce, mut tag) = gcm.encrypt_detached_in_place(&mut rng(), AAD, &mut buf).unwrap();
    tag[0] ^= 1;
    assert!(matches!(
        gcm.decrypt_detached_in_place(&nonce, AAD, &mut buf, &tag),
        Err(SymmetricCipherError::AEADTagCheckFailed)
    ));
    assert!(buf.iter().all(|&b| b == 0));
}

/// Every `_nonce` form, handed the nonce the drawing form drew, produces the drawing form's
/// bytes.
#[test]
fn supplied_nonce_forms_match_the_drawing_forms() {
    fn check<K>(key: &K, msg: &[u8])
    where
        K: AeadEncryptionKey<16, 12, 16, 16> + AeadDecryptionKey<16, 12, 16, 16>,
    {
        let (nonce, ct, tag) = key.encrypt_detached(&mut rng(), AAD, msg).unwrap();
        let inline = key.encrypt_with_aad(&mut rng(), AAD, msg).unwrap().1;

        assert_eq!(key.encrypt_detached_nonce(&nonce, AAD, msg).unwrap(), (ct.clone(), tag));
        assert_eq!(key.encrypt_with_aad_nonce(&nonce, AAD, msg).unwrap(), inline);

        let mut out = vec![0u8; msg.len() + 16];
        let (n, tag_n) = key.encrypt_detached_nonce_out(&nonce, AAD, msg, &mut out).unwrap();
        assert_eq!((n, &out[..n], tag_n), (ct.len(), &ct[..], tag));
        let n = key.encrypt_with_aad_nonce_out(&nonce, AAD, msg, &mut out).unwrap();
        assert_eq!(&out[..n], &inline[..]);

        let mut buf = msg.to_vec();
        assert_eq!(key.encrypt_detached_in_place_nonce(&nonce, AAD, &mut buf).unwrap(), tag);
        assert_eq!(buf, ct);

        let mut enc = key.create_encryptor_nonce(&nonce);
        w::AeadEncryptWorker::do_update_aad(&mut enc, AAD).unwrap();
        let mut streamed = vec![0u8; msg.len()];
        let n = w::AeadEncryptWorker::do_encrypt_out(&mut enc, msg, &mut streamed).unwrap();
        let (_, tag_s) =
            w::AeadEncryptWorker::do_encrypt_final_detached_out(enc, &mut [0u8; 16]).unwrap();
        assert_eq!((&streamed[..n], tag_s), (&ct[..], tag));

        assert_eq!(key.decrypt_detached(&nonce, AAD, &ct, &tag).unwrap(), msg);
    }

    check(&AES128Key::<GCM>::from_key_material(&material::<16>()).unwrap(), &message(200));
}
