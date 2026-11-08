//! The keys under every mode through the `core-test-framework` conformance suites, for one
//! permutation at one key length, and what tells the modes apart on the key path. Each function
//! is one `#[test]` in a cipher crate, called once per key length.

use crate::Permutation;
use crate::material::{mac_material, material, material_flipped, rng};
use bouncycastle_cipher::BlockCipherKey;
use bouncycastle_cipher::modes::hazmat::ecb::ECB;
use bouncycastle_cipher::modes::{
    Blocks, CBC, CCM_Packet, CFB, CFB8, CMAC, CTR, GCM, GMAC, KW, KWP,
};
use bouncycastle_cipher::padding::{NoPadding, PKCS7};
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::hazmat::{EcbEncryptionKey, Mode};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{
    AeadDecryptionKey, AeadEncryptionKey, BlockDecryptionKey, BlockEncryptionKey, FromKeyMaterial,
    MacGenerationKey, MacVerificationKey, NonceMacGenerationKey, NonceMacVerificationKey,
    SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle_core::traits::{BlockCipherEncryptor, MACGenerator};
use bouncycastle_core_test_framework::aead::{
    TestFrameworkAEADCipher, TestFrameworkAEADTaggedLayout,
};
use bouncycastle_core_test_framework::block_cipher::TestFrameworkBlockCipher;
use bouncycastle_core_test_framework::from_key_material::TestFrameworkFromKeyMaterial;
use bouncycastle_core_test_framework::key_wrap::TestFrameworkKeyWrap;
use bouncycastle_core_test_framework::mac::TestFrameworkMAC;
use bouncycastle_core_test_framework::symmetric_ciphers::{
    TestFrameworkStreamCipher, TestFrameworkSymmetricCipher,
};
use bouncycastle_rng::FixedSeedRNG;

/// A 32-byte frame for the fixed-frame CCM key, within the framework's seed buffer.
type Packet = CCM_Packet<12, 16, 64, 32>;

fn make_key<P, M, const KEY_LEN: usize>() -> BlockCipherKey<P, M>
where
    P: Permutation<KEY_LEN>,
    M: Mode<P>,
{
    BlockCipherKey::from_key_material(&material::<KEY_LEN>()).expect("a valid key")
}

/// The construction suite -- key type, strength and `generate` -- for every mode a key can carry,
/// against the name the permutation gives that mode.
pub fn construction<P: Permutation<KEY_LEN>, const KEY_LEN: usize>() {
    fn suite<P: Permutation<KEY_LEN>, M: Mode<P>, const KEY_LEN: usize>(name: &'static str) {
        TestFrameworkFromKeyMaterial::new()
            .test::<KEY_LEN, BlockCipherKey<P, M>>(name, P::MAX_SECURITY_STRENGTH);
    }
    suite::<P, CBC<Blocks>, KEY_LEN>(P::CBC_ALG_NAME);
    suite::<P, CBC<PKCS7>, KEY_LEN>(P::CBC_ALG_NAME);
    suite::<P, CBC<NoPadding>, KEY_LEN>(P::CBC_ALG_NAME);
    suite::<P, ECB<Blocks>, KEY_LEN>(P::ECB_ALG_NAME);
    suite::<P, ECB<PKCS7>, KEY_LEN>(P::ECB_ALG_NAME);
    suite::<P, CFB, KEY_LEN>(P::CFB_ALG_NAME);
    suite::<P, CFB8, KEY_LEN>(P::CFB8_ALG_NAME);
    suite::<P, CTR, KEY_LEN>(P::CTR_ALG_NAME);
    suite::<P, GCM, KEY_LEN>(P::GCM_ALG_NAME);
    suite::<P, Packet, KEY_LEN>(P::CCM_ALG_NAME);
    suite::<P, KW, KEY_LEN>(P::KW_ALG_NAME);
    suite::<P, KWP, KEY_LEN>(P::KWP_ALG_NAME);
}

/// The key-wrap suite: round trips, the length helpers, the error cases and tamper rejection, at
/// an aligned and an unaligned length and KWP's single-block case.
pub fn key_wrap<P: Permutation<KEY_LEN>, const KEY_LEN: usize>() {
    let tf = TestFrameworkKeyWrap::new();
    tf.test::<KEY_LEN, 16, 24, BlockCipherKey<P, KW>>();
    tf.test::<KEY_LEN, 32, 40, BlockCipherKey<P, KW>>();
    tf.test::<KEY_LEN, 7, 16, BlockCipherKey<P, KWP>>();
    tf.test::<KEY_LEN, 20, 32, BlockCipherKey<P, KWP>>();
    tf.test::<KEY_LEN, 32, 40, BlockCipherKey<P, KWP>>();
}

/// The block-cipher suite over `CBC<Blocks>` and the ECB suite over `ECB<Blocks>`.
pub fn block_modes<P: Permutation<KEY_LEN>, const KEY_LEN: usize>() {
    let framework = TestFrameworkBlockCipher::new();
    framework.test_key::<KEY_LEN, 16, 16, _>(&make_key::<P, CBC<Blocks>, KEY_LEN>(), &mut rng());
    framework.test_ecb_key::<KEY_LEN, 16, _>(&make_key::<P, ECB<Blocks>, KEY_LEN>());
}

/// The symmetric-cipher suite over the padded modes, and, with the alignment the framework is
/// told to enforce, over the `NoPadding` ones.
pub fn padded_modes<P: Permutation<KEY_LEN>, const KEY_LEN: usize>() {
    let framework = TestFrameworkSymmetricCipher::new();
    framework.test_key::<KEY_LEN, 16, 16, _>(&make_key::<P, CBC<PKCS7>, KEY_LEN>(), &mut rng());
    framework.test_key::<KEY_LEN, 0, 16, _>(&make_key::<P, ECB<PKCS7>, KEY_LEN>(), &mut rng());
    let mut framework = TestFrameworkSymmetricCipher::new();
    framework.required_alignment = 16;
    framework.test_key::<KEY_LEN, 16, 16, _>(&make_key::<P, CBC<NoPadding>, KEY_LEN>(), &mut rng());
    framework.test_key::<KEY_LEN, 0, 16, _>(&make_key::<P, ECB<NoPadding>, KEY_LEN>(), &mut rng());
}

/// The stream-cipher suite over CFB, CFB8 and CTR.
pub fn stream_modes<P: Permutation<KEY_LEN>, const KEY_LEN: usize>() {
    let framework = TestFrameworkStreamCipher::new();
    framework.test_key::<KEY_LEN, 16, _>(&make_key::<P, CFB, KEY_LEN>(), &mut rng());
    framework.test_key::<KEY_LEN, 16, _>(&make_key::<P, CFB8, KEY_LEN>(), &mut rng());
    framework.test_key::<KEY_LEN, 12, _>(&make_key::<P, CTR, KEY_LEN>(), &mut rng());
}

/// The AEAD suite and the inline `ciphertext || tag` layout over GCM, and the AEAD suite over the
/// fixed-frame CCM key at the one length its workers accept.
pub fn aead_modes<P: Permutation<KEY_LEN>, const KEY_LEN: usize>() {
    let framework = TestFrameworkAEADCipher::new();
    framework.test_key::<KEY_LEN, 12, 16, 16, _>(&make_key::<P, GCM, KEY_LEN>(), &mut rng());
    TestFrameworkAEADTaggedLayout::new().test_key::<KEY_LEN, 12, 16, 16, _>(&make_key::<
        P,
        GCM,
        KEY_LEN,
    >());
    let mut framework = TestFrameworkAEADCipher::new();
    framework.fixed_message_len = Some(32);
    framework.test_key::<KEY_LEN, 12, 16, 16, _>(&make_key::<P, Packet, KEY_LEN>(), &mut rng());
}

/// The nonce is drawn per GCM encryption, so the same plaintext gives different ciphertext, and
/// each still round-trips.
pub fn gcm_draws_a_fresh_nonce<P: Permutation<KEY_LEN>, const KEY_LEN: usize>() {
    let data = *b"the quick brown fox jumps over the lazy dog!!!";
    let key = make_key::<P, GCM, KEY_LEN>();
    let mut rng = rng();
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..16 {
        let mut ct = [0u8; 46];
        let (_, nonce, tag) = key.encrypt_detached_out(&mut rng, b"aad", &data, &mut ct).unwrap();
        assert!(seen.insert(nonce), "nonce repeated across encryptions");
        let mut pt = [0u8; 46];
        key.decrypt_detached_out(&nonce, b"aad", &ct, &tag, &mut pt).unwrap();
        assert_eq!(pt, data);
    }
}

/// ECB has no init data, so the `ECB<Blocks>` key makes its workers with no RNG and nothing to
/// return, and the `ECB<PKCS7>` key, on the symmetric path, takes an RNG it never draws from and
/// returns `[u8; 0]`. The padded ciphertext is the block pair's encryption of the padded block.
pub fn ecb_takes_no_init_data<P: Permutation<KEY_LEN>, const KEY_LEN: usize>() {
    let key = make_key::<P, ECB<Blocks>, KEY_LEN>();
    let mut padded_hello = *b"hello\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
    let mut enc = key.create_encryptor();
    enc.do_encrypt_blocks_inplace(core::slice::from_mut(&mut padded_hello)).unwrap();
    let mut again = *b"hello\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
    assert_eq!(key.encrypt_inplace(&mut again).unwrap(), 16);
    assert_eq!(again, padded_hello, "the worker and the one-shot are the same codebook");

    let padded_key = make_key::<P, ECB<PKCS7>, KEY_LEN>();
    let mut out = [0u8; 16];
    // A seedless RNG panics on any draw, so finishing is the proof that none is made.
    let (written, init): (usize, [u8; 0]) =
        padded_key.encrypt_out(&mut FixedSeedRNG::new([]), b"hello", &mut out).unwrap();
    assert_eq!((written, init), (16, []));
    assert_eq!(out, padded_hello, "PKCS7 over ECB is ECB of the padded block");
    assert_eq!(padded_key.decrypt(&init, &out).unwrap(), b"hello");
}

/// Under a pinned IV, the `CBC<Blocks>` key's in-place one-shot and the `CBC<NoPadding>` key's
/// `encrypt_out` are the same bytes: `NoPadding` is an alignment check over the same mode, and
/// each key's decryptor opens the other's ciphertext.
pub fn cbc_blocks_agrees_with_no_padding<P: Permutation<KEY_LEN>, const KEY_LEN: usize>() {
    let iv = [0xA5u8; 16];
    let msg: [u8; 48] = core::array::from_fn(|i| (i * 7 + 3) as u8);

    let mut in_place = msg;
    let n =
        make_key::<P, CBC<Blocks>, KEY_LEN>().encrypt_inplace_nonce(&iv, &mut in_place).unwrap();
    assert_eq!(n, 48);

    let mut out = [0u8; 48];
    let m =
        make_key::<P, CBC<NoPadding>, KEY_LEN>().encrypt_nonce_out(&iv, &msg, &mut out).unwrap();
    assert_eq!(m, 48);
    assert_eq!(out, in_place);

    make_key::<P, CBC<Blocks>, KEY_LEN>().decrypt_inplace(&iv, &mut out).unwrap();
    assert_eq!(out, msg);
    let mut back = [0u8; 64];
    let k =
        make_key::<P, CBC<NoPadding>, KEY_LEN>().decrypt_out(&iv, &in_place, &mut back).unwrap();
    assert_eq!(&back[..k], &msg[..]);
}

/// Equality is over the expanded schedule, so it follows the material: the same bytes compare
/// equal, as does a clone, and a single flipped bit does not.
pub fn equality<P: Permutation<KEY_LEN>, const KEY_LEN: usize>()
where
    BlockCipherKey<P, CTR>: PartialEq,
{
    let key = make_key::<P, CTR, KEY_LEN>();
    assert!(key == key.clone());
    assert!(key == make_key::<P, CTR, KEY_LEN>());
    assert!(
        key != BlockCipherKey::<P, CTR>::from_key_material(&material_flipped::<KEY_LEN>()).unwrap()
    );
}

/// A MAC-mode key's `KEY_TYPE` is the `MACKey` the mode asks for: MAC material builds it and
/// cipher material is refused by type, for both MAC modes, and `generate` draws a MAC key. Where
/// the key is longer than 128 bits, a MAC key labelled below its own strength is refused at
/// construction, as a cipher key of that strength is: the retagged copy the permutation is
/// built from carries the strength.
pub fn mac_material_policy<P: Permutation<KEY_LEN>, const KEY_LEN: usize>() {
    fn refused<K>(r: Result<K, SymmetricCipherError>) {
        assert!(matches!(
            r,
            Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_)))
        ));
    }
    type Cmac<P> = BlockCipherKey<P, CMAC>;
    type Gmac<P> = BlockCipherKey<P, GMAC>;
    assert_eq!(<Cmac<P> as FromKeyMaterial<KEY_LEN>>::KEY_TYPE, KeyType::MACKey);
    assert_eq!(<Gmac<P> as FromKeyMaterial<KEY_LEN>>::KEY_TYPE, KeyType::MACKey);
    assert!(Cmac::<P>::from_key_material(&mac_material::<KEY_LEN>()).is_ok());
    assert!(Gmac::<P>::from_key_material(&mac_material::<KEY_LEN>()).is_ok());
    refused(Cmac::<P>::from_key_material(&material::<KEY_LEN>()));
    refused(Gmac::<P>::from_key_material(&material::<KEY_LEN>()));
    assert!(Cmac::<P>::generate(&mut rng()).is_ok());

    if KEY_LEN > 16 {
        let mut weak = mac_material::<KEY_LEN>();
        weak.set_security_strength(SecurityStrength::_128bit).unwrap();
        assert!(matches!(
            Cmac::<P>::from_key_material(&weak),
            Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::SecurityStrength(_)))
        ));
        assert!(matches!(
            Gmac::<P>::from_key_material(&weak),
            Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::SecurityStrength(_)))
        ));
    }
}

/// A CMAC key tags and verifies through the role pair, passes the shared MAC key suite, and the
/// tag is bound to the message and the key.
pub fn cmac_round_trip<P: Permutation<KEY_LEN>, const KEY_LEN: usize>() {
    let key = BlockCipherKey::<P, CMAC>::from_key_material(&mac_material::<KEY_LEN>()).unwrap();
    let mut generator = key.create_generator();
    generator.do_update(b"a message that arrives ");
    generator.do_update(b"in pieces");
    let tag: [u8; 16] = generator.do_final();
    assert_eq!(key.mac(b"a message that arrives in pieces"), tag);
    TestFrameworkMAC::new().test_mac_key(&key, b"a message that arrives in pieces", &tag);
    let other = BlockCipherKey::<P, CMAC>::from_key_material(
        &KeyMaterial::<KEY_LEN>::from_bytes_as_type(&[0x43; KEY_LEN], KeyType::MACKey).unwrap(),
    )
    .unwrap();
    assert!(other.verify(b"a message that arrives in pieces", &tag).is_err());
}

/// A GMAC key's generator draws a nonce, its verifier checks under it, the tag is bound to the
/// nonce, the message and the key, and it is the GCM key's tag over the same bytes as AAD with no
/// payload.
pub fn gmac_round_trip<P: Permutation<KEY_LEN>, const KEY_LEN: usize>() {
    let key = BlockCipherKey::<P, GMAC>::from_key_material(&mac_material::<KEY_LEN>()).unwrap();
    let (mut generator, nonce) = key.create_generator(&mut rng()).unwrap();
    generator.do_update(b"a message that arrives ");
    generator.do_update(b"in pieces");
    let tag: [u8; 16] = generator.do_final();
    assert!(key.verify(&nonce, b"a message that arrives in pieces", &tag).is_ok());
    TestFrameworkMAC::new().test_nonce_mac_key(
        &key,
        &nonce,
        b"a message that arrives in pieces",
        &tag,
    );
    let (_, second_nonce) = key.create_generator(&mut rng()).unwrap();
    assert_ne!(second_nonce, nonce, "each generator draws its own nonce");

    const MSG: &[u8] = b"The quick brown fox jumps over the lazy dog";
    let (_, nonce, from_gcm) =
        make_key::<P, GCM, KEY_LEN>().encrypt_detached_out(&mut rng(), MSG, &[], &mut []).unwrap();
    let as_mac = KeyMaterial::<KEY_LEN>::from_bytes_as_type(
        material::<KEY_LEN>().ref_to_bytes(),
        KeyType::MACKey,
    )
    .unwrap();
    let gmac = BlockCipherKey::<P, GMAC>::from_key_material(&as_mac).unwrap();
    assert_eq!(gmac.mac_nonce(&nonce, MSG), from_gcm);
    assert!(gmac.verify(&nonce, MSG, &from_gcm).is_ok());
}
