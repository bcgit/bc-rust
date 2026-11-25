//! Structural tests for CBC with ciphertext stealing (CBC-CS1, CBC-CS2, CBC-CS3), driven by a toy
//! permutation.
//!
//! These check the mode independently of any real cipher: the symmetric-cipher contract for each
//! variant, the key policy, and that decryption takes CBC's batched paths for the blocks it
//! releases while the final's last two portions go a block at a time. The known answers are in the
//! `aes` suites, `crypto/symmetric/tests/aes_cbc_cs_*`.

mod common;

use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{
    FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle_core_test_framework::from_key_material::TestFrameworkFromKeyMaterial;
use bouncycastle_core_test_framework::symmetric_ciphers::TestFrameworkSymmetricCipher;
use bouncycastle_symmetric::BlockCipherKey;
use bouncycastle_symmetric::modes::{CBC_CS_FINAL_LEN, CBC_CS1, CBC_CS2, CBC_CS3, ModeNames};
use common::{SwappedFourToy, SwappedPairToy, TOY_LEN, Toy, os_rng, toy_key};

fn key<P, M>() -> BlockCipherKey<P, M>
where
    BlockCipherKey<P, M>: FromKeyMaterial<TOY_LEN>,
    M: bouncycastle_core::hazmat::Mode<P>,
{
    BlockCipherKey::from_key_material(&toy_key()).expect("the toy key")
}

/// The symmetric-cipher suite for each variant, with every message shorter than a block refused.
#[test]
fn each_variant_conforms_to_the_symmetric_cipher_framework() {
    let mut framework = TestFrameworkSymmetricCipher::new();
    framework.min_message_len = TOY_LEN;
    framework
        .test_key::<TOY_LEN, TOY_LEN, CBC_CS_FINAL_LEN, _>(&key::<Toy, CBC_CS1>(), &mut os_rng());
    framework
        .test_key::<TOY_LEN, TOY_LEN, CBC_CS_FINAL_LEN, _>(&key::<Toy, CBC_CS2>(), &mut os_rng());
    framework
        .test_key::<TOY_LEN, TOY_LEN, CBC_CS_FINAL_LEN, _>(&key::<Toy, CBC_CS3>(), &mut os_rng());
}

/// The key's construction suite: the type, binding and strength policy of `from_key_material`.
#[test]
fn each_variant_key_enforces_the_material_policy() {
    let framework = TestFrameworkFromKeyMaterial::new();
    framework.test::<TOY_LEN, BlockCipherKey<Toy, CBC_CS1>>(
        Toy::CBC_CS1_ALG_NAME,
        SecurityStrength::_128bit,
    );
    framework.test::<TOY_LEN, BlockCipherKey<Toy, CBC_CS2>>(
        Toy::CBC_CS2_ALG_NAME,
        SecurityStrength::_128bit,
    );
    framework.test::<TOY_LEN, BlockCipherKey<Toy, CBC_CS3>>(
        Toy::CBC_CS3_ALG_NAME,
        SecurityStrength::_128bit,
    );
}

/// `pt` under `IV` and the CBC-CS3 key over `P`.
fn cs3_encrypt<P>(pt: &[u8]) -> Vec<u8>
where
    BlockCipherKey<P, CBC_CS3>:
        FromKeyMaterial<TOY_LEN> + SymmetricEncryptionKey<TOY_LEN, TOY_LEN, CBC_CS_FINAL_LEN>,
    CBC_CS3: bouncycastle_core::hazmat::Mode<P>,
{
    key::<P, CBC_CS3>().encrypt_nonce(&IV, pt).expect("encryption")
}

fn cs3_decrypt<P>(ct: &[u8]) -> Vec<u8>
where
    BlockCipherKey<P, CBC_CS3>:
        FromKeyMaterial<TOY_LEN> + SymmetricDecryptionKey<TOY_LEN, TOY_LEN, CBC_CS_FINAL_LEN>,
    CBC_CS3: bouncycastle_core::hazmat::Mode<P>,
{
    key::<P, CBC_CS3>().decrypt(&IV, ct).expect("decryption")
}

const IV: [u8; TOY_LEN] = [0x3C; TOY_LEN];

/// The blocks a decryptor releases go through CBC's batched decryption, four and two at a time,
/// and the last two portions, which the final takes, a block at a time.
///
/// [`SwappedPairToy`] swaps the results of its pair methods and [`SwappedFourToy`] rotates those
/// of its four-block methods; their single-block methods are correct, and encryption, which is
/// serial, uses only those. So both toys encrypt exactly as [`Toy`] does, and decrypting under them
/// is wrong exactly when the decryptor batches: a 133-byte message (nine blocks, seven released as
/// a four, a pair and one) decrypts wrongly under both, and a 40-byte one (three blocks, one
/// released), whose last two portions are all the final's, decrypts correctly.
#[test]
fn decryption_takes_the_batched_paths_and_the_final_does_not() {
    for len in [133usize, 40] {
        let pt: Vec<u8> = (0..len).map(|i| (i * 13 + 5) as u8).collect();
        let ct = cs3_encrypt::<Toy>(&pt);
        assert_eq!(cs3_encrypt::<SwappedPairToy>(&pt), ct, "{len}: encryption never pairs");
        assert_eq!(cs3_encrypt::<SwappedFourToy>(&pt), ct, "{len}: encryption never batches");
        assert_eq!(cs3_decrypt::<Toy>(&ct), pt, "{len}: the correct toy round-trips");

        let batches = len.div_ceil(TOY_LEN) - 2 >= 4;
        assert_eq!(cs3_decrypt::<SwappedPairToy>(&ct) != pt, batches, "{len}: the pair path");
        assert_eq!(cs3_decrypt::<SwappedFourToy>(&ct) != pt, batches, "{len}: the four path");
    }
}
