//! A key that cannot run the derivation itself reads the KDF's description: the shape the
//! description/engine split exists for. `TokenKey` stands for a key held in a token or an HSM,
//! which does ECC CDH and HKDF inside the device so that `Z` never leaves it. It implements the
//! agreement role over the same `KdfParams<'p, HkdfDescription<'s, SHA256>, LEN>` the library's
//! P-256 keys do, so one call site serves both; its worker reads the description's hash, salt
//! and the fixed info and hands them to "the device", here the library's own primitive and HKDF
//! by hand, and its key agrees with the library's software key.

use bouncycastle_core::agreement_key::AgreementKey;
use bouncycastle_core::errors::KeyAgreementError;
use bouncycastle_core::kdf_params::{KdfDescription, KdfParams, KeyLen};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterial0, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, AlgorithmInfo, KDF, KeyAgreement};
use bouncycastle_core_test_framework::DUMMY_SEED;
use bouncycastle_ec::P256;
use bouncycastle_eccdh::eccdh::ECCDH_HKDF_SHA256;
use bouncycastle_eccdh::keys::{ECCDHPrivateKey, ECCDHPublicKey};
use bouncycastle_eccdh::keys_common::AgreementKeyPair;
use bouncycastle_hkdf::HkdfDescription;
use bouncycastle_rng::DefaultRNG;
use bouncycastle_sha2::SHA256;
use bouncycastle_sha2::hkdf::HKDF_SHA256;

/// The device's side of the key: it holds the private key and never hands it out. A real token
/// would hold a handle; this one holds the library's key so the test can run.
struct Token {
    sk: ECCDHPrivateKey<P256>,
}

impl Token {
    /// The device mechanism: ECC CDH then HKDF, from the parameters as the application stated
    /// them, with `Z` never leaving. `salt` is `None` for the absent salt.
    fn derive(
        &self,
        peer_pk: &ECCDHPublicKey<P256>,
        salt: Option<&dyn KeyMaterialTrait>,
        info: &[u8],
        out: &mut KeyMaterial<32>,
    ) -> Result<(), KeyAgreementError> {
        let z = self.sk.agree(peer_pk, ())?;
        let absent = KeyMaterial0::new();
        let salt = salt.unwrap_or(&absent);
        HKDF_SHA256::extract_and_expand_out(salt, &z, info, 32, out)
            .map_err(KeyAgreementError::KDFError)?;
        Ok(())
    }
}

/// The application's handle on the token key: no material, only the roles.
struct TokenKey<'t> {
    token: &'t Token,
}

/// The worker: the handle and the parameters the application gave, read when it agrees.
struct TokenAgreement<'k, 'p, 's> {
    key: &'k TokenKey<'k>,
    params: KdfParams<'p, HkdfDescription<'s, SHA256>, 32>,
}

impl AlgorithmInfo for TokenAgreement<'_, '_, '_> {
    fn alg_name(&self) -> &'static str {
        ECCDH_HKDF_SHA256::<P256>::ALG_NAME
    }
    fn max_security_strength(&self) -> SecurityStrength {
        ECCDH_HKDF_SHA256::<P256>::MAX_SECURITY_STRENGTH
    }
}

impl KeyAgreement<ECCDHPublicKey<P256>, 32> for TokenAgreement<'_, '_, '_> {
    fn agree_out(
        &self,
        peer_pk: &ECCDHPublicKey<P256>,
        ss: &mut KeyMaterial<32>,
    ) -> Result<usize, KeyAgreementError> {
        ss.zeroize();
        // What the description makes readable: the KDF's identity and its salt, beside the info.
        let hkdf = self.params.kdf();
        assert_eq!(hkdf.alg_name(), HKDF_SHA256::ALG_NAME);
        self.key.token.derive(peer_pk, hkdf.salt(), self.params.info(), ss)?;
        Ok(32)
    }
}

impl<'p, 's> AgreementKey<KdfParams<'p, HkdfDescription<'s, SHA256>, 32>, 32> for TokenKey<'_> {
    type Algorithm = ECCDH_HKDF_SHA256<P256>;
    type PublicKey = ECCDHPublicKey<P256>;
    type Agreement<'k>
        = TokenAgreement<'k, 'p, 's>
    where
        Self: 'k;

    fn create_agreement<'k>(
        &'k self,
        params: KdfParams<'p, HkdfDescription<'s, SHA256>, 32>,
    ) -> Result<Self::Agreement<'k>, KeyAgreementError> {
        Ok(TokenAgreement { key: self, params })
    }
}

/// One function for both kinds of key: the application names the derivation once.
fn agree_with<'p, 's, K>(
    key: &K,
    peer_pk: &ECCDHPublicKey<P256>,
    params: KdfParams<'p, HkdfDescription<'s, SHA256>, 32>,
) -> KeyMaterial<32>
where
    K: AgreementKey<
            KdfParams<'p, HkdfDescription<'s, SHA256>, 32>,
            32,
            PublicKey = ECCDHPublicKey<P256>,
        >,
{
    key.agree(peer_pk, params).unwrap()
}

#[test]
fn a_token_key_reads_the_description_and_agrees_with_a_software_key() {
    let mut rng = DefaultRNG::default();
    let (pk_token, sk_token) = P256::generate_agreement_key_pair(&mut rng).unwrap();
    let (pk_soft, sk_soft) = P256::generate_agreement_key_pair(&mut rng).unwrap();
    let token = Token { sk: sk_token };
    let token_key = TokenKey { token: &token };

    let salt =
        KeyMaterial::<32>::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::CryptographicRandom)
            .unwrap();
    let hkdf = HkdfDescription::<SHA256>::with_salt(&salt).unwrap();
    let params = KdfParams::new(&hkdf, b"token key tests", KeyLen::<32>);

    let from_token = agree_with(&token_key, &pk_soft, params);
    let from_software = agree_with(&sk_soft, &pk_token, params);
    assert!(from_token.equals(&from_software));

    // The engine the description builds is what the software side ran.
    let z = sk_soft.agree(&pk_token, ()).unwrap();
    let by_engine = hkdf.engine().unwrap().derive_key(&z, b"token key tests", 32).unwrap();
    assert!(by_engine.equals(&from_software));

    // The absent salt reaches the device as such.
    let no_salt = HkdfDescription::<SHA256>::new();
    let params = KdfParams::new(&no_salt, b"token key tests", KeyLen::<32>);
    assert!(
        agree_with(&token_key, &pk_soft, params).equals(&agree_with(&sk_soft, &pk_token, params))
    );
    assert!(!agree_with(&token_key, &pk_soft, params).equals(&from_token));

    let worker = token_key.create_agreement(params).unwrap();
    assert_eq!(worker.alg_name(), "ECC-CDH-P256-HKDF-SHA256");
    let _: &dyn KeyAgreement<ECCDHPublicKey<P256>, 32> = &worker;
}
