//! [`DHKEM`], generic over the Diffie-Hellman group: a group's crate implements [`DHKEMParams`]
//! for its algorithm struct and calls [`DHKEM::encap_rng_out`] and [`DHKEM::decap_out`] from the
//! workers its keys hand out.

use crate::hazmat::{self as labeled, MAX_NH};
use bouncycastle_core::errors::{KEMError, KeyAgreementError, KeyMaterialError, RNGError};
use bouncycastle_core::kem_key::KEMAlgorithm;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, HashAlgParams, RNG};
use bouncycastle_digest::hmac::HMACParams;
use bouncycastle_utils::secret::Secret;
use core::marker::PhantomData;

// The labels of RFC 9180 Sections 4.1 and 7.1.3.
const LABEL_EAE_PRK: &[u8] = b"eae_prk";
const LABEL_SHARED_SECRET: &[u8] = b"shared_secret";
const LABEL_DKP_PRK: &[u8] = b"dkp_prk";
const LABEL_SK: &[u8] = b"sk";
const LABEL_CANDIDATE: &[u8] = b"candidate";

/// A strength as a bit count, for the compile-time check that a group's hash is long enough.
const fn strength_bits(strength: SecurityStrength) -> usize {
    match strength {
        SecurityStrength::None => 0,
        SecurityStrength::_112bit => 112,
        SecurityStrength::_128bit => 128,
        SecurityStrength::_192bit => 192,
        SecurityStrength::_256bit => 256,
        #[allow(unreachable_patterns)] // the enum is non_exhaustive
        _ => 256,
    }
}

/// How a group derives a key pair from keying material: the two forms of `DeriveKeyPair` in RFC
/// 9180 Section 7.1.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeriveKeyPairForm {
    /// X25519 and X448: "the DeriveKeyPair() function applies a KDF to the input",
    /// `sk = LabeledExpand(dkp_prk, "sk", "", Nsk)`.
    Expand,
    /// P-256, P-384 and P-521: "the DeriveKeyPair() function of the KEM performs rejection
    /// sampling over field elements", each candidate
    /// `LabeledExpand(dkp_prk, "candidate", I2OSP(counter, 1), Nsk)` with its first byte ANDed
    /// with `bitmask` ("0xFF for P-256 and P-384, and 0x01 for P-521").
    Candidate {
        /// The mask on the candidate's first byte.
        bitmask: u8,
    },
}

/// A KEM of RFC 9180 Section 7.1, Table 2: implemented by the algorithm marker of a key's
/// [`EncapsulatingKey`](bouncycastle_core::kem_key::EncapsulatingKey) and
/// [`DecapsulatingKey`](bouncycastle_core::kem_key::DecapsulatingKey) roles, which makes the key
/// one HPKE can be run over.
pub trait HpkeKem: KEMAlgorithm {
    /// The `kem_id`.
    const KEM_ID: u16;
}

/// `AuthEncap` of an authenticated KEM (RFC 9180 Section 4), on the recipient's public key: the
/// encapsulation that binds the sender's private key into the shared secret. With
/// [`AuthDecapsulatingKey`] it is what HPKE's Auth and AuthPSK modes run over. `N_ENC` and
/// `N_SECRET` are the KEM's Nenc and Nsecret.
pub trait AuthEncapsulatingKey<const N_ENC: usize, const N_SECRET: usize> {
    /// The sender's private key.
    type SenderPrivateKey;

    /// `AuthEncap(pkR, skS)` with `self` as `pkR`: the ciphertext into `enc` and the shared
    /// secret into `ss`, both zeroized first and left so on an error. Returns the number of
    /// ciphertext bytes written, always `N_ENC`.
    ///
    /// # Errors
    /// As the key's unauthenticated encapsulation, and if `sk_s` is not usable.
    fn auth_encaps_out(
        &self,
        rng: &mut dyn RNG,
        sk_s: &Self::SenderPrivateKey,
        enc: &mut [u8; N_ENC],
        ss: &mut KeyMaterial<N_SECRET>,
    ) -> Result<usize, KEMError>;
}

/// `AuthDecap` of an authenticated KEM (RFC 9180 Section 4), on the recipient's private key.
/// See [`AuthEncapsulatingKey`].
pub trait AuthDecapsulatingKey<const N_ENC: usize, const N_SECRET: usize> {
    /// The sender's public key.
    type SenderPublicKey;

    /// `AuthDecap(enc, skR, pkS)` with `self` as `skR`: the shared secret into `ss`, zeroized
    /// first and left so on an error. Returns the number of secret bytes written, always
    /// `N_SECRET`. The secret is the sender's only if `enc` was made under the private key of
    /// `pk_s`; a wrong `pk_s` is not an error here, it gives another secret.
    ///
    /// # Errors
    /// As the key's unauthenticated decapsulation, and
    /// [`KEMError::InvalidPublicKey`] if `pk_s` fails the KEM's validation.
    fn auth_decaps_out(
        &self,
        enc: &[u8; N_ENC],
        pk_s: &Self::SenderPublicKey,
        ss: &mut KeyMaterial<N_SECRET>,
    ) -> Result<usize, KEMError>;
}

/// The Diffie-Hellman group of a DHKEM, and the KDF it is paired with: DHKEM(Group, KDF) in RFC 9180
/// Section 4.1.
///
/// Implemented by a group's algorithm struct. The const parameters are the group's sizes from RFC
/// 9180 Section 7.1: `N_PK` is Npk (which equals Nenc), `N_SK` is Nsk and `N_DH` is Ndh.
pub trait DHKEMParams<const N_PK: usize, const N_SK: usize, const N_DH: usize>: Algorithm {
    /// The group's public key.
    type PublicKey;
    /// The group's private key.
    type PrivateKey;
    /// The hash of the DHKEM's KDF, which is HKDF over this hash.
    type KDFHash: HMACParams;
    /// The `kem_id` of RFC 9180 Section 7.1, Table 2.
    const KEM_ID: u16;

    /// `GenerateKeyPair()` (RFC 9180 Section 4), drawing its randomness from `rng`, with the pair
    /// lent to `f` rather than returned, so that the DHKEM never moves the ephemeral key of an
    /// encapsulation: it lives in the implementation's frame and is dropped there. Whether it
    /// is moved before that is the group's own key generation's matter; a group that can
    /// generates the key in place, and one that cannot says so in its Security Considerations.
    fn with_generated_key_pair<R>(
        rng: &mut dyn RNG,
        f: impl FnOnce(&Self::PublicKey, &Self::PrivateKey) -> R,
    ) -> Result<R, KEMError>;

    /// The private key with the byte string `sk` as its value, as `DeriveKeyPair` (RFC 9180
    /// Section 7.1.3) requires, or `None` if `sk` is not a private key of the group: for the
    /// candidate form, the loop's test `sk == 0 or sk >= order`.
    fn private_key_from_bytes(sk: &[u8; N_SK]) -> Option<Self::PrivateKey>;

    /// `pk(skX)` (RFC 9180 Section 4): the public key of `sk`.
    fn pk(sk: &Self::PrivateKey) -> Self::PublicKey;

    /// Which form of `DeriveKeyPair` (RFC 9180 Section 7.1.3) the group has.
    const DERIVE_KEY_PAIR: DeriveKeyPairForm;

    /// `DH(skX, pkY)` (RFC 9180 Section 4.1) into `out`, including the validation of its output
    /// that RFC 9180 Section 7.1.4 requires for the group. A validation failure is an `Err`, with
    /// `out` left zeroized.
    fn dh_into(
        sk: &Self::PrivateKey,
        pk: &Self::PublicKey,
        out: &mut Secret<[u8; N_DH]>,
    ) -> Result<(), KeyAgreementError>;

    /// `SerializePublicKey(pkX)` (RFC 9180 Section 7.1.1).
    fn serialize_public_key(pk: &Self::PublicKey) -> [u8; N_PK];

    /// `DeserializePublicKey(pkXm)` (RFC 9180 Section 7.1.1).
    fn deserialize_public_key(pkm: &[u8; N_PK]) -> Result<Self::PublicKey, KEMError>;
}

/// The DHKEM of RFC 9180 Section 4.1 over the group `G`.
///
/// The const parameters are `G`'s sizes (see [`DHKEMParams`]) plus `N_SECRET`, the Nsecret of RFC
/// 9180 Section 7.1, which must equal the output length of [`DHKEMParams::KDFHash`] (Section 4.1:
/// "the size Nsecret of the KEM shared secret is equal to the output length of the hash function
/// underlying the KDF"). That, and the other relations between the parameters, are checked when
/// a DHKEM is used, so DHKEM(X25519, HKDF-SHA256) with its Nsecret of 32 compiles:
///
/// ```
/// use bouncycastle_core::traits::PrivateKey;
/// use bouncycastle_ed::x25519::{X25519, X25519PrivateKey};
/// use bouncycastle_dhkem::DHKEM;
///
/// let sk = X25519PrivateKey::from_bytes(&[7u8; 32]).unwrap();
/// let _ = DHKEM::<X25519, 32, 32, 32, 32>::decap(&[9u8; 32], &sk);
/// ```
///
/// and with an Nsecret that is not SHA-256's output length it does not:
///
/// ```compile_fail
/// use bouncycastle_core::traits::PrivateKey;
/// use bouncycastle_ed::x25519::{X25519, X25519PrivateKey};
/// use bouncycastle_dhkem::DHKEM;
///
/// let sk = X25519PrivateKey::from_bytes(&[7u8; 32]).unwrap();
/// let _ = DHKEM::<X25519, 32, 32, 32, 64>::decap(&[9u8; 32], &sk);
/// ```
pub struct DHKEM<G, const N_PK: usize, const N_SK: usize, const N_DH: usize, const N_SECRET: usize>
{
    _group: PhantomData<G>,
}

impl<
    G: DHKEMParams<N_PK, N_SK, N_DH>,
    const N_PK: usize,
    const N_SK: usize,
    const N_DH: usize,
    const N_SECRET: usize,
> DHKEM<G, N_PK, N_SK, N_DH, N_SECRET>
{
    /// `suite_id = concat("KEM", I2OSP(kem_id, 2))` (RFC 9180 Section 4.1).
    const SUITE_ID: [u8; 5] = {
        let kem_id = G::KEM_ID.to_be_bytes();
        [b'K', b'E', b'M', kem_id[0], kem_id[1]]
    };

    /// Checked when a DHKEM is instantiated, so a wrong set of const parameters fails to compile.
    const PARAMS_CHECK: () = {
        let nh = <G::KDFHash as HashAlgParams>::OUTPUT_LEN;
        assert!(N_SECRET == nh, "Nsecret must equal the output length of the KDF's hash");
        assert!(nh <= MAX_NH, "the KDF's hash output is longer than MAX_NH");
        // HKDF-Expand's L, which here is Nsecret or Nsk, must be at most 255*HashLen (RFC 5869
        // Section 2.3), and fit the two bytes of I2OSP(L, 2) in LabeledExpand.
        assert!(N_SK <= 255 * nh && N_SK <= 0xFFFF, "Nsk is too long for HKDF-Expand");
        // RFC 9180 Section 7.1, Table 2 pairs each group with a hash of at least twice its
        // strength (X25519 with SHA-256, P-384 with SHA-384, P-521 and X448 with SHA-512); a
        // shorter hash would cap the KEM's secret below the group.
        assert!(
            8 * nh >= 2 * strength_bits(G::MAX_SECURITY_STRENGTH),
            "the KDF's hash must offer twice the group's strength"
        );
    };

    /// `Encap(pkR)` (RFC 9180 Section 4.1), with the ephemeral key pair generated from `rng`:
    /// the shared secret, a [`KeyType::CryptographicRandom`] key at the group's security
    /// strength, into `shared_secret`, and the ephemeral public key into `enc`, each zeroized
    /// first and left so on the error path. Returns the number of bytes written to
    /// `enc`, always Nenc.
    ///
    /// # Errors
    /// * [`KEMError::RNGError`] if `rng`'s security strength is below the group's.
    /// * [`KEMError::InvalidPublicKey`] if `pk_r` fails the group's validation (RFC 9180 Section
    ///   7.1.4), such as an all-zero X25519 output.
    pub fn encap_rng_out(
        pk_r: &G::PublicKey,
        rng: &mut dyn RNG,
        enc: &mut [u8; N_PK],
        shared_secret: &mut KeyMaterial<N_SECRET>,
    ) -> Result<usize, KEMError> {
        let () = Self::PARAMS_CHECK;
        enc.fill(0);
        shared_secret.zeroize();
        if rng.security_strength() < G::MAX_SECURITY_STRENGTH {
            return Err(RNGError::SecurityStrengthInsufficientForAlgorithm.into());
        }
        // skE, pkE = GenerateKeyPair(); skE stays in the group's frame and is dropped there.
        let mut dh = Secret::<[u8; N_DH]>::new();
        G::with_generated_key_pair(rng, |pk_e, sk_e| {
            // dh = DH(skE, pkR)
            G::dh_into(sk_e, pk_r, &mut dh)?;
            // enc = SerializePublicKey(pkE)
            *enc = G::serialize_public_key(pk_e);
            Ok(())
        })?
        .map_err(|_: KeyAgreementError| {
            KEMError::InvalidPublicKey("The recipient's public key failed validation")
        })?;
        // pkRm = SerializePublicKey(pkR); kem_context = concat(enc, pkRm)
        let pk_rm = G::serialize_public_key(pk_r);
        // shared_secret = ExtractAndExpand(dh, kem_context)
        Self::extract_and_expand_into(&[&*dh], &[&*enc, &pk_rm], shared_secret);
        Ok(N_PK)
    }

    /// [`Self::encap_rng_out`] returning the pair by value: the shared secret is moved out of
    /// this frame, which does not wipe its source; prefer the `_out` form where that matters.
    pub fn encap_rng(
        pk_r: &G::PublicKey,
        rng: &mut dyn RNG,
    ) -> Result<(KeyMaterial<N_SECRET>, [u8; N_PK]), KEMError> {
        let mut enc = [0u8; N_PK];
        let mut shared_secret = KeyMaterial::new();
        Self::encap_rng_out(pk_r, rng, &mut enc, &mut shared_secret)?;
        Ok((shared_secret, enc))
    }

    /// `Decap(enc, skR)` (RFC 9180 Section 4.1): the shared secret, a
    /// [`KeyType::CryptographicRandom`] key at the group's security strength, into
    /// `shared_secret`, zeroized first and left so on the error path. Returns the number of
    /// bytes written to it, always Nsecret.
    ///
    /// # Errors
    /// [`KEMError::DecapsulationFailed`] if `enc` does not deserialize or the DH output fails the
    /// group's validation.
    pub fn decap_out(
        enc: &[u8; N_PK],
        sk_r: &G::PrivateKey,
        shared_secret: &mut KeyMaterial<N_SECRET>,
    ) -> Result<usize, KEMError> {
        Self::decap_with_pk_out(enc, sk_r, &G::pk(sk_r), shared_secret)
    }

    /// [`Self::decap_out`] with the recipient's public key supplied, for a group whose private
    /// key does not hold it: a worker computes `pk(skR)` once and decapsulates many times.
    /// `pk_r` must be `pk(sk_r)`; it is bound into the shared secret, so a different key gives
    /// a secret the sender does not share. Returns Nsecret, as [`Self::decap_out`].
    ///
    /// # Errors
    /// As [`Self::decap_out`].
    pub fn decap_with_pk_out(
        enc: &[u8; N_PK],
        sk_r: &G::PrivateKey,
        pk_r: &G::PublicKey,
        shared_secret: &mut KeyMaterial<N_SECRET>,
    ) -> Result<usize, KEMError> {
        let () = Self::PARAMS_CHECK;
        shared_secret.zeroize();
        // pkE = DeserializePublicKey(enc)
        let pk_e = G::deserialize_public_key(enc).map_err(|_| KEMError::DecapsulationFailed)?;
        // dh = DH(skR, pkE)
        let mut dh = Secret::<[u8; N_DH]>::new();
        G::dh_into(sk_r, &pk_e, &mut dh).map_err(|_| KEMError::DecapsulationFailed)?;
        // pkRm = SerializePublicKey(pk(skR)); kem_context = concat(enc, pkRm)
        let pk_rm = G::serialize_public_key(pk_r);
        // shared_secret = ExtractAndExpand(dh, kem_context)
        Self::extract_and_expand_into(&[&*dh], &[enc, &pk_rm], shared_secret);
        Ok(N_SECRET)
    }

    /// [`Self::decap_out`] returning the shared secret by value: it is moved out of this frame,
    /// which does not wipe its source; prefer the `_out` form where that matters.
    pub fn decap(
        enc: &[u8; N_PK],
        sk_r: &G::PrivateKey,
    ) -> Result<KeyMaterial<N_SECRET>, KEMError> {
        let mut shared_secret = KeyMaterial::new();
        Self::decap_out(enc, sk_r, &mut shared_secret)?;
        Ok(shared_secret)
    }

    /// `AuthEncap(pkR, skS)` (RFC 9180 Section 4.1), with the ephemeral key pair generated from
    /// `rng`: as [`Self::encap_rng_out`], with the sender's private key `sk_s` bound into the
    /// shared secret, so that only [`Self::auth_decap_out`] with `pk(sk_s)` recovers it. Returns
    /// the number of bytes written to `enc`, always Nenc.
    ///
    /// # Errors
    /// * [`KEMError::RNGError`] if `rng`'s security strength is below the group's.
    /// * [`KEMError::InvalidPublicKey`] if `pk_r` fails the group's validation (RFC 9180 Section
    ///   7.1.4), or `sk_s` is a key the group's DH refuses.
    pub fn auth_encap_rng_out(
        pk_r: &G::PublicKey,
        sk_s: &G::PrivateKey,
        rng: &mut dyn RNG,
        enc: &mut [u8; N_PK],
        shared_secret: &mut KeyMaterial<N_SECRET>,
    ) -> Result<usize, KEMError> {
        let () = Self::PARAMS_CHECK;
        enc.fill(0);
        shared_secret.zeroize();
        if rng.security_strength() < G::MAX_SECURITY_STRENGTH {
            return Err(RNGError::SecurityStrengthInsufficientForAlgorithm.into());
        }
        // dh = concat(DH(skE, pkR), DH(skS, pkR))
        // The static DH is computed first, so that a refused pkR or skS is reported before an
        // ephemeral key is drawn and before `enc` is written.
        let mut dh_s = Secret::<[u8; N_DH]>::new();
        G::dh_into(sk_s, pk_r, &mut dh_s).map_err(|_| {
            KEMError::InvalidPublicKey(
                "The Diffie-Hellman of the sender's private key and the recipient's public key was refused",
            )
        })?;
        // skE, pkE = GenerateKeyPair(); skE stays in the group's frame and is dropped there.
        let mut dh_e = Secret::<[u8; N_DH]>::new();
        G::with_generated_key_pair(rng, |pk_e, sk_e| {
            G::dh_into(sk_e, pk_r, &mut dh_e)?;
            // enc = SerializePublicKey(pkE)
            *enc = G::serialize_public_key(pk_e);
            Ok(())
        })?
        .map_err(|_: KeyAgreementError| {
            KEMError::InvalidPublicKey("The recipient's public key failed validation")
        })?;
        // pkRm = SerializePublicKey(pkR); pkSm = SerializePublicKey(pk(skS))
        // kem_context = concat(enc, pkRm, pkSm)
        let pk_rm = G::serialize_public_key(pk_r);
        let pk_sm = G::serialize_public_key(&G::pk(sk_s));
        // shared_secret = ExtractAndExpand(dh, kem_context)
        Self::extract_and_expand_into(&[&*dh_e, &*dh_s], &[&*enc, &pk_rm, &pk_sm], shared_secret);
        Ok(N_PK)
    }

    /// `AuthDecap(enc, skR, pkS)` (RFC 9180 Section 4.1): as [`Self::decap_out`], with the
    /// sender's public key `pk_s` bound into the shared secret, which is the sender's only if
    /// `enc` came from [`Self::auth_encap_rng_out`] under the private key of `pk_s`. Returns the
    /// number of bytes written to `shared_secret`, always Nsecret.
    ///
    /// # Errors
    /// * [`KEMError::DecapsulationFailed`] if `enc` does not deserialize or its DH output fails
    ///   the group's validation.
    /// * [`KEMError::InvalidPublicKey`] if `pk_s` fails the group's validation (RFC 9180 Section
    ///   7.1.4: "in authenticated modes, the recipient MUST validate the sender's static public
    ///   key pkS").
    pub fn auth_decap_out(
        enc: &[u8; N_PK],
        sk_r: &G::PrivateKey,
        pk_s: &G::PublicKey,
        shared_secret: &mut KeyMaterial<N_SECRET>,
    ) -> Result<usize, KEMError> {
        Self::auth_decap_with_pk_out(enc, sk_r, &G::pk(sk_r), pk_s, shared_secret)
    }

    /// [`Self::auth_decap_out`] with the recipient's public key supplied, as
    /// [`Self::decap_with_pk_out`] is to [`Self::decap_out`]. `pk_r` must be `pk(sk_r)`.
    /// Returns Nsecret.
    ///
    /// # Errors
    /// As [`Self::auth_decap_out`].
    pub fn auth_decap_with_pk_out(
        enc: &[u8; N_PK],
        sk_r: &G::PrivateKey,
        pk_r: &G::PublicKey,
        pk_s: &G::PublicKey,
        shared_secret: &mut KeyMaterial<N_SECRET>,
    ) -> Result<usize, KEMError> {
        let () = Self::PARAMS_CHECK;
        shared_secret.zeroize();
        // pkE = DeserializePublicKey(enc)
        let pk_e = G::deserialize_public_key(enc).map_err(|_| KEMError::DecapsulationFailed)?;
        // dh = concat(DH(skR, pkE), DH(skR, pkS))
        let mut dh_e = Secret::<[u8; N_DH]>::new();
        G::dh_into(sk_r, &pk_e, &mut dh_e).map_err(|_| KEMError::DecapsulationFailed)?;
        let mut dh_s = Secret::<[u8; N_DH]>::new();
        G::dh_into(sk_r, pk_s, &mut dh_s)
            .map_err(|_| KEMError::InvalidPublicKey("The sender's public key failed validation"))?;
        // pkRm = SerializePublicKey(pk(skR)); pkSm = SerializePublicKey(pkS)
        // kem_context = concat(enc, pkRm, pkSm)
        let pk_rm = G::serialize_public_key(pk_r);
        let pk_sm = G::serialize_public_key(pk_s);
        // shared_secret = ExtractAndExpand(dh, kem_context)
        Self::extract_and_expand_into(&[&*dh_e, &*dh_s], &[enc, &pk_rm, &pk_sm], shared_secret);
        Ok(N_SECRET)
    }

    /// `DeriveKeyPair(ikm)` (RFC 9180 Section 7.1.3), in the group's form
    /// ([`DHKEMParams::DERIVE_KEY_PAIR`]).
    ///
    /// Section 7.1.3: "the ikm parameter given to DeriveKeyPair() SHOULD have length at least Nsk,
    /// and SHOULD have at least Nsk bytes of entropy". This requires `ikm` to be of
    /// [`KeyType::Seed`] or [`KeyType::CryptographicRandom`] and of at least the group's security
    /// strength, which is what a key pair of the group can use; it does not insist on Nsk bytes,
    /// so that a 64-byte seed at 256 bits serves P-521, whose Nsk is 66.
    ///
    /// # Errors
    ///
    /// [`KEMError::KeyGenError`] if `ikm` does not meet those requirements, or, in the candidate
    /// form, if 256 candidates are all refused (the RFC's `DeriveKeyPairError`, whose likelihood
    /// "is negligibly small in all cases").
    pub fn derive_key_pair(
        ikm: &impl KeyMaterialTrait,
    ) -> Result<(G::PublicKey, G::PrivateKey), KEMError> {
        let () = Self::PARAMS_CHECK;

        if !(ikm.key_type() == KeyType::Seed || ikm.key_type() == KeyType::CryptographicRandom) {
            return Err(KEMError::KeyGenError(
                "ikm must be KeyType::Seed or KeyType::CryptographicRandom.",
            ));
        }
        if ikm.security_strength() < G::MAX_SECURITY_STRENGTH {
            return Err(KEMError::KeyGenError(
                "ikm SecurityStrength must match algorithm security strength",
            ));
        }

        // dkp_prk = LabeledExtract("", "dkp_prk", ikm)
        let mut dkp_prk = KeyMaterial::<MAX_NH>::new();
        Self::labeled_extract_into(LABEL_DKP_PRK, &[ikm.ref_to_bytes()], &mut dkp_prk);
        let mut bytes = Secret::<[u8; N_SK]>::new();
        match G::DERIVE_KEY_PAIR {
            DeriveKeyPairForm::Expand => {
                // sk = LabeledExpand(dkp_prk, "sk", "", Nsk)
                Self::labeled_expand(&dkp_prk, LABEL_SK, &[], &mut *bytes);
                // return (sk, pk(sk)); every byte string is a key of such a group.
                let sk = G::private_key_from_bytes(&bytes)
                    .ok_or(KEMError::KeyGenError("the derived bytes are not a private key"))?;
                Ok((G::pk(&sk), sk))
            }
            DeriveKeyPairForm::Candidate { bitmask } => {
                // while sk == 0 or sk >= order: ... counter = counter + 1; "if counter > 255:
                // raise DeriveKeyPairError". A u8 counter takes the values 0 to 255.
                for counter in 0..=u8::MAX {
                    // bytes = LabeledExpand(dkp_prk, "candidate", I2OSP(counter, 1), Nsk)
                    Self::labeled_expand(&dkp_prk, LABEL_CANDIDATE, &[&[counter]], &mut *bytes);
                    // bytes[0] = bytes[0] & bitmask
                    bytes[0] &= bitmask;
                    // sk = OS2IP(bytes), tested by the group
                    if let Some(sk) = G::private_key_from_bytes(&bytes) {
                        // return (sk, pk(sk))
                        return Ok((G::pk(&sk), sk));
                    }
                }
                Err(KEMError::KeyGenError("DeriveKeyPair: 256 candidates were all refused"))
            }
        }
    }

    /// `ExtractAndExpand(dh, kem_context)` (RFC 9180 Section 4.1) into `out`, zeroized first,
    /// with `dh` and `kem_context` each given as the parts it is the concatenation of. The output is labelled
    /// as a full-entropy key at the group's strength: it is HKDF output, and so pseudorandom,
    /// unlike the DH output it is derived from.
    // #[inline(never)]: inlined into encap_rng, its two HMAC states were allocated for the whole
    // encapsulation, on top of the key generation that sets the peak.
    #[inline(never)]
    fn extract_and_expand_into(
        dh: &[&[u8]],
        kem_context: &[&[u8]],
        out: &mut KeyMaterial<N_SECRET>,
    ) {
        out.zeroize();
        // eae_prk = LabeledExtract("", "eae_prk", dh)
        let mut eae_prk = KeyMaterial::<MAX_NH>::new();
        Self::labeled_extract_into(LABEL_EAE_PRK, dh, &mut eae_prk);
        // shared_secret = LabeledExpand(eae_prk, "shared_secret", kem_context, Nsecret)
        let mut shared_secret = Secret::<[u8; N_SECRET]>::new();
        Self::labeled_expand(&eae_prk, LABEL_SHARED_SECRET, kem_context, &mut *shared_secret);

        // An all-zero output, one HMAC value in 2^(8 * Nsecret), is typed Zeroized by the buffer
        // and carries no strength; that is not an error, as for an all-zero agreement output.
        // Nothing else can fail: Nsecret bytes fit the buffer.
        match out.set_bytes_as_type(&*shared_secret, KeyType::CryptographicRandom) {
            Ok(()) | Err(KeyMaterialError::ActingOnZeroizedKey) => {}
            Err(_) => unreachable!("Nsecret bytes fit a KeyMaterial<N_SECRET>"),
        }
        if out.key_type() == KeyType::CryptographicRandom {
            // Cannot fail: N_SECRET >= 32 bytes is enough for any strength, and the inferred
            // strength (set from the length) is lowered, never raised.
            out.set_security_strength(G::MAX_SECURITY_STRENGTH)
                .expect("the group's strength is within Nsecret's");
        }
    }

    /// `LabeledExtract("", label, ikm)` under the KEM's suite id, into `prk` as a MAC key. Every
    /// call in a DHKEM has an empty salt.
    fn labeled_extract_into(label: &[u8], ikm: &[&[u8]], prk: &mut KeyMaterial<MAX_NH>) {
        let salt = labeled::salt_key::<G::KDFHash>(&[]);
        labeled::labeled_extract_prk_into(&Self::SUITE_ID, &salt, label, ikm, prk);
    }

    /// `LabeledExpand(prk, label, info, L)` under the KEM's suite id, with `L` as `out.len()`.
    /// It fills `out` and returns nothing: its callers size `out` themselves, and a count
    /// nobody reads would be a value no test could pin.
    fn labeled_expand(prk: &KeyMaterial<MAX_NH>, label: &[u8], info: &[&[u8]], out: &mut [u8]) {
        // L is Nsecret or Nsk, which PARAMS_CHECK bounds by 255*HashLen and by 0xFFFF.
        labeled::labeled_expand::<G::KDFHash>(&Self::SUITE_ID, prk, label, info, out);
    }
}

// `strength_bits` is private and only read by the compile-time `PARAMS_CHECK`, which `cargo
// mutants` cannot see fail, so its table is pinned here as well.
#[cfg(test)]
mod tests {
    use super::strength_bits;
    use bouncycastle_core::security_strength::SecurityStrength;

    #[test]
    fn strength_bits_is_the_strength_as_a_bit_count() {
        assert_eq!(strength_bits(SecurityStrength::None), 0);
        assert_eq!(strength_bits(SecurityStrength::_112bit), 112);
        assert_eq!(strength_bits(SecurityStrength::_128bit), 128);
        assert_eq!(strength_bits(SecurityStrength::_192bit), 192);
        assert_eq!(strength_bits(SecurityStrength::_256bit), 256);
    }
}
