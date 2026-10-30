//! The DH-Based KEM (DHKEM) of RFC 9180 Section 4.1, generic over the Diffie-Hellman group.
//!
//! A group's crate implements [`DHKEMParams`] for its algorithm struct and then calls
//! [`DHKEM::encap_rng`] and [`DHKEM::decap`] from its
//! [`KEMEncapsulator`](bouncycastle_core::traits::KEMEncapsulator) and
//! [`KEMDecapsulator`](bouncycastle_core::traits::KEMDecapsulator) impls.

use bouncycastle_core::errors::{KEMError, KeyAgreementError, RNGError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{Algorithm, Hash, HashAlgParams, MAC, RNG};
use bouncycastle_hmac::HMAC;
use bouncycastle_utils::secret::Secret;
use core::marker::PhantomData;

/// The version label that RFC 9180 Section 4 puts at the front of every labeled KDF input.
const HPKE_VERSION_LABEL: &[u8] = b"HPKE-v1";

// The labels of RFC 9180 Sections 4.1 and 7.1.3.
const LABEL_EAE_PRK: &[u8] = b"eae_prk";
const LABEL_SHARED_SECRET: &[u8] = b"shared_secret";
const LABEL_DKP_PRK: &[u8] = b"dkp_prk";
const LABEL_SK: &[u8] = b"sk";

/// The largest Nh among the KDFs of RFC 9180 Section 7.2 (HKDF-SHA512). The PRK and HKDF-Expand
/// block buffers are sized to it.
const MAX_NH: usize = 64;

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
    type KDFHash: Hash + HashAlgParams + Default;
    /// The `kem_id` of RFC 9180 Section 7.1, Table 2.
    const KEM_ID: u16;

    /// `GenerateKeyPair()` (RFC 9180 Section 4), drawing its randomness from `rng`.
    fn generate_key_pair_rng(
        rng: &mut dyn RNG,
    ) -> Result<(Self::PublicKey, Self::PrivateKey), KEMError>;

    /// The private key with the byte string `sk` as its value, as `DeriveKeyPair` (RFC 9180
    /// Section 7.1.3) requires.
    fn private_key_from_bytes(sk: &[u8; N_SK]) -> Self::PrivateKey;

    /// `pk(skX)` (RFC 9180 Section 4): the public key of `sk`.
    fn pk(sk: &Self::PrivateKey) -> Self::PublicKey;

    /// `DH(skX, pkY)` (RFC 9180 Section 4.1), including the validation of its output that RFC 9180
    /// Section 7.1.4 requires for the group. A validation failure is an `Err`.
    fn dh(
        sk: &Self::PrivateKey,
        pk: &Self::PublicKey,
    ) -> Result<Secret<[u8; N_DH]>, KeyAgreementError>;

    /// `SerializePublicKey(pkX)` (RFC 9180 Section 7.1.1).
    fn serialize_public_key(pk: &Self::PublicKey) -> [u8; N_PK];

    /// `DeserializePublicKey(pkXm)` (RFC 9180 Section 7.1.1).
    fn deserialize_public_key(pkm: &[u8; N_PK]) -> Result<Self::PublicKey, KEMError>;
}

/// The DHKEM of RFC 9180 Section 4.1 over the group `G`, without the optional `AuthEncap` and
/// `AuthDecap`.
///
/// The const parameters are `G`'s sizes (see [`DHKEMParams`]) plus `N_SECRET`, the Nsecret of RFC
/// 9180 Section 7.1, which must equal the output length of [`DHKEMParams::KDFHash`] (Section 4.1:
/// "the size Nsecret of the KEM shared secret is equal to the output length of the hash function
/// underlying the KDF").
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
    };

    /// `Encap(pkR)` (RFC 9180 Section 4.1), drawing the ephemeral key pair from `rng`.
    ///
    /// Returns the shared secret and `enc`, as a [`KeyType::CryptographicRandom`] key at the
    /// group's security strength.
    ///
    /// # Errors
    ///
    /// * [`KEMError::RNGError`] if `rng`'s security strength is below the group's.
    /// * [`KEMError::InvalidPublicKey`] if `pk_r` fails the group's validation (RFC 9180 Section
    ///   7.1.4: "the sender MUST validate the recipient's public key pkR").
    /// * Any error from [`DHKEMParams::generate_key_pair_rng`].
    pub fn encap_rng(
        pk_r: &G::PublicKey,
        rng: &mut dyn RNG,
    ) -> Result<(KeyMaterial<N_SECRET>, [u8; N_PK]), KEMError> {
        let () = Self::PARAMS_CHECK;

        if rng.security_strength() < G::MAX_SECURITY_STRENGTH {
            return Err(RNGError::SecurityStrengthInsufficientForAlgorithm)?;
        }

        // skE, pkE = GenerateKeyPair()
        let (pk_e, sk_e) = G::generate_key_pair_rng(rng)?;
        // dh = DH(skE, pkR)
        let dh = G::dh(&sk_e, pk_r).map_err(|_| {
            KEMError::InvalidPublicKey("The recipient's public key failed validation")
        })?;
        // enc = SerializePublicKey(pkE)
        let enc = G::serialize_public_key(&pk_e);

        // pkRm = SerializePublicKey(pkR)
        let pk_rm = G::serialize_public_key(pk_r);
        // kem_context = concat(enc, pkRm)
        // shared_secret = ExtractAndExpand(dh, kem_context)
        // Deviation from the RFC: kem_context is passed as its two parts rather than concatenated,
        // since it is only ever fed to HMAC, which absorbs the parts in order.
        let shared_secret = Self::extract_and_expand(&*dh, &[&enc, &pk_rm]);
        // return shared_secret, enc
        Ok((shared_secret, enc))
    }

    /// `Decap(enc, skR)` (RFC 9180 Section 4.1).
    ///
    /// Returns the shared secret, as a [`KeyType::CryptographicRandom`] key at the group's security
    /// strength.
    ///
    /// # Errors
    ///
    /// [`KEMError::DecapsulationFailed`] if `enc` does not deserialize, or fails the group's
    /// validation (RFC 9180 Section 7.1.4: "the recipient MUST validate the ephemeral public key
    /// pkE").
    pub fn decap(
        enc: &[u8; N_PK],
        sk_r: &G::PrivateKey,
    ) -> Result<KeyMaterial<N_SECRET>, KEMError> {
        let () = Self::PARAMS_CHECK;

        // pkE = DeserializePublicKey(enc)
        let pk_e = G::deserialize_public_key(enc).map_err(|_| KEMError::DecapsulationFailed)?;
        // dh = DH(skR, pkE)
        let dh = G::dh(sk_r, &pk_e).map_err(|_| KEMError::DecapsulationFailed)?;

        // pkRm = SerializePublicKey(pk(skR))
        let pk_rm = G::serialize_public_key(&G::pk(sk_r));
        // kem_context = concat(enc, pkRm)
        // shared_secret = ExtractAndExpand(dh, kem_context)
        // Deviation from the RFC: kem_context is passed in two parts; see encap_rng.
        let shared_secret = Self::extract_and_expand(&*dh, &[enc, &pk_rm]);
        // return shared_secret
        Ok(shared_secret)
    }

    /// `DeriveKeyPair(ikm)` (RFC 9180 Section 7.1.3), for groups whose private key is the byte string
    /// itself, such as X25519 and X448.
    ///
    /// Section 7.1.3: "the ikm parameter given to DeriveKeyPair() SHOULD have length at least Nsk,
    /// and SHOULD have at least Nsk bytes of entropy". This requires `ikm` to be at least Nsk bytes,
    /// of [`KeyType::Seed`] or [`KeyType::CryptographicRandom`], and at least the group's security
    /// strength.
    ///
    /// # Errors
    ///
    /// [`KEMError::KeyGenError`] if `ikm` does not meet those requirements.
    pub fn derive_key_pair(
        ikm: &impl KeyMaterialTrait,
    ) -> Result<(G::PublicKey, G::PrivateKey), KEMError> {
        let () = Self::PARAMS_CHECK;

        if !(ikm.key_type() == KeyType::Seed || ikm.key_type() == KeyType::CryptographicRandom)
            || ikm.key_len() < N_SK
        {
            return Err(KEMError::KeyGenError(
                "ikm must be at least Nsk bytes and KeyType::Seed or KeyType::CryptographicRandom.",
            ));
        }
        if ikm.security_strength() < G::MAX_SECURITY_STRENGTH {
            return Err(KEMError::KeyGenError(
                "ikm SecurityStrength must match algorithm security strength",
            ));
        }

        // dkp_prk = LabeledExtract("", "dkp_prk", ikm)
        let dkp_prk = Self::labeled_extract(LABEL_DKP_PRK, ikm.ref_to_bytes());
        // sk = LabeledExpand(dkp_prk, "sk", "", Nsk)
        let mut sk = Secret::<[u8; N_SK]>::new();
        Self::labeled_expand(&dkp_prk, LABEL_SK, &[], &mut *sk);
        let sk = G::private_key_from_bytes(&sk);
        // return (sk, pk(sk))
        Ok((G::pk(&sk), sk))
    }

    /// `ExtractAndExpand(dh, kem_context)` (RFC 9180 Section 4.1), with `kem_context` given as the
    /// parts it is the concatenation of.
    ///
    /// The output is labelled as a full-entropy key at the group's strength: it is HKDF output, and
    /// so pseudorandom, unlike the DH output it is derived from.
    fn extract_and_expand(dh: &[u8], kem_context: &[&[u8]]) -> KeyMaterial<N_SECRET> {
        // eae_prk = LabeledExtract("", "eae_prk", dh)
        let eae_prk = Self::labeled_extract(LABEL_EAE_PRK, dh);
        // shared_secret = LabeledExpand(eae_prk, "shared_secret", kem_context, Nsecret)
        let mut shared_secret = Secret::<[u8; N_SECRET]>::new();
        Self::labeled_expand(&eae_prk, LABEL_SHARED_SECRET, kem_context, &mut *shared_secret);

        // Cannot fail: N_SECRET bytes fit a KeyMaterial<N_SECRET>, and an all-zero output gives
        // Ok(Zeroized).
        let mut key =
            KeyMaterial::from_bytes_as_type(&*shared_secret, KeyType::CryptographicRandom).unwrap();
        if key.key_type() == KeyType::CryptographicRandom {
            // Cannot fail: N_SECRET >= 32 bytes is enough for any strength, and the inferred
            // strength (from_bytes_as_type sets it from the length) is lowered, never raised.
            key.set_security_strength(G::MAX_SECURITY_STRENGTH).unwrap();
        }
        key
    }

    /// `LabeledExtract("", label, ikm)` (RFC 9180 Section 4), where `Extract` is HKDF-Extract
    /// (RFC 5869 Section 2.2) over [`DHKEMParams::KDFHash`]. Every call in a DHKEM has an empty salt.
    ///
    /// Returns the PRK as a MAC key, ready for [`Self::labeled_expand`].
    fn labeled_extract(label: &[u8], ikm: &[u8]) -> KeyMaterial<MAX_NH> {
        // PRK = HMAC-Hash(salt, IKM)
        // An empty salt is an empty HMAC key. RFC 5869 Section 2.2 says an absent salt "is set to a
        // string of HashLen zeros", which is the same HMAC key, as HMAC zero-pads its key.
        // Cannot fail: an empty KeyMaterial is Zeroized, which HMAC accepts as a weak key.
        let mut hmac = HMAC::<G::KDFHash>::new_allow_weak_key(&KeyMaterial::<0>::new()).unwrap();
        // labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
        // Deviation from the RFC: the parts of labeled_ikm are absorbed by HMAC in order rather than
        // concatenated first.
        hmac.do_update(HPKE_VERSION_LABEL);
        hmac.do_update(&Self::SUITE_ID);
        hmac.do_update(label);
        hmac.do_update(ikm);

        let mut prk = Secret::<[u8; MAX_NH]>::new();
        // Cannot fail: the buffer is at least the hash output length (PARAMS_CHECK).
        let nh = hmac.do_final_out(&mut *prk).unwrap();
        // Cannot fail: nh <= MAX_NH bytes fit a KeyMaterial<MAX_NH>.
        KeyMaterial::from_bytes_as_type(&prk[..nh], KeyType::MACKey).unwrap()
    }

    /// `LabeledExpand(prk, label, info, L)` (RFC 9180 Section 4), where `Expand` is HKDF-Expand (RFC
    /// 5869 Section 2.3) over [`DHKEMParams::KDFHash`], `L` is `out.len()`, and `info` is given as
    /// the parts it is the concatenation of.
    fn labeled_expand(prk: &KeyMaterial<MAX_NH>, label: &[u8], info: &[&[u8]], out: &mut [u8]) {
        let nh = <G::KDFHash as HashAlgParams>::OUTPUT_LEN;
        // L is Nsecret or Nsk, which PARAMS_CHECK bounds by 255*HashLen and by 0xFFFF.
        debug_assert!(out.len() <= 255 * nh && out.len() <= 0xFFFF);
        let l = (out.len() as u16).to_be_bytes();

        // T(0) = empty string (zero length)
        let mut t = Secret::<[u8; MAX_NH]>::new();
        let mut t_len = 0;
        // N = ceil(L/HashLen); T = T(1) | T(2) | ... | T(N); OKM = first L octets of T
        // Each chunk of `out` is one T(i), the last one truncated.
        for (i, okm_chunk) in out.chunks_mut(nh).enumerate() {
            // T(i) = HMAC-Hash(PRK, T(i-1) | info | i), with info = labeled_info
            // Cannot fail: the PRK is a MAC key of the hash's full output length.
            let mut hmac = HMAC::<G::KDFHash>::new(prk).unwrap();
            hmac.do_update(&t[..t_len]);
            // labeled_info = concat(I2OSP(L, 2), "HPKE-v1", suite_id, label, info)
            // Deviation from the RFC: absorbed in parts, as in labeled_extract.
            hmac.do_update(&l);
            hmac.do_update(HPKE_VERSION_LABEL);
            hmac.do_update(&Self::SUITE_ID);
            hmac.do_update(label);
            for part in info {
                hmac.do_update(part);
            }
            // i <= N <= 255, since L <= 255*HashLen.
            hmac.do_update(&[(i + 1) as u8]);
            // Cannot fail: the buffer is at least the hash output length (PARAMS_CHECK).
            t_len = hmac.do_final_out(&mut *t).unwrap();
            okm_chunk.copy_from_slice(&t[..okm_chunk.len()]);
        }
    }
}
