//! The DH-Based KEM (DHKEM) of RFC 9180 Section 4.1, generic over the Diffie-Hellman group.
//!
//! A group's crate implements [`DHKEMParams`] for its algorithm struct and then calls
//! [`DHKEM::encap_rng`] and [`DHKEM::decap`] from the workers its keys hand out through
//! [`EncapsulatingKey`](bouncycastle_core::kem_key::EncapsulatingKey) and
//! [`DecapsulatingKey`](bouncycastle_core::kem_key::DecapsulatingKey).

use bouncycastle_core::errors::{KEMError, KeyAgreementError, KeyMaterialError, RNGError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::FromAnyKeyMaterial;
use bouncycastle_core::traits::{Algorithm, Hash, HashAlgParams, RNG};
use bouncycastle_hmac::hazmat as hmac_hazmat;
use bouncycastle_hmac::{HMACParams, HmacKey};
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

    /// `GenerateKeyPair()` (RFC 9180 Section 4), drawing its randomness from `rng`.
    fn generate_key_pair_rng(
        rng: &mut dyn RNG,
    ) -> Result<(Self::PublicKey, Self::PrivateKey), KEMError>;

    /// The private key with the byte string `sk` as its value, as `DeriveKeyPair` (RFC 9180
    /// Section 7.1.3) requires.
    fn private_key_from_bytes(sk: &[u8; N_SK]) -> Self::PrivateKey;

    /// `pk(skX)` (RFC 9180 Section 4): the public key of `sk`.
    fn pk(sk: &Self::PrivateKey) -> Self::PublicKey;

    /// Whether `DeriveKeyPair` (RFC 9180 Section 7.1.3) is the X25519 and X448 form, `sk =
    /// LabeledExpand(dkp_prk, "sk", "", Nsk)` with no rejection loop, which is the only form
    /// [`DHKEM::derive_key_pair`] implements: a group whose form is the NIST curves' candidate
    /// loop sets this `false` and gets a compile error from `derive_key_pair` instead of a wrong
    /// key.
    const DERIVE_KEY_PAIR_BY_EXPAND: bool;
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
        // RFC 9180 Section 7.1, Table 2 pairs each group with a hash of at least twice its
        // strength (X25519 with SHA-256, P-384 with SHA-384, P-521 and X448 with SHA-512); a
        // shorter hash would cap the KEM's secret below the group.
        assert!(
            8 * nh >= 2 * strength_bits(G::MAX_SECURITY_STRENGTH),
            "the KDF's hash must offer twice the group's strength"
        );
    };

    /// `Encap(pkR)` (RFC 9180 Section 4.1), drawing the ephemeral key pair from `rng`.
    ///
    /// Returns the shared secret and `enc`, as a [`KeyType::CryptographicRandom`] key at the
    /// group's security strength.
    ///
    /// # Errors
    ///
    /// `Encap(pkR)` (RFC 9180 Section 4.1), with the ephemeral key pair generated from `rng`:
    /// the shared secret into `shared_secret` and `enc`, the ephemeral public key, into `enc`,
    /// each zeroized first and left so on the error path.
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
    ) -> Result<(), KEMError> {
        let () = Self::PARAMS_CHECK;
        enc.fill(0);
        shared_secret.zeroize();
        if rng.security_strength() < G::MAX_SECURITY_STRENGTH {
            return Err(RNGError::SecurityStrengthInsufficientForAlgorithm.into());
        }
        // skE, pkE = GenerateKeyPair()
        let (pk_e, sk_e) = G::generate_key_pair_rng(rng)?;
        // dh = DH(skE, pkR)
        let mut dh = Secret::<[u8; N_DH]>::new();
        G::dh_into(&sk_e, pk_r, &mut dh).map_err(|_| {
            KEMError::InvalidPublicKey("The recipient's public key failed validation")
        })?;
        // enc = SerializePublicKey(pkE)
        *enc = G::serialize_public_key(&pk_e);
        // pkRm = SerializePublicKey(pkR); kem_context = concat(enc, pkRm)
        let pk_rm = G::serialize_public_key(pk_r);
        // shared_secret = ExtractAndExpand(dh, kem_context)
        Self::extract_and_expand_into(&*dh, &[&*enc, &pk_rm], shared_secret);
        Ok(())
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

    /// `Decap(enc, skR)` (RFC 9180 Section 4.1).
    ///
    /// Returns the shared secret, as a [`KeyType::CryptographicRandom`] key at the group's security
    /// strength.
    ///
    /// # Errors
    ///
    /// `Decap(enc, skR)` (RFC 9180 Section 4.1) into `shared_secret`, zeroized first and left so
    /// on the error path.
    ///
    /// # Errors
    /// [`KEMError::DecapsulationFailed`] if `enc` does not deserialize or the DH output fails the
    /// group's validation.
    pub fn decap_out(
        enc: &[u8; N_PK],
        sk_r: &G::PrivateKey,
        shared_secret: &mut KeyMaterial<N_SECRET>,
    ) -> Result<(), KEMError> {
        let () = Self::PARAMS_CHECK;
        shared_secret.zeroize();
        // pkE = DeserializePublicKey(enc)
        let pk_e = G::deserialize_public_key(enc).map_err(|_| KEMError::DecapsulationFailed)?;
        // dh = DH(skR, pkE)
        let mut dh = Secret::<[u8; N_DH]>::new();
        G::dh_into(sk_r, &pk_e, &mut dh).map_err(|_| KEMError::DecapsulationFailed)?;
        // pkRm = SerializePublicKey(pk(skR)); kem_context = concat(enc, pkRm)
        let pk_rm = G::serialize_public_key(&G::pk(sk_r));
        // shared_secret = ExtractAndExpand(dh, kem_context)
        Self::extract_and_expand_into(&*dh, &[enc, &pk_rm], shared_secret);
        Ok(())
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
        const {
            assert!(
                G::DERIVE_KEY_PAIR_BY_EXPAND,
                "derive_key_pair implements only the X25519 / X448 form of RFC 9180 Section 7.1.3"
            )
        };

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
    // #[inline(never)]: inlined into encap_rng, its two HMAC states were allocated for the whole
    // encapsulation, on top of the key generation that sets the peak.
    /// `ExtractAndExpand(dh, kem_context)` (RFC 9180 Section 4.1) into `out`: the shared secret,
    /// typed `CryptographicRandom` at the group's strength. `out` is zeroized first.
    #[inline(never)]
    fn extract_and_expand_into(dh: &[u8], kem_context: &[&[u8]], out: &mut KeyMaterial<N_SECRET>) {
        out.zeroize();
        // eae_prk = LabeledExtract("", "eae_prk", dh)
        let eae_prk = Self::labeled_extract(LABEL_EAE_PRK, dh);
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

    /// `LabeledExtract("", label, ikm)` (RFC 9180 Section 4), where `Extract` is HKDF-Extract
    /// (RFC 5869 Section 2.2) over [`DHKEMParams::KDFHash`]. Every call in a DHKEM has an empty salt.
    ///
    /// Returns the PRK as a MAC key, ready for [`Self::labeled_expand`].
    fn labeled_extract(label: &[u8], ikm: &[u8]) -> KeyMaterial<MAX_NH> {
        // PRK = HMAC-Hash(salt, IKM)
        // An empty salt is an empty HMAC key. RFC 5869 Section 2.2 says an absent salt "is set to a
        // string of HashLen zeros", which is the same HMAC key, as HMAC zero-pads its key.
        // Cannot fail: an empty KeyMaterial is Zeroized, which HMAC accepts as a weak key.
        let salt =
            HmacKey::<G::KDFHash>::from_key_material_allow_weak(&KeyMaterial::<0>::new()).unwrap();
        // HMAC through its hazmat halves, as HKDF's expand loop runs it: the role wants the tag
        // length as a const, which a hash-generic KDF does not have.
        let mut hmac = hmac_hazmat::inner_state(&salt);
        // labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
        // Deviation from the RFC: the parts of labeled_ikm are absorbed by HMAC in order rather than
        // concatenated first.
        hmac.do_update(HPKE_VERSION_LABEL);
        hmac.do_update(&Self::SUITE_ID);
        hmac.do_update(label);
        hmac.do_update(ikm);

        let mut prk = Secret::<[u8; MAX_NH]>::new();
        // Cannot fail: the buffer is at least the hash output length (PARAMS_CHECK).
        let nh = <G::KDFHash as HashAlgParams>::OUTPUT_LEN;
        let nh = hmac_hazmat::finish_out(&salt, hmac, &mut prk[..nh]);
        // nh <= MAX_NH bytes fit a KeyMaterial<MAX_NH>; the one way this fails is an all-zero
        // PRK (one HMAC output in 2^(8 * nh)), which the buffer types Zeroized and the expand's
        // HmacKey then refuses. Not reachable in practice; a panic is the right report for it.
        KeyMaterial::from_bytes_as_type(&prk[..nh], KeyType::MACKey)
            .expect("an all-zero PRK, one HMAC output in 2^(8 * nh)")
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
        // The PRK keys one HmacKey for the whole expand (review of PR #186: keying it per
        // iteration left one more SHA-256 schedule of `prk XOR opad` per block). It refuses an
        // all-zero PRK, one HMAC output in 2^(8 * nh); see labeled_extract.
        let key = HmacKey::<G::KDFHash>::from_key_material(prk)
            .expect("an all-zero PRK, one HMAC output in 2^(8 * nh)");
        // Each chunk of `out` is one T(i), the last one truncated.
        for (i, okm_chunk) in out.chunks_mut(nh).enumerate() {
            // T(i) = HMAC-Hash(PRK, T(i-1) | info | i), with info = labeled_info
            let mut hmac = hmac_hazmat::inner_state(&key);
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
            t_len = hmac_hazmat::finish_out(&key, hmac, &mut t[..nh]);
            okm_chunk.copy_from_slice(&t[..okm_chunk.len()]);
        }
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
