//! The ML-KEM algorithm over the seed-held private key.
//!
//! Beyond the core KEM traits this crate adds `decaps_from_seed`, the `hazmat` module, and
//! [`MLKEMSeedPrivateKeyExpanded`]: a seed key derives 𝐭̂ inside every decapsulation (a key
//! generation's worth of work), the expanded key holds it, at 384𝑘 more bytes in memory and the
//! same 64-byte encoding on disk, and implements the same [`DecapsulatingKey`] role. The
//! pre-expanded 𝐀̂ of the `bouncycastle_mlkem` crate has no counterpart here: holding 𝐀̂ is what
//! this crate exists to avoid.
//!
//! ```rust
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey};
//! use bouncycastle_mlkem_lowmemory::{MLKEM768, MLKEM768PrivateKeyExpanded, MLKEMTrait};
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let (pk, sk) = MLKEM768::keygen(&mut rng).unwrap();
//! let sk_expanded = MLKEM768PrivateKeyExpanded::from(&sk);
//!
//! let (ss, ct) = pk.encaps(&mut rng, ()).unwrap();
//! let ss1 = sk_expanded.decaps((), &ct).unwrap();
//! assert_eq!(ss, ss1);
//! ```

use crate::low_memory_helpers::{
    compress_u_row, compute_A_hat_dot_y_hat, compute_t_hat_dot_y_hat_row, unpack_ciphertext_u_row,
    unpack_ciphertext_v, unpack_t_hat_row,
};
use crate::mlkem_keys::{
    MLKEMPrivateKeyInternalTrait, MLKEMPrivateKeyTrait, MLKEMPublicKey, MLKEMPublicKeyTrait,
    MLKEMSeedPrivateKey, MLKEMSeedPrivateKeyExpanded,
};
use crate::params::{
    CiphertextLen, MLKEM512Params, MLKEM768Params, MLKEM1024Params, MLKEMParams, MLKEMParamsBase,
    PrivateKeyLen,
};
use bouncycastle_core::errors::{KEMError, RNGError};
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey, KEMAlgorithm};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    Algorithm, AlgorithmOID, Hash, KEMDecapsulator, KEMEncapsulator, RNG, XOF, XOFSqueezer,
};
use bouncycastle_mlkem_common::aux_functions::sample_poly_CBD;
use bouncycastle_mlkem_common::polynomial::Polynomial;
use bouncycastle_utils::ct::{conditional_copy_bytes, ct_eq_bytes, ct_eq_bytes_mask};
use bouncycastle_utils::secret::Secret;
use core::marker::PhantomData;
/*** Constants ***/

// The constants, names and hash aliases FIPS 203 fixes for every parameter set are shared with
// the other ML-KEM crate and live in `bouncycastle-mlkem-common`.
pub(crate) use bouncycastle_mlkem_common::{G, H, J, N, POLY_BYTES, q};
#[doc(inline)]
pub use bouncycastle_mlkem_common::{ML_KEM_512_NAME, ML_KEM_768_NAME, ML_KEM_1024_NAME};
#[doc(inline)]
pub use bouncycastle_mlkem_common::{MLKEM_RND_LEN, MLKEM_SEED_LEN, MLKEM_SS_LEN};

/* ML-KEM-512 params */

/// Length of the \[u8] holding an ML-KEM-512 public key.
pub const MLKEM512_PK_LEN: usize = MLKEM512Params::PK_LEN;
/// Length of the \[u8] holding an ML-KEM-512 seed-based private key.
pub const MLKEM512_SK_LEN: usize = MLKEM_SEED_LEN;
/// Length of the \[u8] holding a full ML-KEM-512 private key in the NIST encoding.
pub const MLKEM512_FULL_SK_LEN: usize = MLKEM512Params::FULL_SK_LEN;
/// Length of the \[u8] holding an ML-KEM-512 ciphertext.
pub const MLKEM512_CT_LEN: usize = MLKEM512Params::CT_LEN;

/*** internal derived values ***/

/* ML-KEM-768 params */

/// Length of the \[u8] holding an ML-KEM-768 public key.
pub const MLKEM768_PK_LEN: usize = MLKEM768Params::PK_LEN;
/// Length of the \[u8] holding an ML-KEM-768 seed-based private key.
pub const MLKEM768_SK_LEN: usize = MLKEM_SEED_LEN;
/// Length of the \[u8] holding a full ML-KEM-768 private key in the NIST encoding.
pub const MLKEM768_FULL_SK_LEN: usize = MLKEM768Params::FULL_SK_LEN;
/// Length of the \[u8] holding an ML-KEM-768 ciphertext.
pub const MLKEM768_CT_LEN: usize = MLKEM768Params::CT_LEN;

/* ML-KEM-1024 params */

/// Length of the \[u8] holding an ML-KEM-1024 public key.
pub const MLKEM1024_PK_LEN: usize = MLKEM1024Params::PK_LEN;
/// Length of the \[u8] holding an ML-KEM-1024 seed-based private key.
pub const MLKEM1024_SK_LEN: usize = MLKEM_SEED_LEN;
/// Length of the \[u8] holding a full ML-KEM-1024 private key in the NIST encoding.
pub const MLKEM1024_FULL_SK_LEN: usize = MLKEM1024Params::FULL_SK_LEN;
/// Length of the \[u8] holding an ML-KEM-1024 ciphertext.
pub const MLKEM1024_CT_LEN: usize = MLKEM1024Params::CT_LEN;

/*** Pub Types ***/

/// The ML-KEM-512 algorithm.
pub type MLKEM512 = MLKEM<MLKEM512Params>;

/// The ML-KEM-768 algorithm.
pub type MLKEM768 = MLKEM<MLKEM768Params>;

/// The ML-KEM-1024 algorithm.
pub type MLKEM1024 = MLKEM<MLKEM1024Params>;

impl<P: MLKEMParams> Algorithm for MLKEM<P> {
    const ALG_NAME: &'static str = P::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

/// The OIDs NIST assigned in the Computer Security Objects Register: id-alg-ml-kem-512
/// { kems 1 }, id-alg-ml-kem-768 { kems 2 } and id-alg-ml-kem-1024 { kems 3 }. As with
/// [`Algorithm`], the values belong to the parameter set, so one impl covers all three.
impl<P: MLKEMParams> AlgorithmOID for MLKEM<P> {
    const OID: &'static [u32] = P::OID;
    const OID_DER: &'static [u8] = P::OID_DER;
}

impl<P: MLKEMParams> KEMAlgorithm for MLKEM<P> {}

/// The ML-KEM algorithm marker for one parameter set: [`MLKEM512`], [`MLKEM768`], [`MLKEM1024`].
/// It carries the metadata ([`Algorithm`], [`AlgorithmOID`]) and, through [`MLKEMTrait`], key
/// generation; encapsulation and decapsulation are methods of the keys ([`EncapsulatingKey`],
/// [`DecapsulatingKey`]), with the marker as the algorithm they name.
pub struct MLKEM<P: MLKEMParams> {
    _phantom: PhantomData<P>,
}

impl<P: MLKEMParams> MLKEM<P> {
    /// Performs the first step of key generation to transform the single provided seed into a set of internal intermediate seeds.
    ///
    /// Unlike other interfaces across the library that take an &impl KeyMaterial, this one
    /// specifically takes a 64-byte [`KeyMaterial512`] and checks that it has [`KeyType::Seed`] and
    /// the appropriate [`SecurityStrength`] for the requested ML-KEM parameter set.
    ///
    /// If you happen to have your seed in a larger KeyMaterial, you'll have to copy it into a
    /// correctly-sized [`KeyMaterial512`] using [`KeyMaterialTrait::truncate`].
    pub(crate) fn keygen_internal(
        seed: &KeyMaterial<64>,
    ) -> Result<(MLKEMPublicKey<P>, MLKEMSeedPrivateKey<P>), KEMError> {
        // The key derives the public key once, for its stored H(ek); this takes it rather than
        // deriving it again.
        MLKEMSeedPrivateKey::from_keymaterial_with_pk(seed).map(|(sk, pk)| (pk, sk))
    }

    /// Algorithm 14 K-PKE.Encrypt(ekPKE, 𝑚, 𝑟)
    /// Uses the encryption key to encrypt a plaintext message using the randomness 𝑟.
    /// Input: encryption key ekPKE ∈ 𝔹384𝑘+32 .
    /// Input: message 𝑚 ∈ 𝔹32 .
    /// Input: randomness 𝑟 ∈ 𝔹32 .
    /// Output: ciphertext 𝑐 ∈ 𝔹32(𝑑𝑢𝑘+𝑑𝑣).
    fn pke_encrypt<const CT_LEN: usize>(
        t_hat_packed: &P::TPacked,
        rho: &[u8; 32],
        m: &[u8; 32],
        r: &[u8; 32],
    ) -> [u8; CT_LEN] {
        let mut ct = [0u8; CT_LEN];

        // 1: 𝑁 ← 0
        //  since the number of loops here is static; the N values can be hard-coded rather than using a counter

        // 2: 𝐭 ← ByteDecode12(ekPKE[0 ∶ 384𝑘])
        // 3: 𝜌 ← ekPKE[384𝑘 ∶ 384𝑘 + 32]
        // not necessary here because ek is already decoded

        // 19: 𝐮 ← NTT−1(𝐀_hat^⊺ ∘ 𝐲_hat) + 𝐞1
        // 22: 𝑐1 ← ByteEncode_𝑑𝑢(Compress_𝑑𝑢(𝐮))

        // 𝐲̂ is used at line 19 (every row of 𝐮 needs all 𝑘 coordinates) and at line 21 (one
        // coordinate per row of 𝐭̂). Holding it would cost 512𝑘 bytes (1 to 2 KB), so each
        // coordinate is sampled and transformed again where it is needed: 𝑘(𝑘 + 1) CBD samplings
        // and NTTs instead of 𝑘, which is 12 instead of 3 for ML-KEM-768. That is the trade this
        // crate makes, memory over time.
        for i in 0..P::k {
            let mut u_i = compute_A_hat_dot_y_hat::<P>(rho, r, i);

            let e1_i = sample_poly_CBD(r, (P::k + i) as u8, P::eta2);
            u_i.add(&e1_i);
            u_i.poly_reduce();

            compress_u_row::<P, CT_LEN>(u_i, i, &mut ct);
        }

        // 17: 𝑒2 ← SamplePolyCBD_𝜂2(PRF𝜂2 (𝑟, 𝑁))
        // 20: 𝜇 ← Decompress1(ByteDecode1(𝑚))
        // 21: 𝑣 ← NTT−1(𝐭_hat_T ∘ 𝐲_hat) + 𝑒2 + 𝜇
        // 23: 𝑐2 ← ByteEncode_𝑑𝑣(Compress_𝑑𝑣(𝑣))
        {
            // compute v, which is a single polynomial, but requires iterating over the vectors t_hat and y_hat
            let mut v = compute_t_hat_dot_y_hat_row::<P>(
                r,
                &unpack_t_hat_row(t_hat_packed.as_ref(), 0),
                /*row*/ 0,
            );

            for i in 1..P::k {
                let v_i = compute_t_hat_dot_y_hat_row::<P>(
                    r,
                    &unpack_t_hat_row(t_hat_packed.as_ref(), i),
                    /*row*/ i,
                );
                v.add(&v_i);
            }

            // perform polynomial addition
            let e2 = sample_poly_CBD(r, 2 * P::k as u8, P::eta2);
            v.add(&e2);

            let mu = Polynomial::from_msg(m);
            v.add(&mu);

            v.poly_reduce();

            v.compress_poly::<P>(&mut ct[CT_LEN - (N * (P::dv as usize) / 8)..]);
        }

        ct
    }

    /// Algorithm 17 ML-KEM.Encaps_internal(ek, 𝑚)
    /// Uses the encapsulation key and randomness to generate a key and an associated ciphertext.
    /// Input: encapsulation key ek ∈ 𝔹384𝑘+32 .
    /// Input: randomness 𝑚 ∈ 𝔹32 .
    /// Output: shared secret key 𝐾 ∈ 𝔹32 .
    /// Output: ciphertext 𝑐 ∈ 𝔹32(𝑑𝑢𝑘+𝑑𝑣).
    ///
    /// Reachable from outside the crate only through
    /// [`EncapsWithRandomness`](crate::hazmat::EncapsWithRandomness), which carries the security
    /// notes on supplying `m`.
    pub(crate) fn encaps_internal<const CT_LEN: usize>(
        ek: &MLKEMPublicKey<P>,
        m: &[u8; 32],
    ) -> (Secret<[u8; MLKEM_SS_LEN]>, [u8; CT_LEN]) {
        // 1: (𝐾, 𝑟) ← G(𝑚‖H(ek))
        //  ▷ derive shared secret key 𝐾 and randomness 𝑟. Both are secret and held in `Secret`,
        //  as is the G output they are split from.
        let (K, r) = {
            let mut g = G::new();
            g.do_update(m);
            g.do_update(&ek.compute_hash());
            let mut buf = Secret::<[u8; 64]>::new();
            let bytes_written = g.do_final_out(&mut *buf);
            debug_assert_eq!(bytes_written, 64);

            let mut K = Secret::<[u8; MLKEM_SS_LEN]>::new();
            K.copy_from_slice(&buf[..32]);
            let mut r = Secret::<[u8; 32]>::new();
            r.copy_from_slice(&buf[32..64]);
            (K, r)
        };

        // 2: 𝑐 ← K-PKE.Encrypt(ek, 𝑚, 𝑟)
        //  ▷ encrypt 𝑚 using K-PKE with randomness 𝑟
        // deviation from FIPS:
        let ct = Self::pke_encrypt(ek.t_hat_packed(), ek.rho(), m, &r);

        (K, ct)
    }

    /// Algorithm 15 K-PKE.Decrypt(dkPKE, 𝑐)
    /// Uses the decryption key to decrypt a ciphertext
    /// Input: decryption key dkPKE ∈ 𝔹384𝑘.
    /// Input: ciphertext 𝑐 ∈ 𝔹32(𝑑𝑢𝑘+𝑑𝑣).
    /// Output: message 𝑚 ∈ 𝔹32 .
    fn pke_decrypt<DK: MLKEMPrivateKeyInternalTrait<P>, const CT_LEN: usize>(
        dk: &DK,
        ct: &[u8; CT_LEN],
    ) -> Secret<[u8; 32]> {
        // 1: 𝑐1 ← 𝑐[0 ∶ 32𝑑𝑢𝑘]
        // 3: 𝐮′ ← Decompress_𝑑𝑢(ByteDecode_𝑑𝑢(𝑐1))

        // 5: 𝐬_hat ← ByteDecode12(dkPKE)
        //   Unnecessary here because they are re-computed row-by-row

        // first half of
        // 6: 𝑤 ← 𝑣′ − NTT−1(𝐬_hat^T ∘ NTT(𝐮′))
        let v1 = {
            // i = 0 case
            let mut v1 = {
                let mut s_hat_i = dk.compute_s_hat_row(0);
                {
                    let mut u_prime_i = unpack_ciphertext_u_row::<P, CT_LEN>(0, ct);
                    u_prime_i.ntt();
                    s_hat_i.base_mult_montgomery(&u_prime_i);
                }
                s_hat_i.inv_ntt();

                s_hat_i
            };

            for i in 1..P::k {
                let mut s_hat_i = dk.compute_s_hat_row(i);
                {
                    let mut u_prime_i = unpack_ciphertext_u_row::<P, CT_LEN>(i, ct);
                    u_prime_i.ntt();
                    s_hat_i.base_mult_montgomery(&u_prime_i);
                }
                s_hat_i.inv_ntt();
                v1.add(&s_hat_i);
            }

            v1
        };

        // 2: 𝑐2 ← 𝑐[32𝑑𝑢𝑘 ∶ 32(𝑑𝑢𝑘 + 𝑑𝑣)]
        // 4: 𝑣′ ← Decompress_𝑑𝑣(ByteDecode_𝑑𝑣(𝑐2))
        let w = {
            // second half of
            // 6: 𝑤 ← 𝑣′ − NTT−1(𝐬_hat^T ∘ NTT(𝐮′))
            let mut v_prime = unpack_ciphertext_v::<P, CT_LEN>(ct);

            v_prime.sub(&v1);
            v_prime.poly_reduce();

            v_prime // rename to w
        };

        // 7: 𝑚 ← ByteEncode1(Compress1(𝑤))
        //   ▷ decode plaintext 𝑚 from polynomial 𝑤, into a `Secret`: it is an internal value
        //   (FIPS 203 Sec 3.3) that must not outlive the decapsulation.
        let mut m = Secret::<[u8; 32]>::new();
        *m = w.to_msg();
        m
    }

    /// Algorithm 18 ML-KEM.Decaps_internal(dk, 𝑐)
    /// Uses the decapsulation key to produce a shared secret key from a ciphertext.
    /// Input: decapsulation key dk ∈ 𝔹768𝑘+96 .
    /// Input: ciphertext 𝑐 ∈ 𝔹32(𝑑𝑢𝑘+𝑑𝑣).
    /// Output: shared secret key 𝐾 ∈ 𝔹32 .
    fn decaps_internal<DK: MLKEMPrivateKeyInternalTrait<P>, const CT_LEN: usize>(
        dk: &DK,
        c: &[u8; CT_LEN],
    ) -> Secret<[u8; MLKEM_SS_LEN]> {
        // I have tried to keep this as clean as possible for correspondence with the FIPS,
        // but I have moved things around so that I can use unnamed scopes to limit how many
        // stack variables are alive at the same time.

        // 1: dkPKE ← dk[0 ∶ 384𝑘] ▷ extract (from KEM decaps key) the PKE decryption key
        // 2: ekPKE ← dk[384𝑘 ∶ 768𝑘 + 32] ▷ extract PKE encryption key
        // 3: ℎ ← dk[768𝑘 + 32 ∶ 768𝑘 + 64] ▷ extract hash of PKE encryption key
        // 4: 𝑧 ← dk[768𝑘 + 64 ∶ 768𝑘 + 96] ▷ extract implicit rejection value
        // Nothing to do since dk is already decoded.

        // 5: 𝑚′ ← K-PKE.Decrypt(dkPKE, 𝑐)
        let m_prime = Self::pke_decrypt(dk, c);

        // Compute the trial shared secret key
        // 6: (𝐾′, 𝑟′) ← G(𝑚′‖ℎ)̄
        let (K_prime, r_prime) = {
            let mut buf: Secret<[u8; 64]> = Secret::new();
            let mut g = G::new();
            g.do_update(&*m_prime);
            g.do_update(dk.pk_hash());
            let bytes_written = g.do_final_out(&mut *buf);
            debug_assert_eq!(bytes_written, 64);

            let mut K_prime: Secret<[u8; MLKEM_SS_LEN]> = Secret::new();
            K_prime.copy_from_slice(&buf[..32]);
            let mut r_prime: Secret<[u8; 32]> = Secret::new();
            r_prime.copy_from_slice(&buf[32..64]);
            (K_prime, r_prime)
        };

        // 7: 𝐾_bar ← J(𝑧‖𝑐)
        //   Compute the rejection sampling key.
        //   Note to future optimizers: this needs to be computed outside of the if at line 9 below
        //   because if its computation is conditional on the Fujisaki-Okamoto check failing, then
        //   there will be a timing difference between success and failure.

        let K_bar: Secret<[u8; MLKEM_SS_LEN]> = {
            let mut K_bar: Secret<[u8; MLKEM_SS_LEN]> = Secret::new();
            let mut j = J::new();
            j.do_update(dk.z());
            j.do_update(c);
            let mut j = j.into_squeezer();
            let bytes_written = j.do_output_out(&mut *K_bar);
            debug_assert_eq!(bytes_written, MLKEM_SS_LEN);

            K_bar
        };

        // 8: 𝑐′ ← K-PKE.Encrypt(ekPKE, 𝑚′, 𝑟′)
        //   ▷ re-encrypt using the derived randomness 𝑟′
        // A seed key holds no 𝐭̂, so it derives one here (Algorithm 13 again, most of what makes
        // this crate's decapsulation slower than its encapsulation); an expanded key hands over
        // the copy it holds.
        let c_prime = Self::pke_encrypt::<CT_LEN>(&dk.t_hat_packed(), dk.rho(), &m_prime, &r_prime);

        // 9: if 𝑐 ≠ 𝑐′ then
        // 10: 𝐾′ ← 𝐾_bar
        //  ▷ if ciphertexts do not match, “implicitly reject"
        let mut K_out = Secret::<[u8; MLKEM_SS_LEN]>::new();
        conditional_copy_bytes(&K_prime, &K_bar, &mut K_out, ct_eq_bytes_mask(c, &c_prime));

        K_out
    }

    /// Decapsulation from the seed form of the private key: builds the key with
    /// `MLKEMPrivateKeyTrait::from_keymaterial` and decapsulates with it. Costs a key generation
    /// on top of the decapsulation.
    pub fn decaps_from_seed<const CT_LEN: usize>(
        seed: &KeyMaterial<64>,
        ct: &[u8; CT_LEN],
    ) -> Result<KeyMaterial<MLKEM_SS_LEN>, KEMError>
    where
        P: CiphertextLen<CT_LEN>,
    {
        let sk = MLKEMSeedPrivateKey::<P>::from_keymaterial(seed)?;

        sk.decaps((), ct)
    }

    /// Algorithm 20 ML-KEM.Encaps(ek), lines 1-5.
    fn encaps_with_rng<const CT_LEN: usize>(
        ek: &MLKEMPublicKey<P>,
        rng: &mut dyn RNG,
        ct: &mut [u8; CT_LEN],
    ) -> Result<(KeyMaterial<MLKEM_SS_LEN>, usize), KEMError> {
        ct.fill(0);

        // 1: 𝑚 ← 𝔹32, from the caller's RNG, which must be at least as strong as the parameter set
        if rng.security_strength() < P::MAX_SECURITY_STRENGTH {
            Err(RNGError::SecurityStrengthInsufficientForAlgorithm)?;
        }
        let mut m = Secret::<[u8; 32]>::new();
        rng.next_bytes_out(&mut *m)?;

        // 5: (𝐾, 𝑐) ← ML-KEM.Encaps_internal(ek, 𝑚)
        let (K, c) = Self::encaps_internal::<CT_LEN>(ek, &m);
        *ct = c;

        Ok((Self::shared_secret_key(&K)?, CT_LEN))
    }

    /// Algorithm 21 ML-KEM.Decaps(dk, 𝑐) over either form of this crate's private key.
    ///
    /// Of the Section 7.3 decapsulation input checks, 1 (the ciphertext length) is the type of
    /// `ct`; 2 and 3 concern the FIPS 203 encoding of dk, which this crate's keys never hold: a
    /// key is derived from its seed, so it is consistent by construction.
    fn decaps_checked<DK: MLKEMPrivateKeyInternalTrait<P>, const CT_LEN: usize>(
        dk: &DK,
        ct: &[u8; CT_LEN],
    ) -> Result<KeyMaterial<MLKEM_SS_LEN>, KEMError> {
        // 1: 𝐾′ ← ML-KEM.Decaps_internal(dk, 𝑐)
        let K = Self::decaps_internal(dk, ct);

        Self::shared_secret_key(&K)
    }

    /// The shared secret as [`KeyMaterial`]: full-entropy bytes at the parameter set's strength.
    fn shared_secret_key(K: &[u8; MLKEM_SS_LEN]) -> Result<KeyMaterial<MLKEM_SS_LEN>, KEMError> {
        let mut key =
            KeyMaterial::<MLKEM_SS_LEN>::from_bytes_as_type(K, KeyType::CryptographicRandom)?;
        do_hazardous_operations(&mut key, |key| {
            key.set_security_strength(P::MAX_SECURITY_STRENGTH)
        })?;

        Ok(key)
    }
}

impl<P: MLKEMParams> MLKEMTrait<P> for MLKEM<P> {
    /// Imports a secret key from a seed.
    fn keygen_from_seed(
        seed: &KeyMaterial<64>,
    ) -> Result<(MLKEMPublicKey<P>, MLKEMSeedPrivateKey<P>), KEMError> {
        Self::keygen_internal(seed)
    }
    /// Imports a secret key from both a seed and an encoded_sk.
    ///
    /// This is a convenience function to expand the key from seed and compare it against
    /// the provided `encoded_sk` using a constant-time equality check.
    /// If everything checks out, the secret key is returned fully populated with pk and seed.
    /// If the provided key and derived key don't match, an error is returned.
    fn keygen_from_seed_and_encoded<const FULL_SK_LEN: usize>(
        seed: &KeyMaterial<64>,
        encoded_sk: &[u8; FULL_SK_LEN],
    ) -> Result<(MLKEMPublicKey<P>, MLKEMSeedPrivateKey<P>), KEMError>
    where
        P: PrivateKeyLen<FULL_SK_LEN>,
    {
        let (pk, sk) = Self::keygen_internal(seed)?;

        // The full encoding is private-key material: made in a `Secret` buffer for the comparison.
        let mut full = Secret::<[u8; FULL_SK_LEN]>::new();
        sk.encode_full_sk_out(&mut full);
        if !ct_eq_bytes(&*full, encoded_sk) {
            return Err(KEMError::KeyGenError("Encoded key does not match generated key"));
        }

        Ok((pk, sk))
    }
    fn keypair_consistency_check(
        pk: &MLKEMPublicKey<P>,
        sk: &MLKEMSeedPrivateKey<P>,
    ) -> Result<(), KEMError> {
        if *sk.pk_hash() == pk.compute_hash() {
            Ok(())
        } else {
            Err(KEMError::ConsistencyCheckFailed("Public key does not match the private key"))
        }
    }
}

/// Trait for all three of the ML-KEM parameter sets.
pub trait MLKEMTrait<P: MLKEMParams>: Sized {
    /// Key generation from the caller's RNG, which must offer at least the parameter set's
    /// security strength.
    // Should still be ok in FIPS mode, provided that you're using the FIPS-approved RNG.
    fn keygen(rng: &mut dyn RNG) -> Result<(MLKEMPublicKey<P>, MLKEMSeedPrivateKey<P>), KEMError> {
        // Source the seed from the provided RNG
        if rng.security_strength() < P::MAX_SECURITY_STRENGTH {
            Err(RNGError::SecurityStrengthInsufficientForAlgorithm)?;
        }
        let mut seed = KeyMaterial::<64>::new();
        rng.fill_keymaterial_out(&mut seed)?;
        Self::keygen_from_seed(&seed)
    }
    /// Imports a secret key from a seed.
    fn keygen_from_seed(
        seed: &KeyMaterial<64>,
    ) -> Result<(MLKEMPublicKey<P>, MLKEMSeedPrivateKey<P>), KEMError>;
    /// Imports a secret key from both a seed and its FIPS 203 encoding.
    ///
    /// Expands the key from the seed and compares its Algorithm 16 encoding
    /// (what [`MLKEMPrivateKeyTrait::encode_full_sk`] produces) against `encoded_sk` in constant
    /// time. If they match, the key is returned; if not, [`KEMError::KeyGenError`].
    fn keygen_from_seed_and_encoded<const FULL_SK_LEN: usize>(
        seed: &KeyMaterial<64>,
        encoded_sk: &[u8; FULL_SK_LEN],
    ) -> Result<(MLKEMPublicKey<P>, MLKEMSeedPrivateKey<P>), KEMError>
    where
        P: PrivateKeyLen<FULL_SK_LEN>;
    /// Given a public key and a secret key, check that the public key matches the secret key:
    /// H(ek) stored in the private key against the hash of `pk`.
    ///
    /// Returns either `()` or [`KEMError::ConsistencyCheckFailed`].
    fn keypair_consistency_check(
        pk: &MLKEMPublicKey<P>,
        sk: &MLKEMSeedPrivateKey<P>,
    ) -> Result<(), KEMError>;
}

/*** The workers and the key roles ***/

/// The encapsulator an ML-KEM public key hands out through [`EncapsulatingKey`]: it borrows the
/// key and draws the encapsulation randomness from the RNG of each call.
pub struct MLKEMEncapsulator<'k, P: MLKEMParams> {
    ek: &'k MLKEMPublicKey<P>,
}

impl<P: MLKEMParams> Algorithm for MLKEMEncapsulator<'_, P> {
    const ALG_NAME: &'static str = P::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

impl<P: MLKEMParams + CiphertextLen<CT_LEN>, const CT_LEN: usize>
    KEMEncapsulator<CT_LEN, MLKEM_SS_LEN> for MLKEMEncapsulator<'_, P>
{
    /// Algorithm 20 ML-KEM.Encaps(ek). The shared secret comes back as a [`KeyMaterial`] of type
    /// [`KeyType::CryptographicRandom`] at the parameter set's security strength.
    fn encaps_out(
        &self,
        rng: &mut dyn RNG,
        ct: &mut [u8; CT_LEN],
    ) -> Result<(KeyMaterial<MLKEM_SS_LEN>, usize), KEMError> {
        MLKEM::<P>::encaps_with_rng(self.ek, rng, ct)
    }
}

/// The decapsulator an ML-KEM private key hands out through [`DecapsulatingKey`]: it borrows the
/// key, seed or expanded.
pub struct MLKEMDecapsulator<'k, P: MLKEMParams, DK: MLKEMPrivateKeyInternalTrait<P>> {
    dk: &'k DK,
    _phantom: PhantomData<P>,
}

impl<P: MLKEMParams, DK: MLKEMPrivateKeyInternalTrait<P>> Algorithm
    for MLKEMDecapsulator<'_, P, DK>
{
    const ALG_NAME: &'static str = P::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

impl<
    P: MLKEMParams + CiphertextLen<CT_LEN>,
    DK: MLKEMPrivateKeyInternalTrait<P>,
    const CT_LEN: usize,
> KEMDecapsulator<CT_LEN, MLKEM_SS_LEN> for MLKEMDecapsulator<'_, P, DK>
{
    /// Algorithm 21 ML-KEM.Decaps(dk, 𝑐). The shared secret comes back as a [`KeyMaterial`] of
    /// type [`KeyType::CryptographicRandom`] at the parameter set's security strength. ML-KEM
    /// rejects implicitly, so a damaged ciphertext yields a different secret, not an error.
    fn decaps(&self, ct: &[u8; CT_LEN]) -> Result<KeyMaterial<MLKEM_SS_LEN>, KEMError> {
        MLKEM::<P>::decaps_checked(self.dk, ct)
    }
}

impl<P: MLKEMParams + CiphertextLen<CT_LEN>, const CT_LEN: usize>
    EncapsulatingKey<(), CT_LEN, MLKEM_SS_LEN> for MLKEMPublicKey<P>
{
    type Algorithm = MLKEM<P>;
    type Encapsulator<'k>
        = MLKEMEncapsulator<'k, P>
    where
        P: 'k;

    /// ML-KEM's shared secret is the primitive's own 𝐾 (FIPS 203, Algorithm 17), so a worker
    /// takes nothing beyond its key.
    fn create_encapsulator<'k>(&'k self, _params: ()) -> Result<Self::Encapsulator<'k>, KEMError> {
        Ok(MLKEMEncapsulator { ek: self })
    }
}

impl<P: MLKEMParams + CiphertextLen<CT_LEN>, const CT_LEN: usize>
    DecapsulatingKey<(), CT_LEN, MLKEM_SS_LEN> for MLKEMSeedPrivateKey<P>
{
    type Algorithm = MLKEM<P>;
    type Decapsulator<'k>
        = MLKEMDecapsulator<'k, P, Self>
    where
        P: 'k;

    fn create_decapsulator<'k>(&'k self, _params: ()) -> Result<Self::Decapsulator<'k>, KEMError> {
        Ok(MLKEMDecapsulator { dk: self, _phantom: PhantomData })
    }
}

impl<P: MLKEMParams + CiphertextLen<CT_LEN>, const CT_LEN: usize>
    DecapsulatingKey<(), CT_LEN, MLKEM_SS_LEN> for MLKEMSeedPrivateKeyExpanded<P>
{
    type Algorithm = MLKEM<P>;
    type Decapsulator<'k>
        = MLKEMDecapsulator<'k, P, Self>
    where
        P: 'k;

    fn create_decapsulator<'k>(&'k self, _params: ()) -> Result<Self::Decapsulator<'k>, KEMError> {
        Ok(MLKEMDecapsulator { dk: self, _phantom: PhantomData })
    }
}
