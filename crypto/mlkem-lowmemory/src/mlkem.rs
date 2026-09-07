//! There are no advanced features in this low memory crate that are not already documented in the standard \[bouncycastle_mlkem] crate.

use crate::aux_functions::sample_poly_CBD;
use crate::low_memory_helpers::{
    compress_u_row, compute_A_hat_dot_y_hat, compute_t_hat_dot_y_hat_row, unpack_ciphertext_u_row,
    unpack_ciphertext_v, unpack_t_hat_row,
};
use crate::mlkem_keys::{
    MLKEM512PrivateKey, MLKEM512PublicKey, MLKEM768PrivateKey, MLKEM768PublicKey,
    MLKEM1024PrivateKey, MLKEM1024PublicKey,
};
use crate::mlkem_keys::{MLKEMPrivateKeyInternalTrait, MLKEMPrivateKeyTrait};
use crate::mlkem_keys::{MLKEMPublicKeyInternalTrait, MLKEMPublicKeyTrait};
use crate::params::{MLKEM512Params, MLKEM768Params, MLKEM1024Params, MLKEMParams};
use crate::polynomial::Polynomial;
use bouncycastle_core::errors::{KEMError, RNGError};
use bouncycastle_core::key_material::{
    KeyMaterial, KeyMaterialTrait, KeyType, do_hazardous_operations,
};
use bouncycastle_core::traits::{
    Algorithm, AlgorithmOID, Hash, KEMDecapsulator, KEMEncapsulator, RNG, SecurityStrength, XOF,
    XofOutput,
};
use bouncycastle_rng::HashDRBG_SHA512;
use bouncycastle_sha3::{SHA3_256, SHA3_512, SHAKE256};
use bouncycastle_utils::ct::{conditional_copy_bytes, ct_eq_bytes};
use bouncycastle_utils::secret::Secret;
use core::marker::PhantomData;
/*** Constants ***/

///
pub const ML_KEM_512_NAME: &str = "ML-KEM-512";
///
pub const ML_KEM_768_NAME: &str = "ML-KEM-768";
///
pub const ML_KEM_1024_NAME: &str = "ML-KEM-1024";

// From FIPS 203 Table 2 and Table 3

// Constants that are the same for all parameter sets
/// Length of the \[u8] holding an ML-KEM seed value.
pub const MLKEM_SEED_LEN: usize = 64;
/// Length of the \[u8] holding an ML-KEM encaps random value, also sometimes called the message `m`
pub const MLKEM_RND_LEN: usize = 32;
/// Size of in bytes of an ML-KEM shared secret key.
pub const MLKEM_SS_LEN: usize = 32;
pub(crate) const N: usize = 256;
pub(crate) const q: i16 = 3329;
pub(crate) const q_inv: i32 = 62209;
pub(crate) const POLY_BYTES: usize = 384;

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

/*** Typedefs just to make the algorithms look more like the FIPS 204 sample code. ***/
pub(crate) type G = SHA3_512;
pub(crate) type H = SHA3_256;
pub(crate) type J = SHAKE256;

/*** Pub Types ***/

/// The ML-KEM-512 algorithm.
pub type MLKEM512 = MLKEM<
    MLKEM512Params,
    MLKEM512PublicKey,
    MLKEM512PrivateKey,
    MLKEM512_PK_LEN,
    MLKEM512_SK_LEN,
    MLKEM512_FULL_SK_LEN,
    MLKEM512_CT_LEN,
    MLKEM_SS_LEN,
>;

/// The ML-KEM-768 algorithm.
pub type MLKEM768 = MLKEM<
    MLKEM768Params,
    MLKEM768PublicKey,
    MLKEM768PrivateKey,
    MLKEM768_PK_LEN,
    MLKEM768_SK_LEN,
    MLKEM768_FULL_SK_LEN,
    MLKEM768_CT_LEN,
    MLKEM_SS_LEN,
>;

/// The ML-KEM-1024 algorithm.
pub type MLKEM1024 = MLKEM<
    MLKEM1024Params,
    MLKEM1024PublicKey,
    MLKEM1024PrivateKey,
    MLKEM1024_PK_LEN,
    MLKEM1024_SK_LEN,
    MLKEM1024_FULL_SK_LEN,
    MLKEM1024_CT_LEN,
    MLKEM_SS_LEN,
>;

impl<
    P: MLKEMParams,
    PK: MLKEMPublicKeyTrait<P, PK_LEN> + MLKEMPublicKeyInternalTrait<P, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<P, SK_LEN, FULL_SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<P, SK_LEN, PK_LEN>,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const FULL_SK_LEN: usize,
    const CT_LEN: usize,
    const SS_LEN: usize,
> Algorithm for MLKEM<P, PK, SK, PK_LEN, SK_LEN, FULL_SK_LEN, CT_LEN, SS_LEN>
{
    const ALG_NAME: &'static str = P::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

/// The OIDs NIST assigned in the Computer Security Objects Register: id-alg-ml-kem-512
/// { kems 1 }, id-alg-ml-kem-768 { kems 2 } and id-alg-ml-kem-1024 { kems 3 }. As with
/// [`Algorithm`], the values belong to the parameter set, so one impl covers all three.
impl<
    P: MLKEMParams,
    PK: MLKEMPublicKeyTrait<P, PK_LEN> + MLKEMPublicKeyInternalTrait<P, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<P, SK_LEN, FULL_SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<P, SK_LEN, PK_LEN>,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const FULL_SK_LEN: usize,
    const CT_LEN: usize,
    const SS_LEN: usize,
> AlgorithmOID for MLKEM<P, PK, SK, PK_LEN, SK_LEN, FULL_SK_LEN, CT_LEN, SS_LEN>
{
    const OID: &'static [u32] = P::OID;
    const OID_DER: &'static [u8] = P::OID_DER;
}

/// The core internal implementation of the ML-KEM algorithm.
/// This needs to be public for the compiler to be able to find it,
/// but is shouldn't ever need to be used directly.
/// Please use the named public types.
pub struct MLKEM<
    P: MLKEMParams,
    PK: MLKEMPublicKeyTrait<P, PK_LEN> + MLKEMPublicKeyInternalTrait<P, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<P, SK_LEN, FULL_SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<P, SK_LEN, PK_LEN>,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const FULL_SK_LEN: usize,
    const CT_LEN: usize,
    const SS_LEN: usize,
> {
    _phantom: PhantomData<(P, PK, SK)>,
}

impl<
    P: MLKEMParams,
    PK: MLKEMPublicKeyTrait<P, PK_LEN> + MLKEMPublicKeyInternalTrait<P, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<P, SK_LEN, FULL_SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<P, SK_LEN, PK_LEN>,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const FULL_SK_LEN: usize,
    const CT_LEN: usize,
    const SS_LEN: usize,
> MLKEM<P, PK, SK, PK_LEN, SK_LEN, FULL_SK_LEN, CT_LEN, SS_LEN>
{
    /// Performs the first step of key generation to transform the single provided seed into a set of internal intermediate seeds.
    ///
    /// Unlike other interfaces across the library that take an &impl KeyMaterial, this one
    /// specifically takes a 64-byte [`KeyMaterial512`] and checks that it has [`KeyType::Seed`] and
    /// the appropriate [`SecurityStrength`] for the requested ML-KEM parameter set.
    ///
    /// If you happen to have your seed in a larger KeyMaterial, you'll have to copy it into a
    /// correctly-sized [`KeyMaterial512`] using [`KeyMaterialTrait::truncate`].
    pub(crate) fn keygen_internal(seed: &KeyMaterial<64>) -> Result<(PK, SK), KEMError> {
        let sk = SK::from_keymaterial(seed)?;
        let pk = sk.pk();
        let pk = PK::new(pk.t_hat_packed, pk.rho); // stupid conversion, but it gets around these overly-generified rust types
        Ok((pk, sk))
    }

    /// Algorithm 14 K-PKE.Encrypt(ekPKE, 𝑚, 𝑟)
    /// Uses the encryption key to encrypt a plaintext message using the randomness 𝑟.
    /// Input: encryption key ekPKE ∈ 𝔹384𝑘+32 .
    /// Input: message 𝑚 ∈ 𝔹32 .
    /// Input: randomness 𝑟 ∈ 𝔹32 .
    /// Output: ciphertext 𝑐 ∈ 𝔹32(𝑑𝑢𝑘+𝑑𝑣).
    fn pke_encrypt(
        t_hat_packed: &P::TPacked,
        rho: &[u8; 32],
        m: [u8; 32],
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

        // Note: y_hat is needed twice: once here at line 19, and again at line 21.
        // Here it is generated each time it is needed in order to save memory.
        for i in 0..P::k {
            let mut u_i = compute_A_hat_dot_y_hat::<P>(rho, &r, i);

            let e1_i = sample_poly_CBD(&r, (P::k + i) as u8, P::eta2);
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
                &r,
                &unpack_t_hat_row(t_hat_packed.as_ref(), 0),
                /*row*/ 0,
            );

            for i in 1..P::k {
                let v_i = compute_t_hat_dot_y_hat_row::<P>(
                    &r,
                    &unpack_t_hat_row(t_hat_packed.as_ref(), i),
                    /*row*/ i,
                );
                v.add(&v_i);
            }

            // perform polynomial addition
            let e2 = sample_poly_CBD(&r, 2 * P::k as u8, P::eta2);
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
    /// Unlike the more public function exposed by [`KEMEncapsulator::encaps`], this returns the shared secret as raw bytes
    /// instead of wrapped in an appropriately-set [`KeyMaterialTrait`].
    /// Proper handling is up to the user's own judgement.
    ///
    /// Note: this is an internal function that allows the caller to specify the encapsulation
    /// randomness (which is the message `m` to be encrypted by the underlying PKE scheme).
    /// This function should not be used directly unless there is a good reason to do so.
    /// [`KEMEncapsulator::encaps`] should be used in 99.9% of cases.
    /// The reason this is exposed publicly is:
    ///     A) for unit testing that requires access to the deterministically reproducible function, and
    ///     B) for operational environments that wish to provide randomness from their own source instead
    ///        of the built-in RNG in bc-rust.
    /// As a reminder, any deterministic KEM (or any encryption mechanism) fails to satisfy any security
    /// notion involving indistinguishability (e.g. IND-CPA, IND-CCA2, etc.).
    /// Failing to use this properly will result in catastrophic vulnerabilities.
    /// Please don't do it.
    pub fn encaps_internal(ek: &PK, m: [u8; 32]) -> ([u8; 32], [u8; CT_LEN]) {
        // 1: (𝐾, 𝑟) ← G(𝑚‖H(ek))
        //  ▷ derive shared secret key 𝐾 and randomness 𝑟
        let K: [u8; MLKEM_SS_LEN];
        let r: [u8; 32];
        (K, r) = {
            let mut g = G::new();
            g.do_update(&m);
            g.do_update(&ek.compute_hash());
            let mut buf = [0u8; 64];
            let bytes_written = g.do_final_out(&mut buf);
            debug_assert_eq!(bytes_written, 64);

            (buf[..32].try_into().unwrap(), buf[32..64].try_into().unwrap())
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
    fn pke_decrypt(dk: &SK, ct: [u8; CT_LEN]) -> [u8; 32] {
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
                    let mut u_prime_i = unpack_ciphertext_u_row::<P, CT_LEN>(0, &ct);
                    u_prime_i.ntt();
                    s_hat_i.base_mult_montgomery(&u_prime_i);
                }
                s_hat_i.inv_ntt();

                s_hat_i
            };

            for i in 1..P::k {
                let mut s_hat_i = dk.compute_s_hat_row(i);
                {
                    let mut u_prime_i = unpack_ciphertext_u_row::<P, CT_LEN>(i, &ct);
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
            let mut v_prime = unpack_ciphertext_v::<P, CT_LEN>(&ct);

            v_prime.sub(&v1);
            v_prime.poly_reduce();

            v_prime // rename to w
        };

        // 7: 𝑚 ← ByteEncode1(Compress1(𝑤))
        //   ▷ decode plaintext 𝑚 from polynomial 𝑤
        w.to_msg()
    }

    /// Algorithm 18 ML-KEM.Decaps_internal(dk, 𝑐)
    /// Uses the decapsulation key to produce a shared secret key from a ciphertext.
    /// Input: decapsulation key dk ∈ 𝔹768𝑘+96 .
    /// Input: ciphertext 𝑐 ∈ 𝔹32(𝑑𝑢𝑘+𝑑𝑣).
    /// Output: shared secret key 𝐾 ∈ 𝔹32 .
    fn decaps_internal(dk: &SK, c: [u8; CT_LEN]) -> [u8; MLKEM_SS_LEN] {
        // I have tried to keep this as clean as possible for correspondence with the FIPS,
        // but I have moved things around so that I can use unnamed scopes to limit how many
        // stack variables are alive at the same time.

        // 1: dkPKE ← dk[0 ∶ 384𝑘] ▷ extract (from KEM decaps key) the PKE decryption key
        // 2: ekPKE ← dk[384𝑘 ∶ 768𝑘 + 32] ▷ extract PKE encryption key
        // 3: ℎ ← dk[768𝑘 + 32 ∶ 768𝑘 + 64] ▷ extract hash of PKE encryption key
        // 4: 𝑧 ← dk[768𝑘 + 64 ∶ 768𝑘 + 96] ▷ extract implicit rejection value
        // Nothing to do since dk is already decoded.

        // 5: 𝑚′ ← K-PKE.Decrypt(dkPKE, 𝑐)
        let m_prime = Self::pke_decrypt(&dk, c);

        // Compute the trial shared secret key
        // 6: (𝐾′, 𝑟′) ← G(𝑚′‖ℎ)̄
        let K_prime: Secret<[u8; MLKEM_SS_LEN]>;
        let r_prime: [u8; 32];
        (K_prime, r_prime) = {
            let mut buf: Secret<[u8; 64]> = Secret::new();
            let mut g = G::new();
            g.do_update(&m_prime);
            g.do_update(&dk.pk().compute_hash());
            let bytes_written = g.do_final_out(&mut *buf);
            debug_assert_eq!(bytes_written, 64);

            let mut K_prime: Secret<[u8; MLKEM_SS_LEN]> = Secret::new();
            K_prime.copy_from_slice(&buf[..32]);
            (K_prime, buf[32..64].try_into().unwrap())
        };

        // 7: 𝐾_bar ← J(𝑧‖𝑐)
        //   Compute the rejection sampling key.
        //   Note to future optimizers: this needs to be computed outside of the if at line 9 below
        //   because if its computation is conditional on the Fujisaki-Okamoto check failing, then
        //   there will be a timing difference between success and failure.

        let K_bar: Secret<[u8; MLKEM_SS_LEN]>;
        K_bar = {
            let mut K_bar: Secret<[u8; MLKEM_SS_LEN]> = Secret::new();
            let mut j = J::new();
            j.do_update(dk.z());
            j.do_update(&c);
            let mut j = j.into_output();
            let bytes_written = j.do_output_out(&mut *K_bar);
            debug_assert_eq!(bytes_written, MLKEM_SS_LEN);

            K_bar
        };

        // 8: 𝑐′ ← K-PKE.Encrypt(ekPKE, 𝑚′, 𝑟′)
        //   ▷ re-encrypt using the derived randomness 𝑟′
        let c_prime = Self::pke_encrypt(&dk.t_hat_packed(), dk.rho(), m_prime, &r_prime);

        // 9: if 𝑐 ≠ 𝑐′ then
        // 10: 𝐾′ ← 𝐾_bar
        //  ▷ if ciphertexts do not match, “implicitly reject"
        let mut K_out = [0u8; MLKEM_SS_LEN];
        conditional_copy_bytes(&K_prime, &K_bar, &mut K_out, ct_eq_bytes(&c, &c_prime));

        K_out
    }

    /// Alternative initialization of the streaming signer where there is a private key
    /// as a seed and its expansion should be delayed as late as possible to reduce memory-usage.
    pub fn decaps_from_seed(
        seed: &KeyMaterial<64>,
        ct: &[u8],
    ) -> Result<KeyMaterial<SS_LEN>, KEMError> {
        let sk = SK::from_keymaterial(seed)?;

        Self::decaps(&sk, ct)
    }
}

impl<
    P: MLKEMParams,
    PK: MLKEMPublicKeyTrait<P, PK_LEN> + MLKEMPublicKeyInternalTrait<P, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<P, SK_LEN, FULL_SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<P, SK_LEN, PK_LEN>,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const FULL_SK_LEN: usize,
    const CT_LEN: usize,
    const SS_LEN: usize,
> MLKEMTrait<P, PK, SK, PK_LEN, SK_LEN, FULL_SK_LEN, CT_LEN, SS_LEN>
    for MLKEM<P, PK, SK, PK_LEN, SK_LEN, FULL_SK_LEN, CT_LEN, SS_LEN>
{
    /// Imports a secret key from a seed.
    fn keygen_from_seed(seed: &KeyMaterial<64>) -> Result<(PK, SK), KEMError> {
        Self::keygen_internal(seed)
    }
    /// Imports a secret key from both a seed and an encoded_sk.
    ///
    /// This is a convenience function to expand the key from seed and compare it against
    /// the provided `encoded_sk` using a constant-time equality check.
    /// If everything checks out, the secret key is returned fully populated with pk and seed.
    /// If the provided key and derived key don't match, an error is returned.
    fn keygen_from_seed_and_encoded(
        seed: &KeyMaterial<64>,
        encoded_sk: &[u8; SK_LEN],
    ) -> Result<(PK, SK), KEMError> {
        let (pk, sk) = Self::keygen_internal(seed)?;

        let sk_from_bytes = SK::sk_decode(encoded_sk);

        // MLKEMPrivateKey impls PartialEq with a constant-time equality check.
        if sk != sk_from_bytes {
            return Err(KEMError::KeyGenError("Encoded key does not match generated key"));
        }

        Ok((pk, sk))
    }
    /// Given a public key and a secret key, check that the public key matches the secret key.
    /// This is a sanity check that the public key was generated correctly from the secret key.
    ///
    /// At the current time, this is only possible if `sk` either contains a public key (in which case
    /// the two pk's are encoded and compared for byte equality), or if `sk` contains a seed
    /// (in which case a keygen_from_seed is run and then the pk's compared).
    ///
    /// Returns either `()` or [`KEMError::ConsistencyCheckFailed`].
    fn keypair_consistency_check(pk: &PK, sk: &SK) -> Result<(), KEMError> {
        let derived_pk = sk.pk();
        if derived_pk.compute_hash() == pk.compute_hash() {
            Ok(())
        } else {
            Err(KEMError::ConsistencyCheckFailed(""))
        }
    }
}

/// Trait for all three of the ML-DSA algorithm variants.
pub trait MLKEMTrait<
    P: MLKEMParams,
    PK: MLKEMPublicKeyTrait<P, PK_LEN> + MLKEMPublicKeyInternalTrait<P, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<P, SK_LEN, FULL_SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<P, SK_LEN, PK_LEN>,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const FULL_SK_LEN: usize,
    const CT_LEN: usize,
    const SS_LEN: usize,
>: Sized
{
    /// Generates a fresh key pair.
    fn keygen() -> Result<(PK, SK), KEMError> {
        let mut os_rng = HashDRBG_SHA512::new_from_os();
        Self::keygen_from_rng(&mut os_rng)
    }
    /// Run a keygen using the provided RNG implementation.
    // Should still be ok in FIPS mode, provided that you're using the FIPS-approved RNG.
    fn keygen_from_rng(rng: &mut dyn RNG) -> Result<(PK, SK), KEMError> {
        // Source the seed from the provided RNG
        if rng.security_strength() < P::MAX_SECURITY_STRENGTH {
            return Err(RNGError::SecurityStrengthInsufficientForAlgorithm)?;
        }
        let mut seed = KeyMaterial::<64>::new();
        rng.fill_keymaterial_out(&mut seed)?;
        Self::keygen_from_seed(&seed)
    }
    /// Imports a secret key from a seed.
    fn keygen_from_seed(seed: &KeyMaterial<64>) -> Result<(PK, SK), KEMError>;
    /// Imports a secret key from both a seed and an encoded_sk.
    ///
    /// This is a convenience function to expand the key from seed and compare it against
    /// the provided `encoded_sk` using a constant-time equality check.
    /// If everything checks out, the secret key is returned fully populated with pk and seed.
    /// If the provided key and derived key don't match, an error is returned.
    fn keygen_from_seed_and_encoded(
        seed: &KeyMaterial<64>,
        encoded_sk: &[u8; SK_LEN],
    ) -> Result<(PK, SK), KEMError>;
    /// Given a public key and a secret key, check that the public key matches the secret key.
    /// This is a sanity check that the public key was generated correctly from the secret key.
    ///
    /// At the current time, this is only possible if `sk` either contains a public key (in which case
    /// the two pk's are encoded and compared for byte equality), or if `sk` contains a seed
    /// (in which case a keygen_from_seed is run and then the pk's compared).
    ///
    /// Returns either `()` or [`KEMError::ConsistencyCheckFailed`].
    fn keypair_consistency_check(pk: &PK, sk: &SK) -> Result<(), KEMError>;
}

impl<
    P: MLKEMParams,
    PK: MLKEMPublicKeyTrait<P, PK_LEN> + MLKEMPublicKeyInternalTrait<P, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<P, SK_LEN, FULL_SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<P, SK_LEN, PK_LEN>,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const FULL_SK_LEN: usize,
    const CT_LEN: usize,
    const SS_LEN: usize,
> KEMEncapsulator<PK, PK_LEN, CT_LEN, SS_LEN>
    for MLKEM<P, PK, SK, PK_LEN, SK_LEN, FULL_SK_LEN, CT_LEN, SS_LEN>
{
    fn encaps(pk: &PK) -> Result<(KeyMaterial<SS_LEN>, [u8; CT_LEN]), KEMError> {
        let mut os_rng = HashDRBG_SHA512::new_from_os();
        Self::encaps_rng(pk, &mut os_rng)
    }

    fn encaps_rng(
        pk: &PK,
        rng: &mut dyn RNG,
    ) -> Result<(KeyMaterial<SS_LEN>, [u8; CT_LEN]), KEMError> {
        // Source the random message m from the provided RNG
        if rng.security_strength() < P::MAX_SECURITY_STRENGTH {
            return Err(RNGError::SecurityStrengthInsufficientForAlgorithm)?;
        }
        let mut m = [0u8; 32];
        rng.next_bytes_out(&mut m)?;

        let (ss_bytes, ct) = Self::encaps_internal(pk, m);

        let mut ss_keymaterial =
            KeyMaterial::<SS_LEN>::from_bytes_as_type(&ss_bytes, KeyType::CryptographicRandom)?;
        do_hazardous_operations(&mut ss_keymaterial, |ss_keymaterial| {
            ss_keymaterial.set_security_strength(P::MAX_SECURITY_STRENGTH)
        })?;

        Ok((ss_keymaterial, ct))
    }
}

impl<
    P: MLKEMParams,
    PK: MLKEMPublicKeyTrait<P, PK_LEN> + MLKEMPublicKeyInternalTrait<P, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<P, SK_LEN, FULL_SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<P, SK_LEN, PK_LEN>,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const FULL_SK_LEN: usize,
    const CT_LEN: usize,
    const SS_LEN: usize,
> KEMDecapsulator<SK, SK_LEN, CT_LEN, SS_LEN>
    for MLKEM<P, PK, SK, PK_LEN, SK_LEN, FULL_SK_LEN, CT_LEN, SS_LEN>
{
    /// Performs a decapsulation of the given ciphertext.
    /// Returns the shared secret key.
    /// The derived shared secret key is returned as a KeyMaterial with the SecurityStrength set to
    /// the security level of the ML-KEM parameter set.
    /// As ML-KEM is an implicitly-rejecting KEM, this returns an error only if the ciphertext is invalid (ie the wrong length)..
    fn decaps(sk: &SK, ct: &[u8]) -> Result<KeyMaterial<SS_LEN>, KEMError> {
        if ct.len() != CT_LEN {
            return Err(KEMError::LengthError("Invalid ciphertext length"));
        }

        let ss_bytes = Self::decaps_internal(sk, ct.try_into().unwrap());

        let mut ss_keymaterial =
            KeyMaterial::<SS_LEN>::from_bytes_as_type(&ss_bytes, KeyType::CryptographicRandom)?;
        do_hazardous_operations(&mut ss_keymaterial, |ss_keymaterial| {
            ss_keymaterial.set_security_strength(P::MAX_SECURITY_STRENGTH)
        })?;

        Ok(ss_keymaterial)
    }
}
