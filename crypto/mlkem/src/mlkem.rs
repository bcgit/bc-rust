//! This page documents advanced features of the Module Lattice Key-Encapsulation Algorithm (ML-KEM)
//! available in this crate.
//!
//! # Pre-expanding the public key for repeated use
//!
//! Within the usual ML-KEM public key representation, the public matrix A is stored as a seed rho, which
//! means that both the ML-KEM.encops() and ML-KEM.decaps() operations need to expand it into a full matrix
//! before performing the matrix multiplication.
//! We offer a version of the public and private key structs that pre-expand the public matrix for repeated use.
//!
//! When done as part of the keygen, expansion of the public matrix accounts for roughly 25% of the keygen time,
//! however it accounts for roughly 35% / 60% / 80% of an encaps and 30% / 45% / 65% of a decaps
//! for MLKEM512 / MLKEM768 / MLKEM1024.
//!
//! Most often, ML-KEM is used in an ephemeral mode where a key pair is generated, used for a single encaps
//! and decaps and then discarded. In this mode, there is no performance difference to whether the
//! public matrix A is expanded as part of keygen or as part of encaps / decaps, but it does make both
//! the public and private key take up more space in memory, so the default ML-KEM public and private key
//! objects defer expansion until it is needed.
//!
//! However, in non-ephemeral uses where many encaps or decaps operations are performed against the same
//! key pair in quick succession, there can be substantial performance improvements to pre-computing
//! this and holding on to a larger key object.
//! This is accomplished via constructing a [MLKEMPublicKeyExpanded] or [MLKEMPrivateKeyExpanded] object
//! of the appropriate parameter set from the original key, and then using this with [MLKEM::encaps_for_expanded_key]
//! or [MLKEM::decaps_with_expanded_key].
//! Both [MLKEMPublicKeyExpanded] and [MLKEMPrivateKeyExpanded] implement the same traits
//! and therefore behave the same as their non-expanded counterparts in most regards.
//!
//! ```rust
//! use bouncycastle_mlkem::{MLKEM768, MLKEMTrait};
//! use bouncycastle_mlkem::{MLKEM768PublicKeyExpanded, MLKEM768PrivateKeyExpanded};
//! use bouncycastle_core::errors::KEMError;
//!
//! let (pk, sk) = MLKEM768::keygen().unwrap();
//!
//! // Pre-expand the public key uses more memory, but has performance
//! // improvements if doing multiple encapsulations for the same key
//! let pk_expanded = MLKEM768PublicKeyExpanded::from(&pk);
//! let (ss, ct) = MLKEM768::encaps_for_expanded_key(&pk_expanded).unwrap();
//!
//! // Pre-expand the private key, which uses more memory, but has performance
//! // improvements if doing multiple decapsulations with the same key
//! let sk_expanded = MLKEM768PrivateKeyExpanded::from(&sk);
//! let ss1 = match MLKEM768::decaps_with_expanded_key(&sk_expanded, &ct) {
//!     Err(KEMError) => panic!("Error decapsulating"),
//!     Ok(ss) => ss,
//! };
//!
//! assert_eq!(ss, ss1);
//! ```
//!
//! # decaps_from_seed
//!
//! This mode is intended for users who want the simplicity of storing only the seed form of the private key.
//! This is merely a convnience function that calls [MLKEM::keygen_from_seed) before performing a decapsulation.
//!
//! Example usage:
//!
//! ```rust
//! use bouncycastle_mlkem::{MLKEM768, MLKEMTrait};
//! use bouncycastle_core::traits::KEMEncapsulator;
//! use bouncycastle_core::errors::KEMError;
//! use bouncycastle_core::key_material::{KeyMaterial512, KeyType};
//! use bouncycastle_hex as hex;
//!
//! let seed = KeyMaterial512::from_bytes_as_type(
//!     &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
//!                   202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").unwrap(),
//!     KeyType::Seed,
//! ).unwrap();
//!
//! // for this demo, we do need to run keygen only to get the public key
//! let (pk, _sk) = MLKEM768::keygen_from_seed(&seed).unwrap();
//!
//! // Create the shared secret and ciphertext using the public key
//! let (ss, ct) = MLKEM768::encaps(&pk).unwrap();
//!
//! // Recover the shared secret using the private key seed
//! let ss1 = match MLKEM768::decaps_from_seed(&seed, &ct) {
//!     Err(KEMError) => panic!("Error decapsulating"),
//!     Ok(ss) => ss,
//! };
//!
//! assert_eq!(ss, ss1);
//! ```
//!
//! While this is currently only supported when operating from a seed-based private key, something analogous
//! could be done that merges the sk_decode() and sign() routines when working with the standardized
//! private key encoding (which is often called the "semi-expanded format" since the in-memory representation
//! is still larger).
//! Contact us if you need such a thing implemented.
//! ## Deterministic encapsulation
//!
//! This section pertains to [MLKEM::encaps_internal] which allows you to pass in the encapsulation randomness
//! and thus obtain a deterministic encapsulation.
//!
//! The only good reasons for doing this are: A) testing if you need reproducible results, or
//! B) if you want to use your own source of randomness, such as a hardware RNG, instead of the library's
//! default RNG.
//! If you think you will invent same clever cryptographic scheme by making clever use of this parameter:
//! don't; you will almost certainly end up with something completely insecure.
//!
//! ```rust
//! use bouncycastle_mlkem::{MLKEM768, MLKEMTrait};
//! use bouncycastle_core::traits::KEMDecapsulator;
//! use bouncycastle_core::errors::KEMError;
//! use bouncycastle_core::key_material::KeyMaterialTrait;
//!
//! let (pk, sk) = MLKEM768::keygen().unwrap();
//! // note: totally insecure and for demonstration purposes only.
//! //       The message `m` needs to be sourced from a cryptographically-secure RNG.
//! let m: [u8; 32] = [0; 32];
//!
//! // Create the shared secret and ciphertext using the public key and the random message `m`
//! let (ss, ct) = MLKEM768::encaps_internal(&pk, None, m);
//!
//! // Recover the shared secret using the private key//!
//! let ss1 = match MLKEM768::decaps(&sk, &ct) {
//!     Err(KEMError) => panic!("Error decapsulating"),
//!     Ok(ss) => ss,
//! };
//!
//! assert_eq!(ss, ss1.ref_to_bytes());
//! ```

use crate::MLKEMPublicKeyExpanded;
use crate::aux_functions::{
    expandA, pack_ciphertext, sample_poly_CBD, sample_vector_CBD, unpack_ciphertext_u,
    unpack_ciphertext_v,
};
use crate::matrix::{Matrix, Vector};
use crate::mlkem_keys::{
    MLKEM512PrivateKey, MLKEM512PublicKey, MLKEM768PrivateKey, MLKEM768PublicKey,
    MLKEM1024PrivateKey, MLKEM1024PublicKey,
};
use crate::mlkem_keys::{
    MLKEMPrivateKeyExpanded, MLKEMPublicKeyInternalTrait, MLKEMPublicKeyTrait,
};
use crate::mlkem_keys::{MLKEMPrivateKeyInternalTrait, MLKEMPrivateKeyTrait};
use crate::polynomial::Polynomial;
use bouncycastle_core::errors::KEMError;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{
    Algorithm, Hash, KEMDecapsulator, KEMEncapsulator, RNG, SecurityStrength, XOF,
};
use bouncycastle_rng::HashDRBG_SHA512;
use bouncycastle_sha3::{SHA3_256, SHA3_512, SHAKE256};
use bouncycastle_utils::ct::{conditional_copy_bytes, ct_eq_bytes};
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
pub(crate) const ETA2: i16 = 2;
pub(crate) const POLY_BYTES: usize = 384;

/* ML-KEM-512 params */

/// Length of the \[u8] holding a ML-KEM-512 public key.
pub const MLKEM512_PK_LEN: usize = 800;
/// Length of the \[u8] holding a ML-KEM-512 private key.
pub const MLKEM512_SK_LEN: usize = 1632;
/// Length of the \[u8] holding a ML-KEM-512 ciphertext.
pub const MLKEM512_CT_LEN: usize = 768;
pub(crate) const MLKEM512_k: usize = 2;
pub(crate) const MLKEM512_ETA1: i16 = 3;
pub(crate) const MLKEM512_DU: i16 = 10;
pub(crate) const MLKEM512_DV: i16 = 4;
/// Maps to "required RBG strength (bits)" in FIPS 203 Table 2
pub(crate) const MLKEM512_LAMBDA: i16 = 128;

/* ML-KEM-768 params */

/// Length of the \[u8] holding a ML-KEM-768 public key.
pub const MLKEM768_PK_LEN: usize = 1184;
/// Length of the \[u8] holding a ML-KEM-768 private key.
pub const MLKEM768_SK_LEN: usize = 2400;
/// Length of the \[u8] holding a ML-KEM-768 ciphertext.
pub const MLKEM768_CT_LEN: usize = 1088;
pub(crate) const MLKEM768_k: usize = 3;
pub(crate) const MLKEM768_ETA1: i16 = 2;
pub(crate) const MLKEM768_DU: i16 = 10;
pub(crate) const MLKEM768_DV: i16 = 4;
/// Maps to "required RBG strength (bits)" in FIPS 203 Table 2
pub(crate) const MLKEM768_LAMBDA: i16 = 192;

/* ML-KEM-1024 params */

/// Length of the \[u8] holding a ML-KEM-1024 public key.
pub const MLKEM1024_PK_LEN: usize = 1568;
/// Length of the \[u8] holding a ML-KEM-1024 private key.
pub const MLKEM1024_SK_LEN: usize = 3168;
/// Length of the \[u8] holding a ML-KEM-1024 ciphertext.
pub const MLKEM1024_CT_LEN: usize = 1568;
pub(crate) const MLKEM1024_k: usize = 4;
pub(crate) const MLKEM1024_ETA1: i16 = 2;
pub(crate) const MLKEM1024_DU: i16 = 11;
pub(crate) const MLKEM1024_DV: i16 = 5;
/// Maps to "required RBG strength (bits)" in FIPS 203 Table 2
pub(crate) const MLKEM1024_LAMBDA: i16 = 256;

// Typedefs just to make the algorithms look more like the FIPS 204 sample code.
pub(crate) type G = SHA3_512;
pub(crate) type H = SHA3_256;
pub(crate) type J = SHAKE256;

/*** Pub Types ***/

/// The ML-KEM-512 algorithm.
pub type MLKEM512 = MLKEM<
    MLKEM512_PK_LEN,
    MLKEM512_SK_LEN,
    MLKEM512_CT_LEN,
    MLKEM_SS_LEN,
    MLKEM512PublicKey,
    MLKEM512PrivateKey,
    MLKEM512_k,
    MLKEM512_ETA1,
    MLKEM512_DU,
    MLKEM512_DV,
    MLKEM512_LAMBDA,
>;

impl Algorithm for MLKEM512 {
    const ALG_NAME: &'static str = ML_KEM_512_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

/// The ML-KEM-768 algorithm.
pub type MLKEM768 = MLKEM<
    MLKEM768_PK_LEN,
    MLKEM768_SK_LEN,
    MLKEM768_CT_LEN,
    MLKEM_SS_LEN,
    MLKEM768PublicKey,
    MLKEM768PrivateKey,
    MLKEM768_k,
    MLKEM768_ETA1,
    MLKEM768_DU,
    MLKEM768_DV,
    MLKEM768_LAMBDA,
>;

impl Algorithm for MLKEM768 {
    const ALG_NAME: &'static str = ML_KEM_768_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}

/// The ML-KEM-1024 algorithm.
pub type MLKEM1024 = MLKEM<
    MLKEM1024_PK_LEN,
    MLKEM1024_SK_LEN,
    MLKEM1024_CT_LEN,
    MLKEM_SS_LEN,
    MLKEM1024PublicKey,
    MLKEM1024PrivateKey,
    MLKEM1024_k,
    MLKEM1024_ETA1,
    MLKEM1024_DU,
    MLKEM1024_DV,
    MLKEM1024_LAMBDA,
>;

impl Algorithm for MLKEM1024 {
    const ALG_NAME: &'static str = ML_KEM_1024_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}

/// The core internal implementation of the ML-KEM algorithm.
/// This needs to be public for the compiler to be able to find it, but you shouldn't ever
/// need to use this directly. Please use the named public types.
pub struct MLKEM<
    const PK_LEN: usize,
    const SK_LEN: usize,
    const CT_LEN: usize,
    const SS_LEN: usize,
    PK: MLKEMPublicKeyTrait<k, PK_LEN> + MLKEMPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<k, PK, SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<k, PK, SK_LEN, PK_LEN>,
    const k: usize,
    const eta: i16,
    const du: i16,
    const dv: i16,
    const LAMBDA: i16,
> {
    _phantom: PhantomData<(PK, SK)>,
}

impl<
    const PK_LEN: usize,
    const SK_LEN: usize,
    const CT_LEN: usize,
    const SS_LEN: usize,
    PK: MLKEMPublicKeyTrait<k, PK_LEN> + MLKEMPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<k, PK, SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<k, PK, SK_LEN, PK_LEN>,
    const k: usize,
    const eta1: i16,
    const du: i16,
    const dv: i16,
    const LAMBDA: i16,
> MLKEM<PK_LEN, SK_LEN, CT_LEN, SS_LEN, PK, SK, k, eta1, du, dv, LAMBDA>
{
    /// Generate a keypair, sourcing randomness from bouncycastle's default os-backed RNG.
    ///
    /// Key generation is intentionally not part of the [KEMEncapsulator] / [KEMDecapsulator] traits;
    /// it is provided as an inherent associated function directly on the algorithm struct.
    /// Error condition: basically only on RNG failures.
    pub fn keygen() -> Result<(PK, SK), KEMError> {
        Self::keygen_from_os_rng()
    }

    /// Should still be ok in FIPS mode
    pub fn keygen_from_os_rng() -> Result<(PK, SK), KEMError> {
        let mut seed = KeyMaterial::<64>::new();
        HashDRBG_SHA512::new_from_os().fill_keymaterial_out(&mut seed)?;
        Self::keygen_internal(&seed)
    }
    /// Algorithm 16 ML-KEM.KeyGen_internal(𝑑, 𝑧)
    /// Uses randomness to generate an encapsulation key and a corresponding decapsulation key.
    /// Input: randomness 𝑑 ∈ 𝔹32 .
    /// Input: randomness 𝑧 ∈ 𝔹32 .
    /// Output: encapsulation key ek ∈ 𝔹384𝑘+32 .
    /// Output: decapsulation key dk ∈ 𝔹768𝑘+96 .
    pub(crate) fn keygen_internal(seed: &KeyMaterial<64>) -> Result<(PK, SK), KEMError> {
        if !(seed.key_type() == KeyType::Seed || seed.key_type() == KeyType::BytesFullEntropy)
            || seed.key_len() != 64
        {
            return Err(KEMError::KeyGenError(
                "Seed must be 64 bytes and KeyType::Seed or KeyType::BytesFullEntropy.",
            ));
        }

        if seed.security_strength() < SecurityStrength::from_bits(LAMBDA as usize) {
            return Err(KEMError::KeyGenError(
                "Seed SecurityStrength must match algorithm security strength",
            ));
        }

        // 1: (ekPKE, dkPKE) ← K-PKE.KeyGen(𝑑)
        let (pk, s_hat) = Self::pke_keygen(&seed.ref_to_bytes()[..32].try_into().unwrap());

        // 2: ek ← ekPKE ▷ KEM encaps key is just the PKE encryption key
        // 3: dk ← (dkPKE‖ek‖H(ek)‖𝑧) ▷ KEM decaps key includes PKE decryption key
        // 4: return (ek, dk)
        let pk_hash = pk.compute_hash();
        Ok((
            pk.clone(),
            SK::new(
                s_hat,
                pk,
                pk_hash,
                seed.ref_to_bytes()[32..].try_into().unwrap(),
                Some(seed.ref_to_bytes()[..32].try_into().unwrap()),
            ),
        ))
    }

    /// Algorithm 13 K-PKE.KeyGen(𝑑)
    /// Uses randomness to generate an encryption key and a corresponding decryption key.
    /// Input: randomness 𝑑 ∈ 𝔹32 .
    /// Output: encryption key ek_PKE ∈ 𝔹384𝑘+32.
    /// Output: decryption key dk_PKE ∈ 𝔹384𝑘.
    fn pke_keygen(d: &[u8; 32]) -> (PK, Vector<k>) {
        // 1: (𝜌, 𝜎) ← G(𝑑‖𝑘)
        //  ▷ expand 32+1 bytes to two pseudorandom 32-byte seeds1
        // rho: public seed
        // sigma: noise seed
        let (rho, mut sigma) = {
            let mut g = G::new();
            g.do_update(d);
            g.do_update(&[k as u8]);
            let mut buf = [0u8; 64];
            let bytes_written = g.do_final_out(&mut buf);
            debug_assert_eq!(bytes_written, 64);

            (buf[..32].try_into().unwrap(), buf[32..64].try_into().unwrap())
        };

        // 2: 𝑁 ← 0
        //  Note: in the definition of PRF_eta on page 18, it's said to be one byte.
        //  since the number of loops here is static; we can hard-code the N values rather than using a counter

        // 8: for (𝑖 ← 0; 𝑖 < 𝑘; 𝑖++)
        //  ▷ generate 𝐬 ∈ (ℤ256)^k
        // 9: 𝐬[𝑖] ← SamplePolyCBD𝜂1(PRF𝜂1 (𝜎, 𝑁 ))
        //   ▷ 𝐬[𝑖] ∈ ℤ256 sampled from CBD
        // 10: 𝑁 ← 𝑁 + 1
        // Note: here n = 0
        let s_hat = {
            let mut s = sample_vector_CBD::<k, eta1>(&sigma, 0);

            // 16: 𝐬_hat ← NTT(𝐬)̂
            s.ntt();
            s.reduce();
            s
        };

        // first half of
        // 18: 𝐭_hat ← 𝐀_hat ∘ 𝐬_hat + 𝐞_hat
        let mut t_hat = {
            // 3: for (𝑖 ← 0; 𝑖 < 𝑘; 𝑖++)
            //  ▷ generate matrix A_hat ∈ (ℤ256)^k x k
            let A_hat = expandA(&rho);

            A_hat.matrix_vector_ntt::<false>(&s_hat)
        };

        // second half of
        // 18: 𝐭_hat ← 𝐀_hat ∘ 𝐬_hat + 𝐞_hat
        {
            // 12: for (𝑖 ← 0; 𝑖 < 𝑘; 𝑖++)
            //  ▷ generate 𝐞 ∈ (ℤ256)^k
            // 13: 𝐞[𝑖] ← SamplePolyCBD𝜂1(PRF𝜂1 (𝜎, 𝑁 ))
            //   ▷ 𝐞[𝑖] ∈ ℤ256 sampled from CBD
            // 14: 𝑁 ← 𝑁 + 1
            // Note: here n = k
            let mut e = sample_vector_CBD::<k, eta1>(&sigma, k as u8);

            e.ntt(); // technically now e_hat
            e.reduce();
            t_hat.add_vector_ntt(&e);
        }

        // Clear the secret data before returning memory to the OS
        sigma.fill(0u8);

        // 19: ekPKE ← ByteEncode12(𝐭)‖𝜌 ▷ run ByteEncode12 𝑘 times, then append 𝐀-seed
        // 20: dkPKE ← ByteEncode12(𝐬)̂ ▷ run ByteEncode12 𝑘 times
        // Note: I'm skipping the encoding at this stage and leaving it expanded for future efficiency when it's used.
        // 21: return (ekPKE, dkPKE)
        (PK::new(t_hat, rho), s_hat)
    }

    /// Algorithm 14 K-PKE.Encrypt(ekPKE, 𝑚, 𝑟)
    /// Uses the encryption key to encrypt a plaintext message using the randomness 𝑟.
    /// Input: encryption key ekPKE ∈ 𝔹384𝑘+32 .
    /// Input: message 𝑚 ∈ 𝔹32 .
    /// Input: randomness 𝑟 ∈ 𝔹32 .
    /// Output: ciphertext 𝑐 ∈ 𝔹32(𝑑𝑢𝑘+𝑑𝑣).
    fn pke_encrypt(ek: &PK, A_hat: &Matrix<k, k>, m: [u8; 32], r: &[u8; 32]) -> [u8; CT_LEN] {
        // 1: 𝑁 ← 0
        //  since the number of loops here is static; we can hard-code the N values rather than using a counter

        // 2: 𝐭 ← ByteDecode12(ekPKE[0 ∶ 384𝑘])
        // 3: 𝜌 ← ekPKE[384𝑘 ∶ 384𝑘 + 32]
        // not necessary here because ek is already decoded

        // 4: for (𝑖 ← 0; 𝑖 < 𝑘; 𝑖++)
        //   ▷ re-generate matrix 𝐀 ∈ (ℤ256_𝑞 )𝑘×𝑘 sampled in Alg. 13
        // We're doing an optimization where the user can pre-expand A_hat within the
        // public key object for faster repeated encapsulations against this public key.

        // 9: for (𝑖 ← 0; 𝑖 < 𝑘; 𝑖++)
        //  ▷ generate 𝐲 ∈ (ℤ256_𝑞)k
        // 10: 𝐲[𝑖] ← SamplePolyCBD𝜂1(PRF𝜂1 (𝑟, 𝑁))
        //   ▷ 𝐲[𝑖] ∈ ℤ256 sampled from CBD
        // 11: 𝑁 ← 𝑁 + 1
        // Note: here n = 0
        let y_hat = {
            let mut y = sample_vector_CBD::<k, eta1>(&r, 0);

            // 18: 𝐲_hat ← NTT(𝐲)
            y.ntt();

            y
        };

        // 19: 𝐮 ← NTT−1(𝐀_hat^⊺ ∘ 𝐲_hat) + 𝐞
        let mut u = A_hat.matrix_vector_ntt::<true>(&y_hat);
        u.inv_ntt();
        {
            // 12: for (𝑖 ← 0; 𝑖 < 𝑘; 𝑖++)
            //  ▷ generate 𝐞 ∈ (ℤ256_𝑞)k
            // 13: 𝐞[𝑖] ← SamplePolyCBD𝜂1(PRF𝜂1 (𝜎, 𝑁))
            //  ▷ 𝐞[𝑖] ∈ ℤ256 sampled from CBD𝑞
            // 14: 𝑁 ← 𝑁 + 1
            // note: here n = k
            let e1 = sample_vector_CBD::<k, ETA2>(&r, k as u8);

            u.add_vector_ntt(&e1);
        }
        u.reduce();

        // 20: 𝜇 ← Decompress1(ByteDecode1(𝑚))
        // 21: 𝑣 ← NTT−1(𝐭_hat^T ∘ 𝐲_hat) + 𝑒2 + 𝜇
        //  ▷ encode plaintext 𝑚 into polynomial 𝑣
        let mut v = ek.t_hat().dot_product(&y_hat);
        v.inv_ntt();

        // 17: 𝑒2 ← SamplePolyCBD𝜂2(PRF𝜂2 (𝑟, 𝑁))
        //  ▷ sample 𝑒2 ∈ ℤ256 from CBD
        // note: here n = 2k
        let e2 = sample_poly_CBD::<ETA2>(&r, 2 * k as u8);
        v.add(&e2);

        let mu = Polynomial::from_msg(m);
        v.add(&mu);

        v.poly_reduce();

        pack_ciphertext::<k, CT_LEN, du, dv>(&u, &v)
    }

    /// Algorithm 17 ML-KEM.Encaps_internal(ek, 𝑚)
    /// Uses the encapsulation key and randomness to generate a key and an associated ciphertext.
    /// Input: encapsulation key ek ∈ 𝔹384𝑘+32 .
    /// Input: randomness 𝑚 ∈ 𝔹32 .
    /// Output: shared secret key 𝐾 ∈ 𝔹32 .
    /// Output: ciphertext 𝑐 ∈ 𝔹32(𝑑𝑢𝑘+𝑑𝑣).
    ///
    /// This function also takes an Option for the public matrix A.
    /// If you don't know what it is, just provide None.
    /// This is to enable performance
    /// optimizations when the same public key is used for multiple encapsulations and the intermediate
    /// value called the public matrix A_hat can be re-used for multiple encapsulations.
    /// A_hat can be obtained from [MLKEMPublicKeyTrait::A_hat].
    /// Alternatively, you can use a [MLKEMPublicKeyExpanded] with [MLKEM::encaps_for_expanded_key].
    /// If you specify None, the function will compute A_hat internally and everything will work fine.
    ///
    /// Unlike the more public function exposed by [KEMEncapsulator::encaps], this returns the shared secret as raw bytes
    /// instead of wrapped in an appropriately-set [KeyMaterialTrait], so you're on your own for handling it properly.
    ///
    /// Note: this is an internal function that allows the caller to specify the encapsulation
    /// randomness (which is the message `m` to be encrypted by the underlying PKE scheme).
    /// This function should not be used directly unless you really have a
    /// good reason. [KEMEncapsulator::encaps] should be used in 99.9% of cases.
    /// The reason this is exposed publicly is: A) for unit testing that requires access
    /// to the deterministically reproducible function, and B) for operational environments
    /// that wish to provide randomness from their own source instead of the built-in RNG in bc-rust.
    /// If you think you will be clever and invent some scheme that uses a deterministic KEM,
    /// then you will almost certainly end up with security problems. Please don't do this.
    pub fn encaps_internal(
        ek: &PK,
        A_hat: Option<&Matrix<k, k>>,
        m: [u8; 32],
    ) -> ([u8; 32], [u8; CT_LEN]) {
        debug_assert_eq!(CT_LEN, 32 * ((du as usize) * k + (dv as usize)));

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
        //  To allow for pre-computing A_hat for multiple encapsulations, we will either take
        // A_hat passed in, or compute it fresh.
        let ct = match A_hat {
            Some(A_hat) => Self::pke_encrypt(ek, A_hat, m, &r),
            None => Self::pke_encrypt(ek, &ek.A_hat(), m, &r),
        };

        (K, ct)
    }

    /// Algorithm 15 K-PKE.Decrypt(dkPKE, 𝑐)
    /// Uses the decryption key to decrypt a ciphertext.
    /// Input: decryption key dkPKE  ∈ 𝔹384𝑘.
    /// Input: ciphertext 𝑐 ∈ 𝔹32(𝑑𝑢𝑘+𝑑𝑣).
    /// Output: message 𝑚 ∈ 𝔹32 .
    fn pke_decrypt(dk: &SK, ct: [u8; CT_LEN]) -> [u8; 32] {
        // 1: 𝑐1 ← 𝑐[0 ∶ 32𝑑𝑢𝑘]
        // 2: 𝑐2 ← 𝑐[32𝑑𝑢𝑘 ∶ 32(𝑑𝑢𝑘 + 𝑑𝑣)]
        // 3: 𝐮′ ← Decompress_𝑑𝑢(ByteDecode_𝑑𝑢(𝑐1))
        // 4: 𝑣′ ← Decompress_𝑑𝑣(ByteDecode_𝑑𝑣(𝑐2))
        let v1 = {
            let mut u_prime = unpack_ciphertext_u::<k, CT_LEN, du, dv>(&ct);

            // 5: 𝐬_hat ← ByteDecode12(dkPKE)
            //   Unnecessary here because dk is already decoded

            // 6: 𝑤 ← 𝑣′ − NTT−1(𝐬_hat^T ∘ NTT(𝐮′))
            u_prime.ntt();
            let mut v1 = dk.s_hat().dot_product(&u_prime);
            v1.inv_ntt();

            v1
        };

        let w = {
            let mut v_prime = unpack_ciphertext_v::<k, CT_LEN, du, dv>(&ct);

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
    fn decaps_internal(
        dk: &SK,
        A_hat: Option<&Matrix<k, k>>,
        c: [u8; CT_LEN],
    ) -> [u8; MLKEM_SS_LEN] {
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
        let K_prime: [u8; MLKEM_SS_LEN];
        let r_prime: [u8; 32];
        (K_prime, r_prime) = {
            let mut g = G::new();
            g.do_update(&m_prime);
            g.do_update(&dk.pk().compute_hash());
            let mut buf = [0u8; 64];
            let bytes_written = g.do_final_out(&mut buf);
            debug_assert_eq!(bytes_written, 64);

            (buf[..32].try_into().unwrap(), buf[32..64].try_into().unwrap())
        };

        // 7: 𝐾_bar ← J(𝑧‖𝑐)
        //   Compute the rejection sampling key.
        //   Note to future optimizers: this needs to be computed outside of the if at line 9 below
        //   because if its computation is conditional on the Fujisaki-Okamoto check failing, then
        //   you'll have a timing difference between success and failure.

        let K_bar: [u8; MLKEM_SS_LEN];
        K_bar = {
            let mut j = J::new();
            j.absorb(dk.z());
            j.absorb(&c);
            let mut buf = [0u8; MLKEM_SS_LEN];
            let bytes_written = j.squeeze_out(&mut buf);
            debug_assert_eq!(bytes_written, MLKEM_SS_LEN);

            buf
        };

        // 8: 𝑐′ ← K-PKE.Encrypt(ekPKE, 𝑚′, 𝑟′)
        //   ▷ re-encrypt using the derived randomness 𝑟′
        // deviation from FIPS:
        //  To allow for pre-computing A_hat for multiple encapsulations, we will either take
        // A_hat passed in, or compute it fresh.
        let c_prime = match A_hat {
            Some(A_hat) => Self::pke_encrypt(dk.pk(), A_hat, m_prime, &r_prime),
            None => Self::pke_encrypt(dk.pk(), &dk.pk().A_hat(), m_prime, &r_prime),
        };

        // 9: if 𝑐 ≠ 𝑐′ then
        // 10: 𝐾′ ← 𝐾_bar
        //  ▷ if ciphertexts do not match, “implicitly reject"
        let mut K_out = [0u8; MLKEM_SS_LEN];
        conditional_copy_bytes(&K_prime, &K_bar, &mut K_out, ct_eq_bytes(&c, &c_prime));

        K_out
    }

    /// Alternative initialization of the streaming signer where you have your private key
    /// as a seed and you want to delay its expansion as late as possible for memory-usage reasons.
    // todo -- should we build a fully-stitched-together decaps-from-seed ... or not?
    pub fn decaps_from_seed(
        seed: &KeyMaterial<64>,
        ct: &[u8],
    ) -> Result<KeyMaterial<SS_LEN>, KEMError> {
        let (_pk, sk) = Self::keygen_from_seed(seed)?;

        Self::decaps(&sk, ct)
    }
}

impl<
    const PK_LEN: usize,
    const SK_LEN: usize,
    const CT_LEN: usize,
    const SS_LEN: usize,
    PK: MLKEMPublicKeyTrait<k, PK_LEN> + MLKEMPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<k, PK, SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<k, PK, SK_LEN, PK_LEN>,
    const k: usize,
    const eta1: i16,
    const du: i16,
    const dv: i16,
    const LAMBDA: i16,
> MLKEMTrait<PK_LEN, SK_LEN, CT_LEN, SS_LEN, PK, SK, k, eta1, du, dv, LAMBDA>
    for MLKEM<PK_LEN, SK_LEN, CT_LEN, SS_LEN, PK, SK, k, eta1, du, dv, LAMBDA>
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

        let sk_from_bytes = SK::sk_decode(encoded_sk)?;

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
    /// Returns either `()` or [KEMError::ConsistencyCheckFailed].
    fn keypair_consistency_check(pk: &PK, sk: &SK) -> Result<(), KEMError> {
        let derived_pk = sk.pk();
        if derived_pk.compute_hash() == pk.compute_hash() {
            Ok(())
        } else {
            Err(KEMError::ConsistencyCheckFailed(""))
        }
    }

    fn encaps_for_expanded_key(
        pk: &MLKEMPublicKeyExpanded<k, PK, PK_LEN>,
    ) -> Result<(KeyMaterial<SS_LEN>, [u8; CT_LEN]), KEMError> {
        let mut m = [0u8; 32];
        HashDRBG_SHA512::new_from_os().next_bytes_out(&mut m)?;

        let (ss, ct) = Self::encaps_internal(&pk.ek, Some(&pk.A_hat), m);

        let mut key = KeyMaterial::<SS_LEN>::from_bytes_as_type(&ss, KeyType::BytesFullEntropy)?;
        key.allow_hazardous_operations();
        key.set_security_strength(SecurityStrength::from_bits(LAMBDA as usize))?;
        key.drop_hazardous_operations();

        Ok((key, ct))
    }

    fn decaps_with_expanded_key(
        sk: &MLKEMPrivateKeyExpanded<k, PK, SK, SK_LEN, PK_LEN>,
        ct: &[u8],
    ) -> Result<KeyMaterial<SS_LEN>, KEMError> {
        /* decapsulation inputs checks described on FIPS 203 section 7.3 */
        // 1. (Ciphertext type check) If 𝑐 is not a byte array of length 32(𝑑𝑢 𝑘 + 𝑑𝑣) for the values of 𝑑𝑢,
        //     𝑑𝑣, and 𝑘 specified by the relevant parameter set, then input checking has failed.
        debug_assert_eq!(CT_LEN, 32 * ((du as usize) * k + (dv as usize)));

        if ct.len() != CT_LEN {
            return Err(KEMError::LengthError("Ciphertext has the incorrect length"));
        }

        // 2. (Decapsulation key type check) If dk is not a byte array of length 768𝑘 + 96 for the value of
        //     𝑘 specified by the relevant parameter set, then input checking has failed.
        // This is handled at the time of loading dk into MLKEMPrivateKey

        // 3. Check that the H(ek) stored in the private key matches the ek also stored in the private key.
        // Again, this is handled by the MLKEMPrivateKey trait.

        /* the actual decaps operation */
        let K = Self::decaps_internal(&sk.dk, Some(&sk.A_hat), ct.try_into().unwrap());

        let mut key = KeyMaterial::<SS_LEN>::from_bytes_as_type(&K, KeyType::BytesFullEntropy)?;
        key.allow_hazardous_operations();
        key.set_security_strength(SecurityStrength::from_bits(LAMBDA as usize))?;
        key.drop_hazardous_operations();

        Ok(key)
    }
}

/// Trait for all three of the ML-DSA algorithm variants.
pub trait MLKEMTrait<
    const PK_LEN: usize,
    const SK_LEN: usize,
    const CT_LEN: usize,
    const SS_LEN: usize,
    PK: MLKEMPublicKeyTrait<k, PK_LEN> + MLKEMPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<k, PK, SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<k, PK, SK_LEN, PK_LEN>,
    const k: usize,
    const eta: i16,
    const du: i16,
    const dv: i16,
    const LAMBDA: i16,
>: Sized
{
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
    /// Returns either `()` or [KEMError::ConsistencyCheckFailed].
    fn keypair_consistency_check(pk: &PK, sk: &SK) -> Result<(), KEMError>;

    /// Same as [KEMEncapsulator::encaps], but acts on an [MLKEMPublicKeyExpanded].
    fn encaps_for_expanded_key(
        pk: &MLKEMPublicKeyExpanded<k, PK, PK_LEN>,
    ) -> Result<(KeyMaterial<SS_LEN>, [u8; CT_LEN]), KEMError>;

    /// Same as [KEMDecapsulator::decaps], but acts on an [MLKEMPrivateKeyExpanded].
    fn decaps_with_expanded_key(
        sk: &MLKEMPrivateKeyExpanded<k, PK, SK, SK_LEN, PK_LEN>,
        ct: &[u8],
    ) -> Result<KeyMaterial<SS_LEN>, KEMError>;
}

impl<
    const PK_LEN: usize,
    const SK_LEN: usize,
    const CT_LEN: usize,
    const SS_LEN: usize,
    PK: MLKEMPublicKeyTrait<k, PK_LEN> + MLKEMPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<k, PK, SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<k, PK, SK_LEN, PK_LEN>,
    const k: usize,
    const eta: i16,
    const du: i16,
    const dv: i16,
    const LAMBDA: i16,
> KEMEncapsulator<PK, PK_LEN, CT_LEN, SS_LEN>
    for MLKEM<PK_LEN, SK_LEN, CT_LEN, SS_LEN, PK, SK, k, eta, du, dv, LAMBDA>
{
    /// Performs an encapsulation against the given public key, using the library's default internal RNG.
    /// Returns (shared_secret_key, ciphertext)
    /// The derived shared secret key is returned as a KeyMaterial with the SecurityStrength set to
    /// the security level of the ML-KEM parameter set.
    ///
    /// Algorithm 20 ML-KEM.Encaps(ek)
    /// Uses the encapsulation key to generate a shared secret key and an associated ciphertext.
    /// Checked input: encapsulation key ek ∈ 𝔹384𝑘+32 .
    /// Output: shared secret key 𝐾 ∈ 𝔹32 .
    /// Output: ciphertext 𝑐 ∈ 𝔹32(𝑑𝑢𝑘+𝑑𝑣).
    fn encaps(pk: &PK) -> Result<(KeyMaterial<SS_LEN>, [u8; CT_LEN]), KEMError> {
        Self::encaps_for_expanded_key(&MLKEMPublicKeyExpanded::<k, PK, PK_LEN>::from(pk))
    }
}

impl<
    const PK_LEN: usize,
    const SK_LEN: usize,
    const CT_LEN: usize,
    const SS_LEN: usize,
    PK: MLKEMPublicKeyTrait<k, PK_LEN> + MLKEMPublicKeyInternalTrait<k, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<k, PK, SK_LEN, PK_LEN>
        + MLKEMPrivateKeyInternalTrait<k, PK, SK_LEN, PK_LEN>,
    const k: usize,
    const eta: i16,
    const du: i16,
    const dv: i16,
    const LAMBDA: i16,
> KEMDecapsulator<SK, SK_LEN, CT_LEN, SS_LEN>
    for MLKEM<PK_LEN, SK_LEN, CT_LEN, SS_LEN, PK, SK, k, eta, du, dv, LAMBDA>
{
    /// Performs a decapsulation of the given ciphertext.
    /// Returns the shared secret key.
    /// The derived shared secret key is returned as a KeyMaterial with the SecurityStrength set to
    /// the security level of the ML-KEM parameter set.
    fn decaps(sk: &SK, ct: &[u8]) -> Result<KeyMaterial<SS_LEN>, KEMError> {
        Self::decaps_with_expanded_key(
            &MLKEMPrivateKeyExpanded::<k, PK, SK, SK_LEN, PK_LEN>::from(sk),
            ct,
        )
    }
}
