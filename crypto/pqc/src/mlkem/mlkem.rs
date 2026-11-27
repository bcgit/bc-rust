//! This page documents advanced features of the Module Lattice Key-Encapsulation Algorithm (ML-KEM)
//! available in this module.
//!
//! # Pre-expanding the public key for repeated use
//!
//! Within the usual ML-KEM public key representation, the public matrix A is stored as a seed rho, which
//! means that both the ML-KEM.encaps() and ML-KEM.decaps() operations need to expand it into a full matrix
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
//! This is accomplished via constructing a [`MLKEMPublicKeyExpanded`] or [`MLKEMPrivateKeyExpanded`] object
//! of the appropriate parameter set from the original key. Both implement the same traits as their
//! non-expanded counterparts, including the [`EncapsulatingKey`] and [`DecapsulatingKey`] roles, and
//! therefore behave the same in every regard but speed and size.
//!
//! ```rust
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_pqc::mlkem::{MLKEM768, MLKEMTrait};
//! use bouncycastle_pqc::mlkem::{MLKEM768PublicKeyExpanded, MLKEM768PrivateKeyExpanded};
//! use bouncycastle_core::kem_key::{EncapsulatingKey, DecapsulatingKey};
//! use bouncycastle_core::errors::KEMError;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let (pk, sk) = MLKEM768::keygen(&mut rng).unwrap();
//!
//! // Pre-expand the public key uses more memory, but has performance
//! // improvements if doing multiple encapsulations for the same key
//! let pk_expanded = MLKEM768PublicKeyExpanded::from(&pk);
//! let (ss, ct) = pk_expanded.encaps(&mut rng, ()).unwrap();
//!
//! // Pre-expand the private key, which uses more memory, but has performance
//! // improvements if doing multiple decapsulations with the same key
//! let sk_expanded = MLKEM768PrivateKeyExpanded::from(&sk);
//! let ss1 = match sk_expanded.decaps(&ct, ()) {
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
//! This is merely a convenience function that calls [`MLKEMTrait::keygen_from_seed`] before performing a decapsulation.
//!
//! Example usage:
//!
//! ```rust
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_pqc::mlkem::{MLKEM768, MLKEMTrait};
//! use bouncycastle_core::kem_key::EncapsulatingKey;
//! use bouncycastle_core::errors::KEMError;
//! use bouncycastle_core::key_material::{KeyMaterial512, KeyType};
//! use bouncycastle_core::hex as hex;
//!
//! let seed = KeyMaterial512::from_bytes_as_type(
//!     &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
//!                   202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").unwrap(),
//!     KeyType::Seed,
//! ).unwrap();
//!
//! // for this demo, it is necessary to run keygen only to get the public key
//! let (pk, _sk) = MLKEM768::keygen_from_seed(&seed).unwrap();
//!
//! // Create the shared secret and ciphertext using the public key
//! let (ss, ct) = pk.encaps(&mut HashDRBG_SHA512::new_from_os(), ()).unwrap();
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
//! This is only offered for the seed form of the private key; a decapsulation straight from the
//! FIPS 203 encoding of `dk` would be `sk_decode()` followed by `decaps()`, which is what loading the
//! key and decapsulating already does.
//!
//! ## Deterministic encapsulation
//!
//! [`EncapsWithRandomness`](crate::mlkem::hazmat::EncapsWithRandomness) takes the encapsulation
//! randomness from the caller; its docs say when that is acceptable and why it is under `hazmat`.
//!
//! ```rust
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_pqc::mlkem::hazmat::EncapsWithRandomness;
//! use bouncycastle_pqc::mlkem::{MLKEM768, MLKEMTrait};
//! use bouncycastle_core::kem_key::DecapsulatingKey;
//! use bouncycastle_core::errors::KEMError;
//! use bouncycastle_core::key_material::KeyMaterialTrait;
//!
//! let (pk, sk) = MLKEM768::keygen(&mut HashDRBG_SHA512::new_from_os()).unwrap();
//! // note: totally insecure and for demonstration purposes only.
//! //       The message `m` needs to be sourced from a cryptographically-secure RNG.
//! let m: [u8; 32] = [0; 32];
//!
//! // Create the shared secret and ciphertext using the public key and the random message `m`
//! let (ss, ct) = pk.encaps_with_randomness(m);
//!
//! // Recover the shared secret using the private key
//! let ss1 = match sk.decaps(&ct, ()) {
//!     Err(KEMError) => panic!("Error decapsulating"),
//!     Ok(ss) => ss,
//! };
//!
//! assert_eq!(ss, ss1.ref_to_bytes());
//! ```

use crate::mlkem::aux_functions::{
    expandA, pack_ciphertext_out, sample_vector_CBD_out, unpack_ciphertext_u, unpack_ciphertext_v,
};
use crate::mlkem::matrix::{MatrixTrait, VectorTrait};
use crate::mlkem::mlkem_keys::{
    MLKEMPrivateKey, MLKEMPrivateKeyExpanded, MLKEMPrivateKeyInternalTrait, MLKEMPrivateKeyTrait,
    MLKEMPublicKey, MLKEMPublicKeyExpanded, MLKEMPublicKeyInternalTrait, MLKEMPublicKeyTrait,
};
use crate::mlkem::params::{
    CiphertextLen, MLKEM512Params, MLKEM768Params, MLKEM1024Params, MLKEMParams, MLKEMParamsBase,
    PrivateKeyLen,
};
use crate::mlkem_common::aux_functions::sample_poly_CBD_out;
use crate::mlkem_common::polynomial::Polynomial;
use bouncycastle_core::errors::KEMError;
use bouncycastle_core::errors::RNGError;
use bouncycastle_core::hazmat::{do_hazardous_operations, finish_token};
use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey, KEMAlgorithm};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    Algorithm, AlgorithmOID, Hash, KEMDecapsulator, KEMEncapsulator, RNG, RNGExt, XOFSqueezer,
};
use bouncycastle_utils::ct::{conditional_copy_bytes, ct_eq_bytes_condition};
use bouncycastle_utils::secret::Secret;
use core::marker::PhantomData;
/*** Constants ***/

// The constants, names and hash aliases FIPS 203 fixes for every parameter set are shared with
// the other ML-KEM module and live in `pqc::mlkem_common`.
pub(in crate::mlkem) use crate::mlkem_common::{G, H, J, N, POLY_BYTES, q};
#[doc(inline)]
pub use crate::mlkem_common::{ML_KEM_512_NAME, ML_KEM_768_NAME, ML_KEM_1024_NAME};
#[doc(inline)]
pub use crate::mlkem_common::{MLKEM_RND_LEN, MLKEM_SEED_LEN, MLKEM_SS_LEN};

/* ML-KEM-512 sizes (FIPS 203, Table 3) */

/// Length of the \[u8] holding an ML-KEM-512 public key.
pub const MLKEM512_PK_LEN: usize = MLKEM512Params::PK_LEN;
/// Length of the \[u8] holding an ML-KEM-512 private key.
pub const MLKEM512_SK_LEN: usize = MLKEM512Params::SK_LEN;
/// Length of the \[u8] holding an ML-KEM-512 ciphertext.
pub const MLKEM512_CT_LEN: usize = MLKEM512Params::CT_LEN;

/* ML-KEM-768 sizes (FIPS 203, Table 3) */

/// Length of the \[u8] holding an ML-KEM-768 public key.
pub const MLKEM768_PK_LEN: usize = MLKEM768Params::PK_LEN;
/// Length of the \[u8] holding an ML-KEM-768 private key.
pub const MLKEM768_SK_LEN: usize = MLKEM768Params::SK_LEN;
/// Length of the \[u8] holding an ML-KEM-768 ciphertext.
pub const MLKEM768_CT_LEN: usize = MLKEM768Params::CT_LEN;

/* ML-KEM-1024 sizes (FIPS 203, Table 3) */

/// Length of the \[u8] holding an ML-KEM-1024 public key.
pub const MLKEM1024_PK_LEN: usize = MLKEM1024Params::PK_LEN;
/// Length of the \[u8] holding an ML-KEM-1024 private key.
pub const MLKEM1024_SK_LEN: usize = MLKEM1024Params::SK_LEN;
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
    /// Algorithm 16 ML-KEM.KeyGen_internal(𝑑, 𝑧)
    /// Uses randomness to generate an encapsulation key and a corresponding decapsulation key.
    /// Input: randomness 𝑑 ∈ 𝔹32 .
    /// Input: randomness 𝑧 ∈ 𝔹32 .
    /// Output: encapsulation key ek ∈ 𝔹384𝑘+32 .
    /// Output: decapsulation key dk ∈ 𝔹768𝑘+96 .
    pub(in crate::mlkem) fn keygen_internal(
        seed: &KeyMaterial<64>,
    ) -> Result<(MLKEMPublicKey<P>, MLKEMPrivateKey<P>), KEMError> {
        // One assembly, shared with `keygen_internal_out`.
        let mut sk = MLKEMPrivateKey::<P>::zeroized();
        Self::keygen_internal_out(seed, &mut sk)?;
        Ok((sk.ek().clone(), sk))
    }

    /// The seed checks of [`keygen_internal`](Self::keygen_internal).
    fn check_seed(seed: &KeyMaterial<64>) -> Result<(), KEMError> {
        if !(seed.key_type() == KeyType::Seed || seed.key_type() == KeyType::CryptographicRandom)
            || seed.key_len() != 64
        {
            return Err(KEMError::KeyGenError(
                "Seed must be 64 bytes and KeyType::Seed or KeyType::CryptographicRandom.",
            ));
        }

        if seed.security_strength() < P::MAX_SECURITY_STRENGTH {
            return Err(KEMError::KeyGenError(
                "Seed SecurityStrength must match algorithm security strength",
            ));
        }
        Ok(())
    }

    /// [`keygen_internal`](Self::keygen_internal) into a key the caller holds: every field is
    /// computed where it will live. The key is cleared first and left so on an error.
    pub(in crate::mlkem) fn keygen_internal_out(
        seed: &KeyMaterial<64>,
        sk: &mut MLKEMPrivateKey<P>,
    ) -> Result<(), KEMError> {
        sk.clear();
        Self::check_seed(seed)?;
        sk.fill(seed);
        Ok(())
    }

    /// Algorithm 13 K-PKE.KeyGen(𝑑)
    /// Uses randomness to generate an encryption key and a corresponding decryption key.
    /// Input: randomness 𝑑 ∈ 𝔹32 .
    /// Output: encryption key ek_PKE ∈ 𝔹384𝑘+32.
    /// Output: decryption key dk_PKE ∈ 𝔹384𝑘.
    ///
    /// Into `ek` and `s_hat`, which the caller holds: ekPKE's 𝐭̂ and 𝜌 and dkPKE's 𝐬̂ are
    /// computed where they will live.
    pub(in crate::mlkem) fn pke_keygen_out(
        d: &[u8; 32],
        ek: &mut MLKEMPublicKey<P>,
        s_hat: &mut P::VecK,
    ) {
        // 1: (𝜌, 𝜎) ← G(𝑑‖𝑘)
        //  ▷ expand 32+1 bytes to two pseudorandom 32-byte seeds1
        // rho: public seed
        // sigma: noise seed
        // sigma is the noise seed: secret, so it is read where the G output holds it, in a
        // `Secret` of this frame, and not copied out. rho is public (it is part of ek).
        let mut g_out = Secret::<[u8; 64]>::new();
        {
            let mut g = G::new();
            g.do_update(d);
            g.do_update(&[P::k as u8]);
            // In place, not by the consuming final: a move would leave the secret input unwiped.
            let bytes_written = g.finish_into(&finish_token(), &mut *g_out);
            debug_assert_eq!(bytes_written, 64);
        }
        // The ranges are 32 bytes, so the conversions cannot fail.
        let rho: &[u8; 32] = g_out[..32].try_into().unwrap();
        let sigma: &[u8; 32] = g_out[32..64].try_into().unwrap();

        // 2: 𝑁 ← 0
        //  Note: in the definition of PRF_eta on page 18, it's said to be one byte.
        //  since the number of loops here is static, it is possible to hard-code the N values
        //  rather than using a counter

        // 8: for (𝑖 ← 0; 𝑖 < 𝑘; 𝑖++)
        //  ▷ generate 𝐬 ∈ (ℤ256)^k
        // 9: 𝐬[𝑖] ← SamplePolyCBD𝜂1(PRF𝜂1 (𝜎, 𝑁 ))
        //   ▷ 𝐬[𝑖] ∈ ℤ256 sampled from CBD
        // 10: 𝑁 ← 𝑁 + 1
        // Note: here n = 0
        sample_vector_CBD_out::<P>(sigma, 0, P::eta1, s_hat);

        // 16: 𝐬_hat ← NTT(𝐬)̂
        s_hat.ntt();
        s_hat.reduce();

        // first half of
        // 18: 𝐭_hat ← 𝐀_hat ∘ 𝐬_hat + 𝐞_hat
        ek.keygen_A_hat_s_hat(rho, s_hat);

        // second half of
        // 18: 𝐭_hat ← 𝐀_hat ∘ 𝐬_hat + 𝐞_hat
        {
            // 12: for (𝑖 ← 0; 𝑖 < 𝑘; 𝑖++)
            //  ▷ generate 𝐞 ∈ (ℤ256)^k
            // 13: 𝐞[𝑖] ← SamplePolyCBD𝜂1(PRF𝜂1 (𝜎, 𝑁 ))
            //   ▷ 𝐞[𝑖] ∈ ℤ256 sampled from CBD
            // 14: 𝑁 ← 𝑁 + 1
            // Note: here n = k
            let mut e = Secret::<P::VecK>::new();
            sample_vector_CBD_out::<P>(sigma, P::k as u8, P::eta1, &mut e);

            e.ntt(); // technically now e_hat
            e.reduce();
            ek.keygen_add_e_hat(&e);
        }

        // 19: ekPKE ← ByteEncode12(𝐭)‖𝜌 ▷ run ByteEncode12 𝑘 times, then append 𝐀-seed
        // 20: dkPKE ← ByteEncode12(𝐬)̂ ▷ run ByteEncode12 𝑘 times
        // Note: The encoding is skipped at this stage and left expanded for future efficiency when it's used.
        // 21: return (ekPKE, dkPKE)
    }

    /// Algorithm 14 K-PKE.Encrypt(ekPKE, 𝑚, 𝑟)
    /// Uses the encryption key to encrypt a plaintext message using the randomness 𝑟.
    /// Input: encryption key ekPKE ∈ 𝔹384𝑘+32 .
    /// Input: message 𝑚 ∈ 𝔹32 .
    /// Input: randomness 𝑟 ∈ 𝔹32 .
    /// Output: ciphertext 𝑐 ∈ 𝔹32(𝑑𝑢𝑘+𝑑𝑣).
    ///
    /// Into `ct`, which the caller holds. Everything derived from 𝑟 and 𝑚 on the way is held in
    /// a `Secret` of this frame, and so is wiped when it returns.
    fn pke_encrypt_out<EK: MLKEMPublicKeyInternalTrait<P>, const CT_LEN: usize>(
        ek: &EK,
        A_hat: &P::MatrixA,
        m: &[u8; 32],
        r: &[u8; 32],
        ct: &mut [u8; CT_LEN],
    ) {
        // 1: 𝑁 ← 0
        //  since the number of loops here is static, the N values can be hard-coded rather than using a counter

        // 2: 𝐭 ← ByteDecode12(ekPKE[0 ∶ 384𝑘])
        // 3: 𝜌 ← ekPKE[384𝑘 ∶ 384𝑘 + 32]
        // not necessary here because ek is already decoded

        // 4: for (𝑖 ← 0; 𝑖 < 𝑘; 𝑖++)
        //   ▷ re-generate matrix 𝐀 ∈ (ℤ256_𝑞 )𝑘×𝑘 sampled in Alg. 13
        // An optimization is done where the user can pre-expand A_hat within the
        // public key object for faster repeated encapsulations against this public key.

        // 9: for (𝑖 ← 0; 𝑖 < 𝑘; 𝑖++)
        //  ▷ generate 𝐲 ∈ (ℤ256_𝑞)k
        // 10: 𝐲[𝑖] ← SamplePolyCBD𝜂1(PRF𝜂1 (𝑟, 𝑁))
        //   ▷ 𝐲[𝑖] ∈ ℤ256 sampled from CBD
        // 11: 𝑁 ← 𝑁 + 1
        // Note: here n = 0
        let mut y_hat = Secret::<P::VecK>::new();
        sample_vector_CBD_out::<P>(r, 0, P::eta1, &mut y_hat);

        // 18: 𝐲_hat ← NTT(𝐲)
        y_hat.ntt();

        // 19: 𝐮 ← NTT−1(𝐀_hat^⊺ ∘ 𝐲_hat) + 𝐞
        let mut u = Secret::<P::VecK>::new();
        A_hat.matrix_vector_ntt_out::<true>(&y_hat, &mut u);
        u.inv_ntt();
        {
            // 12: for (𝑖 ← 0; 𝑖 < 𝑘; 𝑖++)
            //  ▷ generate 𝐞 ∈ (ℤ256_𝑞)k
            // 13: 𝐞[𝑖] ← SamplePolyCBD𝜂1(PRF𝜂1 (𝜎, 𝑁))
            //  ▷ 𝐞[𝑖] ∈ ℤ256 sampled from CBD𝑞
            // 14: 𝑁 ← 𝑁 + 1
            // note: here n = k
            let mut e1 = Secret::<P::VecK>::new();
            sample_vector_CBD_out::<P>(r, P::k as u8, P::eta2, &mut e1);

            u.add_vector_ntt(&e1);
        }
        u.reduce();

        // 20: 𝜇 ← Decompress1(ByteDecode1(𝑚))
        // 21: 𝑣 ← NTT−1(𝐭_hat^T ∘ 𝐲_hat) + 𝑒2 + 𝜇
        //  ▷ encode plaintext 𝑚 into polynomial 𝑣
        let mut v = Secret::<Polynomial>::new();
        ek.t_hat().dot_product_out(&y_hat, &mut v);
        v.inv_ntt();

        {
            // 17: 𝑒2 ← SamplePolyCBD𝜂2(PRF𝜂2 (𝑟, 𝑁))
            //  ▷ sample 𝑒2 ∈ ℤ256 from CBD
            // note: here n = 2k
            let mut e2 = Secret::<Polynomial>::new();
            sample_poly_CBD_out(r, 2 * P::k as u8, P::eta2, &mut e2);
            v.add(&e2);
        }

        // 𝜇 is added as it is decoded, and not held.
        v.add_msg(m);

        v.poly_reduce();

        // 22: 𝑐1 ← ByteEncode𝑑𝑢(Compress𝑑𝑢(𝐮))
        // 23: 𝑐2 ← ByteEncode𝑑𝑣(Compress𝑑𝑣(𝑣))
        pack_ciphertext_out::<P, CT_LEN>(&u, &v, ct);
    }

    /// Algorithm 17 ML-KEM.Encaps_internal(ek, 𝑚)
    /// Uses the encapsulation key and randomness to generate a key and an associated ciphertext.
    /// Input: encapsulation key ek ∈ 𝔹384𝑘+32 .
    /// Input: randomness 𝑚 ∈ 𝔹32 .
    /// Output: shared secret key 𝐾 ∈ 𝔹32 .
    /// Output: ciphertext 𝑐 ∈ 𝔹32(𝑑𝑢𝑘+𝑑𝑣).
    ///
    /// An expanded key supplies the public matrix 𝐀̂ it holds; a plain key has it expanded here.
    ///
    /// Reachable from outside the module only through
    /// [`EncapsWithRandomness`](crate::mlkem::hazmat::EncapsWithRandomness), which carries the security
    /// notes on supplying `m`.
    ///
    /// Into `ct` and `K`, which the caller holds, so that no copy of 𝐾 is returned by value.
    pub(in crate::mlkem) fn encaps_internal_out<
        EK: MLKEMPublicKeyInternalTrait<P>,
        const CT_LEN: usize,
    >(
        ek: &EK,
        m: &[u8; 32],
        ct: &mut [u8; CT_LEN],
        K: &mut [u8; MLKEM_SS_LEN],
    ) {
        // 1: (𝐾, 𝑟) ← G(𝑚‖H(ek))
        //  ▷ derive shared secret key 𝐾 and randomness 𝑟. Both are secret: 𝑟 is read where the G
        //  output holds it, in a `Secret` of this frame.
        let mut g_out = Secret::<[u8; 64]>::new();
        {
            let mut g = G::new();
            g.do_update(m);
            g.do_update(&ek.compute_hash());
            // In place, not by the consuming final: a move would leave the secret input unwiped.
            let bytes_written = g.finish_into(&finish_token(), &mut *g_out);
            debug_assert_eq!(bytes_written, 64);
        }
        K.copy_from_slice(&g_out[..32]);
        // The range is 32 bytes, so the conversion cannot fail.
        let r: &[u8; 32] = g_out[32..64].try_into().unwrap();

        // 2: 𝑐 ← K-PKE.Encrypt(ek, 𝑚, 𝑟)
        //  ▷ encrypt 𝑚 using K-PKE with randomness 𝑟
        // deviation from FIPS:
        //  To allow for pre-computing A_hat for multiple encapsulations, the code either takes
        // the A_hat the key holds, or computes it fresh.
        match ek.A_hat_cached() {
            Some(A_hat) => Self::pke_encrypt_out::<EK, CT_LEN>(ek, A_hat, m, r, ct),
            None => {
                let mut A_hat = P::MatrixA::new();
                expandA::<P>(ek.rho(), &mut A_hat);
                Self::pke_encrypt_out::<EK, CT_LEN>(ek, &A_hat, m, r, ct)
            }
        }
    }

    /// Algorithm 15 K-PKE.Decrypt(dkPKE, 𝑐)
    /// Uses the decryption key to decrypt a ciphertext.
    /// Input: decryption key dkPKE  ∈ 𝔹384𝑘.
    /// Input: ciphertext 𝑐 ∈ 𝔹32(𝑑𝑢𝑘+𝑑𝑣).
    /// Output: message 𝑚 ∈ 𝔹32 .
    ///
    /// Into `m`, which the caller holds: 𝑚 is an internal value (FIPS 203 Sec 3.3) that must not
    /// outlive the decapsulation, and 𝐬̂ ∘ 𝐮̂ and 𝑤 are held in `Secret`s of this frame.
    fn pke_decrypt_out<DK: MLKEMPrivateKeyInternalTrait<P>, const CT_LEN: usize>(
        dk: &DK,
        ct: &[u8; CT_LEN],
        m: &mut [u8; 32],
    ) {
        // 1: 𝑐1 ← 𝑐[0 ∶ 32𝑑𝑢𝑘]
        // 2: 𝑐2 ← 𝑐[32𝑑𝑢𝑘 ∶ 32(𝑑𝑢𝑘 + 𝑑𝑣)]
        // 3: 𝐮′ ← Decompress_𝑑𝑢(ByteDecode_𝑑𝑢(𝑐1))
        // 4: 𝑣′ ← Decompress_𝑑𝑣(ByteDecode_𝑑𝑣(𝑐2))
        let mut v1 = Secret::<Polynomial>::new();
        {
            // 𝐮′ is the ciphertext's, so public.
            let mut u_prime = unpack_ciphertext_u::<P, CT_LEN>(ct);

            // 5: 𝐬_hat ← ByteDecode12(dkPKE)
            //   Unnecessary here because dk is already decoded

            // 6: 𝑤 ← 𝑣′ − NTT−1(𝐬_hat^T ∘ NTT(𝐮′))
            u_prime.ntt();
            dk.s_hat().dot_product_out(&u_prime, &mut v1);
            v1.inv_ntt();
        }

        let mut w = Secret::<Polynomial>::new();
        *w = unpack_ciphertext_v::<P, CT_LEN>(ct);
        w.sub(&v1);
        w.poly_reduce();

        // 7: 𝑚 ← ByteEncode1(Compress1(𝑤))
        //   ▷ decode plaintext 𝑚 from polynomial 𝑤
        w.to_msg_out(m);
    }

    /// Algorithm 18 ML-KEM.Decaps_internal(dk, 𝑐)
    /// Uses the decapsulation key to produce a shared secret key from a ciphertext.
    /// Input: decapsulation key dk ∈ 𝔹768𝑘+96 .
    /// Input: ciphertext 𝑐 ∈ 𝔹32(𝑑𝑢𝑘+𝑑𝑣).
    /// Output: shared secret key 𝐾 ∈ 𝔹32 .
    ///
    /// Into `K`, which the caller holds; the intermediates are held in `Secret`s of this frame.
    // Not inlined, so that in a caller that builds an expanded key and then decapsulates, its
    // frame is a sibling of the construction's and not stacked on it (8 kB for ML-KEM-1024, the
    // memory table's expanded-key Decaps row).
    #[inline(never)]
    fn decaps_internal_out<DK: MLKEMPrivateKeyInternalTrait<P>, const CT_LEN: usize>(
        dk: &DK,
        c: &[u8; CT_LEN],
        K: &mut [u8; MLKEM_SS_LEN],
    ) {
        // Structured to mirror the FIPS as closely as possible, with unnamed scopes
        // used to limit the number of live stack variables at any given time.

        // 1: dkPKE ← dk[0 ∶ 384𝑘] ▷ extract (from KEM decaps key) the PKE decryption key
        // 2: ekPKE ← dk[384𝑘 ∶ 768𝑘 + 32] ▷ extract PKE encryption key
        // 3: ℎ ← dk[768𝑘 + 32 ∶ 768𝑘 + 64] ▷ extract hash of PKE encryption key
        // 4: 𝑧 ← dk[768𝑘 + 64 ∶ 768𝑘 + 96] ▷ extract implicit rejection value
        // Nothing to do since dk is already decoded: ℎ is the stored hash, which the decoder
        // checked against H(ek) (Section 7.3), so it is used as Algorithm 18 says rather than
        // recomputed from ek on every decapsulation.

        // 5: 𝑚′ ← K-PKE.Decrypt(dkPKE, 𝑐)
        let mut m_prime = Secret::<[u8; 32]>::new();
        Self::pke_decrypt_out(dk, c, &mut m_prime);

        // Compute the trial shared secret key
        // 6: (𝐾′, 𝑟′) ← G(𝑚′‖ℎ)̄
        // K' and r' are the candidate shared secret and the re-encryption randomness: secret,
        // read where the G output holds them, in a `Secret` (FIPS 203 Sec 3.3, Sec 6.3).
        let mut g_out = Secret::<[u8; 64]>::new();
        {
            let mut g = G::new();
            g.do_update(&*m_prime);
            g.do_update(dk.pk_hash());
            // In place, not by the consuming final: a move would leave the secret input unwiped.
            let bytes_written = g.finish_into(&finish_token(), &mut *g_out);
            debug_assert_eq!(bytes_written, 64);
        }
        // The ranges are 32 bytes, so the conversions cannot fail.
        let K_prime: &[u8; MLKEM_SS_LEN] = g_out[..32].try_into().unwrap();
        let r_prime: &[u8; 32] = g_out[32..64].try_into().unwrap();

        // 7: 𝐾_bar ← J(𝑧‖𝑐)
        //   Compute the rejection sampling key.
        //   Note to future optimizers: this needs to be computed outside of the conditional at line 9 below.
        //   This is because if the computation is conditional on the Fujisaki-Okamoto check failing, then
        //   it will result in a timing difference between success and failure.
        let mut K_bar = Secret::<[u8; MLKEM_SS_LEN]>::new();
        {
            let mut j = J::new();
            j.do_update(dk.z().as_ref());
            j.do_update(c);
            let mut j = j.finish_squeezer(&finish_token());
            let bytes_written = j.do_output_out(&mut *K_bar);
            debug_assert_eq!(bytes_written, MLKEM_SS_LEN);
        }

        // 8: 𝑐′ ← K-PKE.Encrypt(ekPKE, 𝑚′, 𝑟′)
        //   ▷ re-encrypt using the derived randomness 𝑟′
        // deviation from FIPS:
        // To allow for pre-computing A_hat for multiple decapsulations, we will either take
        // the A_hat the key holds, or compute it fresh.
        // 𝑐′ differs from 𝑐 when the ciphertext was not one made to this key, and then it is
        // derived from 𝑚′, so it is held in a `Secret`.
        let mut c_prime = Secret::<[u8; CT_LEN]>::new();
        match dk.A_hat_cached() {
            Some(A_hat) => {
                Self::pke_encrypt_out::<_, CT_LEN>(dk.ek(), A_hat, &m_prime, r_prime, &mut c_prime)
            }
            None => {
                let mut A_hat = P::MatrixA::new();
                expandA::<P>(dk.ek().rho(), &mut A_hat);
                Self::pke_encrypt_out::<_, CT_LEN>(dk.ek(), &A_hat, &m_prime, r_prime, &mut c_prime)
            }
        }

        // 9: if 𝑐 ≠ 𝑐′ then
        // 10: 𝐾′ ← 𝐾_bar
        //  ▷ if ciphertexts do not match, “implicitly reject"
        conditional_copy_bytes(K_prime, &K_bar, K, ct_eq_bytes_condition(c, &*c_prime));
    }

    /// Decapsulation from the seed form of the private key: expands the key with
    /// [`MLKEMTrait::keygen_from_seed`] and decapsulates with it. Costs a key generation on top
    /// of the decapsulation; see the module docs.
    pub fn decaps_from_seed<const CT_LEN: usize>(
        seed: &KeyMaterial<64>,
        ct: &[u8; CT_LEN],
    ) -> Result<KeyMaterial<MLKEM_SS_LEN>, KEMError>
    where
        P: CiphertextLen<CT_LEN>,
    {
        let (_pk, sk) = Self::keygen_from_seed(seed)?;

        sk.decaps(ct, ())
    }

    /// Algorithm 20 ML-KEM.Encaps(ek), lines 1-5, over either form of this module's public key,
    /// into `ct` and `ss`, both cleared first and left so on an error.
    pub(in crate::mlkem) fn encaps_with_rng<
        EK: MLKEMPublicKeyInternalTrait<P>,
        const CT_LEN: usize,
    >(
        ek: &EK,
        rng: &mut dyn RNG,
        ct: &mut [u8; CT_LEN],
        ss: &mut KeyMaterial<MLKEM_SS_LEN>,
    ) -> Result<usize, KEMError> {
        ct.fill(0);
        ss.zeroize();

        // 1: 𝑚 ← 𝔹32, from the caller's RNG, which must be at least as strong as the parameter set
        if rng.security_strength() < P::MAX_SECURITY_STRENGTH {
            Err(RNGError::SecurityStrengthInsufficientForAlgorithm)?;
        }
        let mut m = Secret::<[u8; 32]>::new();
        rng.next_bytes_exact_out(&mut *m)?;

        // 5: (𝐾, 𝑐) ← ML-KEM.Encaps_internal(ek, 𝑚)
        let mut K = Secret::<[u8; MLKEM_SS_LEN]>::new();
        Self::encaps_internal_out::<EK, CT_LEN>(ek, &m, ct, &mut K);

        if let Err(e) = Self::shared_secret_key_out(&K, ss) {
            ct.fill(0);
            return Err(e);
        }
        Ok(CT_LEN)
    }

    /// Algorithm 21 ML-KEM.Decaps(dk, 𝑐) over either form of this module's private key, into
    /// `ss`, cleared first and left so on an error.
    ///
    /// Of the Section 7.3 decapsulation input checks, 1 (the ciphertext length) is the type of
    /// `ct`, and 2 (the key encoding) and 3 (the hash check) are done once, when the key is
    /// loaded, by [`MLKEMPrivateKeyTrait::sk_decode`].
    pub(in crate::mlkem) fn decaps_checked<
        DK: MLKEMPrivateKeyInternalTrait<P>,
        const CT_LEN: usize,
    >(
        dk: &DK,
        ct: &[u8; CT_LEN],
        ss: &mut KeyMaterial<MLKEM_SS_LEN>,
    ) -> Result<usize, KEMError> {
        ss.zeroize();
        dk.check_filled()?;
        // 1: 𝐾′ ← ML-KEM.Decaps_internal(dk, 𝑐)
        let mut K = Secret::<[u8; MLKEM_SS_LEN]>::new();
        Self::decaps_internal_out(dk, ct, &mut K);

        Self::shared_secret_key_out(&K, ss)?;
        Ok(MLKEM_SS_LEN)
    }

    /// The shared secret into `key`: full-entropy bytes at the parameter set's strength.
    /// Typed inside the hazardous window, where an all-zero value is not re-typed `Zeroized`:
    /// 𝐾 is uniform, so all zeros (probability 2^-256) is a valid secret, not an error. `key`
    /// is left zeroized on an error.
    fn shared_secret_key_out(
        K: &[u8; MLKEM_SS_LEN],
        key: &mut KeyMaterial<MLKEM_SS_LEN>,
    ) -> Result<(), KEMError> {
        let typed = do_hazardous_operations(key, |key| {
            key.set_bytes_as_type(K, KeyType::CryptographicRandom)?;
            key.set_security_strength(P::MAX_SECURITY_STRENGTH)
        });
        if typed.is_err() {
            key.zeroize();
        }
        Ok(typed?)
    }
}

/// Trait for all three of the ML-KEM parameter sets.
pub trait MLKEMTrait<P: MLKEMParams>: Sized {
    /// Key generation from the caller's RNG, which must offer at least the parameter set's
    /// security strength.
    // Should still be ok in FIPS mode, provided that you're using the FIPS-approved RNG.
    fn keygen(rng: &mut dyn RNG) -> Result<(MLKEMPublicKey<P>, MLKEMPrivateKey<P>), KEMError> {
        // Source the seed from the provided RNG
        if rng.security_strength() < P::MAX_SECURITY_STRENGTH {
            Err(RNGError::SecurityStrengthInsufficientForAlgorithm)?;
        }
        let mut seed = KeyMaterial::<64>::new();
        rng.fill_keymaterial_out(&mut seed)?;
        Self::keygen_from_seed(&seed)
    }
    /// [`keygen`](Self::keygen) into a private key the caller holds: each field is computed in
    /// `sk` itself, so no copy of it is staged on the way and none is left behind by a move,
    /// which wipes nothing. Start from [`MLKEMPrivateKey::zeroized`]; the public key is
    /// [`sk.pk()`](MLKEMPrivateKeyTrait::pk). `sk` is cleared first and left so on every error.
    ///
    /// After an error `sk.pk()` refuses with
    /// [`ActingOnZeroizedKey`](bouncycastle_core::errors::KeyMaterialError::ActingOnZeroizedKey).
    fn keygen_out(rng: &mut dyn RNG, sk: &mut MLKEMPrivateKey<P>) -> Result<(), KEMError> {
        sk.clear();
        if rng.security_strength() < P::MAX_SECURITY_STRENGTH {
            Err(RNGError::SecurityStrengthInsufficientForAlgorithm)?;
        }
        let mut seed = KeyMaterial::<64>::new();
        rng.fill_keymaterial_out(&mut seed)?;
        Self::keygen_from_seed_out(&seed, sk)
    }
    /// Imports a secret key from a seed.
    fn keygen_from_seed(
        seed: &KeyMaterial<64>,
    ) -> Result<(MLKEMPublicKey<P>, MLKEMPrivateKey<P>), KEMError>;
    /// [`keygen_from_seed`](Self::keygen_from_seed) into a private key the caller holds; see
    /// [`keygen_out`](Self::keygen_out).
    fn keygen_from_seed_out(
        seed: &KeyMaterial<64>,
        sk: &mut MLKEMPrivateKey<P>,
    ) -> Result<(), KEMError>;
    /// Imports a secret key from both a seed and an encoded_sk.
    ///
    /// This is a convenience function to expand the key from seed and compare it against
    /// the provided `encoded_sk` using a constant-time equality check.
    /// If everything checks out, the secret key is returned fully populated with pk and seed.
    /// If the provided key and derived key don't match, an error is returned.
    fn keygen_from_seed_and_encoded<const SK_LEN: usize>(
        seed: &KeyMaterial<64>,
        encoded_sk: &[u8; SK_LEN],
    ) -> Result<(MLKEMPublicKey<P>, MLKEMPrivateKey<P>), KEMError>
    where
        P: PrivateKeyLen<SK_LEN>;
    /// Given a public key and a secret key, check that the public key matches the secret key.
    /// This is a sanity check that the public key was generated correctly from the secret key.
    ///
    /// At the current time, this is only possible if `sk` either contains a public key (in which case
    /// the two pk's are encoded and compared for byte equality), or if `sk` contains a seed
    /// (in which case a keygen_from_seed is run and then the pk's compared).
    ///
    /// Returns either `()` or [`KEMError::ConsistencyCheckFailed`]; a private key that was never
    /// filled ([`MLKEMPrivateKey::zeroized`]) is refused.
    fn keypair_consistency_check(
        pk: &MLKEMPublicKey<P>,
        sk: &MLKEMPrivateKey<P>,
    ) -> Result<(), KEMError>;
}

impl<P: MLKEMParams> MLKEMTrait<P> for MLKEM<P> {
    /// Imports a secret key from a seed.
    fn keygen_from_seed(
        seed: &KeyMaterial<64>,
    ) -> Result<(MLKEMPublicKey<P>, MLKEMPrivateKey<P>), KEMError> {
        Self::keygen_internal(seed)
    }

    fn keygen_from_seed_out(
        seed: &KeyMaterial<64>,
        sk: &mut MLKEMPrivateKey<P>,
    ) -> Result<(), KEMError> {
        Self::keygen_internal_out(seed, sk)
    }

    fn keygen_from_seed_and_encoded<const SK_LEN: usize>(
        seed: &KeyMaterial<64>,
        encoded_sk: &[u8; SK_LEN],
    ) -> Result<(MLKEMPublicKey<P>, MLKEMPrivateKey<P>), KEMError>
    where
        P: PrivateKeyLen<SK_LEN>,
    {
        let (pk, sk) = Self::keygen_internal(seed)?;

        let sk_from_bytes = MLKEMPrivateKey::<P>::sk_decode(encoded_sk)?;

        // MLKEMPrivateKey impls PartialEq with a constant-time equality check.
        if sk != sk_from_bytes {
            return Err(KEMError::KeyGenError("Encoded key does not match generated key"));
        }

        Ok((pk, sk))
    }

    fn keypair_consistency_check(
        pk: &MLKEMPublicKey<P>,
        sk: &MLKEMPrivateKey<P>,
    ) -> Result<(), KEMError> {
        // A private key that was never filled is refused, not compared.
        let derived_pk = sk.pk()?;
        if derived_pk.compute_hash() == pk.compute_hash() {
            Ok(())
        } else {
            Err(KEMError::ConsistencyCheckFailed(""))
        }
    }
}

/*** The workers and the key roles ***/

/// The encapsulator an ML-KEM public key hands out through [`EncapsulatingKey`]: it borrows the
/// key, plain or expanded, and draws the encapsulation randomness from the RNG of each call.
pub struct MLKEMEncapsulator<'k, P: MLKEMParams, EK: MLKEMPublicKeyInternalTrait<P>> {
    ek: &'k EK,
    _phantom: PhantomData<P>,
}

impl<P: MLKEMParams, EK: MLKEMPublicKeyInternalTrait<P>> Algorithm
    for MLKEMEncapsulator<'_, P, EK>
{
    const ALG_NAME: &'static str = P::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

impl<
    P: MLKEMParams + CiphertextLen<CT_LEN>,
    EK: MLKEMPublicKeyInternalTrait<P>,
    const CT_LEN: usize,
> KEMEncapsulator<CT_LEN, MLKEM_SS_LEN> for MLKEMEncapsulator<'_, P, EK>
{
    /// Algorithm 20 ML-KEM.Encaps(ek). The shared secret comes back as a [`KeyMaterial`] of type
    /// [`KeyType::CryptographicRandom`] at the parameter set's security strength.
    fn encaps_out(
        &self,
        rng: &mut dyn RNG,
        ct: &mut [u8; CT_LEN],
        ss: &mut KeyMaterial<MLKEM_SS_LEN>,
    ) -> Result<usize, KEMError> {
        MLKEM::<P>::encaps_with_rng(self.ek, rng, ct, ss)
    }
}

/// The decapsulator an ML-KEM private key hands out through [`DecapsulatingKey`]: it borrows the
/// key, plain or expanded.
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
    fn decaps_out(
        &self,
        ct: &[u8; CT_LEN],
        ss: &mut KeyMaterial<MLKEM_SS_LEN>,
    ) -> Result<usize, KEMError> {
        MLKEM::<P>::decaps_checked(self.dk, ct, ss)
    }
}

impl<P: MLKEMParams + CiphertextLen<CT_LEN>, const CT_LEN: usize>
    EncapsulatingKey<(), CT_LEN, MLKEM_SS_LEN> for MLKEMPublicKey<P>
{
    type Algorithm = MLKEM<P>;
    type Encapsulator<'k>
        = MLKEMEncapsulator<'k, P, Self>
    where
        P: 'k;

    /// ML-KEM's shared secret is the primitive's own 𝐾 (FIPS 203, Algorithm 17), so a worker
    /// takes nothing beyond its key.
    fn create_encapsulator<'k>(&'k self, _params: ()) -> Result<Self::Encapsulator<'k>, KEMError> {
        Ok(MLKEMEncapsulator { ek: self, _phantom: PhantomData })
    }
}

impl<P: MLKEMParams + CiphertextLen<CT_LEN>, const CT_LEN: usize>
    EncapsulatingKey<(), CT_LEN, MLKEM_SS_LEN> for MLKEMPublicKeyExpanded<P>
{
    type Algorithm = MLKEM<P>;
    type Encapsulator<'k>
        = MLKEMEncapsulator<'k, P, Self>
    where
        P: 'k;

    /// ML-KEM's shared secret is the primitive's own 𝐾 (FIPS 203, Algorithm 17), so a worker
    /// takes nothing beyond its key.
    fn create_encapsulator<'k>(&'k self, _params: ()) -> Result<Self::Encapsulator<'k>, KEMError> {
        Ok(MLKEMEncapsulator { ek: self, _phantom: PhantomData })
    }
}

impl<P: MLKEMParams + CiphertextLen<CT_LEN>, const CT_LEN: usize>
    DecapsulatingKey<(), CT_LEN, MLKEM_SS_LEN> for MLKEMPrivateKey<P>
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
    DecapsulatingKey<(), CT_LEN, MLKEM_SS_LEN> for MLKEMPrivateKeyExpanded<P>
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
