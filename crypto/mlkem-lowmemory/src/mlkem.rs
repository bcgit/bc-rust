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
/// Length of the \[u8] holding a ML-KEM-512 seed-based private key.
pub const MLKEM512_SK_LEN: usize = MLKEM_SEED_LEN;
/// Length of the \[u8] holding a full ML-KEM-512 private key in the NIST encoding.
pub const MLKEM512_FULL_SK_LEN: usize = 1632;
/// Length of the \[u8] holding a ML-KEM-512 ciphertext.
pub const MLKEM512_CT_LEN: usize = 768;
pub(crate) const MLKEM512_k: usize = 2;
pub(crate) const MLKEM512_ETA1: i16 = 3;
pub(crate) const MLKEM512_DU: i16 = 10;
pub(crate) const MLKEM512_DV: i16 = 4;
/// Maps to "required RBG strength (bits)" in FIPS 203 Table 2
pub(crate) const MLKEM512_LAMBDA: i16 = 128;

// internal derived values
pub(crate) const MLKEM512_T_PACKED_LEN: usize = 12 * MLKEM512_k * 32;

/* ML-KEM-768 params */

/// Length of the \[u8] holding a ML-KEM-768 public key.
pub const MLKEM768_PK_LEN: usize = 1184;
/// Length of the \[u8] holding a ML-KEM-768 seed-based private key.
pub const MLKEM768_SK_LEN: usize = MLKEM_SEED_LEN;
/// Length of the \[u8] holding a full ML-KEM-768 private key in the NIST encoding.
pub const MLKEM768_FULL_SK_LEN: usize = 2400;
/// Length of the \[u8] holding a ML-KEM-768 ciphertext.
pub const MLKEM768_CT_LEN: usize = 1088;
pub(crate) const MLKEM768_k: usize = 3;
pub(crate) const MLKEM768_ETA1: i16 = 2;
pub(crate) const MLKEM768_DU: i16 = 10;
pub(crate) const MLKEM768_DV: i16 = 4;
/// Maps to "required RBG strength (bits)" in FIPS 203 Table 2
pub(crate) const MLKEM768_LAMBDA: i16 = 192;

// internal derived values
pub(crate) const MLKEM768_T_PACKED_LEN: usize = 12 * MLKEM768_k * 32;

/* ML-KEM-1024 params */

/// Length of the \[u8] holding a ML-KEM-1024 public key.
pub const MLKEM1024_PK_LEN: usize = 1568;
/// Length of the \[u8] holding a ML-KEM-512 seed-based private key.
pub const MLKEM1024_SK_LEN: usize = MLKEM_SEED_LEN;
/// Length of the \[u8] holding a full ML-KEM-512 private key in the NIST encoding.
pub const MLKEM1024_FULL_SK_LEN: usize = 3168;
/// Length of the \[u8] holding a ML-KEM-1024 ciphertext.
pub const MLKEM1024_CT_LEN: usize = 1568;
pub(crate) const MLKEM1024_k: usize = 4;
pub(crate) const MLKEM1024_ETA1: i16 = 2;
pub(crate) const MLKEM1024_DU: i16 = 11;
pub(crate) const MLKEM1024_DV: i16 = 5;
/// Maps to "required RBG strength (bits)" in FIPS 203 Table 2
pub(crate) const MLKEM1024_LAMBDA: i16 = 256;

// internal derived values
pub(crate) const MLKEM1024_T_PACKED_LEN: usize = 12 * MLKEM1024_k * 32;

// Typedefs just to make the algorithms look more like the FIPS 204 sample code.
pub(crate) type G = SHA3_512;
pub(crate) type H = SHA3_256;
pub(crate) type J = SHAKE256;

/*** Pub Types ***/

/// The ML-KEM-512 algorithm.
pub type MLKEM512 = MLKEM<
    MLKEM512_PK_LEN,
    MLKEM512_SK_LEN,
    MLKEM512_FULL_SK_LEN,
    MLKEM512_CT_LEN,
    MLKEM_SS_LEN,
    MLKEM512PublicKey,
    MLKEM512PrivateKey,
    MLKEM512_k,
    MLKEM512_ETA1,
    MLKEM512_DU,
    MLKEM512_DV,
    MLKEM512_LAMBDA,
    MLKEM512_T_PACKED_LEN,
>;

impl Algorithm for MLKEM512 {
    const ALG_NAME: &'static str = ML_KEM_512_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

/// The ML-KEM-768 algorithm.
pub type MLKEM768 = MLKEM<
    MLKEM768_PK_LEN,
    MLKEM768_SK_LEN,
    MLKEM768_FULL_SK_LEN,
    MLKEM768_CT_LEN,
    MLKEM_SS_LEN,
    MLKEM768PublicKey,
    MLKEM768PrivateKey,
    MLKEM768_k,
    MLKEM768_ETA1,
    MLKEM768_DU,
    MLKEM768_DV,
    MLKEM768_LAMBDA,
    MLKEM768_T_PACKED_LEN,
>;

impl Algorithm for MLKEM768 {
    const ALG_NAME: &'static str = ML_KEM_768_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}

/// The ML-KEM-1024 algorithm.
pub type MLKEM1024 = MLKEM<
    MLKEM1024_PK_LEN,
    MLKEM1024_SK_LEN,
    MLKEM1024_FULL_SK_LEN,
    MLKEM1024_CT_LEN,
    MLKEM_SS_LEN,
    MLKEM1024PublicKey,
    MLKEM1024PrivateKey,
    MLKEM1024_k,
    MLKEM1024_ETA1,
    MLKEM1024_DU,
    MLKEM1024_DV,
    MLKEM1024_LAMBDA,
    MLKEM1024_T_PACKED_LEN,
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
    const FULL_SK_LEN: usize,
    const CT_LEN: usize,
    const SS_LEN: usize,
    PK: MLKEMPublicKeyTrait<k, PK_LEN, T_PACKED_LEN>
        + MLKEMPublicKeyInternalTrait<k, T_PACKED_LEN, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<k, SK_LEN, FULL_SK_LEN, PK_LEN, T_PACKED_LEN>
        + MLKEMPrivateKeyInternalTrait<k, SK_LEN, PK_LEN, T_PACKED_LEN>,
    const k: usize,
    const eta1: i16,
    const du: i16,
    const dv: i16,
    const LAMBDA: i16,
    const T_PACKED_LEN: usize,
> {
    _phantom: PhantomData<(PK, SK)>,
}

impl<
    const PK_LEN: usize,
    const SK_LEN: usize,
    const FULL_SK_LEN: usize,
    const CT_LEN: usize,
    const SS_LEN: usize,
    PK: MLKEMPublicKeyTrait<k, PK_LEN, T_PACKED_LEN>
        + MLKEMPublicKeyInternalTrait<k, T_PACKED_LEN, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<k, SK_LEN, FULL_SK_LEN, PK_LEN, T_PACKED_LEN>
        + MLKEMPrivateKeyInternalTrait<k, SK_LEN, PK_LEN, T_PACKED_LEN>,
    const k: usize,
    const eta1: i16,
    const du: i16,
    const dv: i16,
    const LAMBDA: i16,
    const T_PACKED_LEN: usize,
>
    MLKEM<
        PK_LEN,
        SK_LEN,
        FULL_SK_LEN,
        CT_LEN,
        SS_LEN,
        PK,
        SK,
        k,
        eta1,
        du,
        dv,
        LAMBDA,
        T_PACKED_LEN,
    >
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
        // Self::keygen_internal(&seed)
        Self::keygen_internal(&seed)
    }
    /// Performs the first step of key generation to transform the single provided seed into a set of internal intermediate seeds.
    ///
    /// Unlike other interfaces across the library that take an &impl KeyMaterial, this one
    /// specifically takes a 64-byte [KeyMaterial512] and checks that it has [KeyType::Seed] and
    /// the appropriate [SecurityStrength] for the requested ML-KEM parameter set.
    /// If you happen to have your seed in a larger KeyMaterial, you'll have to copy it using
    /// [KeyMaterial::from_key].
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
        t_hat_packed: &[u8; T_PACKED_LEN],
        rho: &[u8; 32],
        m: [u8; 32],
        r: &[u8; 32],
    ) -> [u8; CT_LEN] {
        let mut ct = [0u8; CT_LEN];

        // 1: 𝑁 ← 0
        //  since the number of loops here is static; we can hard-code the N values rather than using a counter

        // 2: 𝐭 ← ByteDecode12(ekPKE[0 ∶ 384𝑘])
        // 3: 𝜌 ← ekPKE[384𝑘 ∶ 384𝑘 + 32]
        // not necessary here because ek is already decoded

        // 19: 𝐮 ← NTT−1(𝐀_hat^⊺ ∘ 𝐲_hat) + 𝐞1
        // 22: 𝑐1 ← ByteEncode_𝑑𝑢(Compress_𝑑𝑢(𝐮))

        // Note: you need y_hat twice: once here at line 19, and again at line 21.
        //  We'll just generate it twice to save the memory of holding on to it.
        for i in 0..k {
            let mut u_i = compute_A_hat_dot_y_hat::<k, eta1>(rho, &r, i);

            let e1_i = sample_poly_CBD::<ETA2>(&r, (k + i) as u8);
            u_i.add(&e1_i);
            u_i.poly_reduce();

            compress_u_row::<du, CT_LEN>(u_i, i, &mut ct);
        }

        // 17: 𝑒2 ← SamplePolyCBD_𝜂2(PRF𝜂2 (𝑟, 𝑁))
        // 20: 𝜇 ← Decompress1(ByteDecode1(𝑚))
        // 21: 𝑣 ← NTT−1(𝐭_hat_T ∘ 𝐲_hat) + 𝑒2 + 𝜇
        // 23: 𝑐2 ← ByteEncode_𝑑𝑣(Compress_𝑑𝑣(𝑣))
        {
            // compute v, which is a single polynomial, but requires iterating over the vectors t_hat and y_hat
            let mut v = compute_t_hat_dot_y_hat_row::<k, eta1>(
                &r,
                &unpack_t_hat_row(t_hat_packed, 0),
                /*row*/ 0,
            );

            for i in 1..k {
                let v_i = compute_t_hat_dot_y_hat_row::<k, eta1>(
                    &r,
                    &unpack_t_hat_row(t_hat_packed, i),
                    /*row*/ i,
                );
                v.add(&v_i);
            }

            // perform polynomial addition
            let e2 = sample_poly_CBD::<ETA2>(&r, 2 * k as u8);
            v.add(&e2);

            let mu = Polynomial::from_msg(m);
            v.add(&mu);

            v.poly_reduce();

            v.compress_poly::<dv>(&mut ct[CT_LEN - (N * (dv as usize) / 8)..]);
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
    pub fn encaps_internal(ek: &PK, m: [u8; 32]) -> ([u8; 32], [u8; CT_LEN]) {
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
        //   Unnecessary here because we're gonna re-compute them row-by-row

        // first half of
        // 6: 𝑤 ← 𝑣′ − NTT−1(𝐬_hat^T ∘ NTT(𝐮′))
        let v1 = {
            // i = 0 case
            let mut v1 = {
                let mut s_hat_i = dk.compute_s_hat_row(0);
                {
                    let mut u_prime_i = unpack_ciphertext_u_row::<du, CT_LEN>(0, &ct);
                    u_prime_i.ntt();
                    s_hat_i.base_mult_montgomery(&u_prime_i);
                }
                s_hat_i.inv_ntt();

                s_hat_i
            };

            for i in 1..k {
                let mut s_hat_i = dk.compute_s_hat_row(i);
                {
                    let mut u_prime_i = unpack_ciphertext_u_row::<du, CT_LEN>(i, &ct);
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
        let c_prime = Self::pke_encrypt(&dk.t_hat_packed(), dk.rho(), m_prime, &r_prime);

        // 9: if 𝑐 ≠ 𝑐′ then
        // 10: 𝐾′ ← 𝐾_bar
        //  ▷ if ciphertexts do not match, “implicitly reject"
        let mut K_out = [0u8; MLKEM_SS_LEN];
        conditional_copy_bytes(&K_prime, &K_bar, &mut K_out, ct_eq_bytes(&c, &c_prime));

        K_out
    }

    /// Alternative initialization of the streaming signer where you have your private key
    /// as a seed and you want to delay its expansion as late as possible for memory-usage reasons.
    pub fn decaps_from_seed(
        seed: &KeyMaterial<64>,
        ct: &[u8],
    ) -> Result<KeyMaterial<SS_LEN>, KEMError> {
        let sk = SK::from_keymaterial(seed)?;

        Self::decaps(&sk, ct)
    }
}

impl<
    const PK_LEN: usize,
    const SK_LEN: usize,
    const FULL_SK_LEN: usize,
    const CT_LEN: usize,
    const SS_LEN: usize,
    PK: MLKEMPublicKeyTrait<k, PK_LEN, T_PACKED_LEN>
        + MLKEMPublicKeyInternalTrait<k, T_PACKED_LEN, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<k, SK_LEN, FULL_SK_LEN, PK_LEN, T_PACKED_LEN>
        + MLKEMPrivateKeyInternalTrait<k, SK_LEN, PK_LEN, T_PACKED_LEN>,
    const k: usize,
    const eta1: i16,
    const du: i16,
    const dv: i16,
    const LAMBDA: i16,
    const T_PACKED_LEN: usize,
>
    MLKEMTrait<
        PK_LEN,
        SK_LEN,
        FULL_SK_LEN,
        CT_LEN,
        SS_LEN,
        PK,
        SK,
        k,
        eta1,
        du,
        dv,
        LAMBDA,
        T_PACKED_LEN,
    >
    for MLKEM<
        PK_LEN,
        SK_LEN,
        FULL_SK_LEN,
        CT_LEN,
        SS_LEN,
        PK,
        SK,
        k,
        eta1,
        du,
        dv,
        LAMBDA,
        T_PACKED_LEN,
    >
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
    /// Returns either `()` or [KEMError::ConsistencyCheckFailed].
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
    const PK_LEN: usize,
    const SK_LEN: usize,
    const FULL_SK_LEN: usize,
    const CT_LEN: usize,
    const SS_LEN: usize,
    PK: MLKEMPublicKeyTrait<k, PK_LEN, T_PACKED_LEN>
        + MLKEMPublicKeyInternalTrait<k, T_PACKED_LEN, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<k, SK_LEN, FULL_SK_LEN, PK_LEN, T_PACKED_LEN>
        + MLKEMPrivateKeyInternalTrait<k, SK_LEN, PK_LEN, T_PACKED_LEN>,
    const k: usize,
    const eta: i16,
    const du: i16,
    const dv: i16,
    const LAMBDA: i16,
    const T_PACKED_LEN: usize,
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
}

impl<
    const PK_LEN: usize,
    const SK_LEN: usize,
    const FULL_SK_LEN: usize,
    const CT_LEN: usize,
    const SS_LEN: usize,
    PK: MLKEMPublicKeyTrait<k, PK_LEN, T_PACKED_LEN>
        + MLKEMPublicKeyInternalTrait<k, T_PACKED_LEN, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<k, SK_LEN, FULL_SK_LEN, PK_LEN, T_PACKED_LEN>
        + MLKEMPrivateKeyInternalTrait<k, SK_LEN, PK_LEN, T_PACKED_LEN>,
    const k: usize,
    const eta: i16,
    const du: i16,
    const dv: i16,
    const LAMBDA: i16,
    const T_PACKED_LEN: usize,
> KEMEncapsulator<PK, PK_LEN, CT_LEN, SS_LEN>
    for MLKEM<
        PK_LEN,
        SK_LEN,
        FULL_SK_LEN,
        CT_LEN,
        SS_LEN,
        PK,
        SK,
        k,
        eta,
        du,
        dv,
        LAMBDA,
        T_PACKED_LEN,
    >
{
    fn encaps(pk: &PK) -> Result<(KeyMaterial<SS_LEN>, [u8; CT_LEN]), KEMError> {
        let mut m = [0u8; 32];
        HashDRBG_SHA512::new_from_os().next_bytes_out(&mut m)?;

        let (ss_bytes, ct) = Self::encaps_internal(pk, m);

        let mut ss_keymaterial =
            KeyMaterial::<SS_LEN>::from_bytes_as_type(&ss_bytes, KeyType::BytesFullEntropy)?;
        ss_keymaterial.allow_hazardous_operations();
        ss_keymaterial.set_security_strength(SecurityStrength::from_bits(LAMBDA as usize))?;
        ss_keymaterial.drop_hazardous_operations();

        Ok((ss_keymaterial, ct))
    }
}

impl<
    const PK_LEN: usize,
    const SK_LEN: usize,
    const FULL_SK_LEN: usize,
    const CT_LEN: usize,
    const SS_LEN: usize,
    PK: MLKEMPublicKeyTrait<k, PK_LEN, T_PACKED_LEN>
        + MLKEMPublicKeyInternalTrait<k, T_PACKED_LEN, PK_LEN>,
    SK: MLKEMPrivateKeyTrait<k, SK_LEN, FULL_SK_LEN, PK_LEN, T_PACKED_LEN>
        + MLKEMPrivateKeyInternalTrait<k, SK_LEN, PK_LEN, T_PACKED_LEN>,
    const k: usize,
    const eta: i16,
    const du: i16,
    const dv: i16,
    const LAMBDA: i16,
    const T_PACKED_LEN: usize,
> KEMDecapsulator<SK, SK_LEN, CT_LEN, SS_LEN>
    for MLKEM<
        PK_LEN,
        SK_LEN,
        FULL_SK_LEN,
        CT_LEN,
        SS_LEN,
        PK,
        SK,
        k,
        eta,
        du,
        dv,
        LAMBDA,
        T_PACKED_LEN,
    >
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
            KeyMaterial::<SS_LEN>::from_bytes_as_type(&ss_bytes, KeyType::BytesFullEntropy)?;
        ss_keymaterial.allow_hazardous_operations();
        ss_keymaterial.set_security_strength(SecurityStrength::from_bits(LAMBDA as usize))?;
        ss_keymaterial.drop_hazardous_operations();

        Ok(ss_keymaterial)
    }
}
