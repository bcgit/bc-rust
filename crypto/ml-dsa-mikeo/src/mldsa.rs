use crate::MLDSAParams;
use crate::aux_functions::{expand_a, expand_s, inv_ntt_vec, ntt_vec, power_2_round_vec};
use crate::mldsa_keys::{MLDSAPrivatekey, MLDSAPublickey};
use bouncycastle_core_interface::errors::SignatureError;
use bouncycastle_core_interface::key_material::{KeyMaterial, KeyMaterial256, KeyType};
use bouncycastle_core_interface::traits::{SecurityStrength, XOF};
use bouncycastle_sha3::{SHAKE128, SHAKE256};

// Typedefs just to make the algorithms look more like the FIPS 204 sample code.
pub(crate) type H = SHAKE256;
pub(crate) type G = SHAKE128;

pub struct MLDSA<
    const k: usize,
    const l: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const SIG_LEN: usize,
    PARAMS: MLDSAParams,
> {
    _params: std::marker::PhantomData<PARAMS>,
    // only used in streaming sign operations
    priv_key: Option<MLDSAPrivatekey<k, l, SK_LEN>>,

    // only used in streaming verify operations
    pub_key: Option<MLDSAPublickey<k, PK_LEN>>,
}

impl<
    const k: usize,
    const l: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const SIG_LEN: usize,
    PARAMS: MLDSAParams,
>  MLDSA<k, l, PK_LEN, SK_LEN, SIG_LEN, PARAMS> {
    /// Implements Algorithm 6 of FIPS 204
    /// Note: NIST has made a special exception in the FIPS 204 FAQ that this _internal function
    /// may in fact be exposed outside the crypto module.
    ///
    /// Unlike other interfaces across the library that take an &impl KeyMaterial, this one
    /// specifically takes a 32-byte [KeyMaterial256] and checks that it has [KeyType::Seed] and
    /// [SecurityStrength::_128bit].
    /// If you happen to have your seed in a larger KeyMaterial, you'll have to copy it using
    /// [KeyMaterial::from_key] -- todo: make sure this works and copies key type and security strength correctly.
    pub fn keygen_internal(
        seed: &KeyMaterial256,
    ) -> Result<(MLDSAPublickey<k, PK_LEN>, MLDSAPrivatekey<k, l, SK_LEN>), SignatureError> {
        if seed.key_type() != KeyType::Seed
            || seed.key_len() != 32
            || seed.security_strength() != SecurityStrength::_128bit
        {
            return Err(SignatureError::KeyGenError(
                "Seed must be 32 bytes, of KeyType::Seed and SecurityStrength::_128bit.",
            ));
        }

        // Alg 6 line 1: (rho, rho_prime, K) <- H(𝜉||IntegerToBytes(𝑘, 1)||IntegerToBytes(ℓ, 1), 128)
        //   ▷ expand seed
        let mut rho: [u8; 32] = [0u8; 32];
        let mut rho_prime: [u8; 64] = [0u8; 64];
        let mut priv_seed_k: [u8; 32] = [0u8; 32];

        let mut h = H::default();
        h.absorb(seed.ref_to_bytes());
        h.absorb(&(PARAMS::k as u8).to_le_bytes());
        h.absorb(&(PARAMS::l as u8).to_le_bytes());
        let bytes_written = h.squeeze_out(&mut rho);
        debug_assert_eq!(bytes_written, 32); // todo: remove these asserts once we have unit tests that pass
        let bytes_written = h.squeeze_out(&mut rho_prime);
        debug_assert_eq!(bytes_written, 64);
        let bytes_written = h.squeeze_out(&mut priv_seed_k);
        debug_assert_eq!(bytes_written, 32);

        // 3: 𝐀 ← ExpandA(𝜌) ▷ 𝐀 is generated and stored in NTT representation as 𝐀
        #[allow(non_snake_case)]
        let mut A_hat = expand_a::<k,l>(&rho);

        // 4: (𝐬1, 𝐬2) ← ExpandS(𝜌′)
        let (s1, s2) = expand_s::<k,l,PARAMS>(&rho_prime);

        // 5: 𝐭 ← NTT−1(𝐀 ∘ NTT(𝐬1)) + 𝐬2
        //   ▷ compute 𝐭 = 𝐀𝐬1 + 𝐬2
        let s1_hat = ntt_vec::<l>(&s1);
        let s_tmp = A_hat.mult_by_vec(&s1_hat); // performs operation in-place on A_hat
        let mut t = inv_ntt_vec(&s_tmp);
        t.add(&s2);

        // 6: (𝐭1, 𝐭0) ← Power2Round(𝐭)
        //   ▷ compress 𝐭
        //   ▷ PowerTwoRound is applied componentwise (see explanatory text in Section 7.4)
        let (t1, t0) = power_2_round_vec::<k>(&t);

        // 8: 𝑝𝑘 ← pkEncode(𝜌, 𝐭1)
        let pk = MLDSAPublickey::<k,PK_LEN>::new(&rho, &t1);

        // 9: 𝑡𝑟 ← H(𝑝𝑘, 64)
        let mut tr = [0u8; 64];
        H::new().hash_xof_out(&pk.encode(), &mut tr);
        // todo: write pk.encode()

        // 10: 𝑠𝑘 ← skEncode(𝜌, 𝐾, 𝑡𝑟, 𝐬1, 𝐬2, 𝐭0) ▷ 𝐾 and 𝑡𝑟 are for use in signing

        // 11: return (𝑝𝑘, 𝑠𝑘)

        Ok(())
    }
}
