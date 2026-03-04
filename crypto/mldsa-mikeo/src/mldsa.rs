use bouncycastle_core_interface::errors::SignatureError;
use bouncycastle_core_interface::key_material::{
    KeyMaterial, KeyMaterial256, KeyMaterialSized, KeyType,
};
use bouncycastle_core_interface::traits::{SecurityStrength, Signature, SignaturePrivateKey, SignaturePublicKey, RNG, XOF};
use bouncycastle_sha3::{SHAKE128, SHAKE256};
use bouncycastle_rng::hash_drbg80090a::HashDRBG80090A;
use bouncycastle_rng::HashDRBG_SHA256;
use crate::MLDSAParams;
use crate::aux_functions::{expandA, expandS, expand_mask, high_bits, inv_ntt_vec, make_hint_vec, ntt, ntt_vec, power_2_round_vec, sample_in_ball, sig_encode};
use crate::matrix::Vector;
use crate::mldsa_keys::{MLDSAPrivateKey, MLDSAPublicKey};
use crate::polynomial::Polynomial;

// Typedefs just to make the algorithms look more like the FIPS 204 sample code.
pub(crate) type H = SHAKE256;
pub(crate) type G = SHAKE128;

// needed because MLDSAParams is on-purpose a private trait so that users cannot instantiate their
// own parametrization of ML-DSA.
#[allow(private_bounds)]
pub struct MLDSA<
    const k: usize,
    const l: usize,
    const eta: usize,
    const LAMBDA_over_4: usize,
    const GAMMA1: i32,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const SIG_LEN: usize,
    PARAMS: MLDSAParams,
> {
    _params: std::marker::PhantomData<PARAMS>,

    // only used in streaming sign operations
    priv_key: Option<MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN>>,

    // only used in streaming verify operations
    pub_key: Option<MLDSAPublicKey<k, PK_LEN>>,
}

#[allow(private_bounds)]
impl<
    const k: usize,
    const l: usize,
    const eta: usize,
    const LAMBDA_over_4: usize,
    const GAMMA1: i32,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const SIG_LEN: usize,
    PARAMS: MLDSAParams,
> MLDSA<k, l, eta, LAMBDA_over_4, GAMMA1, PK_LEN, SK_LEN, SIG_LEN, PARAMS>
{
    /// Implements Algorithm 6 of FIPS 204
    /// Note: NIST has made a special exception in the FIPS 204 FAQ that this _internal function
    /// may in fact be exposed outside the crypto module.
    ///
    /// Unlike other interfaces across the library that take an &impl KeyMaterial, this one
    /// specifically takes a 32-byte [KeyMaterial256] and checks that it has [KeyType::Seed] and
    /// [SecurityStrength::_256bit].
    /// If you happen to have your seed in a larger KeyMaterial, you'll have to copy it using
    /// [KeyMaterial::from_key] -- todo: make sure this works and copies key type and security strength correctly.
    pub fn keygen_internal(
        seed: &KeyMaterial256,
    ) -> Result<
        (MLDSAPublicKey<k, PK_LEN>, MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN>),
        SignatureError,
    > {
        if seed.key_type() != KeyType::Seed
            || seed.key_len() != 32
            || seed.security_strength() != SecurityStrength::_256bit
        {
            return Err(SignatureError::KeyGenError(
                "Seed must be 32 bytes, of KeyType::Seed and SecurityStrength::_128bit.",
            ));
        }

        // Alg 6 line 1: (rho, rho_prime, K) <- H(𝜉||IntegerToBytes(𝑘, 1)||IntegerToBytes(ℓ, 1), 128)
        //   ▷ expand seed
        let mut rho: [u8; 32] = [0u8; 32];
        let mut rho_prime: [u8; 64] = [0u8; 64];
        let mut K: [u8; 32] = [0u8; 32];

        // TODO: optimization: re-use variables rather than allocating new ones.
        // TODO: do with benches because it might not actually be faster. Rust seems to like local vars.

        let mut h = H::default();
        h.absorb(seed.ref_to_bytes());
        h.absorb(&(PARAMS::k as u8).to_le_bytes());
        h.absorb(&(PARAMS::l as u8).to_le_bytes());
        let bytes_written = h.squeeze_out(&mut rho);
        debug_assert_eq!(bytes_written, 32); // todo: remove these asserts once we have unit tests that pass?
        let bytes_written = h.squeeze_out(&mut rho_prime);
        debug_assert_eq!(bytes_written, 64);
        let bytes_written = h.squeeze_out(&mut K);
        debug_assert_eq!(bytes_written, 32);

        // 3: 𝐀_hat ← ExpandA(𝜌) ▷ 𝐀 is generated and stored in NTT representation as 𝐀
        let A_hat = expandA::<k, l>(&rho);

        // 4: (𝐬1, 𝐬2) ← ExpandS(𝜌′)
        let (s1, s2) = expandS::<k, l, PARAMS>(&rho_prime);

        // 5: 𝐭 ← NTT−1(𝐀 ∘ NTT(𝐬1)) + 𝐬2
        //   ▷ compute 𝐭 = 𝐀𝐬1 + 𝐬2
        let s1_hat = ntt_vec::<l>(&s1);
        let mut t_hat = A_hat.matrix_vector_ntt(&s1_hat);
        t_hat.reduce();
        let mut t = inv_ntt_vec(&t_hat);
        t.add_vector_ntt(&s2);
        t.conditional_add_q();

        // 6: (𝐭1, 𝐭0) ← Power2Round(𝐭)
        //   ▷ compress 𝐭
        //   ▷ PowerTwoRound is applied componentwise (see explanatory text in Section 7.4)
        let (t1, t0) = power_2_round_vec::<k>(&t);

        // 8: 𝑝𝑘 ← pkEncode(𝜌, 𝐭1)
        let pk = MLDSAPublicKey::<k, PK_LEN>::new(&rho, &t1);

        // 9: 𝑡𝑟 ← H(𝑝𝑘, 64)
        let tr = pk.compute_tr();

        // 10: 𝑠𝑘 ← skEncode(𝜌, 𝐾, 𝑡𝑟, 𝐬1, 𝐬2, 𝐭0)
        //   ▷ 𝐾 and 𝑡𝑟 are for use in signing
        let sk = MLDSAPrivateKey::new(
            &rho,
            &K,
            &tr,
            &s1,
            &s2,
            &t0,
            Some(seed.clone()),
        );

        // 11: return (𝑝𝑘, 𝑠𝑘)
        Ok((pk, sk))
    }

    /*** Key Generation and PK / SK consistency checks ***/

    /// Should still be ok in FIPS mode
    pub fn keygen_from_os_rng() -> Result<
        (MLDSAPublicKey<k, PK_LEN>, MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN>),
        SignatureError,
    > {
        let mut seed = KeyMaterial256::new();
        HashDRBG_SHA256::new_from_os().fill_keymaterial_out(&mut seed)?;
        Self::keygen_internal(&seed)
    }

    /// Expand a (pk, sk) keypair from a private key seed.
    /// Both pk and sk objects will be fully populated.
    /// This is simply a pass-through to [MLDSA::keygen_internal], which is allowed to be exposed externally by NIST.
    pub fn keygen_from_seed(
        seed: &KeyMaterialSized<32>,
    ) -> Result<
        (MLDSAPublicKey<k, PK_LEN>, MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN>),
        SignatureError,
    > {
        Self::keygen_internal(&seed)
    }

    /// Imports a secret key from both a seed and an encoded_sk.
    ///
    /// This is a convenience function to expand the key from seed and compare it against
    /// the provided `encoded_sk` using a constant-time equality check.
    /// If everything checks out, the secret key is returned fully populated with pk and seed.
    /// If the provided key and derived key don't match, an error is returned.
    pub fn sk_from_seed_and_encoded(
        seed: &KeyMaterialSized<32>,
        encoded_sk: &[u8; SK_LEN],
    ) -> Result<MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN>, SignatureError> {
        let (_, sk) = Self::keygen_from_seed(seed)?;

        let sk_from_bytes = MLDSAPrivateKey::<k, l, eta, SK_LEN, PK_LEN>::from_bytes(encoded_sk)?;

        // MLDSAPrivateKey impls PartialEq with a constant-time equality check.
        if sk != sk_from_bytes {
            return Err(SignatureError::KeyGenError("Encoded key does not match generated key"));
        }

        Ok(sk)
    }

    /// Given a public key and a secret key, check that the public key matches the secret key.
    /// This is a sanity check that the public key was generated correctly from the secret key.
    ///
    /// At the current time, this is only possible if `sk` either contains a public key (in which case
    /// the two pk's are encoded and compared for byte equality), or if `sk` contains a seed
    /// (in which case a keygen_from_seed is run and then the pk's compared).
    /// TODO -- sync with openssl implementation
    /// TODO -- https://github.com/openssl/openssl/blob/master/crypto/ml_dsa/ml_dsa_key.c#L385
    pub fn keypair_consistency_check(
        pk: MLDSAPublicKey<k, PK_LEN>,
        sk: MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN>,
    ) {
        todo!()
    }

    /// This provides the first half of the "External Mu" interface to ML-DSA which is described
    /// in, and allowed under, NIST's FAQ that accompanies FIPS 204.
    ///
    /// This function, together with [sign_mu] perform a complete ML-DSA signature which is indistinguishable
    /// from one produced by the one-shot sign APIs.
    ///
    /// The utility of this function is exactly as described
    /// on Line 6 of Algorithm 7 of FIPS 204:
    ///
    ///    message representative that may optionally be computed in a different cryptographic module
    ///
    /// The utility is when an extremely large message needs to be signed, where the message exists on one
    /// computing system and the private key to sign it is held on another and either the transfer time or bandwidth
    /// causes operational concerns (this is common for example with network HSMs or sending large messages
    /// to be signed by a smartcard communicating over near-field radio). Another use case is if the
    /// contents of the message are sensitive and the signer does not want to transmit the message itself
    /// for fear of leaking it via proxy logging and instead would prefer to only transmit a hash of it.
    ///
    /// Since "External Mu" mode is well-defined by FIPS 204 and allowed by NIST, the mu value produced here
    /// can be used with many hardware crypto modules.
    ///
    /// This "External Mu" mode of ML-DSA provides an alternative to the HashML-DSA algorithm in that it
    /// allows the message to be externally pre-hashed, however, unlike HashML-DSA, this is merely an optimization
    /// between the application holding the to-be-signed message and the cryptographic module holding the private key
    /// -- in particular, while HashML-DSA requires the verifier to know whether ML-DSA or HashML-DSA was used to sign
    /// the message, both "direct" ML-DSA and "External Mu" signatures can be verified with a standard
    /// ML-DSA verifier.
    ///
    /// This function requires the public key hash `tr`, which can be computed from the public key using [MLDSAPublicKey::compute_tr].
    ///
    /// For a streaming version of this, see [MuBuilder].
    pub fn compute_mu_from_tr(msg: &[u8], ctx: &[u8], tr: [u8; 64]) -> Result<[u8; 64], SignatureError> {
        let mut mu_builder = MuBuilder::do_init(&tr, ctx)?;
        mu_builder.do_update(msg);
        let mu = mu_builder.do_final();

        Ok(mu)
    }

    /// Performs an ML-DSA signature using the provided external message representative `mu`.
    /// This implements FIPS 204 Algorithm 7 with line 6 removed; a modification that is allowed by both
    /// FIPS 204 itself, as well as subsequent FAQ documents.
    /// This mode uses randomized signing (called "hedged mode" in FIPS 204).
    pub fn sign_mu(
        sk: &MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN>,
        mu: &[u8; 64],
    ) -> [u8; SIG_LEN] {
        let mut out: [u8; SIG_LEN] = [0u8; SIG_LEN];
        Self::sign_mu_out(sk, mu, &mut out);
        out
    }

    /// Performs an ML-DSA signature using the provided external message representative `mu`.
    /// This implements FIPS 204 Algorithm 7 with line 6 removed; a modification that is allowed by both
    /// FIPS 204 itself, as well as subsequent FAQ documents.
    /// This mode uses randomized signing (called "hedged mode" in FIPS 204).
    pub fn sign_mu_out(
        sk: &MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN>,
        mu: &[u8; 64],
        output: &mut [u8; SIG_LEN],
    ) -> Result<(), SignatureError> {
        let mut rnd: [u8; 32] = [0u8; 32];
        HashDRBG_SHA256::new_from_os().next_bytes_out(&mut rnd)?;

        Self::sign_mu_deterministic_out(sk, mu, &mut rnd, output)
    }

    /// Algorithm 7
    /// Input: Private key 𝑠𝑘 ∈ 𝔹32+32+64+32⋅((ℓ+𝑘)⋅bitlen (2𝜂)+𝑑𝑘), formatted message 𝑀 ′ ∈ {0, 1}∗ , and
    /// per message randomness or dummy variable 𝑟𝑛𝑑 ∈ 𝔹32 .
    /// Output: Signature 𝜎 ∈ 𝔹𝜆/4+ℓ⋅32⋅(1+bitlen (𝛾1−1))+𝜔+𝑘.
    pub(crate) fn sign_mu_deterministic_out(
        sk: &MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN>,
        mu: &[u8; 64],
        rnd: &[u8; 32],
        output: &mut [u8; SIG_LEN]
    ) -> Result<(), SignatureError> {
        // 1: (𝜌, 𝐾, 𝑡𝑟, 𝐬1, 𝐬2, 𝐭0) ← skDecode(𝑠𝑘)
        // Already done -- the sk struct is already decoded

        // 2: 𝐬1̂_hat ← NTT(𝐬1)
        let s1_hat = ntt_vec::<l>(&sk.s1);

        // 3: 𝐬2̂_hat ← NTT(𝐬2)
        let s2_hat = ntt_vec::<k>(&sk.s2);

        // 4: 𝐭0̂_hat ← NTT(𝐭0)̂
        let t0_hat = ntt_vec::<k>(&sk.t0);

        // 5: 𝐀_hat ← ExpandA(𝜌)
        let A_hat = expandA::<k, l>(&sk.rho);

        // 6: 𝜇 ← H(BytesToBits(𝑡𝑟)||𝑀 ′, 64)
        // skip: mu has already been provided

        // 7: 𝜌″ ← H(𝐾||𝑟𝑛𝑑||𝜇, 64)
        let mut h = H::new();
        h.absorb(&sk.K);
        h.absorb(rnd);
        h.absorb(mu);
        let mut rho_p_p = [0u8; 64];
        h.squeeze_out(&mut rho_p_p);

        // 8: 𝜅 ← 0
        //  ▷ initialize counter 𝜅
        let mut kappa: u16 = 0;

        // 9: (𝐳, 𝐡) ← ⊥
        // todo

        // 10: while (𝐳, 𝐡) = ⊥ do
        //  ▷ rejection sampling loop
        // // todo -- can the counter kappa serve double-duty as this counter?
        // let mut count: u16 = 0;

        // these need to be outside the loop because they form the encoded signature value
        let mut sig_val_c_tilde = [0u8; LAMBDA_over_4];
        let mut sig_val_z: Vector<l>;
        let mut sig_val_h: [u8; 64];
        loop {
            // FIPS 204 s. 6.2 allows:
            //   "Implementations may limit the number of iterations in this loop to not exceed a finite maximum value."
            // if count > 1000 { return Err(SignatureError::GenericError("Rejection sampling loop hit the hard-coded maximum number of iterations. Simply try again with a different random nonce rnd.")); }
            // count += 1;

            // todo: as the nursary does, could optimize by having the output vars work directly in the output signature buffer
            // todo: optimize by changing many of the member functions of matrix.rs to work in-ploce, then `let` rename the variable
            // todo:   ie figure out where you can consume the input variable, then just do it in place with a rename instead.

            // 11: 𝐲 ∈ 𝑅^ℓ ← ExpandMask(𝜌″, 𝜅)
            // todo -- what the heck compiler, why can't I do this? Go study how RustCrypto does this successfully
            // todo -- it might have something to do with const generics
            let mut y = expand_mask::<l, PARAMS::GAMMA1, PARAMS::GAMMA1_MASK_LEN>(&rho_p_p, kappa);

            // 12: 𝐰 ← NTT−1(𝐀_hat * NTT(𝐲))
            let y_hat = &y.ntt();
            let w_hat = A_hat.matrix_vector_ntt(y_hat);
            let w = w_hat.inv_ntt();

            // 13: 𝐰1 ← HighBits(𝐰)
            //  ▷ signer’s commitment
            let w1 = w.high_bits::<PARAMS::GAMMA2>();

            // 15: 𝑐_tilde ← H(𝜇||w1Encode(𝐰1), 𝜆/4)
            //  ▷ commitment hash
            let mut h = H::new();
            h.absorb(mu);
            h.absorb(&w1.w1_encode::<PARAMS::POLY_W1_PACKED_LEN>());
            h.squeeze_out(&mut sig_val_c_tilde);

            // 16: 𝑐 ∈ 𝑅𝑞 ← SampleInBall(𝑐)̃
            //  ▷ verifier’s challenge
            let c = sample_in_ball::<PARAMS::LAMBDA_over_4, PARAMS::TAU>(&sig_val_c_tilde);

            // 17: 𝑐_hat ← NTT(𝑐)
            let c_hat = ntt(&c);

            // 18: ⟨⟨𝑐𝐬1⟩⟩ ← NTT−1(𝑐_hat * 𝐬1_hat )
            //  Note: <<.>> means that this value will be used again later, so you should hang on to it.
            let cs1 = (s1_hat.scalar_vector_ntt(&c_hat)).inv_ntt();

            // 19: ⟨⟨𝑐𝐬2⟩⟩ ← NTT−1(𝑐 ∘̂ 𝐬2̂ )
            let cs2 = (s2_hat.scalar_vector_ntt(&c_hat)).inv_ntt();

            // 20: 𝐳 ← 𝐲 + ⟨⟨𝑐𝐬1⟩⟩
            y.add_vector_ntt(&cs1);
            sig_val_z = y;

            // 21: 𝐫0 ← LowBits(𝐰 − ⟨⟨𝑐𝐬2⟩⟩)
            let r0 = w.sub_vector(&cs2).lew_bits();

            // 23: if ||𝐳||∞ ≥ 𝛾1 − 𝛽 or ||𝐫0||∞ ≥ 𝛾2 − 𝛽 then (z, h) ← ⊥
            //  ▷ validity checks
            if sig_val_z.check_norm( PARAMS::GAMMA1 - PARAMS::BETA ) { kappa += l as u16; continue };
            if r0.check_norm( PARAMS::GAMMA2 - PARAMS::BETA ) { kappa += l as u16; continue };

            // 25: ⟨⟨𝑐𝐭0⟩⟩ ← NTT−1(𝑐_hat * 𝐭0̂_hat )
            let ct0 = t0_hat.scalar_vector_ntt(&c).inv_ntt();

            // 26: 𝐡 ← MakeHint(−⟨⟨𝑐𝐭0⟩⟩, 𝐰 − ⟨⟨𝑐𝐬2⟩⟩ + ⟨⟨𝑐𝐭0⟩⟩)
            //  ▷ Signer’s hint
            let mut cs2_plus_ct0 = cs2.clone();
            cs2_plus_ct0.add_vector_ntt(&ct0);
            let (hint, hint_hamming_weight) = make_hint_vec::<k, PARAMS::GAMMA2>(&ct0.neg(), &w.sub_vector(&cs2_plus_ct0));

            // 28: if ||⟨⟨𝑐𝐭0⟩⟩||∞ ≥ 𝛾2 or the number of 1’s in 𝐡 is greater than 𝜔, then (z, h) ← ⊥
            if hint_hamming_weight > PARAMS::OMEGA { kappa += l as u16; continue };
            if ct0.check_norm( PARAMS::GAMMA2) { kappa += l as u16; continue }; // todo -- this one can be moved up after line 25


            // "In addition, there is an alternative way of implementing the validity checks on 𝐳 and the computation of
            // 𝐡, which is described in Section 5.1 of. This method may also be used in implementations of ML-DSA."
            // todo -- check this out

            break;
        }

        // 33: 𝜎 ← sigEncode(𝑐, 𝐳̃ mod±𝑞, 𝐡)
        // todo -- am I accounting for the mod±𝑞 ?
        let sig = sig_encode(&sig_val_c_tilde, &sig_val_z, &sig_val_h)?;

        todo!()

        // Ok(())
    }
}

#[allow(private_bounds)]
impl<
    const k: usize,
    const l: usize,
    const eta: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
    const SIG_LEN: usize,
    PARAMS: MLDSAParams,
> Signature for MLDSA<k, l, eta, PK_LEN, SK_LEN, SIG_LEN, PARAMS>
{
    /// Algorithm 2 ML-DSA.Sign(𝑠𝑘, 𝑀, 𝑐𝑡𝑥)
    fn sign(
        priv_key: &impl SignaturePrivateKey,
        msg: &[u8],
        ctx: &[u8],
    ) -> Result<Vec<u8>, SignatureError> {
        let mut out = vec![0u8; SIG_LEN];
        Self::sign_out(priv_key, ctx, msg, &mut out)?;
        Ok(out)
    }

    /// Algorithm 2 ML-DSA.Sign(𝑠𝑘, 𝑀, 𝑐𝑡𝑥)
    fn sign_out(
        priv_key: &impl SignaturePrivateKey,
        msg: &[u8],
        ctx: &[u8],
        output: &mut [u8],
    ) -> Result<(), SignatureError> {

        // todo: need to do some rust learning about how to typecast `impl SignaturePrivateKey` to MLDSAPrivateKey
        // let sk: MLDSAPrivateKey<k, l, eta, SK_LEN, PK_LEN> = priv_key.try_into()?;
        // Self::sign_deterministic(priv_key, msg, ctx, &rnd, output)
        todo!()
    }

    fn verify(
        pub_key: &impl SignaturePublicKey,
        msg: &[u8],
        ctx: &[u8],
        sig: &[u8],
    ) -> Result<bool, SignatureError> {
        todo!()
    }

    fn sign_init(&mut self, priv_key: &impl SignaturePrivateKey) -> Result<(), SignatureError> {
        todo!()
    }

    fn sign_update(&mut self, msg_chunk: &[u8]) {
        todo!()
    }

    fn sign_final(&mut self, msg_chunk: &[u8], ctx: &[u8]) -> Result<Vec<u8>, SignatureError> {
        todo!()
    }

    fn sign_final_out(
        &mut self,
        msg_chunk: &[u8],
        ctx: &[u8],
        output: &mut [u8],
    ) -> Result<(), SignatureError> {
        todo!()
    }

    fn verify_init(&mut self, pub_key: &impl SignaturePublicKey) -> Result<(), SignatureError> {
        todo!()
    }

    fn verify_update(&mut self, msg_chunk: &[u8]) {
        todo!()
    }

    fn verify_final(&mut self, msg_chunk: &[u8], ctx: &[u8]) -> Result<bool, SignatureError> {
        todo!()
    }
}

/// Implements parts of Algorithm 2 and Line 6 of Algorithm 7 of FIPS 204.
/// Provides a stateful version of [compute_mu_from_pk] and [compute_mu_from_tr] that supports streaming
/// large to-be-signed messages.
pub struct MuBuilder {
    h: H,
}

impl MuBuilder {
    /// This function requires the public key hash `tr`, which can be computed from the public key using [MLDSAPublicKey::compute_tr].
    pub fn do_init(tr: &[u8; 64], ctx: &[u8]) -> Result<Self, SignatureError> {
        // Algorithm 2
        // 1: if |𝑐𝑡𝑥| > 255 then
        if ctx.len() > 255 {
            return Err(SignatureError::LengthError("ctx value is longer than 255 bytes"));
        }

        // Algorithm 7
        // 6: 𝜇 ← H(BytesToBits(𝑡𝑟)||𝑀', 64)
        // and
        // Algorithm 2
        // 10: 𝑀′ ← BytesToBits(IntegerToBytes(0, 1) ∥ IntegerToBytes(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥) ∥ 𝑀
        // all done together
        let mut mb = Self { h: H::new() };
        mb.h.absorb(tr);
        mb.h.absorb(&[0u8]);
        mb.h.absorb(&[ctx.len() as u8]);
        mb.h.absorb(ctx);

        Ok(mb)
    }

    pub fn do_update(&mut self, msg_chunk: &[u8]) {
        self.h.absorb(msg_chunk);
    }

    pub fn do_final(mut self) -> [u8; 64] {
        // Completion of\
        // Algorithm 7
        // 6: 𝜇 ← H(BytesToBits(𝑡𝑟)||𝑀 ′, 64)
        let mut mu = [0u8; 64];
        self.h.squeeze_out(&mut mu);

        mu
    }
}


struct MLDSA44 {
}