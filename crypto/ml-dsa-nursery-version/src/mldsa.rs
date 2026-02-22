use crate::{
    encodings, polynomial::Polynomial, poly_vec_k::PolyVecK, poly_vec_l::PolyVecL,
    poly_vec_matrix::PolyVecMatrix, /*symmetric::Symmetric*/,
};
use bouncycastle_core_interface::traits::{Hash, RNG};
use bouncycastle_sha3::{SHAKE, SHAKE128, SHAKE256};
use std::any::Any;
// use std::cmp::min;
use bouncycastle_utils::{
    CipherParameters, Error::InvalidOperationError, Error::ParameterError, Result, SecureRandom,
    arrays,
};

// todo implement 3.6.2 Public-Key and Signature Length Checks




pub(crate) type H = SHAKE256;
pub(crate) type G = SHAKE128;


#[derive(Clone)]
struct MLDSA<MLDSAParams> {
    // todo: how many of these actually need to be runtime dynamic parameters? How many could be compiled parameters?
    pub mode: i32,
    pub k: usize,
    pub l: usize,
    pub eta: i32,
    pub tau: i32,
    pub beta: i32,
    pub gamma1: i32,
    pub gamma2: i32,
    pub omega: i32,
    pub c_tilde: usize,
    pub poly_vec_h_packed_bytes: usize,
    pub poly_z_packed_bytes: usize,
    pub poly_w1_packed_bytes: usize,
    pub poly_eta_packed_bytes: usize,
    pub crypto_public_key_bytes: usize,
    pub crypto_secret_key_bytes: usize,
    pub crypto_bytes: usize,
    pub poly_uniform_gamma1_n_bytes: usize,
    // pub symmetric: Symmetric,
    _random: Option<Box<dyn SecureRandom>>,
}

// #[derive(Clone, Copy)]
// pub struct MlDsaParameters {
//     k: i32,
// }

// impl MlDsaParameters {
//     pub(crate) fn new(k: i32) -> Self {
//         Self { k }
//     }
//     pub(crate) fn get_engine(&self, random: Option<Box<dyn SecureRandom>>) -> Result<MlDsaEngine> {
//         MlDsaEngine::new(self.k, random)
//     }
// }

// todo -- figure out external mu API

// todo -- ML-DSA ph modes

pub struct MlDsaPrivateKeyParameters {
    pub(crate) m_parameters: MlDsaParameters,
    m_rho: Vec<u8>,
    m_k: Vec<u8>,
    m_tr: Vec<u8>,
    m_s1: Vec<u8>,
    m_s2: Vec<u8>,
    m_t0: Vec<u8>,
    m_t1: Vec<u8>,
}

impl MlDsaPrivateKeyParameters {
    pub(crate) fn parameters(&self) -> MlDsaParameters {
        self.m_parameters
    }
    pub fn rho(&self) -> Vec<u8> {
        self.m_rho.clone()
    }
    pub fn k(&self) -> Vec<u8> {
        self.m_k.clone()
    }
    pub fn tr(&self) -> Vec<u8> {
        self.m_tr.clone()
    }
    pub fn s1(&self) -> Vec<u8> {
        self.m_s1.clone()
    }
    pub fn s2(&self) -> Vec<u8> {
        self.m_s2.clone()
    }
    pub fn t0(&self) -> Vec<u8> {
        self.m_t0.clone()
    }
    pub fn t1(&self) -> Vec<u8> {
        self.m_t1.clone()
    }

    pub(crate) fn init(param: &Self) -> Self {
        Self {
            m_parameters: param.m_parameters,
            m_rho: param.m_rho.clone(),
            m_k: param.m_k.clone(),
            m_tr: param.m_tr.clone(),
            m_s1: param.m_s1.clone(),
            m_s2: param.m_s2.clone(),
            m_t0: param.m_t0.clone(),
            m_t1: param.m_t1.clone(),
        }
    }

    // todo -- does this have to be an init? Can it not be a new?
    pub fn init_from_encoding(
        param: MlDsaParameters,
        encoding: &[u8],
        pub_key: Option<MlDsaPublicKeyParameters>,
    ) -> Result<Self> {
        let engine = &param.get_engine(None)?;
        let mut index = 0;
        let mut delta;
        let rho = arrays::copy_of_range(encoding, 0, SEED_BYTES);
        index += SEED_BYTES;
        let k = arrays::copy_of_range(encoding, index, index + SEED_BYTES);
        index += SEED_BYTES;
        let tr = arrays::copy_of_range(encoding, index, index + TR_BYTES);
        index += TR_BYTES;
        delta = engine.l * engine.poly_eta_packed_bytes;
        let s1 = arrays::copy_of_range(encoding, index, index + delta);
        index += delta;
        delta = engine.k * engine.poly_eta_packed_bytes;
        let s2 = arrays::copy_of_range(encoding, index, index + delta);
        index += delta;
        delta = engine.k * POLY_T0PACKED_BYTES;
        let t0 = arrays::copy_of_range(encoding, index, index + delta);
        let t1 = match pub_key {
            None => {
                vec![0u8; 0]
            }
            Some(pk) => pk.t1(),
        };
        Ok(Self {
            m_parameters: param,
            m_rho: rho,
            m_k: k,
            m_tr: tr,
            m_s1: s1,
            m_s2: s2,
            m_t0: t0,
            m_t1: t1,
        })
    }

    pub fn get_encoded(&self) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        result.extend(&self.m_rho);
        result.extend(&self.m_k);
        result.extend(&self.m_tr);
        result.extend(&self.m_s1);
        result.extend(&self.m_s2);
        result.extend(&self.m_t0);
        result
    }
}

impl CipherParameters for MlDsaPrivateKeyParameters {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

// todo -- delete
pub struct MlDsaPublicKeyParameters {
    m_parameters: MlDsaParameters,
    m_rho: Vec<u8>,
    m_t1: Vec<u8>,
}

impl MlDsaPublicKeyParameters {
    pub(crate) fn parameters(&self) -> MlDsaParameters {
        self.m_parameters
    }
    pub fn t1(&self) -> Vec<u8> {
        self.m_t1.clone()
    }
    pub fn rho(&self) -> Vec<u8> {
        self.m_rho.clone()
    }
    pub(crate) fn init(param: &Self) -> Self {
        Self {
            m_parameters: param.m_parameters,
            m_rho: param.m_rho.clone(),
            m_t1: param.m_t1.clone(),
        }
    }

    pub fn init_from_encoding(param: MlDsaParameters, encoding: &[u8]) -> Self {
        let rho = arrays::copy_of_range(encoding, 0, SEED_BYTES);
        let t1 = arrays::copy_of_range(encoding, SEED_BYTES, encoding.len());
        Self { m_parameters: param, m_t1: t1, m_rho: rho }
    }

    pub fn get_encoded(&self) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        result.extend(&self.m_rho);
        result.extend(&self.m_t1);
        result
    }
}
impl CipherParameters for MlDsaPublicKeyParameters {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

pub struct MlDsaKeyPair {
    pub public: MlDsaPublicKeyParameters,
    pub private: MlDsaPrivateKeyParameters,
}

pub struct MlDsaKeyPairGenerator {
    random: Box<dyn SecureRandom>,
    parameters: MlDsaParameters,
}

impl MlDsaKeyPairGenerator {
    pub fn init(random: Box<dyn SecureRandom>, parameters: MlDsaParameters) -> Self {
        Self { random, parameters }
    }

    pub fn generate_key_pair(&self) -> Result<MlDsaKeyPair> {
        let mut engine = self.parameters.get_engine(Some(self.random.clone()))?;
        engine.generate_key_pair(&self.parameters)
    }
}

pub struct MlDsaSigner {
    priv_key: Option<MlDsaPrivateKeyParameters>,
    pub_key: Option<MlDsaPublicKeyParameters>,
    random: Option<Box<dyn SecureRandom>>,
}

impl MlDsaSigner {
    pub fn init(
        for_signing: bool,
        param: Box<dyn CipherParameters>,
        random: Option<Box<dyn SecureRandom>>,
    ) -> Result<Self> {
        if for_signing {
            let p: &MlDsaPrivateKeyParameters =
                match param.as_any().downcast_ref::<MlDsaPrivateKeyParameters>() {
                    Some(p) => p,
                    None => {
                        return Err(ParameterError(
                            "param can't be cast to MlDsaPrivateKeyParameters".to_string(),
                        ));
                    }
                };
            Ok(Self { priv_key: Some(MlDsaPrivateKeyParameters::init(p)), pub_key: None, random })
        } else {
            let p: &MlDsaPublicKeyParameters =
                match param.as_any().downcast_ref::<MlDsaPublicKeyParameters>() {
                    Some(p) => p,
                    None => {
                        return Err(ParameterError(
                            "param can't be cast to MlDsaPublicKeyParameters".to_string(),
                        ));
                    }
                };
            Ok(Self { priv_key: None, pub_key: Some(MlDsaPublicKeyParameters::init(p)), random })
        }
    }

    pub fn generate_signature(&self, message: &[u8]) -> Result<Vec<u8>> {
        let param = match &self.priv_key {
            Some(p) => p,
            None => return Err(InvalidOperationError("no private key available".to_string())),
        };
        let mut engine = param.m_parameters.get_engine(self.random.clone())?;
        let mut sig = vec![0u8; engine.crypto_bytes];
        engine.sign(
            sig.as_mut_slice(),
            message,
            &param.m_rho,
            &param.m_k,
            &param.m_tr,
            &param.m_t0,
            &param.m_s1,
            &param.m_s2,
        )?;
        Ok(sig)
    }

    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let param = match &self.pub_key {
            Some(p) => p,
            None => return Err(InvalidOperationError("no public key available".to_string())),
        };
        let mut engine = param.m_parameters.get_engine(self.random.clone())?;
        engine.sign_open(message, signature, &param.m_rho, &param.m_t1)
    }
}

impl MlDsaEngine {
    // pub(crate) fn new(mode: i32, random: Option<Box<dyn SecureRandom>>) -> Result<Self> {
    // todo -- Option<&impl RNG> is actually better than what I curretly have in the KeyMaterial class ... maybe?
    // todo --- or do I want to copy that pattern and have a new_from_rng() ?
    pub(crate) fn new(mode: i32, rng: Option<&impl RNG>) -> Self {
        let k;
        let l;
        let eta;
        let tau;
        let beta;
        let gamma1;
        let gamma2;
        let omega;
        let c_tilde;

        let poly_z_packed_bytes;
        let poly_w1_packed_bytes;
        let poly_eta_packed_bytes;

        let poly_uniform_gamma1_n_bytes;
        // let symmetric = Symmetric::new();
        let _random = random;

        match mode {
            2 => {
                k = 4;
                l = 4;
                eta = 2;
                tau = 39;
                beta = 78;
                gamma1 = 1 << 17;
                gamma2 = (Q - 1) / 88;
                omega = 80;
                poly_z_packed_bytes = 576;
                poly_w1_packed_bytes = 192;
                poly_eta_packed_bytes = 96;
                c_tilde = 32;
            }
            3 => {
                k = 6;
                l = 5;
                eta = 4;
                tau = 49;
                beta = 196;
                gamma1 = 1 << 19;
                gamma2 = (Q - 1) / 32;
                omega = 55;
                poly_z_packed_bytes = 640;
                poly_w1_packed_bytes = 128;
                poly_eta_packed_bytes = 128;
                c_tilde = 48;
            }
            5 => {
                k = 8;
                l = 7;
                eta = 2;
                tau = 60;
                beta = 120;
                gamma1 = 1 << 19;
                gamma2 = (Q - 1) / 32;
                omega = 75;
                poly_z_packed_bytes = 640;
                poly_w1_packed_bytes = 128;
                poly_eta_packed_bytes = 96;
                c_tilde = 64;
            }
            _ => {
                return Err(ParameterError(
                    "The mode {mode} is not supported by ML-DSA!".to_string(),
                ));
            }
        }
        let poly_vec_h_packed_bytes = omega as usize + k;
        let crypto_public_key_bytes = SEED_BYTES + k * POLY_T1PACKED_BYTES;
        let crypto_secret_key_bytes = 3 * SEED_BYTES
            + l * poly_eta_packed_bytes
            + k * poly_eta_packed_bytes
            + k * POLY_T0PACKED_BYTES;
        let crypto_bytes = c_tilde + l * poly_z_packed_bytes + poly_vec_h_packed_bytes;

        if gamma1 == (1 << 17) {
            poly_uniform_gamma1_n_bytes = 576usize.div_ceil(symmetric.stream_256_block_bytes);
        } else if gamma1 == (1 << 19) {
            poly_uniform_gamma1_n_bytes = 640usize.div_ceil(symmetric.stream_256_block_bytes);
        } else {
            return Err(ParameterError("Wrong ML-DSA Gamma1!".to_string()));
        }
        Ok(Self {
            mode,
            k,
            l,
            eta,
            tau,
            beta,
            gamma1,
            gamma2,
            omega,
            c_tilde,
            poly_vec_h_packed_bytes,
            poly_z_packed_bytes,
            poly_w1_packed_bytes,
            poly_eta_packed_bytes,
            crypto_public_key_bytes,
            crypto_secret_key_bytes,
            crypto_bytes,
            poly_uniform_gamma1_n_bytes,
            symmetric,
            _random,
        })
    }

    pub(crate) fn generate_key_pair(
        &mut self,
        parameters: &MlDsaParameters,
    ) -> Result<MlDsaKeyPair> {
        let mut seed_buf = [0u8; SEED_BYTES];
        let mut buf = [0u8; 2 * SEED_BYTES + CRH_BYTES];
        let mut rho_prime = [0u8; CRH_BYTES];
        let mut tr = [0u8; TR_BYTES];
        let mut rho = [0u8; SEED_BYTES];
        let mut key = [0u8; SEED_BYTES];
        let size = self.l * self.poly_eta_packed_bytes;
        let mut s1_ = vec![0u8; size];
        let size = self.k * self.poly_eta_packed_bytes;
        let mut s2_ = vec![0u8; size];
        let size = self.k * POLY_T0PACKED_BYTES;
        let mut t0_ = vec![0u8; size];

        let mut matrix: PolyVecMatrix = PolyVecMatrix::new(self);
        let mut s1: PolyVecL = PolyVecL::new(self);
        let mut s1_hat: PolyVecL = PolyVecL::new(self);
        let mut s2: PolyVecK = PolyVecK::new(self);
        let mut t1: PolyVecK = PolyVecK::new(self);
        let mut t0: PolyVecK = PolyVecK::new(self);

        match &mut self._random {
            Some(rnd) => {
                rnd.next_bytes(&mut seed_buf);
            }
            None => return Err(InvalidOperationError("need RNG for key generation".to_string())),
        }

        let mut shake256digest: SHAKE = SHAKE::new(256);
        shake256digest.update_bytes(&seed_buf);
        shake256digest.output_final(&mut buf);

        rho.copy_from_slice(&buf[..SEED_BYTES]);
        rho_prime.copy_from_slice(&buf[SEED_BYTES..SEED_BYTES + CRH_BYTES]);
        key.copy_from_slice(&buf[SEED_BYTES + CRH_BYTES..]);

        matrix.expand_matrix(&rho);

        s1.uniform_eta(&rho_prime, 0)?;
        s2.uniform_eta(&rho_prime, self.l as u16)?;

        s1.copy_poly_vec_l(&mut s1_hat);
        s1_hat.ntt();

        matrix.pointwise_montgomery(&mut t1, &s1_hat);

        t1.reduce();
        t1.inverse_ntt_to_mont();

        t1.add_poly_vec_k(&s2);
        t1.conditional_add_q();
        t1.power_2_round(&mut t0);

        let mut enc_t1 = vec![0u8; self.crypto_public_key_bytes - SEED_BYTES];
        encodings::pack_public_key(&t1, self, enc_t1.as_mut_slice());

        shake256digest.update_bytes(&rho);
        shake256digest.update_bytes(&enc_t1);
        shake256digest.do_final(&mut tr);

        encodings::pack_secret_key(
            &t0,
            &s1,
            &s2,
            self,
            t0_.as_mut_slice(),
            s1_.as_mut_slice(),
            s2_.as_mut_slice(),
        )?;

        let pub_key: MlDsaPublicKeyParameters = MlDsaPublicKeyParameters {
            m_parameters: *parameters,
            m_rho: Vec::from(rho),
            m_t1: enc_t1.clone(),
        };
        let priv_key = MlDsaPrivateKeyParameters {
            m_parameters: *parameters,
            m_rho: Vec::from(rho),
            m_k: Vec::from(key),
            m_tr: Vec::from(tr),
            m_s1: s1_,
            m_s2: s2_,
            m_t0: t0_,
            m_t1: enc_t1,
        };
        Ok(MlDsaKeyPair { public: pub_key, private: priv_key })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn sign_signature(
        &mut self,
        sig: &mut [u8],
        msg: &[u8],
        rho: &[u8],
        key: &[u8],
        tr: &[u8],
        t0_enc: &[u8],
        s1_enc: &[u8],
        s2_enc: &[u8],
    ) -> Result<()> {
        let mut n: i32;
        let mut mu = [0u8; CRH_BYTES];
        let mut rho_prime = [0u8; CRH_BYTES];
        let mut key_mu = [0u8; SEED_BYTES + RND_BYTES + CRH_BYTES];
        let rnd = [0u8; RND_BYTES];
        let mut nonce: u16 = 0;

        let mut matrix: PolyVecMatrix = PolyVecMatrix::new(self);
        let mut s1: PolyVecL = PolyVecL::new(self);
        let mut y: PolyVecL = PolyVecL::new(self);
        let mut z: PolyVecL = PolyVecL::new(self);
        let mut t0: PolyVecK = PolyVecK::new(self);
        let mut s2: PolyVecK = PolyVecK::new(self);
        let mut w1: PolyVecK = PolyVecK::new(self);
        let mut w0: PolyVecK = PolyVecK::new(self);
        let mut h: PolyVecK = PolyVecK::new(self);
        let mut cp: Polynomial = Polynomial::new(self);

        encodings::unpack_secret_key(&mut t0, &mut s1, &mut s2, self, t0_enc, s1_enc, s2_enc);

        let mut shake256digest: SHAKE = SHAKE::new(256);
        shake256digest.update_bytes(tr);
        shake256digest.update_bytes(msg);
        shake256digest.output_final(&mut mu);

        if let Some(random) = &mut self._random {
            random.next_bytes(&mut rho_prime);
        }

        let len: usize = min(key.len(), SEED_BYTES + RND_BYTES + CRH_BYTES);
        key_mu[..len].copy_from_slice(&key[..len]);
        key_mu[SEED_BYTES..SEED_BYTES + RND_BYTES].copy_from_slice(&rnd);
        key_mu[SEED_BYTES + RND_BYTES..].copy_from_slice(&mu);
        shake256digest.update_bytes(&key_mu);
        shake256digest.output_final(&mut rho_prime);

        matrix.expand_matrix(rho);

        s1.ntt();
        s2.ntt();
        t0.ntt();

        'rej: loop {
            y.uniform_gamma1(&rho_prime, nonce)?;
            nonce += 1;
            y.copy_poly_vec_l(&mut z);
            z.ntt();

            matrix.pointwise_montgomery(&mut w1, &z);

            w1.reduce();
            w1.inverse_ntt_to_mont();

            w1.conditional_add_q();
            w1.decompose(&mut w0)?;

            w1.pack_w1(sig);

            shake256digest.update_bytes(&mu);
            shake256digest.update_bytes(&sig[..self.k * self.poly_w1_packed_bytes]);
            shake256digest.output_final(&mut sig[..self.c_tilde]);

            cp.challenge(sig); // use only first SeedBytes of sig
            cp.poly_ntt();

            z.pointwise_poly_montgomery(&cp, &s1);
            z.inverse_ntt_to_mont();
            z.add_poly_vec_l(&y);
            z.reduce();
            if z.check_norm(self.gamma1 - self.beta) {
                continue 'rej;
            }

            h.pointwise_poly_montgomery(&cp, &s2);
            h.inverse_ntt_to_mont();

            w0.subtract_poly_vec_k(&h);
            w0.reduce();
            if w0.check_norm(self.gamma2 - self.beta) {
                continue 'rej;
            }

            h.pointwise_poly_montgomery(&cp, &t0);
            h.inverse_ntt_to_mont();
            h.reduce();
            if h.check_norm(self.gamma2) {
                continue 'rej;
            }

            w0.add_poly_vec_k(&h);
            w0.conditional_add_q();

            n = h.make_hint(&w0, &w1);
            if n > self.omega {
                continue 'rej;
            }

            // c is already written to first bytes in sig (see Algorithm 20 https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.ipd.pdf)
            encodings::pack_signature(sig, &z, &h, self)?;
            return Ok(());
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn sign(
        &mut self,
        sig: &mut [u8],
        msg: &[u8],
        rho: &[u8],
        key: &[u8],
        tr: &[u8],
        t0: &[u8],
        s1: &[u8],
        s2: &[u8],
    ) -> Result<()> {
        self.sign_signature(sig, msg, rho, key, tr, t0, s1, s2)
    }

    pub(crate) fn sign_verify(
        &mut self,
        sig: &[u8],
        msg: &[u8],
        rho: &[u8],
        enc_t1: &[u8],
    ) -> Result<bool> {
        let mut buf = vec![0u8; self.k * self.poly_w1_packed_bytes];
        let mut mu = [0u8; CRH_BYTES];
        let mut c = vec![0u8; self.c_tilde];
        let mut c2 = vec![0u8; self.c_tilde];

        let mut cp: Polynomial = Polynomial::new(self);
        let mut matrix: PolyVecMatrix = PolyVecMatrix::new(self);
        let mut z: PolyVecL = PolyVecL::new(self);
        let mut t1: PolyVecK = PolyVecK::new(self);
        let mut w1: PolyVecK = PolyVecK::new(self);
        let mut h: PolyVecK = PolyVecK::new(self);

        if sig.len() != self.crypto_bytes {
            return Ok(false);
        }

        encodings::unpack_public_key(&mut t1, self, enc_t1);

        if !encodings::unpack_signature(&mut z, &mut h, sig, self)? {
            return Ok(false);
        }
        c.copy_from_slice(&sig[..self.c_tilde]);

        if z.check_norm(self.gamma1 - self.beta) {
            return Ok(false);
        }

        let mut shake256digest: SHAKE = SHAKE::new(256);
        shake256digest.update_bytes(rho);
        shake256digest.update_bytes(enc_t1);
        shake256digest.output_final(&mut mu[..TR_BYTES]);

        shake256digest.update_bytes(&mu[..TR_BYTES]);
        shake256digest.update_bytes(msg);
        shake256digest.do_final(&mut mu);

        cp.challenge(&c);

        matrix.expand_matrix(rho);

        z.ntt();
        matrix.pointwise_montgomery(&mut w1, &z);

        cp.poly_ntt();

        t1.shift_left();
        t1.ntt();
        t1.pointwise_poly_montgomery(&cp, &t1.clone());

        w1.subtract_poly_vec_k(&t1);
        w1.reduce();
        w1.inverse_ntt_to_mont();

        w1.conditional_add_q();
        w1.use_hint(&w1.clone(), &h)?;

        w1.pack_w1(&mut buf);

        shake256digest.update_bytes(&mu);
        shake256digest.update_bytes(&buf);
        shake256digest.output_final(&mut c2);

        Ok(c2.eq(&c))
    }

    pub(crate) fn sign_open(
        &mut self,
        msg: &[u8],
        sig: &[u8],
        rho: &[u8],
        t1: &[u8],
    ) -> Result<bool> {
        self.sign_verify(sig, msg, rho, t1)
    }
}
