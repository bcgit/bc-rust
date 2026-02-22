//! Represents a polynomial over the ML-DSA ring.

use bouncycastle_core_interface::traits::XOF;
use crate::{mldsa, ntt, poly_vec_l::PolyVecL, reduce, rounding, MLDSAParams, MldsaSize, D, POLY_T1PACKED_LEN, Q, SEED_LEN};
use bouncycastle_sha3::{SHAKE128, SHAKE256};
// use bouncycastle_utils::{Error::ParameterError, Result};

use crate::N;

const STREAM_128_BLOCK_LEN: usize = 168;
const STREAM_256_BLOCK_LEN: usize = 136;

#[derive(Clone)]
pub(crate) struct Polynomial<PARAMS: MLDSAParams> {
    _params: std::marker::PhantomData<PARAMS>,
    pub coeffs: [i32; N],
    // engine: MlDsaEngine,
    // poly_uniform_n_blocks: usize,
    // symmetric: Symmetric, // todo what's this used for?
}

impl<PARAMS: MLDSAParams> Polynomial<PARAMS> {
    pub(crate) fn new(/*engine: &MlDsaEngine*/) -> Self {
        Self {
            coeffs: [0_i32; N],
            // engine: engine.clone(),
            // symmetric: engine.symmetric.clone(),
            // poly_uniform_n_blocks: 768usize.div_ceil(engine.symmetric.stream_128_block_bytes), // todo -- can this be moved to a params const?
        }
    }

    fn stream_init(digest: &mut impl XOF, seed: &[u8], nonce: u16) {
        // digest.keccak.reset();
        let mut tmp: [u8; 2] = [0; 2];
        tmp[0] = nonce as u8;
        tmp[1] = (nonce >> 8) as u8;

        digest.absorb(seed);
        digest.absorb(&tmp);
    }

    pub(crate) fn uniform_blocks(&mut self, seed: &[u8], nonce: u16) {
        let mut off;
        // let mut BUFLEN = self.poly_uniform_n_blocks * self.symmetric.stream_128_block_bytes;
        const BUFLEN: usize = 768usize.div_ceil(STREAM_128_BLOCK_LEN) * STREAM_128_BLOCK_LEN;
        let mut buf: Vec<u8> = vec![0; BUFLEN];
        self.symmetric.stream128_init(seed, nonce);
        self.symmetric.stream128_squeeze_blocks(buf.as_mut_slice(), 0, BUFLEN);
        let mut ctr = Self::reject_uniform(&mut self.coeffs, 0, N, &buf, BUFLEN);
        while ctr < N {
            off = BUFLEN % 3;
            for i in 0..off {
                buf[i] = buf[BUFLEN - off + i];
            }
            self.symmetric.stream128_squeeze_blocks(
                buf.as_mut_slice(),
                off,
                self.symmetric.stream_128_block_bytes,
            );
            BUFLEN = self.symmetric.stream_128_block_bytes + off;
            ctr += Self::reject_uniform(&mut self.coeffs, ctr, N - ctr, &buf, BUFLEN);
        }
    }

    fn reject_uniform(
        coeffs: &mut [i32],
        off: usize,
        len: usize,
        buf: &[u8],
        buflen: usize,
    ) -> usize {
        let mut ctr = 0;
        let mut pos = 0;
        let mut t: u32;
        while ctr < len && pos + 3 <= buflen {
            t = buf[pos] as u32;
            pos += 1;
            t |= (buf[pos] as u32) << 8;
            pos += 1;
            t |= (buf[pos] as u32) << 16;
            pos += 1;
            t &= 0x7FFFFF;

            if t < Q as u32 {
                coeffs[off + ctr] = t as i32;
                ctr += 1;
            }
        }
        ctr
    }

    pub(crate) fn uniform_eta(&mut self, seed: &[u8], nonce: u16) {
        let poly_uniform_eta_n_blocks;
        let eta = PARAMS::ETA;
        // if self.engine.eta == 2 {
        match PARAMS::ALG {
            MldsaSize::MlDsa44 | MldsaSize::MlDsa87 => {
                poly_uniform_eta_n_blocks = 136usize.div_ceil(self.symmetric.stream_256_block_bytes); // todo compute statically?
            },
            // } else if self.engine.eta == 4 {
            MldsaSize::MlDsa65 => {
                poly_uniform_eta_n_blocks = 227usize.div_ceil(self.symmetric.stream_256_block_bytes);
            },
            // } else {
            //     return Err(ParameterError("Wrong ML-DSA Eta!".to_string()));
            // }
        }

        let buflen = poly_uniform_eta_n_blocks * self.symmetric.stream_256_block_bytes;
        let mut buf: Vec<u8> = vec![0; buflen];

        self.symmetric.stream256_init(seed, nonce);
        self.symmetric.stream256_squeeze_blocks(buf.as_mut_slice(), 0, buflen);
        let mut ctr = Self::reject_eta(&mut self.coeffs, 0, N, &buf, buflen, eta);

        while ctr < N {
            self.symmetric.stream256_squeeze_blocks(
                buf.as_mut_slice(),
                0,
                self.symmetric.stream_256_block_bytes,
            );
            ctr += Self::reject_eta(&mut self.coeffs, ctr, N - ctr, &buf, buflen, eta);
        }
        // Ok(())
    }

    fn reject_eta(
        coeffs: &mut [i32],
        off: usize,
        len: usize,
        buf: &[u8],
        buflen: usize,
        eta: i32,
    ) -> usize {
        let mut ctr = 0;
        let mut pos: usize = 0;
        let mut t0: u32;
        let mut t1: u32;

        while ctr < len && pos < buflen {
            t0 = (buf[pos] as u32) & 0x0F;
            t1 = (buf[pos] as u32) >> 4;
            pos += 1;
            if eta == 2 {
                if t0 < 15 {
                    t0 = t0 - ((205 * t0) >> 10) * 5;
                    coeffs[off + ctr] = 2 - t0 as i32;
                    ctr += 1;
                }
                if t1 < 15 && ctr < len {
                    t1 = t1 - ((205 * t1) >> 10) * 5;
                    coeffs[off + ctr] = 2 - t1 as i32;
                    ctr += 1;
                }
            } else if eta == 4 {
                if t0 < 9 {
                    coeffs[off + ctr] = 4 - t0 as i32;
                    ctr += 1;
                }
                if t1 < 9 && ctr < len {
                    coeffs[off + ctr] = 4 - t1 as i32;
                    ctr += 1;
                }
            }
        }
        ctr
    }

    pub(crate) fn pointwise_montgomery(&mut self, v: &Self, w: &Self) {
        for i in 0..N {
            self.coeffs[i] = reduce::montgomery_reduce((v.coeffs[i] as i64) * (w.coeffs[i] as i64));
        }
    }

    pub(crate) fn pointwise_account_montgomery(&mut self, u: &PolyVecL, v: &PolyVecL) {
        let mut t: Polynomial<PARAMS> = Polynomial::<PARAMS>::new();
        self.pointwise_montgomery(&u.vec[0], &v.vec[0]);

        for i in 1..PARAMS::L {
            t.pointwise_montgomery(&u.vec[i], &v.vec[i]);
            self.add_poly(&t);
        }
    }

    pub(crate) fn add_poly(&mut self, a: &Self) {
        for i in 0..N {
            self.coeffs[i] += a.coeffs[i];
        }
    }

    pub(crate) fn subtract_poly(&mut self, b: &Self) {
        for i in 0..N {
            self.coeffs[i] -= b.coeffs[i];
        }
    }

    pub(crate) fn reduce_poly(&mut self) {
        for x in self.coeffs.iter_mut() {
            *x = reduce::reduce32(*x);
        }
    }

    pub(crate) fn poly_ntt(&mut self) {
        ntt::ntt(&mut self.coeffs);
    }
    pub(crate) fn inverse_ntt_to_mont(&mut self) {
        ntt::inverse_ntt_to_mont(&mut self.coeffs);
    }

    pub(crate) fn conditional_add_q(&mut self) {
        for x in self.coeffs.iter_mut() {
            *x = reduce::conditional_add_q(*x);
        }
    }

    pub(crate) fn power_2_round(&mut self, a: &mut Self) {
        for i in 0..N {
            let power2round = rounding::power_2_round(self.coeffs[i]);
            self.coeffs[i] = power2round[0];
            a.coeffs[i] = power2round[1];
        }
    }

    pub(crate) fn poly_t0_pack(&self, r: &mut [u8], off: usize) {
        let mut t = [0; 8];
        for i in 0..N/8 {
            t[0] = (1 << (D - 1)) - self.coeffs[8 * i];
            t[1] = (1 << (D - 1)) - self.coeffs[8 * i + 1];
            t[2] = (1 << (D - 1)) - self.coeffs[8 * i + 2];
            t[3] = (1 << (D - 1)) - self.coeffs[8 * i + 3];
            t[4] = (1 << (D - 1)) - self.coeffs[8 * i + 4];
            t[5] = (1 << (D - 1)) - self.coeffs[8 * i + 5];
            t[6] = (1 << (D - 1)) - self.coeffs[8 * i + 6];
            t[7] = (1 << (D - 1)) - self.coeffs[8 * i + 7];

            r[off + 13 * i] = t[0] as u8;

            r[off + 13 * i + 1] = (t[0] >> 8) as u8;
            r[off + 13 * i + 1] |= (t[1] << 5) as u8;
            r[off + 13 * i + 2] = (t[1] >> 3) as u8;
            r[off + 13 * i + 3] = (t[1] >> 11) as u8;
            r[off + 13 * i + 3] |= (t[2] << 2) as u8;
            r[off + 13 * i + 4] = (t[2] >> 6) as u8;
            r[off + 13 * i + 4] |= (t[3] << 7) as u8;
            r[off + 13 * i + 5] = (t[3] >> 1) as u8;
            r[off + 13 * i + 6] = (t[3] >> 9) as u8;
            r[off + 13 * i + 6] |= (t[4] << 4) as u8;
            r[off + 13 * i + 7] = (t[4] >> 4) as u8;
            r[off + 13 * i + 8] = (t[4] >> 12) as u8;
            r[off + 13 * i + 8] |= (t[5] << 1) as u8;
            r[off + 13 * i + 9] = (t[5] >> 7) as u8;
            r[off + 13 * i + 9] |= (t[6] << 6) as u8;
            r[off + 13 * i + 10] = (t[6] >> 2) as u8;
            r[off + 13 * i + 11] = (t[6] >> 10) as u8;
            r[off + 13 * i + 11] |= (t[7] << 3) as u8;
            r[off + 13 * i + 12] = (t[7] >> 5) as u8;
        }
    }

    pub(crate) fn poly_t0_unpack(&mut self, a: &[u8], off: usize) {
        for i in 0..N/8 {
            self.coeffs[8 * i] =
                ((a[off + 13 * i] as i32) | ((a[off + 13 * i + 1] as i32) << 8)) & 0x1FFF;
            self.coeffs[8 * i + 1] = ((((a[off + 13 * i + 1] as i32) >> 5)
                | (a[off + 13 * i + 2] as i32) << 3)
                | ((a[off + 13 * i + 3] as i32) << 11))
                & 0x1FFF;
            self.coeffs[8 * i + 2] = (((a[off + 13 * i + 3] as i32) >> 2)
                | ((a[off + 13 * i + 4] as i32) << 6))
                & 0x1FFF;
            self.coeffs[8 * i + 3] = ((((a[off + 13 * i + 4] as i32) >> 7)
                | (a[off + 13 * i + 5] as i32) << 1)
                | ((a[off + 13 * i + 6] as i32) << 9))
                & 0x1FFF;
            self.coeffs[8 * i + 4] = ((((a[off + 13 * i + 6] as i32) >> 4)
                | (a[off + 13 * i + 7] as i32) << 4)
                | ((a[off + 13 * i + 8] as i32) << 12))
                & 0x1FFF;
            self.coeffs[8 * i + 5] = (((a[off + 13 * i + 8] as i32) >> 1)
                | ((a[off + 13 * i + 9] as i32) << 7))
                & 0x1FFF;
            self.coeffs[8 * i + 6] = ((((a[off + 13 * i + 9] as i32) >> 6)
                | (a[off + 13 * i + 10] as i32) << 2)
                | ((a[off + 13 * i + 11] as i32) << 10))
                & 0x1FFF;
            self.coeffs[8 * i + 7] = (((a[off + 13 * i + 11] as i32) >> 3)
                | ((a[off + 13 * i + 12] as i32) << 5))
                & 0x1FFF;

            self.coeffs[8 * i] = (1 << (D - 1)) - self.coeffs[8 * i];
            self.coeffs[8 * i + 1] = (1 << (D - 1)) - self.coeffs[8 * i + 1];
            self.coeffs[8 * i + 2] = (1 << (D - 1)) - self.coeffs[8 * i + 2];
            self.coeffs[8 * i + 3] = (1 << (D - 1)) - self.coeffs[8 * i + 3];
            self.coeffs[8 * i + 4] = (1 << (D - 1)) - self.coeffs[8 * i + 4];
            self.coeffs[8 * i + 5] = (1 << (D - 1)) - self.coeffs[8 * i + 5];
            self.coeffs[8 * i + 6] = (1 << (D - 1)) - self.coeffs[8 * i + 6];
            self.coeffs[8 * i + 7] = (1 << (D - 1)) - self.coeffs[8 * i + 7];
        }
    }

    pub(crate) fn poly_t1_pack(&self) -> [u8; POLY_T1PACKED_LEN] {
        let mut output = [0u8; POLY_T1PACKED_LEN];
        for i in 0..(N / 4) {
            output[5 * i] = self.coeffs[4 * i] as u8;
            output[5 * i + 1] = ((self.coeffs[4 * i] >> 8) | (self.coeffs[4 * i + 1] << 2)) as u8;
            output[5 * i + 2] =
                ((self.coeffs[4 * i + 1] >> 6) | (self.coeffs[4 * i + 2] << 4)) as u8;
            output[5 * i + 3] =
                ((self.coeffs[4 * i + 2] >> 4) | (self.coeffs[4 * i + 3] << 6)) as u8;
            output[5 * i + 4] = (self.coeffs[4 * i + 3] >> 2) as u8;
        }
        output
    }

    pub(crate) fn poly_t1_unpack(&mut self, a: &[u8]) {
        for i in 0..N/4 {
            self.coeffs[4 * i] = ((a[5 * i] as i32) | ((a[5 * i + 1] as i32) << 8)) & 0x3FF;
            self.coeffs[4 * i + 1] =
                (((a[5 * i + 1] as i32) >> 2) | ((a[5 * i + 2] as i32) << 6)) & 0x3FF;
            self.coeffs[4 * i + 2] =
                (((a[5 * i + 2] as i32) >> 4) | ((a[5 * i + 3] as i32) << 4)) & 0x3FF;
            self.coeffs[4 * i + 3] =
                (((a[5 * i + 3] as i32) >> 6) | ((a[5 * i + 4] as i32) << 2)) & 0x3FF;
        }
    }

    pub(crate) fn poly_eta_pack(&self, r: &mut [u8], off: usize) {
        let eta = PARAMS::ETA;
        let mut t: [u8; 8] = [0; 8];
        // if self.engine.eta == 2 {
        // todo could probably macro this
        match PARAMS::ALG {
            MldsaSize::MlDsa44 | MldsaSize::MlDsa87 => {
                for i in 0..N/8 {
                    t[0] = (eta - self.coeffs[8 * i]) as u8;
                    t[1] = (eta - self.coeffs[8 * i + 1]) as u8;
                    t[2] = (eta - self.coeffs[8 * i + 2]) as u8;
                    t[3] = (eta - self.coeffs[8 * i + 3]) as u8;
                    t[4] = (eta - self.coeffs[8 * i + 4]) as u8;
                    t[5] = (eta - self.coeffs[8 * i + 5]) as u8;
                    t[6] = (eta - self.coeffs[8 * i + 6]) as u8;
                    t[7] = (eta - self.coeffs[8 * i + 7]) as u8;

                    r[off + 3 * i] = t[0] | (t[1] << 3) | (t[2] << 6);
                    r[off + 3 * i + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
                    r[off + 3 * i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
                }
            },
            // } else if self.engine.eta == 4 {
            MldsaSize::MlDsa65 => {
                for i in 0..N/2 {
                    t[0] = (eta - self.coeffs[2 * i]) as u8;
                    t[1] = (eta - self.coeffs[2 * i + 1]) as u8;
                    r[off + i] = t[0] | t[1] << 4;
                }
            },
        }
        // } else {
        //     return Err(ParameterError("Eta needs to be 2 or 4!".to_string()));
        // }
        Ok(())
    }

    pub(crate) fn poly_eta_unpack(&mut self, a: &[u8], off: usize) {
        let eta = PARAMS::ETA;
        // if eta == 2 {
        // todo could probably macro this
        match PARAMS::ALG {
            MldsaSize::MlDsa44 | MldsaSize::MlDsa87 => {
                for i in 0..N / 8 {
                    self.coeffs[8 * i] = (a[off + 3 * i] & 7) as i32;
                    self.coeffs[8 * i + 1] = ((a[off + 3 * i] >> 3) & 7) as i32;
                    self.coeffs[8 * i + 2] =
                        ((a[off + 3 * i] >> 6) | (a[off + 3 * i + 1] << 2) & 7) as i32;
                    self.coeffs[8 * i + 3] = ((a[off + 3 * i + 1] >> 1) & 7) as i32;
                    self.coeffs[8 * i + 4] = ((a[off + 3 * i + 1] >> 4) & 7) as i32;
                    self.coeffs[8 * i + 5] =
                        ((a[off + 3 * i + 1] >> 7) | (a[off + 3 * i + 2] << 1) & 7) as i32;
                    self.coeffs[8 * i + 6] = ((a[off + 3 * i + 2] >> 2) & 7) as i32;
                    self.coeffs[8 * i + 7] = ((a[off + 3 * i + 2] >> 5) & 7) as i32;

                    self.coeffs[8 * i] = eta - self.coeffs[8 * i];
                    self.coeffs[8 * i + 1] = eta - self.coeffs[8 * i + 1];
                    self.coeffs[8 * i + 2] = eta - self.coeffs[8 * i + 2];
                    self.coeffs[8 * i + 3] = eta - self.coeffs[8 * i + 3];
                    self.coeffs[8 * i + 4] = eta - self.coeffs[8 * i + 4];
                    self.coeffs[8 * i + 5] = eta - self.coeffs[8 * i + 5];
                    self.coeffs[8 * i + 6] = eta - self.coeffs[8 * i + 6];
                    self.coeffs[8 * i + 7] = eta - self.coeffs[8 * i + 7];
                }
            },
        // } else if eta == 4 {
            MldsaSize::MlDsa65 => {
                for i in 0..N / 2 {
                    self.coeffs[2 * i] = (a[off + i] & 0x0F) as i32;
                    self.coeffs[2 * i + 1] = (a[off + i] >> 4) as i32;

                    self.coeffs[2 * i] = eta - self.coeffs[2 * i];
                    self.coeffs[2 * i + 1] = eta - self.coeffs[2 * i + 1];
                }
            },
        }
    }

    pub(crate) fn uniform_gamma1(&mut self, seed: &[u8], nonce: u16) {
        let buflen =
            // self.engine.poly_uniform_gamma1_n_bytes * self.symmetric.stream_256_block_bytes;
            PARAMS::POLY_UNIFORM_GAMMA1_N_LEN * self.symmetric.stream_256_block_bytes;
        let mut buf: Vec<u8> = vec![0; buflen]; // todo -- this has a definite size, so shouldn't need a Vec. Maybe needs a macro?
        self.symmetric.stream256_init(seed, nonce);
        self.symmetric.stream256_squeeze_blocks(buf.as_mut_slice(), 0, buflen);
        self.unpack_z(&buf)
    }

    pub(crate) fn pack_z(&self, r: &mut [u8], off: usize) {
        let mut t: [u32; 4] = [0; 4];
        // if self.engine.gamma1 == (1 << 17) {
        // todo could probably macro this
        match PARAMS::ALG {
            MldsaSize::MlDsa44 => {
                for i in 0..N / 4 {
                    t[0] = (PARAMS::GAMMA1 - self.coeffs[4 * i]) as u32;
                    t[1] = (PARAMS::GAMMA1 - self.coeffs[4 * i + 1]) as u32;
                    t[2] = (PARAMS::GAMMA1 - self.coeffs[4 * i + 2]) as u32;
                    t[3] = (PARAMS::GAMMA1 - self.coeffs[4 * i + 3]) as u32;

                    r[off + 9 * i] = t[0] as u8;
                    r[off + 9 * i + 1] = (t[0] >> 8) as u8;
                    r[off + 9 * i + 2] = ((t[0] >> 16) | (t[1] << 2)) as u8;
                    r[off + 9 * i + 3] = (t[1] >> 6) as u8;
                    r[off + 9 * i + 4] = ((t[1] >> 14) | (t[2] << 4)) as u8;
                    r[off + 9 * i + 5] = (t[2] >> 4) as u8;
                    r[off + 9 * i + 6] = ((t[2] >> 12) | (t[3] << 6)) as u8;
                    r[off + 9 * i + 7] = (t[3] >> 2) as u8;
                    r[off + 9 * i + 8] = (t[3] >> 10) as u8;
                }
            },
            // } else if self.engine.gamma1 == (1 << 19) {
            MldsaSize::MlDsa65 | MldsaSize::MlDsa87 => {
                for i in 0..N / 2 {
                    t[0] = (PARAMS::GAMMA1 - self.coeffs[2 * i]) as u32;
                    t[1] = (PARAMS::GAMMA1 - self.coeffs[2 * i + 1]) as u32;

                    r[off + 5 * i] = t[0] as u8;
                    r[off + 5 * i + 1] = (t[0] >> 8) as u8;
                    r[off + 5 * i + 2] = ((t[0] >> 16) | (t[1] << 4)) as u8;
                    r[off + 5 * i + 3] = (t[1] >> 4) as u8;
                    r[off + 5 * i + 4] = (t[1] >> 12) as u8;
                }
            },
        }
        // } else {
        //     return Err(ParameterError("Wrong ML-DSA Gamma1!".to_string()));
        // }
        // Ok(())
    }

    pub(crate) fn unpack_z(&mut self, a: &[u8]) { // todo -- does this have a definite size?
        // if self.engine.gamma1 == (1 << 17) {
        // todo could probably macro this
        match PARAMS::ALG {
            MldsaSize::MlDsa44 => {
                for i in 0..(N / 4) {
                    self.coeffs[4 * i] = (((a[9 * i] as i32) | ((a[9 * i + 1] as i32) << 8))
                        | ((a[9 * i + 2] as i32) << 16))
                        & 0x3FFFF;
                    self.coeffs[4 * i + 1] = ((((a[9 * i + 2] as i32) >> 2)
                        | ((a[9 * i + 3] as i32) << 6))
                        | ((a[9 * i + 4] as i32) << 14))
                        & 0x3FFFF;
                    self.coeffs[4 * i + 2] = ((((a[9 * i + 4] as i32) >> 4)
                        | ((a[9 * i + 5] as i32) << 4))
                        | ((a[9 * i + 6] as i32) << 12))
                        & 0x3FFFF;
                    self.coeffs[4 * i + 3] = ((((a[9 * i + 6] as i32) >> 6)
                        | ((a[9 * i + 7] as i32) << 2))
                        | ((a[9 * i + 8] as i32) << 10))
                        & 0x3FFFF;

                    self.coeffs[4 * i] = PARAMS::GAMMA1 - self.coeffs[4 * i];
                    self.coeffs[4 * i + 1] = PARAMS::GAMMA1 - self.coeffs[4 * i + 1];
                    self.coeffs[4 * i + 2] = PARAMS::GAMMA1 - self.coeffs[4 * i + 2];
                    self.coeffs[4 * i + 3] = PARAMS::GAMMA1 - self.coeffs[4 * i + 3];
                }
            },
        // } else if self.engine.gamma1 == (1 << 19) {
            MldsaSize::MlDsa65 | MldsaSize::MlDsa87 => {
                for i in 0..(N / 2) {
                    self.coeffs[2 * i] = (((a[5 * i] as i32) | ((a[5 * i + 1] as i32) << 8))
                        | ((a[5 * i + 2] as i32) << 16))
                        & 0xFFFFF;
                    self.coeffs[2 * i + 1] = ((((a[5 * i + 2] as i32) >> 4)
                        | ((a[5 * i + 3] as i32) << 4))
                        | ((a[5 * i + 4] as i32) << 12))
                        & 0xFFFFF;

                    self.coeffs[2 * i] = PARAMS::GAMMA1 - self.coeffs[2 * i];
                    self.coeffs[2 * i + 1] = PARAMS::GAMMA1 - self.coeffs[2 * i + 1];
                }
            },
        // } else {
        //     return Err(ParameterError("Wrong ML-DSA Gamma1!".to_string()));
        }
    }

    pub(crate) fn decompose(&mut self, a: &mut Self) -> Result<()> {
        for i in 0..N {
            let decomp = rounding::decompose(self.coeffs[i], PARAMS::GAMMA2)?;
            a.coeffs[i] = decomp[0];
            self.coeffs[i] = decomp[1];
        }
        Ok(())
    }

    pub(crate) fn pack_w1(&self, r: &mut [u8], off: usize) {
        // todo -- since this is switching on constants, why not actually switch on constants?
        // if PARAMS::GAMMA2 == (Q - 1) / 88 {
        // todo -- this seems like a perfect use for a macro
        match PARAMS::ALG {
            MldsaSize::MlDsa44 => {
                for i in 0..(N / 4) {
                    r[off + 3 * i] =
                        ((self.coeffs[4 * i]) as u8) | ((self.coeffs[4 * i + 1] << 6) as u8);
                    r[off + 3 * i + 1] =
                        ((self.coeffs[4 * i + 1] >> 2) as u8) | ((self.coeffs[4 * i + 2] << 4) as u8);
                    r[off + 3 * i + 2] =
                        ((self.coeffs[4 * i + 2] >> 4) as u8) | ((self.coeffs[4 * i + 3] << 2) as u8);
                }
            }, //else if PARAMS::GAMMA2 == (Q - 1) / 32 {
            MldsaSize::MlDsa65 | MldsaSize::MlDsa87 => {
                for i in 0..(N / 2) {
                    r[off + i] = ((self.coeffs[2 * i]) | (self.coeffs[2 * i + 1] << 4)) as u8;
                }
            }
        }
    }

    pub(crate) fn challenge(&mut self, seed: &[u8; 32]) {
        let mut buf = vec![0u8; self.symmetric.stream_256_block_bytes]; // todo -- what's that constant?
        // shake_digest_256.update_bytes(&seed[..SEED_LEN]);
        let mut shake256 = SHAKE256::new();

        // shake256.update_bytes(seed);
        // shake256.do_output(&mut buf);
        shake256.hash_xof_out(seed, &mut buf);

        let mut signs: u64 = 0;
        for (i, item) in buf.iter().enumerate().take(8) {
            signs |= (*item as u64) << (8 * i);
        }

        for i in 0 .. N {
            self.coeffs[i] = 0;
        }

        let mut pos = 8;
        let mut b;
        for i in (N - PARAMS::TAU as usize) .. N {
            do_while! {
                do {
                    if pos >= self.symmetric.stream_256_block_bytes {
                        shake_digest_256.do_output(buf.as_mut_slice());
                        pos = 0;
                    }
                    b = buf[pos] as usize;
                    pos += 1;
                } while b > i;
            }

            self.coeffs[i] = self.coeffs[b];
            self.coeffs[b] = (1u64.wrapping_sub(2 * (signs & 1))) as i32;
            signs >>= 1;
        }
    }

    pub(crate) fn check_norm(&self, b: i32) -> bool {
        if b > (Q - 1) / 8 {
            return true;
        }

        let mut t: i32;
        for x in self.coeffs.iter() {
            t = *x >> 31;
            t = *x - (t & (2 * *x));

            if t >= b {
                return true;
            }
        }
        false
    }

    pub(crate) fn poly_make_hint(&mut self, a0: &Self, a1: &Self) -> i32 {
        let mut s = 0;
        for i in 0..N {
            self.coeffs[i] = rounding::make_hint(a0.coeffs[i], a1.coeffs[i], &self.engine);
            s += self.coeffs[i];
        }
        s
    }

    pub(crate) fn poly_use_hint(&mut self, a: &Self, h: &Self) -> Result<()> {
        for i in 0..N {
            let x = rounding::use_hint(a.coeffs[i], h.coeffs[i], self.engine.gamma2)?;
            self.coeffs[i] = x;
        }
        Ok(())
    }

    pub(crate) fn shift_left(&mut self) {
        for x in self.coeffs.iter_mut() {
            *x <<= D;
        }
    }
}
