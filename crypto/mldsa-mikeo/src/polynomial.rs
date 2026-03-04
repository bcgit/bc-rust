//! Represents a polynomial over the ML-DSA ring.

use crate::{q, q_inv, MLDSA44Params, MLDSA65Params, MLDSAParams};
use crate::aux_functions::{high_bits, low_bits, make_hint};
use crate::N;

const STREAM_128_BLOCK_LEN: usize = 168;
const STREAM_256_BLOCK_LEN: usize = 136;


// pub(crate) type Polynomial = [i32; N];
#[derive(Clone)]
pub(crate) struct Polynomial(pub(crate) [i32; N]);

impl Polynomial {
    pub(crate) const fn new() -> Self {
        Self{ 0: [0i32; N] }
    }

    /// negates each entry
    pub(crate) fn neg(&mut self){
        for i in 0..N {
            self.0[i] = - self.0[i];
        }
    }
    
    
    /// Algorithm 44 AddNTT(𝑎, 𝑏)̂
    /// Computes the sum a + 𝑏 of two elements 𝑎, 𝑏 ∈ 𝑇𝑞.
    /// Note: result could be up to 2q.
    pub(crate) fn add_ntt(&mut self, w: &Self) {
        for i in 0..N {
            self.0[i] += w.0[i];
        }
    }

    pub(crate) fn sub(&mut self, w: &Self) {
        for i in 0..N {
            self.0[i] -= w.0[i];
        }
    }

    // todo: will anything use this?
    // /// Algorithm 45 MultiplyNTT(𝑎, 𝑏)̂
    // /// Computes the product 𝑎 ∘̂ 𝑏 of two elements 𝑎, 𝑏 ∈ 𝑇𝑞.
    // /// Input: 𝑎, 𝑏 ∈ 𝑇𝑞.
    // /// Output: 𝑐 ∈ 𝑇𝑞.
    // /// Multiply the coefficients in this polynomial by those in another polynomial and perform montgomery reduction.
    // /// Also called pointwise montgomery multiplication
    // pub(crate) fn multiply_ntt(&mut self, w: &Polynomial){
    //     for i in 0..N {
    //         self.0[i] = montgomery_reduce((self.0[i] as i64) * (w.0[i] as i64));
    //     }
    // }

    pub(crate) fn high_bits<const GAMMA2: i32>(&self) -> Self {
        let mut w = Self::new();
        for i in 0..N {
            w.0[i] = high_bits::<GAMMA2>(self.0[i]);
        }

        w
    }

    pub(crate) fn low_bits<const GAMMA2: i32>(&self) -> Self {
        let mut w = Self::new();
        for i in 0..N {
            w.0[i] = low_bits::<GAMMA2>(self.0[i]);
        }

        w
    }

    pub(crate) fn check_norm(&self, bound: i32) -> bool {
        // Fine that this is not constant-time because it is used in a rejection loop -- the early quit leads to rejection.
        // todo: convince myself that only the `false` path leads to valid signature output.
        if bound > (q - 1) / 8 {
            return true;
        }

        let mut t: i32;
        for x in self.0.iter() {
            t = *x >> 31;
            t = *x - (t & (2 * *x));

            if t >= bound {
                return true;
            }
        }
        false
    }

    /// Creates the hint vector, and also returns its hamming weight (ie the number of 1's).
    pub(crate) fn make_hint<const GAMMA2: i32>(&self, r: &Self) -> (Self, i32) {
        let mut out = Polynomial::new();
        let mut count = 0i32;
        for i in 0..N {
            // todo -- wait, what do you do with the bool?
            let x = make_hint::<GAMMA2>(self.0[i], r.0[i]);
            out.0[i] = x;
            count += x;
        }

        (out, count)
    }

    #[inline]
    pub(crate) fn w1_encode<const POLY_W1_PACKED_LEN: usize>(&self) -> [u8; POLY_W1_PACKED_LEN] {
        // todo -- optimize this to take a slice and write directly to it
        // todo -- debug_assert_eq!(buf.len(), POLY1_PACKED_LEN)
        //

        let mut r = [0u8; POLY_W1_PACKED_LEN];

        match POLY_W1_PACKED_LEN {
            MLDSA44Params::POLY_W1_PACKED_LEN => {
                for i in 0..N/4 {
                    r[3 * i] =
                        ((self.0[4 * i]) as u8) | ((self.0[4 * i + 1] << 6) as u8);
                    r[3 * i + 1] =
                        ((self.0[4 * i + 1] >> 2) as u8) | ((self.0[4 * i + 2] << 4) as u8);
                    r[3 * i + 2] =
                        ((self.0[4 * i + 2] >> 4) as u8) | ((self.0[4 * i + 3] << 2) as u8);
                }
            },
            // ML-DSA65 and 87 share a POLY_W1_PACKED_LEN value
            MLDSA65Params::POLY_W1_PACKED_LEN => {
                for i in 0..N/2 {
                    r[i] = ((self.0[2 * i]) | (self.0[2 * i + 1] << 4)) as u8;
                }
            },
            _ => { panic!("Invalid GAMMA2 value") }
        }

        r
    }
}

impl Drop for Polynomial {
    fn drop(&mut self) {
        self.0.fill(0i32);
    }
}

impl From<Polynomial> for [i32; N] {
    fn from(p: Polynomial) -> [i32; N] {
        p.0
    }
}


/// Algorithm 45 MultiplyNTT(𝑎, 𝑏)̂
/// Computes the product 𝑎 ∘̂ 𝑏 of two elements 𝑎, 𝑏 ∈ 𝑇𝑞.
/// Input: 𝑎, 𝑏 ∈ 𝑇𝑞.
/// Output: 𝑐 ∈ 𝑇𝑞.
/// Multiply the coefficients in this polynomial by those in another polynomial and perform montgomery reduction.
/// Also called pointwise montgomery multiplication
pub(crate) fn multiply_ntt(a: &Polynomial, b: &Polynomial) -> Polynomial {
    let mut out = Polynomial::new();
    for i in 0..N {
        out.0[i] = montgomery_reduce((a.0[i] as i64) * (b.0[i] as i64));
    }

    out
}

/// FIPS 204 Algorithm 49
/// As described in FIPS 204 Appendix A, montgomery reduction allows for efficient computation
/// of expressions of the form c = a * b (mod q).
/// The output is not necessarily less than q in absolute value, but it is less than 2q in absolute value
pub(crate) fn montgomery_reduce(a: i64) -> i32 {
    debug_assert!(a > - ((q as i64) <<31) && a < ((q as i64) <<31));

    // 2: 𝑡 ← ((𝑎 mod 2^32) ⋅ QINV) mod 2^32
    let t: i32 = (a as i32).wrapping_mul(q_inv);

    // 3: 𝑟 ← (𝑎 − 𝑡 ⋅ 𝑞)/2^32
    ((a - ((t as i64) * (q as i64))) >> 32) as i32

    // todo: openssl has a version of this with fewer operations.
    // todo: Once I have benchmarks, see if I can squeeze some more performance by copying?
    // todo: https://github.com/openssl/openssl/blob/3be12549113b955a19a2bde5eed9a0b1649e2168/crypto/ml_dsa/ml_dsa_ntt.c#L93
    // 2026-02-26: I tried this, but couldn't get it working -- needed to find the openssl impl of reduce_once()
}


pub(crate) fn reduce_poly(w: &mut Polynomial) {
    for x in w.0.iter_mut() {
        *x = reduce32(*x);
    }
}

pub(crate) fn reduce32(a: i32) -> i32 {
    let t = (a + (1 << 22)) >> 23;
    a - t * q
}

pub(crate) fn conditional_add_q_poly(w: &mut Polynomial) {
    for x in w.0.iter_mut() {
        *x = conditional_add_q(*x);
    }
}

// TODO: this could use some unit testing to figure out exactly what it does.
pub(crate) fn conditional_add_q(a: i32) -> i32 {
    a + ((a >> 31) & q)
}

#[test]
/// These are the results it's giving; I'm not sure if these are "correct" or not.
fn test_conditional_add_q() {
    assert_eq!(conditional_add_q(-q -1), -1);
    assert_eq!(conditional_add_q(-q), 0);
    assert_eq!(conditional_add_q(-q -2), -2);
    assert_eq!(conditional_add_q(-q +1), 1);
    assert_eq!(conditional_add_q(-1), q-1);
    assert_eq!(conditional_add_q(0), 0);
    assert_eq!(conditional_add_q(1), 1);
    assert_eq!(conditional_add_q(q -1), q-1);
    assert_eq!(conditional_add_q(q), q);
    assert_eq!(conditional_add_q(q +1), q+1);
}


// #[derive(Clone, Copy)]
// pub(crate) struct Polynomial<PARAMS: MLDSAParams> {
//     _params: std::marker::PhantomData<PARAMS>,
//     pub coeffs: [i32; N],
//     // engine: MlDsaEngine,
//     // poly_uniform_n_blocks: usize,
//     // symmetric: Symmetric, // todo what's this used for?
// }

// impl<PARAMS: MLDSAParams> Polynomial<PARAMS> {
//     pub(crate) fn new(/*engine: &MlDsaEngine*/) -> Self {
//         Self {
//             _params: Default::default(),
//             coeffs: [0_i32; N],
//             // engine: engine.clone(),
//             // symmetric: engine.symmetric.clone(),
//             // poly_uniform_n_blocks: 768usize.div_ceil(engine.symmetric.stream_128_block_bytes), // todo -- can this be moved to a params const?
//         }
//     }
//
//     /// Add another polynomial to this polynomial and perform montgomery reduction.
//     /// Also called pointwise montgomery addition
//     pub(crate) fn add(&mut self, w: &Self) {
//         for i in 0..N {
//             self.coeffs[i] = montgomery_reduce(self.coeffs[i] as i64 + w.coeffs[i] as i64);
//         }
//     }
//

//
//
//
//     /*** Old Stuff -- delete if not used ***/
//
//     /// Algorithm 30 RejNTTPoly(𝜌)
//     // TODO -- moved to aux_functions.rs -- delete
//     pub(crate) fn rej_ntt_poly(&mut self, seed: &[u8], nonce: u16) {
//         let mut off;
//         // let mut BUFLEN = self.poly_uniform_n_blocks * self.symmetric.stream_128_block_bytes;
//         const BUFLEN: usize = 768usize.div_ceil(STREAM_128_BLOCK_LEN) * STREAM_128_BLOCK_LEN;
//         let mut buf: Vec<u8> = vec![0; BUFLEN];
//         self.symmetric.stream128_init(seed, nonce);
//         self.symmetric.stream128_squeeze_blocks(buf.as_mut_slice(), 0, BUFLEN);
//         let mut ctr = Self::reject_uniform(&mut self.coeffs, 0, N, &buf, BUFLEN);
//         while ctr < N {
//             off = BUFLEN % 3;
//             for i in 0..off {
//                 buf[i] = buf[BUFLEN - off + i];
//             }
//             self.symmetric.stream128_squeeze_blocks(
//                 buf.as_mut_slice(),
//                 off,
//                 self.symmetric.stream_128_block_bytes,
//             );
//             BUFLEN = self.symmetric.stream_128_block_bytes + off;
//             ctr += Self::reject_uniform(&mut self.coeffs, ctr, N - ctr, &buf, BUFLEN);
//         }
//     }
//
//
//     fn reject_uniform(
//         coeffs: &mut [i32],
//         off: usize,
//         len: usize,
//         buf: &[u8],
//         buflen: usize,
//     ) -> usize {
//         let mut ctr = 0;
//         let mut pos = 0;
//         let mut t: u32;
//         while ctr < len && pos + 3 <= buflen {
//             t = buf[pos] as u32;
//             pos += 1;
//             t |= (buf[pos] as u32) << 8;
//             pos += 1;
//             t |= (buf[pos] as u32) << 16;
//             pos += 1;
//             t &= 0x7FFFFF;
//
//             if t < Q as u32 {
//                 coeffs[off + ctr] = t as i32;
//                 ctr += 1;
//             }
//         }
//         ctr
//     }
//
//     pub(crate) fn uniform_eta(&mut self, seed: &[u8], nonce: u16) {
//         let poly_uniform_eta_n_blocks;
//         let eta = PARAMS::ETA;
//         // if self.engine.eta == 2 {
//         match PARAMS::ALG {
//             MldsaSize::MlDsa44 | MldsaSize::MlDsa87 => {
//                 poly_uniform_eta_n_blocks = 136usize.div_ceil(self.symmetric.stream_256_block_bytes); // todo compute statically?
//             },
//             // } else if self.engine.eta == 4 {
//             MldsaSize::MlDsa65 => {
//                 poly_uniform_eta_n_blocks = 227usize.div_ceil(self.symmetric.stream_256_block_bytes);
//             },
//             // } else {
//             //     return Err(ParameterError("Wrong ML-DSA Eta!".to_string()));
//             // }
//         }
//
//         let buflen = poly_uniform_eta_n_blocks * self.symmetric.stream_256_block_bytes;
//         let mut buf: Vec<u8> = vec![0; buflen];
//
//         self.symmetric.stream256_init(seed, nonce);
//         self.symmetric.stream256_squeeze_blocks(buf.as_mut_slice(), 0, buflen);
//         let mut ctr = Self::reject_eta(&mut self.coeffs, 0, N, &buf, buflen, eta);
//
//         while ctr < N {
//             self.symmetric.stream256_squeeze_blocks(
//                 buf.as_mut_slice(),
//                 0,
//                 self.symmetric.stream_256_block_bytes,
//             );
//             ctr += Self::reject_eta(&mut self.coeffs, ctr, N - ctr, &buf, buflen, eta);
//         }
//         // Ok(())
//     }
//
//     fn reject_eta(
//         coeffs: &mut [i32],
//         off: usize,
//         len: usize,
//         buf: &[u8],
//         buflen: usize,
//         eta: i32,
//     ) -> usize {
//         let mut ctr = 0;
//         let mut pos: usize = 0;
//         let mut t0: u32;
//         let mut t1: u32;
//
//         while ctr < len && pos < buflen {
//             t0 = (buf[pos] as u32) & 0x0F;
//             t1 = (buf[pos] as u32) >> 4;
//             pos += 1;
//             if eta == 2 {
//                 if t0 < 15 {
//                     t0 = t0 - ((205 * t0) >> 10) * 5;
//                     coeffs[off + ctr] = 2 - t0 as i32;
//                     ctr += 1;
//                 }
//                 if t1 < 15 && ctr < len {
//                     t1 = t1 - ((205 * t1) >> 10) * 5;
//                     coeffs[off + ctr] = 2 - t1 as i32;
//                     ctr += 1;
//                 }
//             } else if eta == 4 {
//                 if t0 < 9 {
//                     coeffs[off + ctr] = 4 - t0 as i32;
//                     ctr += 1;
//                 }
//                 if t1 < 9 && ctr < len {
//                     coeffs[off + ctr] = 4 - t1 as i32;
//                     ctr += 1;
//                 }
//             }
//         }
//         ctr
//     }
//
//     pub(crate) fn conditional_add_q(&mut self) {
//         for x in self.coeffs.iter_mut() {
//             *x = reduce::conditional_add_q(*x);
//         }
//     }
//
//     pub(crate) fn poly_t1_pack(&self) -> [u8; POLY_T1PACKED_LEN] {
//         let mut output = [0u8; POLY_T1PACKED_LEN];
//         for i in 0..(N / 4) {
//             output[5 * i] = self.coeffs[4 * i] as u8;
//             output[5 * i + 1] = ((self.coeffs[4 * i] >> 8) | (self.coeffs[4 * i + 1] << 2)) as u8;
//             output[5 * i + 2] =
//                 ((self.coeffs[4 * i + 1] >> 6) | (self.coeffs[4 * i + 2] << 4)) as u8;
//             output[5 * i + 3] =
//                 ((self.coeffs[4 * i + 2] >> 4) | (self.coeffs[4 * i + 3] << 6)) as u8;
//             output[5 * i + 4] = (self.coeffs[4 * i + 3] >> 2) as u8;
//         }
//         output
//     }
//
//     pub(crate) fn poly_t1_unpack(&mut self, a: &[u8]) {
//         for i in 0..N/4 {
//             self.coeffs[4 * i] = ((a[5 * i] as i32) | ((a[5 * i + 1] as i32) << 8)) & 0x3FF;
//             self.coeffs[4 * i + 1] =
//                 (((a[5 * i + 1] as i32) >> 2) | ((a[5 * i + 2] as i32) << 6)) & 0x3FF;
//             self.coeffs[4 * i + 2] =
//                 (((a[5 * i + 2] as i32) >> 4) | ((a[5 * i + 3] as i32) << 4)) & 0x3FF;
//             self.coeffs[4 * i + 3] =
//                 (((a[5 * i + 3] as i32) >> 6) | ((a[5 * i + 4] as i32) << 2)) & 0x3FF;
//         }
//     }
//
//     pub(crate) fn poly_eta_pack(&self, r: &mut [u8], off: usize) {
//         let eta = PARAMS::ETA;
//         let mut t: [u8; 8] = [0; 8];
//         // if self.engine.eta == 2 {
//         // todo could probably macro this
//         match PARAMS::ALG {
//             MldsaSize::MlDsa44 | MldsaSize::MlDsa87 => {
//                 for i in 0..N / 8 {
//                     t[0] = (eta - self.coeffs[8 * i]) as u8;
//                     t[1] = (eta - self.coeffs[8 * i + 1]) as u8;
//                     t[2] = (eta - self.coeffs[8 * i + 2]) as u8;
//                     t[3] = (eta - self.coeffs[8 * i + 3]) as u8;
//                     t[4] = (eta - self.coeffs[8 * i + 4]) as u8;
//                     t[5] = (eta - self.coeffs[8 * i + 5]) as u8;
//                     t[6] = (eta - self.coeffs[8 * i + 6]) as u8;
//                     t[7] = (eta - self.coeffs[8 * i + 7]) as u8;
//
//                     r[off + 3 * i] = t[0] | (t[1] << 3) | (t[2] << 6);
//                     r[off + 3 * i + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
//                     r[off + 3 * i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
//                 }
//             },
//             // } else if self.engine.eta == 4 {
//             MldsaSize::MlDsa65 => {
//                 for i in 0..N / 2 {
//                     t[0] = (eta - self.coeffs[2 * i]) as u8;
//                     t[1] = (eta - self.coeffs[2 * i + 1]) as u8;
//                     r[off + i] = t[0] | t[1] << 4;
//                 }
//             },
//         }
//         // } else {
//         //     return Err(ParameterError("Eta needs to be 2 or 4!".to_string()));
//         // }
//         Ok(())
//     }
//
//     pub(crate) fn poly_eta_unpack(&mut self, a: &[u8], off: usize) {
//         let eta = PARAMS::ETA;
//         // if eta == 2 {
//         // todo could probably macro this
//         match PARAMS::ALG {
//             MldsaSize::MlDsa44 | MldsaSize::MlDsa87 => {
//                 for i in 0..N / 8 {
//                     self.coeffs[8 * i] = (a[off + 3 * i] & 7) as i32;
//                     self.coeffs[8 * i + 1] = ((a[off + 3 * i] >> 3) & 7) as i32;
//                     self.coeffs[8 * i + 2] =
//                         ((a[off + 3 * i] >> 6) | (a[off + 3 * i + 1] << 2) & 7) as i32;
//                     self.coeffs[8 * i + 3] = ((a[off + 3 * i + 1] >> 1) & 7) as i32;
//                     self.coeffs[8 * i + 4] = ((a[off + 3 * i + 1] >> 4) & 7) as i32;
//                     self.coeffs[8 * i + 5] =
//                         ((a[off + 3 * i + 1] >> 7) | (a[off + 3 * i + 2] << 1) & 7) as i32;
//                     self.coeffs[8 * i + 6] = ((a[off + 3 * i + 2] >> 2) & 7) as i32;
//                     self.coeffs[8 * i + 7] = ((a[off + 3 * i + 2] >> 5) & 7) as i32;
//
//                     self.coeffs[8 * i] = eta - self.coeffs[8 * i];
//                     self.coeffs[8 * i + 1] = eta - self.coeffs[8 * i + 1];
//                     self.coeffs[8 * i + 2] = eta - self.coeffs[8 * i + 2];
//                     self.coeffs[8 * i + 3] = eta - self.coeffs[8 * i + 3];
//                     self.coeffs[8 * i + 4] = eta - self.coeffs[8 * i + 4];
//                     self.coeffs[8 * i + 5] = eta - self.coeffs[8 * i + 5];
//                     self.coeffs[8 * i + 6] = eta - self.coeffs[8 * i + 6];
//                     self.coeffs[8 * i + 7] = eta - self.coeffs[8 * i + 7];
//                 }
//             },
//         // } else if eta == 4 {
//             MldsaSize::MlDsa65 => {
//                 for i in 0..N / 2 {
//                     self.coeffs[2 * i] = (a[off + i] & 0x0F) as i32;
//                     self.coeffs[2 * i + 1] = (a[off + i] >> 4) as i32;
//
//                     self.coeffs[2 * i] = eta - self.coeffs[2 * i];
//                     self.coeffs[2 * i + 1] = eta - self.coeffs[2 * i + 1];
//                 }
//             },
//         }
//     }
//
//     pub(crate) fn uniform_gamma1(&mut self, seed: &[u8], nonce: u16) {
//         let buflen =
//             // self.engine.poly_uniform_gamma1_n_bytes * self.symmetric.stream_256_block_bytes;
//             PARAMS::POLY_UNIFORM_GAMMA1_N_LEN * self.symmetric.stream_256_block_bytes;
//         let mut buf: Vec<u8> = vec![0; buflen]; // todo -- this has a definite size, so shouldn't need a Vec. Maybe needs a macro?
//         self.symmetric.stream256_init(seed, nonce);
//         self.symmetric.stream256_squeeze_blocks(buf.as_mut_slice(), 0, buflen);
//         self.unpack_z(&buf)
//     }
//
//     pub(crate) fn pack_z(&self, r: &mut [u8], off: usize) {
//         let mut t: [u32; 4] = [0; 4];
//         // if self.engine.gamma1 == (1 << 17) {
//         // todo could probably macro this
//         match PARAMS::ALG {
//             MldsaSize::MlDsa44 => {
//                 for i in 0..N / 4 {
//                     t[0] = (PARAMS::GAMMA1 - self.coeffs[4 * i]) as u32;
//                     t[1] = (PARAMS::GAMMA1 - self.coeffs[4 * i + 1]) as u32;
//                     t[2] = (PARAMS::GAMMA1 - self.coeffs[4 * i + 2]) as u32;
//                     t[3] = (PARAMS::GAMMA1 - self.coeffs[4 * i + 3]) as u32;
//
//                     r[off + 9 * i] = t[0] as u8;
//                     r[off + 9 * i + 1] = (t[0] >> 8) as u8;
//                     r[off + 9 * i + 2] = ((t[0] >> 16) | (t[1] << 2)) as u8;
//                     r[off + 9 * i + 3] = (t[1] >> 6) as u8;
//                     r[off + 9 * i + 4] = ((t[1] >> 14) | (t[2] << 4)) as u8;
//                     r[off + 9 * i + 5] = (t[2] >> 4) as u8;
//                     r[off + 9 * i + 6] = ((t[2] >> 12) | (t[3] << 6)) as u8;
//                     r[off + 9 * i + 7] = (t[3] >> 2) as u8;
//                     r[off + 9 * i + 8] = (t[3] >> 10) as u8;
//                 }
//             },
//             // } else if self.engine.gamma1 == (1 << 19) {
//             MldsaSize::MlDsa65 | MldsaSize::MlDsa87 => {
//                 for i in 0..N / 2 {
//                     t[0] = (PARAMS::GAMMA1 - self.coeffs[2 * i]) as u32;
//                     t[1] = (PARAMS::GAMMA1 - self.coeffs[2 * i + 1]) as u32;
//
//                     r[off + 5 * i] = t[0] as u8;
//                     r[off + 5 * i + 1] = (t[0] >> 8) as u8;
//                     r[off + 5 * i + 2] = ((t[0] >> 16) | (t[1] << 4)) as u8;
//                     r[off + 5 * i + 3] = (t[1] >> 4) as u8;
//                     r[off + 5 * i + 4] = (t[1] >> 12) as u8;
//                 }
//             },
//         }
//         // } else {
//         //     return Err(ParameterError("Wrong ML-DSA Gamma1!".to_string()));
//         // }
//         // Ok(())
//     }
//
//     pub(crate) fn unpack_z(&mut self, a: &[u8]) { // todo -- does this have a definite size?
//         // if self.engine.gamma1 == (1 << 17) {
//         // todo could probably macro this
//         match PARAMS::ALG {
//             MldsaSize::MlDsa44 => {
//                 for i in 0..(N / 4) {
//                     self.coeffs[4 * i] = (((a[9 * i] as i32) | ((a[9 * i + 1] as i32) << 8))
//                         | ((a[9 * i + 2] as i32) << 16))
//                         & 0x3FFFF;
//                     self.coeffs[4 * i + 1] = ((((a[9 * i + 2] as i32) >> 2)
//                         | ((a[9 * i + 3] as i32) << 6))
//                         | ((a[9 * i + 4] as i32) << 14))
//                         & 0x3FFFF;
//                     self.coeffs[4 * i + 2] = ((((a[9 * i + 4] as i32) >> 4)
//                         | ((a[9 * i + 5] as i32) << 4))
//                         | ((a[9 * i + 6] as i32) << 12))
//                         & 0x3FFFF;
//                     self.coeffs[4 * i + 3] = ((((a[9 * i + 6] as i32) >> 6)
//                         | ((a[9 * i + 7] as i32) << 2))
//                         | ((a[9 * i + 8] as i32) << 10))
//                         & 0x3FFFF;
//
//                     self.coeffs[4 * i] = PARAMS::GAMMA1 - self.coeffs[4 * i];
//                     self.coeffs[4 * i + 1] = PARAMS::GAMMA1 - self.coeffs[4 * i + 1];
//                     self.coeffs[4 * i + 2] = PARAMS::GAMMA1 - self.coeffs[4 * i + 2];
//                     self.coeffs[4 * i + 3] = PARAMS::GAMMA1 - self.coeffs[4 * i + 3];
//                 }
//             },
//         // } else if self.engine.gamma1 == (1 << 19) {
//             MldsaSize::MlDsa65 | MldsaSize::MlDsa87 => {
//                 for i in 0..(N / 2) {
//                     self.coeffs[2 * i] = (((a[5 * i] as i32) | ((a[5 * i + 1] as i32) << 8))
//                         | ((a[5 * i + 2] as i32) << 16))
//                         & 0xFFFFF;
//                     self.coeffs[2 * i + 1] = ((((a[5 * i + 2] as i32) >> 4)
//                         | ((a[5 * i + 3] as i32) << 4))
//                         | ((a[5 * i + 4] as i32) << 12))
//                         & 0xFFFFF;
//
//                     self.coeffs[2 * i] = PARAMS::GAMMA1 - self.coeffs[2 * i];
//                     self.coeffs[2 * i + 1] = PARAMS::GAMMA1 - self.coeffs[2 * i + 1];
//                 }
//             },
//         // } else {
//         //     return Err(ParameterError("Wrong ML-DSA Gamma1!".to_string()));
//         }
//     }
//
//     pub(crate) fn decompose(&mut self, a: &mut Self) -> Result<()> {
//         for i in 0..N {
//             let decomp = rounding::decompose(self.coeffs[i], PARAMS::GAMMA2)?;
//             a.coeffs[i] = decomp[0];
//             self.coeffs[i] = decomp[1];
//         }
//         Ok(())
//     }
//
//     pub(crate) fn pack_w1(&self, r: &mut [u8], off: usize) {
//         // todo -- since this is switching on constants, why not actually switch on constants?
//         // if PARAMS::GAMMA2 == (Q - 1) / 88 {
//         // todo -- this seems like a perfect use for a macro
//         match PARAMS::ALG {
//             MldsaSize::MlDsa44 => {
//                 for i in 0..(N / 4) {
//                     r[off + 3 * i] =
//                         ((self.coeffs[4 * i]) as u8) | ((self.coeffs[4 * i + 1] << 6) as u8);
//                     r[off + 3 * i + 1] =
//                         ((self.coeffs[4 * i + 1] >> 2) as u8) | ((self.coeffs[4 * i + 2] << 4) as u8);
//                     r[off + 3 * i + 2] =
//                         ((self.coeffs[4 * i + 2] >> 4) as u8) | ((self.coeffs[4 * i + 3] << 2) as u8);
//                 }
//             }, //else if PARAMS::GAMMA2 == (Q - 1) / 32 {
//             MldsaSize::MlDsa65 | MldsaSize::MlDsa87 => {
//                 for i in 0..(N / 2) {
//                     r[off + i] = ((self.coeffs[2 * i]) | (self.coeffs[2 * i + 1] << 4)) as u8;
//                 }
//             }
//         }
//     }
//
//     pub(crate) fn challenge(&mut self, seed: &[u8; 32]) {
//         let mut buf = vec![0u8; self.symmetric.stream_256_block_bytes]; // todo -- what's that constant?
//         // shake_digest_256.update_bytes(&seed[..SEED_LEN]);
//         let mut shake256 = SHAKE256::new();
//
//         // shake256.update_bytes(seed);
//         // shake256.do_output(&mut buf);
//         shake256.hash_xof_out(seed, &mut buf);
//
//         let mut signs: u64 = 0;
//         for (i, item) in buf.iter().enumerate().take(8) {
//             signs |= (*item as u64) << (8 * i);
//         }
//
//         for i in 0 .. N {
//             self.coeffs[i] = 0;
//         }
//
//         let mut pos = 8;
//         let mut b;
//         for i in (N - PARAMS::TAU as usize) .. N {
//             do_while! {
//                 do {
//                     if pos >= self.symmetric.stream_256_block_bytes {
//                         shake_digest_256.do_output(buf.as_mut_slice());
//                         pos = 0;
//                     }
//                     b = buf[pos] as usize;
//                     pos += 1;
//                 } while b > i;
//             }
//
//             self.coeffs[i] = self.coeffs[b];
//             self.coeffs[b] = (1u64.wrapping_sub(2 * (signs & 1))) as i32;
//             signs >>= 1;
//         }
//     }
//
//     pub(crate) fn check_norm(&self, b: i32) -> bool {
//         if b > (Q - 1) / 8 {
//             return true;
//         }
//
//         let mut t: i32;
//         for x in self.coeffs.iter() {
//             t = *x >> 31;
//             t = *x - (t & (2 * *x));
//
//             if t >= b {
//                 return true;
//             }
//         }
//         false
//     }
//
//     pub(crate) fn poly_make_hint(&mut self, a0: &Self, a1: &Self) -> i32 {
//         let mut s = 0;
//         for i in 0..N {
//             self.coeffs[i] = rounding::make_hint(a0.coeffs[i], a1.coeffs[i], &self.engine);
//             s += self.coeffs[i];
//         }
//         s
//     }
//
//     pub(crate) fn poly_use_hint(&mut self, a: &Self, h: &Self) -> Result<()> {
//         for i in 0..N {
//             let x = rounding::use_hint(a.coeffs[i], h.coeffs[i], self.engine.gamma2)?;
//             self.coeffs[i] = x;
//         }
//         Ok(())
//     }
//
//     pub(crate) fn shift_left(&mut self) {
//         for x in self.coeffs.iter_mut() {
//             *x <<= D;
//         }
//     }
// }