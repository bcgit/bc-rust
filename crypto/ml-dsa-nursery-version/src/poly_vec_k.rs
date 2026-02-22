//! Represents a vector of polynomials over the ML-DSA ring.

use crate::{polynomial::Polynomial};

#[derive(Clone)]
pub(crate) struct PolyVec<const LEN: usize> {
    pub vec: [Polynomial; LEN],
    // engine: MlDsaEngine,
    // k: usize,
}

impl<const LEN: usize> PolyVec<LEN> {
    // pub(crate) fn new(engine: &MlDsaEngine) -> Self {
    //     Self { vec: vec![Poly::new(engine); engine.k], engine: engine.clone(), k: engine.k }
    // }

    pub(crate) fn new() -> Self {
        Self { vec: [Polynomial::new(); LEN] }
    }

    pub(crate) fn uniform_eta(&mut self, seed: &[u8], nonce: u16) {
        let mut n = nonce;
        for x in self.vec.iter_mut() {
            x.uniform_eta(seed, n);
            n += 1;
        }
    }

    pub(crate) fn reduce(&mut self) {
        for x in self.vec.iter_mut() {
            x.reduce_poly();
        }
    }

    pub(crate) fn ntt(&mut self) {
        for x in self.vec.iter_mut() {
            x.poly_ntt();
        }
    }

    pub(crate) fn inverse_ntt_to_mont(&mut self) {
        for x in self.vec.iter_mut() {
            x.inverse_ntt_to_mont();
        }
    }

    pub(crate) fn add_poly_vec_k(&mut self, b: &Self) {
        for i in 0..self.k {
            self.vec[i].add_poly(&b.vec[i]);
        }
    }

    pub(crate) fn subtract_poly_vec_k(&mut self, v: &Self) {
        for i in 0..self.k {
            self.vec[i].subtract_poly(&v.vec[i]);
        }
    }

    pub(crate) fn conditional_add_q(&mut self) {
        for x in self.vec.iter_mut() {
            x.conditional_add_q();
        }
    }

    pub(crate) fn power_2_round(&mut self, v: &mut Self) {
        for i in 0..self.k {
            self.vec[i].power_2_round(&mut v.vec[i]);
        }
    }

    pub(crate) fn decompose(&mut self, v: &mut Self) -> Result<()> {
        for i in 0..self.k {
            self.vec[i].decompose(&mut v.vec[i])?;
        }
        Ok(())
    }

    pub(crate) fn pack_w1(&mut self, r: &mut [u8]) {
        for i in 0..self.k {
            self.vec[i].pack_w1(r, i * self.engine.poly_w1_packed_bytes);
        }
    }

    pub(crate) fn pointwise_poly_montgomery(&mut self, a: &Polynomial, v: &Self) {
        for i in 0..self.k {
            self.vec[i].pointwise_montgomery(a, &v.vec[i]);
        }
    }

    pub(crate) fn check_norm(&self, bound: i32) -> bool {
        for x in self.vec.iter() {
            if x.check_norm(bound) {
                return true;
            }
        }
        false
    }

    pub(crate) fn make_hint(&mut self, v0: &Self, v1: &Self) -> i32 {
        let mut s = 0;
        for i in 0..self.k {
            s += self.vec[i].poly_make_hint(&v0.vec[i], &v1.vec[i]);
        }
        s
    }

    pub(crate) fn use_hint(&mut self, a: &Self, h: &Self) -> Result<()> {
        for i in 0..self.k {
            self.vec[i].poly_use_hint(&a.vec[i], &h.vec[i])?;
        }
        Ok(())
    }

    pub(crate) fn shift_left(&mut self) {
        for x in self.vec.iter_mut() {
            x.shift_left();
        }
    }
}
