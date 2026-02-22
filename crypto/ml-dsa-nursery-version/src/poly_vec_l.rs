use crate::{mldsa, mldsa::MlDsaEngine, polynomial::Polynomial};
use utils::Result;

#[derive(Clone)]
pub(crate) struct PolyVecL {
    pub vec: Vec<Polynomial>,
    l: usize,
    k: usize,
}

impl PolyVecL {
    pub(crate) fn new(engine: &MlDsaEngine) -> Self {
        Self { vec: vec![Polynomial::new(engine); engine.l], l: engine.l, k: engine.k }
    }

    pub(crate) fn uniform_eta(&mut self, seed: &[u8], nonce: u16) -> Result<()> {
        let mut n = nonce;
        for x in self.vec.iter_mut() {
            x.uniform_eta(seed, n)?;
            n += 1;
        }
        Ok(())
    }

    pub(crate) fn copy_poly_vec_l(&self, out_poly: &mut PolyVecL) {
        for i in 0..self.l {
            for j in 0..mldsa::N {
                out_poly.vec[i].coeffs[j] = self.vec[i].coeffs[j];
            }
        }
    }

    pub(crate) fn ntt(&mut self) {
        for x in self.vec.iter_mut() {
            x.poly_ntt();
        }
    }

    // Design choice: don't do the NTT in-place, but copy data to a new array.
    // This uses slightly more memory and requires a copy, but makes the code easier to read
    // and less likely to contain a bug. But this optimization could be considered in the future.
    pub(crate) fn inverse_ntt_to_mont(&mut self) {
        for x in self.vec.iter_mut() {
            x.inverse_ntt_to_mont();
        }
    }

    pub(crate) fn uniform_gamma1(&mut self, seed: &[u8], nonce: u16) -> Result<()> {
        for i in 0..self.l {
            self.vec[i].uniform_gamma1(seed, (self.l * (nonce as usize) + i) as u16)?;
        }
        Ok(())
    }

    pub(crate) fn pointwise_poly_montgomery(&mut self, a: &Polynomial, v: &Self) {
        for i in 0..self.l {
            self.vec[i].pointwise_montgomery(a, &v.vec[i]);
        }
    }

    pub(crate) fn add_poly_vec_l(&mut self, b: &Self) {
        for i in 0..self.l {
            self.vec[i].add_poly(&b.vec[i]);
        }
    }

    pub(crate) fn reduce(&mut self) {
        for x in self.vec.iter_mut() {
            x.reduce_poly();
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
}
