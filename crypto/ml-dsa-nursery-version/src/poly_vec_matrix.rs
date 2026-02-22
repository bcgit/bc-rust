use crate::{mldsa::MlDsaEngine, poly_vec_k::PolyVecK, poly_vec_l::PolyVecL};

pub(crate) struct PolyVecMatrix {
    pub(crate) matrix: Vec<PolyVecL>,
    l: usize,
    k: usize,
}

impl PolyVecMatrix {
    pub(crate) fn new(engine: &MlDsaEngine) -> Self {
        Self { matrix: vec![PolyVecL::new(engine); engine.k], l: engine.l, k: engine.k }
    }

    pub(crate) fn expand_matrix(&mut self, rho: &[u8]) {
        for i in 0..self.k {
            for j in 0..self.l {
                self.matrix[i].vec[j].uniform_blocks(rho, ((i << 8) + j) as u16)
            }
        }
    }

    pub(crate) fn pointwise_montgomery(&self, t: &mut PolyVecK, v: &PolyVecL) {
        for i in 0..self.k {
            t.vec[i].pointwise_account_montgomery(&self.matrix[i], v);
        }
    }
}
