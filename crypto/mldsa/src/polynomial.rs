//! Represents a polynomial over the ML-DSA ring.

use std::fmt::{Debug, Display, Formatter};
use bouncycastle_core_interface::traits::Secret;
use crate::mldsa::{N, q, q_inv, MLDSA44_POLY_W1_PACKED_LEN, MLDSA65_POLY_W1_PACKED_LEN};
use crate::aux_functions::{high_bits, low_bits, make_hint};



// pub(crate) type Polynomial = [i32; N];
#[derive(Clone)]
pub(crate) struct Polynomial(pub(crate) [i32; N]);

impl Polynomial {
    pub(crate) const fn new() -> Self {
        Self{ 0: [0i32; N] }
    }

    pub(crate) fn conditional_add_q(&mut self) {
        for x in self.0.iter_mut() {
            *x = conditional_add_q(*x);
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
        // Fine that this is not constant-time (returns true early) because it is used in a rejection loop.
        // IE the early quit here leads to rejection and continuing to the top of the rejection loop, or failing the signature validation.
        // So the i32 that we just checked in a non-constant-time manner is about to get thrown away.
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

    pub(crate) fn shift_left<const d: i32>(&mut self) {
        for x in self.0.iter_mut() {
            *x <<= d;
        }
    }

    /// Creates the hint vector, and also returns its hamming weight (ie the number of 1's).
    pub(crate) fn make_hint<const GAMMA2: i32>(&self, r: &Self) -> (Self, i32) {
        let mut out = Polynomial::new();
        let mut count = 0i32;
        for i in 0..N {
            let x = make_hint::<GAMMA2>(self.0[i], r.0[i]);
            out.0[i] = x;
            count += x;
        }

        (out, count)
    }

    pub(crate) fn w1_encode<const POLY_W1_PACKED_LEN: usize>(&self) -> [u8; POLY_W1_PACKED_LEN] {
        let mut r = [0u8; POLY_W1_PACKED_LEN];

        match POLY_W1_PACKED_LEN {
            MLDSA44_POLY_W1_PACKED_LEN => {
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
            MLDSA65_POLY_W1_PACKED_LEN => {
                for i in 0..N/2 {
                    r[i] = ((self.0[2 * i]) | (self.0[2 * i + 1] << 4)) as u8;
                }
            },
            _ => { unreachable!() }
        }

        r
    }
}

impl Secret for Polynomial {}

impl Drop for Polynomial {
    fn drop(&mut self) {
        self.0.fill(0i32);
    }
}

impl Debug for Polynomial {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Polynomial (data masked)")
    }
}

impl Display for Polynomial {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Polynomial (data masked)")
    }
}

#[test]
fn test_display() {
    // Polynomials (could) contain private data,
    // and therefore should be protected against accidental crash dumps:
    
    // fmt
    let p = Polynomial::new();
    assert_eq!(format!("{}", p), "Polynomial (data masked)");

    // debug
    let p = Polynomial::new();
    assert_eq!(format!("{:?}", p), "Polynomial (data masked)");
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
}

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
