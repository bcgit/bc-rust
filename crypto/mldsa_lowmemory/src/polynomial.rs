//! Represents a polynomial over the ML-DSA ring.

use core::fmt::{Debug, Display, Formatter};
use bouncycastle_core_interface::traits::Secret;
use crate::mldsa::{N, q, q_inv, MLDSA44_POLY_W1_PACKED_LEN, MLDSA65_POLY_W1_PACKED_LEN};
use crate::aux_functions::{high_bits, low_bits, make_hint, use_hint};
use crate::polynomial;

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

    /// Algorithm 45 MultiplyNTT(𝑎, 𝑏)̂
    /// Computes the product 𝑎 ∘̂ 𝑏 of two elements 𝑎, 𝑏 ∈ 𝑇𝑞.
    /// Input: 𝑎, 𝑏 ∈ 𝑇𝑞.
    /// Output: 𝑐 ∈ 𝑇𝑞.
    /// Multiply the coefficients in this polynomial by those in another polynomial and perform montgomery reduction.
    /// Also called pointwise montgomery multiplication
    pub(crate) fn multiply_ntt(&mut self, b: &Polynomial) {
        for i in 0..N {
            self.0[i] = montgomery_reduce((self.0[i] as i64) * (b.0[i] as i64));
        }
    }

    pub(crate) fn high_bits<const GAMMA2: i32>(&mut self) {
        for i in 0..N {
            self.0[i] = high_bits::<GAMMA2>(self.0[i]);
        }
    }

    pub(crate) fn low_bits<const GAMMA2: i32>(&mut self) {
        for i in 0..N {
            self.0[i] = low_bits::<GAMMA2>(self.0[i]);
        }
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
    pub(crate) fn make_hint_row<const GAMMA2: i32>(&self, r: &Self) -> (Self, i32) {
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
        // It might seem counter-intuitive for a low-memory implementation to create a tmp buffer
        // rather than work in the provided buffer, but my benchmarking shows that for whatever
        // reason, rust is like an order of magnitude faster working in a scope-local array than
        // in a referenced piece of memory.
        // My guess is that when you tell the compiler that the intermediate values are scope-local,
        // then it's free to optimize all of the computation into CPU registers and skip, in this case,
        // several hundred physical memory writes.
        // So while it looks odd to use a scope variable in a low-memory implementation, it's way faster
        // and I'm not convinced that it uses any more physical memory.        
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

    /// Algorithm 41 NTT(𝑤)
    /// Computes the NTT.
    /// Input: Polynomial 𝑤(𝑋)
    /// 𝑗=0 𝑤𝑗𝑋𝑗 ∈ 𝑅𝑞.
    /// Output: 𝑤_hat = (𝑤_hat\[0], ..., 𝑤_hat\[255]) ∈ 𝑇𝑞.
    ///
    /// Note: by convention, variables holding the output of the NTT function should be named "_ntt"
    /// to indicate that they are in the NTT domain (sometimes called the frequency domain), not the natural domain.
    /// I considered using the rust type system to enforce this, but it seemed like overkill, cause that's what
    /// NIST test vectors are for.
    ///
    /// Design choice: don't do the NTT in-place, but copy data to a new array.
    /// This uses slightly more memory and requires a copy, but makes the code easier to read
    /// and less likely to contain a bug. But this optimization could be considered in the future.
    pub(crate) fn ntt(&mut self) {
        let mut m: usize = 0;
        let mut len: usize = 128;

        while len >= 1 {
            let mut start: usize = 0;
            while start < N {
                m += 1;
                let z: i32 = ZETAS[m];

                for j in start..start + len {
                    let t = polynomial::montgomery_reduce(z as i64 * self.0[j + len] as i64);
                    self.0[j + len] = self.0[j] - t; // '% q' not strictly needed cause it gets reduced at some point later. Removing it gave +5% in benchmarking
                    self.0[j] = self.0[j] + t; // '% q' not strictly needed
                }
                start = start + 2 * len;
            }
            len >>= 1;
        }
    }

    /// Algorithm 42 NTT−1(𝑤)̂
    /// Computes the inverse of the NTT.
    /// Input: ̂̂ ̂ 𝑤 = (𝑤\[0], … , 𝑤\[255]) ∈ 𝑇𝑞.
    /// Output: Polynomial 𝑤(𝑋) = ∑255
    /// 𝑗=0 𝑤𝑗𝑋𝑗 ∈ 𝑅𝑞
    pub(crate) fn inv_ntt(&mut self) {
        let mut m: usize = N;
        let mut len: usize = 1;

        while len < N {
            let mut start: usize = 0;
            while start < N {
                m -= 1;
                let z = (-1) * ZETAS[m];

                // j = start;
                // while j < start + len {
                for j in start..start + len {
                    // 𝑡 ← 𝑤𝑗
                    let t: i32 = self.0[j];

                    // 𝑤𝑗 ← (𝑡 + 𝑤𝑗+𝑙𝑒𝑛) mod 𝑞
                    self.0[j] = t + self.0[j + len];

                    // 𝑤𝑗+𝑙𝑒𝑛 ← (𝑡 − 𝑤𝑗+𝑙𝑒𝑛) mod 𝑞
                    self.0[j + len] = t - self.0[j + len];

                    // 𝑤𝑗+𝑙𝑒𝑛 ← (𝑧 ⋅ 𝑤𝑗+𝑙𝑒𝑛) mod 𝑞
                    self.0[j + len] = polynomial::montgomery_reduce(z as i64 * self.0[j + len] as i64);
                    print!("");
                }
                start = start + 2 * len; // could be optimized to save the multiply-by-two since j finishes as `start + len`. That said 2* is just << 1, which is basically free.
            }
            len <<= 1;
        }

        // f = 256^-1 mod q
        // const f: i64 = 8347681;
        // bc-java uses this value rather than the one in FIPS 204
        const f: i64 = 41978;
        for j in 0..N {
            // equiv. to the global constant N
            self.0[j] = polynomial::montgomery_reduce(f * self.0[j] as i64);
        }
    }


    pub(crate) fn use_hint<const GAMMA2: i32>(
        &mut self,
        h: &Polynomial,
    ) {
        for i in 0..N {
            self.0[i] = use_hint::<GAMMA2>(self.0[i], h.0[i]);
        }
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

/// Constants for NTT
const ZETAS: [i32; 256] = [
    0, 25847, -2608894, -518909, 237124, -777960, -876248, 466468, 1826347, 2353451, -359251,
    -2091905, 3119733, -2884855, 3111497, 2680103, 2725464, 1024112, -1079900, 3585928, -549488,
    -1119584, 2619752, -2108549, -2118186, -3859737, -1399561, -3277672, 1757237, -19422, 4010497,
    280005, 2706023, 95776, 3077325, 3530437, -1661693, -3592148, -2537516, 3915439, -3861115,
    -3043716, 3574422, -2867647, 3539968, -300467, 2348700, -539299, -1699267, -1643818, 3505694,
    -3821735, 3507263, -2140649, -1600420, 3699596, 811944, 531354, 954230, 3881043, 3900724,
    -2556880, 2071892, -2797779, -3930395, -1528703, -3677745, -3041255, -1452451, 3475950,
    2176455, -1585221, -1257611, 1939314, -4083598, -1000202, -3190144, -3157330, -3632928, 126922,
    3412210, -983419, 2147896, 2715295, -2967645, -3693493, -411027, -2477047, -671102, -1228525,
    -22981, -1308169, -381987, 1349076, 1852771, -1430430, -3343383, 264944, 508951, 3097992,
    44288, -1100098, 904516, 3958618, -3724342, -8578, 1653064, -3249728, 2389356, -210977, 759969,
    -1316856, 189548, -3553272, 3159746, -1851402, -2409325, -177440, 1315589, 1341330, 1285669,
    -1584928, -812732, -1439742, -3019102, -3881060, -3628969, 3839961, 2091667, 3407706, 2316500,
    3817976, -3342478, 2244091, -2446433, -3562462, 266997, 2434439, -1235728, 3513181, -3520352,
    -3759364, -1197226, -3193378, 900702, 1859098, 909542, 819034, 495491, -1613174, -43260,
    -522500, -655327, -3122442, 2031748, 3207046, -3556995, -525098, -768622, -3595838, 342297,
    286988, -2437823, 4108315, 3437287, -3342277, 1735879, 203044, 2842341, 2691481, -2590150,
    1265009, 4055324, 1247620, 2486353, 1595974, -3767016, 1250494, 2635921, -3548272, -2994039,
    1869119, 1903435, -1050970, -1333058, 1237275, -3318210, -1430225, -451100, 1312455, 3306115,
    -1962642, -1279661, 1917081, -2546312, -1374803, 1500165, 777191, 2235880, 3406031, -542412,
    -2831860, -1671176, -1846953, -2584293, -3724270, 594136, -3776993, -2013608, 2432395, 2454455,
    -164721, 1957272, 3369112, 185531, -1207385, -3183426, 162844, 1616392, 3014001, 810149,
    1652634, -3694233, -1799107, -3038916, 3523897, 3866901, 269760, 2213111, -975884, 1717735,
    472078, -426683, 1723600, -1803090, 1910376, -1667432, -1104333, -260646, -3833893, -2939036,
    -2235985, -420899, -2286327, 183443, -976891, 1612842, -3545687, -554416, 3919660, -48306,
    -1362209, 3937738, 1400424, -846154, 1976782,
];