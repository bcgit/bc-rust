//! This module provides generic functionality for modular arithmetic.
// TODO -- is this right to be its own crate? Presumably over time, we'll get more generic math functions and it'll make sense to have a math crate.

// pub fn mod_odd_inverse(m: &[u64], x: &[u64], z: &mut [u64]) -> Condition<u64> {
//     let len64 = m.len();
//     debug_assert!(len64 > 0);
//     debug_assert!((m[0] & 1) != 0);
//     debug_assert!(m[len64 - 1] != 0);
//
//     let bits = (len64 << 6) - m[len64 - 1].leading_zeros() as usize;
//     let len62 = bits.div_ceil(62);
//
//     // TODO Stack allocate for small sizes
//     let buf = &mut vec![0_i64; len62 * 5].into_boxed_slice();
//
//     let (m62, buf) = buf.split_at_mut(len62);
//     let (d62, buf) = buf.split_at_mut(len62);
//     let (e62, buf) = buf.split_at_mut(len62);
//     let (f62, g62) = buf.split_at_mut(len62);
//
//     encode62(bits, m, m62);
//     e62[0] = 1;
//     f62.copy_from_slice(m62);
//     encode62(bits, x, g62);
//
//     // We use the "half delta" variant here, with theta == delta - 1/2
//     let mut theta = 0_i64;
//     let m0_inv64 = inverse64(m62[0] as u64) as i64;
//     let max_divsteps = get_maximum_hddivsteps(bits);
//     let mut t;
//
//     for _ in (0..max_divsteps).step_by(62) {
//         (theta, t) = hddivsteps::<62>(theta, f62[0], g62[0]);
//         update_de62(len62, d62, e62, &t, m0_inv64, m62);
//         update_fg62(len62, f62, g62, &t);
//     }
//
//     let sign_f62 = Condition::<i64>::is_negative(f62[len62 - 1]);
//     cnegate62(len62, sign_f62, f62);
//     cnormalize62(len62, sign_f62, d62, m62);
//
//     decode62(bits, d62, z);
//     debug_assert!(nat::lt(m.len(), z, m).to_bool_var());
//
//     equal_to(len62, f62, 1) & equal_to(len62, g62, 0)
// }
