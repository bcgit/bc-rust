use crate::mldsa;

pub(crate) fn montgomery_reduce(a: i64) -> i32 {
    let t: i32 = a.wrapping_mul(mldsa::Q_INV as i64) as i32;
    ((a - ((t as i64) * (mldsa::Q as i64))) >> 32) as i32
}
pub(crate) fn reduce32(a: i32) -> i32 {
    let t = (a + (1 << 22)) >> 23;
    a - t * mldsa::Q
}
pub(crate) fn conditional_add_q(a: i32) -> i32 {
    a + ((a >> 31) & mldsa::Q)
}
