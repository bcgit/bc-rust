use crate::{mldsa, mldsa::MlDsaEngine};
use utils::{Error::ParameterError, Result};

pub(super) fn power_2_round(a: i32) -> [i32; 2] {
    let mut r = [0; 2];
    r[0] = (a + (1 << (mldsa::D - 1)) - 1) >> mldsa::D;
    r[1] = a - (r[0] << mldsa::D);
    r
}

pub(super) fn decompose(a: i32, gamma2: i32) -> Result<[i32; 2]> {
    let mut a0;
    let mut a1 = (a + 127) >> 7;
    if gamma2 == (mldsa::Q - 1) / 32 {
        a1 = (a1 * 1025 + (1 << 21)) >> 22;
        a1 &= 15;
    } else if gamma2 == (mldsa::Q - 1) / 88 {
        a1 = (a1 * 11275 + (1 << 23)) >> 24;
        a1 ^= ((43 - a1) >> 31) & a1;
    } else {
        return Err(ParameterError("Wrong Gamma2!".to_string()));
    }
    a0 = a - a1 * 2 * gamma2;
    a0 -= (((mldsa::Q - 1) / 2 - a0) >> 31) & mldsa::Q;
    Ok([a0, a1])
}

pub(super) fn make_hint(a0: i32, a1: i32, engine: &MlDsaEngine) -> i32 {
    let g2 = engine.gamma2;
    let q = mldsa::Q;
    if a0 <= g2 || a0 > q - g2 || (a0 == q - g2 && a1 == 0) {
        return 0;
    }
    1
}

pub(super) fn use_hint(a: i32, hint: i32, gamma2: i32) -> Result<i32> {
    let [a0, a1] = decompose(a, gamma2)?;

    if hint == 0 {
        return Ok(a1);
    }

    if gamma2 == (mldsa::Q - 1) / 32 {
        if a0 > 0 { Ok((a1 + 1) & 15) } else { Ok((a1 - 1) & 15) }
    } else if gamma2 == (mldsa::Q - 1) / 88 {
        if a0 > 0 {
            Ok(if a1 == 43 { 0 } else { a1 + 1 })
        } else {
            Ok(if a1 == 0 { 43 } else { a1 - 1 })
        }
    } else {
        Err(ParameterError("Wrong Gamma2!".to_string()))
    }
}
