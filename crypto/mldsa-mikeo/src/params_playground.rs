
// play with const and non-const params

use crate::{MLDSA44Params, MLDSAParams};

fn fill<const N: usize>() -> [u8; N] {
    let out = [N as u8; N];
    out
}

#[test]
fn main() {
    _ = fill::<{MLDSA44Params::l}>();
}