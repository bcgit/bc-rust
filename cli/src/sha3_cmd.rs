use bouncycastle::sha3::{SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256};

use crate::helpers::{stream_hash, stream_xof};

pub(crate) fn sha3_cmd(bit_len: usize, output_hex: bool) {
    match bit_len {
        224 => stream_hash(SHA3_224::new(), output_hex),
        256 => stream_hash(SHA3_256::new(), output_hex),
        384 => stream_hash(SHA3_384::new(), output_hex),
        512 => stream_hash(SHA3_512::new(), output_hex),
        _ => panic!("Unsupported algorithm: SHA3-{}", bit_len),
    }
}

pub(crate) fn shake_cmd(bit_len: usize, output_len: usize, output_hex: bool) {
    match bit_len {
        128 => stream_xof(SHAKE128::new(), output_len, output_hex),
        256 => stream_xof(SHAKE256::new(), output_len, output_hex),
        _ => panic!("Unsupported algorithm: SHAKE-{}", bit_len),
    }
}
