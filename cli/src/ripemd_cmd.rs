use crate::helpers::stream_hash;
use bouncycastle::digest::ripemd::{RIPEMD128, RIPEMD160, RIPEMD256, RIPEMD320};

pub(crate) enum RIPEMDVariant {
    RIPEMD128,
    RIPEMD160,
    RIPEMD256,
    RIPEMD320,
}

pub(crate) fn ripemd_cmd(variant: RIPEMDVariant, output_hex: bool) {
    match variant {
        RIPEMDVariant::RIPEMD128 => stream_hash(RIPEMD128::new(), output_hex),
        RIPEMDVariant::RIPEMD160 => stream_hash(RIPEMD160::new(), output_hex),
        RIPEMDVariant::RIPEMD256 => stream_hash(RIPEMD256::new(), output_hex),
        RIPEMDVariant::RIPEMD320 => stream_hash(RIPEMD320::new(), output_hex),
    }
}
