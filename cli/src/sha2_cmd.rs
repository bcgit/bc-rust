use crate::helpers::stream_hash;
use bouncycastle::sha2::{SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256};

#[allow(non_camel_case_types)]
pub(crate) enum SHA2Variant {
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    SHA512_224,
    SHA512_256,
}

pub(crate) fn sha2_cmd(variant: SHA2Variant, output_hex: bool) {
    match variant {
        SHA2Variant::SHA224 => stream_hash(SHA224::new(), output_hex),
        SHA2Variant::SHA256 => stream_hash(SHA256::new(), output_hex),
        SHA2Variant::SHA384 => stream_hash(SHA384::new(), output_hex),
        SHA2Variant::SHA512 => stream_hash(SHA512::new(), output_hex),
        SHA2Variant::SHA512_224 => stream_hash(SHA512_224::new(), output_hex),
        SHA2Variant::SHA512_256 => stream_hash(SHA512_256::new(), output_hex),
    }
}
