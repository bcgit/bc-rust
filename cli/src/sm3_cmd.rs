use crate::helpers::stream_hash;
use bouncycastle::sm3::SM3;

pub(crate) fn sm3_cmd(output_hex: bool) {
    stream_hash(SM3::new(), output_hex);
}
