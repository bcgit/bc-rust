use crate::helpers::stream_hash;
use bouncycastle::digest::sha1::SHA1;

pub(crate) fn sha1_cmd(output_hex: bool) {
    stream_hash(SHA1::new(), output_hex);
}
