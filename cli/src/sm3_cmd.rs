use bouncycastle::core::traits::Hash;
use std::io;
use std::io::Read;

use bouncycastle::sm3::SM3;

pub(crate) fn sm3_cmd(output_hex: bool) {
    let mut sm3 = SM3::new();
    let mut buf: [u8; 1024] = [0u8; 1024];

    // read from stdin
    let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    while bytes_read != 0 {
        sm3.do_update(&buf[..bytes_read]);
        bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    }

    let out = sm3.do_final();

    crate::helpers::write_bytes_or_hex(&out, output_hex);
    crate::helpers::write_stdout(b"\n");
}
