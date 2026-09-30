use bouncycastle::core::traits::Hash;
use std::io;
use std::io::{Read, Write};

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

    if output_hex {
        for b in out.iter() {
            print!("{b:02x}");
        }
    } else {
        io::stdout().write_all(&out).unwrap();
    }
    println!();
}
