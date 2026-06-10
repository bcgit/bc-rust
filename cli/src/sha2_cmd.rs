use bouncycastle::core::traits::{Hash};
use std::io;
use std::io::{Read, Write};

use bouncycastle::sha2::{SHA224, SHA256, SHA384, SHA512};

pub(crate) fn sha2_cmd(bit_len: usize, output_hex: bool) {
    match bit_len {
        224 => do_sha2(SHA224::new(), output_hex),
        256 => do_sha2(SHA256::new(), output_hex),
        384 => do_sha2(SHA384::new(), output_hex),
        512 => do_sha2(SHA512::new(), output_hex),
        _ => panic!("Unsupported algorithm: SHA{}", bit_len)
    }
}

fn do_sha2(mut sha2: impl Hash, output_hex: bool) {
    let mut buf: [u8; 1024] = [0u8; 1024];

    // read from stdin
    let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    while bytes_read != 0 {
        sha2.do_update(&buf[..bytes_read]);
        bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    }

    let mut out = [0u8; 64];
    let bytes_written = sha2.do_final_out(&mut out);
    let out = &out[..bytes_written];

    if output_hex {
        for b in out.iter() {
            print!("{b:02x}");
        }
    } else { io::stdout().write(out).unwrap(); }
    println!();
}