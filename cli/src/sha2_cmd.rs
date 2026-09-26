use bouncycastle::core::traits::Hash;
use std::io;
use std::io::{Read, Write};

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
        SHA2Variant::SHA224 => do_sha2(SHA224::new(), output_hex),
        SHA2Variant::SHA256 => do_sha2(SHA256::new(), output_hex),
        SHA2Variant::SHA384 => do_sha2(SHA384::new(), output_hex),
        SHA2Variant::SHA512 => do_sha2(SHA512::new(), output_hex),
        SHA2Variant::SHA512_224 => do_sha2(SHA512_224::new(), output_hex),
        SHA2Variant::SHA512_256 => do_sha2(SHA512_256::new(), output_hex),
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

    let out = sha2.do_final();

    if output_hex {
        for b in out.iter() {
            print!("{b:02x}");
        }
    } else {
        io::stdout().write(&out).unwrap();
    }
    println!();
}
