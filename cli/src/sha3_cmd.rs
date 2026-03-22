use bouncycastle::core_interface::traits::{Hash, XOF};
use std::io;
use std::io::{Read, Write};


use bouncycastle::sha3::{SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256};

pub(crate) fn sha3_cmd(bit_len: usize, output_hex: bool) {
    match bit_len {
        224 => do_sha3(SHA3_224::new(), output_hex),
        256 => do_sha3(SHA3_256::new(), output_hex),
        384 => do_sha3(SHA3_384::new(), output_hex),
        512 => do_sha3(SHA3_512::new(), output_hex),
        _ => panic!("Unsupported algorithm: SHA3-{}", bit_len)
    }
}

fn do_sha3(mut sha3: impl Hash, output_hex: bool) {
    let mut buf: [u8; 1024] = [0u8; 1024];

    // read from stdin
    let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    while bytes_read != 0 {
        sha3.do_update(&buf[..bytes_read]);
        bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    }

    let out = sha3.do_final();

    if output_hex {
        for b in out.iter() {
            print!("{b:02x}");
        }
    } else { io::stdout().write(&out).unwrap(); }
    println!();
}

pub(crate) fn shake_cmd(bit_len: usize, output_len: usize, output_hex: bool) {
    match bit_len {
        128 => do_shake(SHAKE128::new(), output_len, output_hex),
        256 => do_shake(SHAKE256::new(), output_len, output_hex),
        _ => panic!("Unsupported algorithm: SHAKE-{}", bit_len)
    }
}

fn do_shake(mut shake: impl XOF, output_len: usize, output_hex: bool) {
    let mut buf: [u8; 1024] = [0u8; 1024];
    // read from stdin
    let mut bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    while bytes_read != 0 {
        shake.absorb(&buf[..bytes_read]);
        bytes_read = io::stdin().read(&mut buf).expect("Failed to read from stdin");
    }

    let out = shake.squeeze(output_len);
    if output_hex {
        for b in out.iter() {
            print!("{b:02x}");
        }
    } else { io::stdout().write(&out).unwrap(); }
    println!();
}