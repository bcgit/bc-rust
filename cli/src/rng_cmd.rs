use bouncycastle::core_interface::traits::{RNG};
use bouncycastle::factory::AlgorithmFactory;
use bouncycastle::factory::rng_factory::RNGFactory;

use crate::print_bytes_or_hex;

pub(crate) fn rng_cmd(len: Option<u32>, output_hex: bool) {
    let mut rng = RNGFactory::default_256_bit();
    let mut buf = vec![0u8; 1024];

    let loop_forever = len.is_none();
    let mut bytes_left_to_write = len.unwrap_or(u32::MAX) as usize;
    while loop_forever || bytes_left_to_write > 0 {
        rng.next_bytes_out(&mut buf).unwrap();

        if bytes_left_to_write < buf.len() { buf.truncate(bytes_left_to_write); }
        println!("buf.len(): {}", buf.len());
        // if output_hex {
        //     for b in buf.iter() {
        //         print!("{b:02x}");
        //     }
        // } else { io::stdout().write(&buf).unwrap(); }
        print_bytes_or_hex(&buf, output_hex);
        bytes_left_to_write -= buf.len();
    }
    println!();
}