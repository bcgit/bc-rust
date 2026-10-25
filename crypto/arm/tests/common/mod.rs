//! Helpers shared by the integration tests.

#![allow(dead_code)]

use bouncycastle_arm::Aes;
use bouncycastle_hex as hex;

/// The proof the kernels need, or `None` on a CPU without the instructions, where the test
/// returns early. Only a `std` build can reach `None`; one that declares `aes` always has it.
pub fn cx() -> Option<Aes> {
    let cx = Aes::detect();
    if cx.is_none() {
        println!("WARNING: this CPU lacks FEAT_AES or FEAT_PMULL; skipping");
    }
    cx
}

/// A xorshift64 generator, so the random-input tests need no external crate; the same shape
/// `bouncycastle-cipher`'s GHASH tests use.
pub struct Xorshift(pub u64);

impl Xorshift {
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    pub fn fill(&mut self, out: &mut [u8]) {
        for b in out.iter_mut() {
            *b = self.next_u64() as u8;
        }
    }

    pub fn block(&mut self) -> [u8; 16] {
        let mut b = [0u8; 16];
        self.fill(&mut b);
        b
    }

    pub fn element(&mut self) -> [u64; 2] {
        [self.next_u64(), self.next_u64()]
    }
}

/// Decodes `2 * N` hex characters into `N` bytes.
pub fn hex_bytes<const N: usize>(s: &str) -> [u8; N] {
    hex::decode(s).expect("valid hex").try_into().expect("the expected length")
}

/// Decodes a 16-byte block.
pub fn hex_block(s: &str) -> [u8; 16] {
    hex_bytes::<16>(s)
}
