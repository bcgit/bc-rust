//! `crypto/modexp/src/rsa/eme_oaep.rs`, included by path and unmodified, with the MGF an opaque
//! call so that `decode_out` lands in the assembly as one symbol. `../check_oaep_ct.sh` builds
//! this for the Cortex-M0 and RISC-V 32I targets and checks the decode for a multiply, a divide
//! or a call it should not make, and runs `src/bin/memcheck.rs` over it on the host.
#![no_std]
#![forbid(unsafe_code)]
#![allow(dead_code)]

mod rsa;

use bouncycastle_core::traits::{HashAlgParams, HashOneShot};
pub use rsa::{decode_any, decode_exact};

/// A 32-byte hash, for `hLen`; the decode never calls it.
#[derive(Default)]
pub struct H32;
impl HashAlgParams for H32 {
    const OUTPUT_LEN: usize = 32;
}
impl HashOneShot for H32 {
    #[inline(never)]
    fn hash_out(_data: &[u8], out: &mut [u8]) -> usize {
        out.fill(0);
        32
    }
}
