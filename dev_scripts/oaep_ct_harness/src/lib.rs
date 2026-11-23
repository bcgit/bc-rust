//! `crypto/rsa/src/eme_oaep.rs`, included by path and unmodified, with the MGF an opaque call so
//! that `decode_out` lands in the assembly as one symbol. `../check_oaep_ct.sh` builds this for
//! the Cortex-M0 and RISC-V 32I targets and checks the decode for a multiply, a divide or a call
//! it should not make, and runs `src/bin/memcheck.rs` over it on the host.
#![no_std]
#![forbid(unsafe_code)]
#![allow(dead_code)]

#[path = "../../../crypto/rsa/src/eme_oaep.rs"]
mod eme_oaep;

/// What `eme_oaep.rs` uses of the crate's `mgf1` module. The mask is not what is under test: it
/// only has to keep the decode's input opaque to the optimiser and, under memcheck, undefined.
mod mgf1 {
    pub(crate) const MAX_HASH_LEN: usize = 64;

    #[inline(never)]
    pub(crate) fn mgf1_xor<M>(seed: &[u8], target: &mut [u8]) {
        for (t, s) in target.iter_mut().zip(seed.iter().cycle()) {
            *t ^= core::hint::black_box(*s);
        }
    }
}

use bouncycastle_core::traits::{HashAlgParams, HashOneShot};

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

/// The key-transport path: a message of any length up to `out.len()`.
#[inline(never)]
pub fn decode_any(l_hash: &[u8], em: &mut [u8], out: &mut [u8]) -> Option<usize> {
    eme_oaep::decode_out::<H32, H32>(l_hash, em, None, out)
}

/// The KEM path: the message must be exactly `len` bytes.
#[inline(never)]
pub fn decode_exact(l_hash: &[u8], em: &mut [u8], len: usize, out: &mut [u8]) -> Option<usize> {
    eme_oaep::decode_out::<H32, H32>(l_hash, em, Some(len), out)
}
