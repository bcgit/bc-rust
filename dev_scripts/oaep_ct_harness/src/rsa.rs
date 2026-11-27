//! Stands where the `rsa` module of `bouncycastle-modexp` does: `eme_oaep.rs` names its neighbour
//! as `crate::rsa::mgf1`, and its items are `pub(in crate::rsa)`.

use super::H32;

#[path = "../../../crypto/modexp/src/rsa/eme_oaep.rs"]
mod eme_oaep;

/// What `eme_oaep.rs` uses of the `rsa` module's `mgf1`. The mask is not what is under
/// test: it only has to keep the decode's input opaque to the optimiser and, under memcheck,
/// undefined.
mod mgf1 {
    pub(in crate::rsa) const MAX_HASH_LEN: usize = 64;

    #[inline(never)]
    pub(in crate::rsa) fn mgf1_xor<M>(seed: &[u8], target: &mut [u8]) {
        for (t, s) in target.iter_mut().zip(seed.iter().cycle()) {
            *t ^= core::hint::black_box(*s);
        }
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
