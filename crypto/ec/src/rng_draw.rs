//! The RNG draw every secret in this crate is taken through.

use bouncycastle_core::errors::RNGError;
use bouncycastle_core::traits::RNG;

/// Fills `out` from `rng`. A count short of the buffer is the RNG failing to deliver, as its
/// own error is.
pub(crate) fn fill_bytes(rng: &mut dyn RNG, out: &mut [u8]) -> Result<(), RNGError> {
    match rng.next_bytes_out(out) {
        Ok(written) if written == out.len() => Ok(()),
        Ok(_) => Err(RNGError::GenericError("the RNG wrote fewer bytes than it was asked for")),
        Err(e) => Err(e),
    }
}
