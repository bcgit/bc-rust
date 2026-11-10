//! The two halves of an HMAC computation, for a construction that cannot hold an [`HMAC`]
//! worker: HKDF's extract phase owns its salt key and so cannot also hold a worker that borrows
//! it. See [`bouncycastle_core::hazmat`] for what the path means.
//!
//! # 🚨 Security Considerations 🚨
//!
//! [`inner_state`] is `H(K XOR ipad)` with nothing absorbed, and [`finish_out`] finishes any
//! `HASH` value through the key's outer pad. Nothing checks that the hash handed to `finish_out`
//! came from `inner_state` of the same key, or that it was fed exactly the message: a caller that
//! composes the two wrongly computes something that is not HMAC over that message. Use the
//! [`HMAC`] worker from [`HmacKey::create_generator`] unless the worker's borrow is what stands
//! in the way.
//!
//! [`HMAC`]: crate::HMAC
//! [`HmacKey::create_generator`]: bouncycastle_core::symmetric_key::MacGenerationKey::create_generator

use crate::{HMACParams, HmacKey};

/// `H` after absorbing `K XOR ipad`, ready for the text: the start of RFC 2104 Section 2 step
/// (4). What a worker's updates feed; [`finish_out`] is its other half.
pub fn inner_state<HASH: HMACParams>(key: &HmacKey<HASH>) -> HASH {
    key.inner_state()
}

/// RFC 2104 Section 2 steps (4), (6) and (7) over an inner hash that has absorbed the text:
/// finishes it, feeds the result to the key's outer pad state, and finishes that into `out` as
/// `Hash::do_final_out` does: the whole buffer is zeroized first, a buffer shorter than the
/// hash's output takes a truncated tag, and a longer one takes the tag at its start and zeros
/// after. Returns the number of bytes written.
pub fn finish_out<HASH: HMACParams>(key: &HmacKey<HASH>, inner: HASH, out: &mut [u8]) -> usize {
    key.finish_out(inner, out)
}
