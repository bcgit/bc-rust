//! Raw primitives whose safe use is the caller's responsibility; see [`bouncycastle_core::hazmat`]
//! for what the path means and the supported uses.
//!
//! [`key_from_bytes`] is the only way to make a [`Poly1305Key`], because Poly1305's security rests
//! on something only the caller can know: that the key is fresh, unpredictable and used for one
//! message. It is for a construction that derives its own one-time key, as ChaCha20-Poly1305 does
//! (RFC 8439 Sec 2.6), and for test vectors.

use crate::{KEY_LEN, Poly1305Key};

/// A [`Poly1305Key`] from the 32-byte one-time key `r || s` of RFC 8439 Sec 2.5, with no check of
/// its value: an all-zero key is accepted, as the RFC accepts it.
///
/// # 🚨 Security Considerations 🚨
/// The caller vouches for the key: it must be unpredictable, and authenticate one message only.
/// The key returned is consumed by the one worker it makes, but nothing stops a second key being
/// made from the same bytes. RFC 8439 Sec 2.6 derives a fresh key per message from ChaCha20.
pub fn key_from_bytes(key: &[u8; KEY_LEN]) -> Poly1305Key {
    Poly1305Key::from_key_bytes(key)
}
