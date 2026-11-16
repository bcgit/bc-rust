//! [`finish_token`]: a [`FinishToken`] for code that finishes a worker it owns where it sits.

use crate::traits::FinishToken;

/// A [`FinishToken`], for code outside this crate that owns a worker for one job and finishes it
/// through its `&mut self` finishing method rather than a consuming final, so that the worker is
/// never moved and its `Secret` state is wiped in the slot it was made in: a KDF's block loop
/// over a hash, HMAC's hazmat half finishing the inner hash it is lent, a key enum finishing the
/// variant it holds.
///
/// ```
/// use bouncycastle_core::hazmat::finish_token;
/// # use bouncycastle_core::traits::Hash;
/// fn digest_block<H: Hash + Default>(input: &[u8], block: &mut [u8]) {
///     let mut hash = H::default();
///     hash.do_update(input);
///     hash.finish_into(&finish_token(), block);
///     // `hash` is not used again; it is dropped, and wiped, here.
/// }
/// ```
///
/// # 🚨 Security Considerations 🚨
///
/// The worker traits' consuming finals are what make a second final, or input after the final,
/// a compile error. Finishing through a token gives that up: the caller must finish the worker
/// exactly once and let it drop without using it again. A second final over a MAC, an AEAD or a
/// signer repeats a nonce or a one-time key.
pub fn finish_token() -> FinishToken {
    FinishToken::new()
}
