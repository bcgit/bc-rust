//! The message representative 𝜇 of FIPS 204, computed incrementally.

use crate::{H, MLDSA_MU_LEN, MLDSA_TR_LEN};
use bouncycastle_core::errors::{SignatureError, SuspendableError};
use bouncycastle_core::traits::{Hash, Suspendable, XOF, XOFSqueezer};
use bouncycastle_sha3::SUSPENDED_SHA3_STATE_LEN;

/// Implements parts of Algorithm 2 and Line 6 of Algorithm 7 of FIPS 204.
/// Provides a stateful version of `MLDSATrait::compute_mu_from_pk` and `MLDSATrait::compute_mu_from_tr`
/// that supports streaming large to-be-signed messages.
///
/// Note: this struct is only exposed for "pure" ML-DSA and not for HashML-DSA because HashML-DSA
/// does not benefit from allowing external construction of the message representative mu.
/// The same behaviour can be obtained by computing the pre-hash `ph` with the appropriate hash function
/// and providing that to HashMLDSA via `PHSigner::sign_ph`.
#[derive(Clone)]
pub struct MuBuilder {
    h: H,
}

impl MuBuilder {
    /// Algorithm 7
    /// 6: 𝜇 ← H(BytesToBits(𝑡𝑟)||𝑀′, 64)
    pub fn compute_mu(
        tr: &[u8; MLDSA_TR_LEN],
        msg: &[u8],
        ctx: Option<&[u8]>,
    ) -> Result<[u8; MLDSA_MU_LEN], SignatureError> {
        let mut mu_builder = MuBuilder::do_init(tr, ctx)?;
        mu_builder.do_update(msg);
        let mu = mu_builder.do_final();

        Ok(mu)
    }

    /// The HashML-DSA message representative: Algorithm 7, line 6, over the 𝑀′ of Algorithm 4,
    /// line 23, which carries the pre-hash `ph` and the DER-encoded OID of the hash that produced
    /// it. `ctx` longer than 255 bytes is the error of Algorithm 4, line 1 (and Algorithm 5,
    /// line 1).
    pub fn compute_mu_ph(
        tr: &[u8; MLDSA_TR_LEN],
        ctx: Option<&[u8]>,
        oid_der: &[u8],
        ph: &[u8],
    ) -> Result<[u8; MLDSA_MU_LEN], SignatureError> {
        let ctx = ctx.unwrap_or(&[]);

        // Algorithm 4
        // 1: if |𝑐𝑡𝑥| > 255 then
        if ctx.len() > 255 {
            return Err(SignatureError::LengthError("ctx value is longer than 255 bytes"));
        }

        // Algorithm 7
        // 6: 𝜇 ← H(BytesToBits(𝑡𝑟)||𝑀', 64)
        let mut h = H::new();
        h.do_update(tr);

        // Algorithm 4
        // 23: 𝑀' ← BytesToBits(IntegerToBytes(1, 1) ∥ IntegerToBytes(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥 ∥ OID ∥ PH𝑀)
        // all done together
        h.do_update(&[1u8]);
        h.do_update(&[ctx.len() as u8]);
        h.do_update(ctx);
        h.do_update(oid_der);
        h.do_update(ph);

        let mut mu = [0u8; MLDSA_MU_LEN];
        let bytes_written = h.into_squeezer().do_output_out(&mut mu);
        debug_assert_eq!(bytes_written, MLDSA_MU_LEN);

        Ok(mu)
    }

    /// This function requires the public key hash `tr`, which can be computed from the public key
    /// using `MLDSAPublicKeyTrait::compute_tr`.
    pub fn do_init(tr: &[u8; MLDSA_TR_LEN], ctx: Option<&[u8]>) -> Result<Self, SignatureError> {
        let ctx = match ctx {
            Some(ctx) => ctx,
            None => &[],
        };

        // Algorithm 2
        // 1: if |𝑐𝑡𝑥| > 255 then
        if ctx.len() > 255 {
            return Err(SignatureError::LengthError("ctx value is longer than 255 bytes"));
        }

        // Algorithm 7
        // 6: 𝜇 ← H(BytesToBits(𝑡𝑟)||𝑀', 64)
        let mut mb = Self { h: H::new() };
        mb.h.do_update(tr);

        // Algorithm 2
        // 10: 𝑀′ ← BytesToBits(IntegerToBytes(0, 1) ∥ IntegerToBytes(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥) ∥ 𝑀
        // all done together
        mb.h.do_update(&[0u8]);
        mb.h.do_update(&[ctx.len() as u8]);
        mb.h.do_update(ctx);

        // now ready to absorb M
        Ok(mb)
    }

    /// Stream a chunk of the message.
    pub fn do_update(&mut self, msg_chunk: &[u8]) {
        self.h.do_update(msg_chunk);
    }

    /// Finalize and return the mu value.
    pub fn do_final(self) -> [u8; MLDSA_MU_LEN] {
        // Completion of
        // Algorithm 7
        // 6: 𝜇 ← H(BytesToBits(𝑡𝑟)||𝑀 ′, 64)
        let mut mu = [0u8; MLDSA_MU_LEN];
        self.h.into_squeezer().do_output_out(&mut mu);

        mu
    }
}

/// The length, in bytes, of a serialized state of a [`MuBuilder`] object.
pub const SUSPENDED_MU_BUILDER_STATE_LEN: usize = SUSPENDED_SHA3_STATE_LEN;

/// If you are processing a large input message into ML-DSA and want to pause the operation
/// -- maybe while waiting for slow network IO), you'll need to use [`Suspendable`].
/// Serialization of the state of an in-progress ML-DSA instance is really just serialization
/// of the construction of the message representative mu, since no other part of the ML-DSA algorithm
/// has a pausable state.
// A [MuBuilder]'s (and by virtue, an ML-DSA instance's) entire mutable state is its inner SHAKE256 sponge,
// so serialization delegates directly to [SHAKE256]'s [SerializableState] impl.
impl Suspendable<SUSPENDED_SHA3_STATE_LEN> for MuBuilder {
    fn suspend(self) -> [u8; SUSPENDED_SHA3_STATE_LEN] {
        self.h.suspend()
    }

    fn from_suspended(
        serialized_state: [u8; SUSPENDED_SHA3_STATE_LEN],
    ) -> Result<Self, SuspendableError> {
        Ok(MuBuilder { h: H::from_suspended(serialized_state)? })
    }
}
