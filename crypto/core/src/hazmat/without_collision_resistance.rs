//! [`WithoutCollisionResistance`]: the wrapper that lets a hash without the
//! [`CollisionResistantHash`] marker produce a signature.

use crate::errors::HashError;
use crate::security_strength::SecurityStrength;
use crate::signature_key::PreHashStrengthRule;
use crate::traits::{
    Algorithm, AlgorithmOID, CollisionResistantHash, FinishToken, Hash, HashAlgParams, HashOneShot,
};

/// The hash `H`, accepted where a signature is produced although `H` is not a
/// [`CollisionResistantHash`]: naming `WithoutCollisionResistance<H>` as a signing key's hash is
/// the caller's statement that a signature over a hash whose collision resistance is broken is
/// what they mean to make.
///
/// It is `H` in everything else: the same digest, lengths, name, OID,
/// [`MAX_SECURITY_STRENGTH`](Algorithm::MAX_SECURITY_STRENGTH) and
/// [`PRE_HASH_STRENGTH_RULE`](HashAlgParams::PRE_HASH_STRENGTH_RULE). The algorithm is therefore
/// the one over `H`: a signature made with `WithoutCollisionResistance<H>` is the bytes `H` would
/// give, and it verifies under a key over `H` alone, which needs no wrapper.
///
/// ```text
/// let sk = ECDSAPrivateKey::<P256, RIPEMD160>::from_bytes(d)?;
/// sk.sign_deterministic(msg, None);                               // does not compile
/// let sk = sk.with_hash::<WithoutCollisionResistance<RIPEMD160>>();
/// let sig = sk.sign_deterministic(msg, None)?;
/// ECDSAPublicKey::<P256, RIPEMD160>::from_bytes(q)?.verify(msg, None, &sig)?;
/// ```
///
/// # 🚨 Security Considerations 🚨
///
/// A signature made through this wrapper says nothing an attacker who can find collisions in `H`
/// cannot make it say: of two colliding messages, the signature of one is a valid signature of
/// the other. It exists for reproducing test vectors and for a protocol that still requires such
/// a signature, the case SP 800-131A Rev. 2 Section 9 leaves open: "SHA-1 may only be used for
/// digital signature generation where specifically allowed by NIST protocol-specific guidance.
/// For all other applications, SHA-1 is disallowed for digital signature generation." Whether a
/// protocol allows it is the caller's to establish. Verifying needs no wrapper.
#[derive(Clone, Default)]
pub struct WithoutCollisionResistance<H> {
    hash: H,
}

/// The claim the wrapper exists to make, on the caller's say-so.
impl<H: Hash + Algorithm> CollisionResistantHash for WithoutCollisionResistance<H> {}

/// The name and the strength are `H`'s: the algorithm is the one over `H`.
impl<H: Algorithm> Algorithm for WithoutCollisionResistance<H> {
    const ALG_NAME: &'static str = H::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = H::MAX_SECURITY_STRENGTH;
}

impl<H: HashAlgParams> HashAlgParams for WithoutCollisionResistance<H> {
    const OUTPUT_LEN: usize = H::OUTPUT_LEN;
    const BLOCK_LEN: usize = H::BLOCK_LEN;
    // Passed through, so that a strength waiver inside this wrapper is still one.
    const PRE_HASH_STRENGTH_RULE: PreHashStrengthRule = H::PRE_HASH_STRENGTH_RULE;
}

impl<H: AlgorithmOID> AlgorithmOID for WithoutCollisionResistance<H> {
    const OID: &'static [u32] = H::OID;
    const OID_DER: &'static [u8] = H::OID_DER;
}

impl<H: Hash + Algorithm> Hash for WithoutCollisionResistance<H> {
    fn block_bitlen(&self) -> usize {
        self.hash.block_bitlen()
    }

    fn output_len(&self) -> usize {
        self.hash.output_len()
    }

    fn do_update(&mut self, data: &[u8]) {
        self.hash.do_update(data)
    }

    fn finish_into(&mut self, token: &FinishToken, output: &mut [u8]) -> usize {
        self.hash.finish_into(token, output)
    }

    fn finish_partial_bits_into(
        &mut self,
        token: &FinishToken,
        partial_byte: u8,
        num_bits: usize,
        output: &mut [u8],
    ) -> Result<usize, HashError> {
        self.hash.finish_partial_bits_into(token, partial_byte, num_bits, output)
    }
}

impl<H: HashOneShot + Algorithm> HashOneShot for WithoutCollisionResistance<H> {}
