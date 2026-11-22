//! [`AnyStrength`], the pre-hash wrapper that opts out of HashML-DSA's strength rule. Both ML-DSA
//! crates re-export it from their own `hazmat` module.

use bouncycastle_core::errors::HashError;
use bouncycastle_core::hazmat::waive_pre_hash_strength_rule;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::PreHashStrengthRule;
use bouncycastle_core::traits::{
    Algorithm, AlgorithmOID, CollisionResistantHash, FinishToken, Hash, HashAlgParams, HashOneShot,
};

/// The pre-hash `H`, accepted by HashML-DSA with any parameter set: naming `AnyStrength<H>` as
/// the hash of a HashML-DSA key, `as_prehash::<AnyStrength<H>>()`, opts out of the check that
/// otherwise refuses a hash weaker than the parameter set with `SignatureError::PreHashTooWeak`.
///
/// It is `H` in everything else: the same digest, lengths, name, OID and
/// [`MAX_SECURITY_STRENGTH`](Algorithm::MAX_SECURITY_STRENGTH), so a signature made with
/// `AnyStrength<H>` is the signature `H` gives, under the same algorithm name, and each verifies
/// as the other wherever `H` alone is accepted. The algorithm's strength is the weaker of the
/// parameter set's and `H`'s. It exists for interoperability with a peer that uses a weak
/// pairing and for validation testing, where NIST's ACVP vectors pair every approved hash with
/// every parameter set.
///
/// ```text
/// let ph = SHA224::hash(msg);
/// sk.as_prehash::<SHA224>().sign_ph_deterministic(&ph, None);       // ML-DSA-87: PreHashTooWeak
/// let sig = sk.as_prehash::<AnyStrength<SHA224>>().sign_ph_deterministic(&ph, None)?;
/// pk.as_prehash::<AnyStrength<SHA224>>().verify_ph(&ph, None, &sig)?;
/// ```
///
/// # 🚨 Security Considerations 🚨
///
/// FIPS 204 Section 5.4: "In order to maintain the same level of security strength when the
/// content is hashed at the application level or using HashML-DSA, the digest that is signed
/// needs to be generated using an approved hash function or XOF (e.g., from FIPS 180 \[8\] or
/// FIPS 202 \[7\]) that provides at least λ bits of classical security strength against both
/// collision and second preimage attacks \[7, Table 4\]." A signature made through this wrapper
/// with a hash below that is only as strong as the hash: ML-DSA-87 over SHA-224 is a 112-bit
/// signature, whatever the key. A verifier that accepts such a pairing accepts a forgery found
/// by attacking the hash. Whether `H` is an approved hash remains the caller's to ensure.
///
/// The waiver is of the strength rule alone: `AnyStrength<H>` is a
/// [`CollisionResistantHash`], which signing requires, only where `H` is. A hash without that
/// marker signs as `AnyStrength<WithoutCollisionResistance<H>>`, or with the two the other way
/// round, through [`bouncycastle_core::hazmat::WithoutCollisionResistance`].
#[derive(Clone, Default)]
pub struct AnyStrength<H> {
    hash: H,
}

/// Passed through from `H`, not claimed: the strength waiver says nothing of collision resistance.
impl<H: CollisionResistantHash + Algorithm> CollisionResistantHash for AnyStrength<H> {}

/// The name and the strength are `H`'s: the wrapper claims nothing `H` does not.
impl<H: Algorithm> Algorithm for AnyStrength<H> {
    const ALG_NAME: &'static str = H::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = H::MAX_SECURITY_STRENGTH;
}

impl<H: HashAlgParams> HashAlgParams for AnyStrength<H> {
    const OUTPUT_LEN: usize = H::OUTPUT_LEN;
    const BLOCK_LEN: usize = H::BLOCK_LEN;
    // The one difference from `H`, and what the ML-DSA crates' `check_hash_strength` reads.
    const PRE_HASH_STRENGTH_RULE: PreHashStrengthRule = waive_pre_hash_strength_rule();
}

impl<H: AlgorithmOID> AlgorithmOID for AnyStrength<H> {
    const OID: &'static [u32] = H::OID;
    const OID_DER: &'static [u8] = H::OID_DER;
}

impl<H: Hash + Algorithm> Hash for AnyStrength<H> {
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

impl<H: HashOneShot + Algorithm> HashOneShot for AnyStrength<H> {}
