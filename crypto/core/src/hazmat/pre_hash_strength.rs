//! [`waive_pre_hash_strength_rule`]: the value a pre-hash wrapper type opts out with.

use crate::signature_key::PreHashStrengthRule;

/// The [`PreHashStrengthRule`] that opts a type out, for the
/// [`HashAlgParams::PRE_HASH_STRENGTH_RULE`](crate::traits::HashAlgParams::PRE_HASH_STRENGTH_RULE)
/// of a wrapper type that a caller names in order to pre-hash with a hash weaker than the
/// signature scheme's parameter set. A hash function does not use it.
///
/// # 🚨 Security Considerations 🚨
///
/// A signature over a digest is no stronger than the hash that made the digest. A scheme that
/// honours the waiver signs and verifies with whatever hash the type wraps, so the type must be
/// one a caller cannot name by accident, documented as lowering the signature's strength.
pub const fn waive_pre_hash_strength_rule() -> PreHashStrengthRule {
    PreHashStrengthRule::WAIVED
}
