//! `HashAlgParams::PRE_HASH_STRENGTH_RULE`: enforced unless a type overrides it with the value
//! `hazmat::waive_pre_hash_strength_rule` makes, and the override leaves the type's strength alone.

use bouncycastle_core::hazmat::waive_pre_hash_strength_rule;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::PreHashStrengthRule;
use bouncycastle_core::traits::{Algorithm, HashAlgParams};

struct Toy;

impl Algorithm for Toy {
    const ALG_NAME: &'static str = "Toy";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_112bit;
}

impl HashAlgParams for Toy {
    const OUTPUT_LEN: usize = 28;
    const BLOCK_LEN: usize = 64;
}

struct ToyWaived;

impl Algorithm for ToyWaived {
    const ALG_NAME: &'static str = Toy::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = Toy::MAX_SECURITY_STRENGTH;
}

impl HashAlgParams for ToyWaived {
    const OUTPUT_LEN: usize = Toy::OUTPUT_LEN;
    const BLOCK_LEN: usize = Toy::BLOCK_LEN;
    const PRE_HASH_STRENGTH_RULE: PreHashStrengthRule = waive_pre_hash_strength_rule();
}

#[test]
fn the_rule_is_enforced_by_default() {
    assert!(!PreHashStrengthRule::ENFORCED.is_waived());
    assert!(!Toy::PRE_HASH_STRENGTH_RULE.is_waived());
    assert_eq!(Toy::PRE_HASH_STRENGTH_RULE, PreHashStrengthRule::ENFORCED);
}

#[test]
fn the_hazmat_value_waives_it_and_nothing_else() {
    assert!(waive_pre_hash_strength_rule().is_waived());
    assert_ne!(waive_pre_hash_strength_rule(), PreHashStrengthRule::ENFORCED);
    assert!(ToyWaived::PRE_HASH_STRENGTH_RULE.is_waived());
    assert_eq!(ToyWaived::MAX_SECURITY_STRENGTH, SecurityStrength::_112bit);
}
