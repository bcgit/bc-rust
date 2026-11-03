//! `AlgorithmInfo` is the run-time form of `Algorithm`: the blanket impl must report the
//! implementor's constants, and it must be reachable through a trait object (issue #173).

use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, AlgorithmInfo};

struct Toy;

impl Algorithm for Toy {
    const ALG_NAME: &'static str = "Toy";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}

#[test]
fn blanket_impl_reports_the_constants_through_a_trait_object() {
    let info: &dyn AlgorithmInfo = &Toy;
    assert_eq!(info.alg_name(), Toy::ALG_NAME);
    assert_eq!(info.max_security_strength(), Toy::MAX_SECURITY_STRENGTH);
}
