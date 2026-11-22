//! The BLAKE2 hashes carry `CollisionResistantHash`, the marker a signature's hash needs.

use bouncycastle_core_test_framework::hash::test_collision_resistant_hash;
use bouncycastle_digest::blake2::{BLAKE2b_512, BLAKE2s_256};

#[test]
fn the_hashes_carry_the_marker() {
    test_collision_resistant_hash::<BLAKE2b_512>();
    test_collision_resistant_hash::<BLAKE2s_256>();
}
