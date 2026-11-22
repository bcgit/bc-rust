//! SM3 carries `CollisionResistantHash`, the marker a signature's hash needs.

use bouncycastle_core_test_framework::hash::test_collision_resistant_hash;
use bouncycastle_digest::sm3::SM3;

#[test]
fn sm3_carries_the_marker() {
    test_collision_resistant_hash::<SM3>();
}
