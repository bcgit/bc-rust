//! SHA-1 does not carry `CollisionResistantHash`, the marker a signature's hash needs.

use bouncycastle_core_test_framework::assert_not_collision_resistant_hash;
use bouncycastle_digest::sha1::SHA1;

#[test]
fn sha1_does_not_carry_the_marker() {
    assert_not_collision_resistant_hash!(SHA1);
}
