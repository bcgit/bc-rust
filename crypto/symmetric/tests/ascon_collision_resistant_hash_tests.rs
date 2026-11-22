//! Ascon-Hash256 carries `CollisionResistantHash`, the marker a signature's hash needs; the
//! XOFs, which have no fixed digest length, do not.

use bouncycastle_core_test_framework::assert_not_collision_resistant_hash;
use bouncycastle_core_test_framework::hash::test_collision_resistant_hash;
use bouncycastle_symmetric::ascon::{AsconCXof128, AsconHash256, AsconXof128};

#[test]
fn the_hash_carries_the_marker() {
    test_collision_resistant_hash::<AsconHash256>();
}

#[test]
fn the_xofs_do_not() {
    assert_not_collision_resistant_hash!(AsconXof128);
    assert_not_collision_resistant_hash!(AsconCXof128);
}
