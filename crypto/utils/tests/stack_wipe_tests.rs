//! What the stack wipes do to the stack is checked by `dev_scripts/check_*_stack.sh`; these tests
//! pin what a caller sees: the wrapped computation's result, and that a wipe returns.

use bouncycastle_utils::stack_wipe::{
    WipeStackBelowOnDrop, WipeStackBelowScaledOnDrop, in_wiped_frame, in_wiped_frame_scaled,
    wipe_stack_below, wipe_stack_below_scaled,
};

#[test]
fn in_wiped_frame_returns_the_result() {
    let mut calls = 0;
    let r = in_wiped_frame::<64, _>(|| {
        calls += 1;
        [7u8; 40]
    });
    assert_eq!(r, [7u8; 40]);
    assert_eq!(calls, 1);

    let mut calls = 0;
    let r = in_wiped_frame_scaled::<[u64; 4], 3, 64, _>(|| {
        calls += 1;
        Ok::<_, ()>([9u64; 6])
    });
    assert_eq!(r, Ok([9u64; 6]));
    assert_eq!(calls, 1);
}

#[test]
fn wipes_and_guards_return() {
    wipe_stack_below::<512>();
    wipe_stack_below_scaled::<[u64; 4], 30, 240>();
    wipe_stack_below_scaled::<u64, 0, 1>();
    {
        let _wipe = WipeStackBelowOnDrop::<128>;
        let _scaled = WipeStackBelowScaledOnDrop::<[u64; 8], 2, 16>::new();
    }
}
