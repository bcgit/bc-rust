use bouncycastle_ec::nat;

#[test]
fn add_no_carry() {
    let a: [u64; 4] = [1, 2, 3, 4];
    let b: [u64; 4] = [10, 20, 30, 40];
    let (sum, carry) = nat::add(&a, &b);
    assert_eq!(sum, [11, 22, 33, 44]);
    assert_eq!(carry, 0);
}

#[test]
fn add_with_ripple_carry() {
    let a: [u64; 4] = [u64::MAX, u64::MAX, u64::MAX, 0];
    let b: [u64; 4] = [1, 0, 0, 0];
    let (sum, carry) = nat::add(&a, &b);
    // 0xff..f, 0xff..f, 0xff..f, 0 + 1 -> carries all the way through the first three limbs
    assert_eq!(sum, [0, 0, 0, 1]);
    assert_eq!(carry, 0);
}

#[test]
fn add_with_carry_out() {
    let a: [u64; 4] = [u64::MAX; 4];
    let b: [u64; 4] = [1, 0, 0, 0];
    let (sum, carry) = nat::add(&a, &b);
    assert_eq!(sum, [0, 0, 0, 0]);
    assert_eq!(carry, 1);
}

#[test]
fn sub_no_borrow() {
    let a: [u64; 4] = [10, 20, 30, 40];
    let b: [u64; 4] = [1, 2, 3, 4];
    let (diff, borrow) = nat::sub(&a, &b);
    assert_eq!(diff, [9, 18, 27, 36]);
    assert_eq!(borrow, 0);
}

#[test]
fn sub_with_ripple_borrow() {
    let a: [u64; 4] = [0, 0, 0, 1];
    let b: [u64; 4] = [1, 0, 0, 0];
    let (diff, borrow) = nat::sub(&a, &b);
    assert_eq!(diff, [u64::MAX, u64::MAX, u64::MAX, 0]);
    assert_eq!(borrow, 0);
}

#[test]
fn sub_with_borrow_out() {
    let a: [u64; 4] = [0, 0, 0, 0];
    let b: [u64; 4] = [1, 0, 0, 0];
    let (diff, borrow) = nat::sub(&a, &b);
    assert_eq!(diff, [u64::MAX; 4]);
    assert_eq!(borrow, 1);
}

#[test]
fn add_sub_are_inverses() {
    let a: [u64; 4] =
        [0x1122334455667788, 0x99aabbccddeeff00, 0x0102030405060708, 0x0f0e0d0c0b0a0908];
    let b: [u64; 4] =
        [0xfedcba9876543210, 0x0123456789abcdef, 0xdeadbeefcafebabe, 0x1234567890abcdef];
    let (sum, carry) = nat::add(&a, &b);
    let (back, borrow) = nat::sub(&sum, &b);
    assert_eq!(back, a);
    // whatever carry add produced, subtracting b back out produces the matching borrow
    assert_eq!(borrow, carry);
}

#[test]
fn is_zero() {
    assert!(nat::is_zero(&[0u64; 4]).to_bool());
    assert!(!nat::is_zero(&[1, 0, 0, 0]).to_bool());
    assert!(!nat::is_zero(&[0, 0, 0, 1]).to_bool());
    assert!(!nat::is_zero(&[0, 0, 1, 0]).to_bool());
}
