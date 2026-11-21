//! [`ConstStr`]: concatenation in a `const`, read back as `&'static str`, including through a
//! generic type's associated constant, which is the use it exists for.

use bouncycastle_utils::const_str::ConstStr;

trait Named {
    const NAME: &'static str;
}
struct P256;
impl Named for P256 {
    const NAME: &'static str = "P256";
}
struct Brainpool;
impl Named for Brainpool {
    const NAME: &'static str = "brainpoolP512r1";
}

struct Alg<C>(core::marker::PhantomData<C>);
impl<C: Named> Alg<C> {
    const NAME: ConstStr<32> = ConstStr::concat(&["ECC-CDH-", C::NAME]);
    const ALG_NAME: &'static str = Self::NAME.as_str();
}

fn name<C: Named>() -> &'static str {
    Alg::<C>::ALG_NAME
}

#[test]
fn concatenates_through_a_generic_associated_const() {
    assert_eq!(name::<P256>(), "ECC-CDH-P256");
    assert_eq!(name::<Brainpool>(), "ECC-CDH-brainpoolP512r1");
}

#[test]
fn exact_fit_empty_and_length() {
    const EXACT: ConstStr<5> = ConstStr::concat(&["ab", "", "cde"]);
    assert_eq!(EXACT.as_str(), "abcde");
    assert_eq!(EXACT.len(), 5);
    assert!(!EXACT.is_empty());
    const EMPTY: ConstStr<4> = ConstStr::concat(&[]);
    assert_eq!(EMPTY.as_str(), "");
    assert!(EMPTY.is_empty());
    const SPARE: ConstStr<16> = ConstStr::concat(&["x"]);
    assert_eq!(SPARE.as_str(), "x");
    assert_eq!(SPARE.len(), 1);
}

#[test]
fn multibyte_parts_stay_valid_utf8() {
    const S: ConstStr<16> = ConstStr::concat(&["🚨", "-", "ü"]);
    assert_eq!(S.as_str(), "🚨-ü");
}

#[test]
fn decimal_digits_of_a_number() {
    const ZERO: ConstStr<1> = ConstStr::decimal(0);
    assert_eq!(ZERO.as_str(), "0");
    const ONE_DIGIT: ConstStr<8> = ConstStr::decimal(7);
    assert_eq!(ONE_DIGIT.as_str(), "7");
    const SALT: ConstStr<8> = ConstStr::decimal(32);
    assert_eq!(SALT.as_str(), "32");
    assert_eq!(SALT.len(), 2);
    const EXACT: ConstStr<3> = ConstStr::decimal(100);
    assert_eq!(EXACT.as_str(), "100");
    const MAX: ConstStr<20> = ConstStr::decimal(usize::MAX);
    assert_eq!(MAX.as_str(), "18446744073709551615");
    const IN_NAME: ConstStr<32> =
        ConstStr::concat(&["-MGF1-SHA256-", ConstStr::<8>::decimal(32).as_str()]);
    assert_eq!(IN_NAME.as_str(), "-MGF1-SHA256-32");
}
