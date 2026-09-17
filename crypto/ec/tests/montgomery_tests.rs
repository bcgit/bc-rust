//! Cross-validation for [`bouncycastle_ec::montgomery`]'s generic `widening_mul`/`redc` against
//! [`P256ScalarField`], whose own hand-written Montgomery arithmetic is already independently
//! verified (KATs, RFC 6979 vectors, wycheproof, and its own mutation-testing pass). `N_PRIME` and
//! `R_SQUARED_LIMBS` below are derived independently (`-n⁻¹ mod 2^64`, `R² mod n` computed directly
//! in Python from `N_LIMBS`, not copied from `p256_scalar`'s own private constants of the same
//! name) -- this is exactly the same shape of check a brand new curve gets, just against a curve
//! whose correct answer is already known, so it validates the generic module itself rather than
//! any particular brainpool curve's own parameters.

use bouncycastle_ec::montgomery::{redc, widening_mul};
use bouncycastle_ec::nat;
use bouncycastle_ec::p256_scalar::{N_LIMBS, P256ScalarField};

const N_PRIME: u64 = 0xccd1c8aaee00bc4f;
const R_SQUARED_LIMBS: [u64; 4] =
    [0x83244c95be79eea2, 0x4699799c49bd6fa6, 0x2845b2392b6bec59, 0x66e12d94f3d95620];
/// `R mod n` (`R = 2^256`), independently computed the same way as `N_PRIME`/`R_SQUARED_LIMBS`
/// above -- used by [`reduce_once`]'s `extra == 1` case exactly as every hand-written per-curve
/// `redc` in this crate uses its own identically-derived constant (e.g.
/// [`bouncycastle_ec::p256_scalar`]'s private `R_LIMBS`).
const R_MOD_N_LIMBS: [u64; 4] =
    [0x0c46353d039cdaaf, 0x4319055258e8617b, 0x0000000000000000, 0x00000000ffffffff];

/// `redc`'s output (`high + extra*R`, proven `< 2n`) reduced to the canonical `< n` value: if
/// `extra == 1`, `high + R_MOD_N_LIMBS` (no further reduction needed, mirroring every per-curve
/// `redc`'s identical final step); otherwise `high`, minus `n` once if `high >= n`.
fn reduce_once((high, extra): ([u64; 4], u64)) -> [u64; 4] {
    if extra == 1 {
        let (sum, _) = nat::add(&high, &R_MOD_N_LIMBS);
        sum
    } else {
        let (diff, borrow) = nat::sub(&high, &N_LIMBS);
        if borrow == 1 { high } else { diff }
    }
}

/// `a * b mod n` via the generic module: `widening_mul`, `redc` (bringing into Montgomery form via
/// `R_SQUARED_LIMBS` first, exactly as [`P256ScalarField::from_limbs`] does), then the same
/// single-conditional-subtraction final step every curve's own `redc` caller performs.
fn generic_mul_via_montgomery_form(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    fn to_montgomery(x: [u64; 4]) -> [u64; 4] {
        let t = widening_mul::<4, 8>(&x, &R_SQUARED_LIMBS);
        reduce_once(redc::<4, 8, 9>(&t, &N_LIMBS, N_PRIME))
    }

    let am = to_montgomery(a);
    let bm = to_montgomery(b);
    let t = widening_mul::<4, 8>(&am, &bm);
    let product_montgomery = reduce_once(redc::<4, 8, 9>(&t, &N_LIMBS, N_PRIME));
    // Converting back out of Montgomery form: REDC of `product_montgomery` placed in the *low*
    // half of a 2L-limb value with a zero high half (i.e. `T = product_montgomery`, `T < R`)
    // computes `T * R^-1 mod n = product_montgomery * R^-1 mod n`, undoing the Montgomery scaling.
    let mut wide = [0u64; 8];
    wide[..4].copy_from_slice(&product_montgomery);
    reduce_once(redc::<4, 8, 9>(&wide, &N_LIMBS, N_PRIME))
}

struct Xorshift64(u64);

impl Xorshift64 {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn next_limbs(&mut self) -> [u64; 4] {
        [self.next_u64(), self.next_u64(), self.next_u64(), self.next_u64()]
    }
}

#[test]
fn generic_montgomery_matches_p256_scalar_field_over_many_pseudorandom_values() {
    let mut rng = Xorshift64(0xA11CE5A11CE5A11C);
    for _ in 0..2000 {
        let a = rng.next_limbs();
        let b = rng.next_limbs();

        let expected = P256ScalarField::from_limbs(a).mul(&P256ScalarField::from_limbs(b));
        let got_limbs = generic_mul_via_montgomery_form(a, b);
        let got = P256ScalarField::from_limbs(got_limbs);
        assert_eq!(got, expected, "a={a:x?} b={b:x?}");
    }
}

#[test]
fn generic_montgomery_matches_p256_scalar_field_worst_case() {
    let n_minus_1 = {
        let mut l = N_LIMBS;
        l[0] -= 1;
        l
    };
    let expected =
        P256ScalarField::from_limbs(n_minus_1).mul(&P256ScalarField::from_limbs(n_minus_1));
    let got = P256ScalarField::from_limbs(generic_mul_via_montgomery_form(n_minus_1, n_minus_1));
    assert_eq!(got, expected);
}
