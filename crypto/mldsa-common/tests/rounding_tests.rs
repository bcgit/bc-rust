//! The branch-free forms of `make_hint` and `Polynomial::check_norm` against the comparisons they
//! replace, over every input the signer can feed them.

use bouncycastle_mldsa_common::aux_functions::make_hint;
use bouncycastle_mldsa_common::params::{MLDSA44Params, MLDSA65Params, MLDSAParamsBase};
use bouncycastle_mldsa_common::polynomial::Polynomial;
use bouncycastle_mldsa_common::q;

/// `make_hint` as the comparisons of its doc comment, which are FIPS 204 Algorithm 39 in the
/// reference implementation's (low, high) form.
fn make_hint_by_comparison<P: MLDSAParamsBase>(low: i32, high: i32) -> i32 {
    if low <= P::gamma2 || low > q - P::gamma2 || (low == q - P::gamma2 && high == 0) {
        0
    } else {
        1
    }
}

fn make_hint_grid<P: MLDSAParamsBase>() {
    let high_max = (q - 1) / (2 * P::gamma2);
    for high in [0, 1, 2, high_max - 1, high_max] {
        for low in 0..q {
            assert_eq!(
                make_hint::<P>(low, high),
                make_hint_by_comparison::<P>(low, high),
                "low {low} high {high}"
            );
        }
    }
}

#[test]
fn make_hint_matches_the_comparisons_for_gamma2_88() {
    make_hint_grid::<MLDSA44Params>();
}

#[test]
fn make_hint_matches_the_comparisons_for_gamma2_32() {
    make_hint_grid::<MLDSA65Params>();
}

/// `check_norm` as FIPS 204 reads it: true when any |coefficient| >= bound.
fn check_norm_by_comparison(p: &Polynomial, bound: i32) -> bool {
    (0..256).any(|i| p[i].abs() >= bound)
}

#[test]
fn check_norm_matches_the_comparison_at_every_index_and_edge() {
    let bounds = [
        MLDSA44Params::gamma1_minus_beta,
        MLDSA44Params::gamma2_minus_beta,
        MLDSA44Params::gamma2,
        MLDSA65Params::gamma1_minus_beta,
        MLDSA65Params::gamma2_minus_beta,
        MLDSA65Params::gamma2,
        1,
    ];
    for bound in bounds {
        for i in 0..256 {
            for v in [bound - 1, bound, bound + 1, -(bound - 1), -bound, -(bound + 1), 0] {
                let mut p = Polynomial::new();
                p[i] = v;
                assert_eq!(
                    p.check_norm(bound),
                    check_norm_by_comparison(&p, bound),
                    "bound {bound} index {i} value {v}"
                );
            }
        }
    }
}

#[test]
fn check_norm_matches_the_comparison_on_mixed_polynomials() {
    // A small LCG so the test needs no RNG crate; values spread over (-q, q).
    let mut x: u32 = 0x2545_F491;
    let mut next = || {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        (x % (2 * q as u32)) as i32 - q
    };
    let bound = MLDSA44Params::gamma1_minus_beta;
    for _ in 0..200 {
        let mut p = Polynomial::new();
        for i in 0..256 {
            // Mostly in range, so that both outcomes occur.
            p[i] = next() % bound;
        }
        if next() & 1 == 0 {
            p[(next().unsigned_abs() % 256) as usize] = next();
        }
        assert_eq!(p.check_norm(bound), check_norm_by_comparison(&p, bound));
    }
}
