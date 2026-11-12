//! [`Curve`] on the seven markers: one generic suite, run per curve, checking that the trait's
//! routing agrees with the hazmat modules it names (the order, the generator, key generation,
//! the SEC 1 codec), that the element traits satisfy the field identities, that the three scalar
//! multiplications agree, and that the length table matches the array types at run time as well
//! as in `check_lengths`.

use bouncycastle_core::errors::RNGError;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::RNG;
use bouncycastle_ec::curve::{
    Array, Curve, FieldElement, JacobianPoint, PublicScalar, ScalarFieldElement, SecretScalar,
    private_scalar_from_be_bytes,
};
use bouncycastle_ec::hazmat::{
    bp256r1_domain, bp256r1_keygen, bp256r1_scalar, bp384r1_domain, bp384r1_keygen, bp384r1_scalar,
    bp512r1_domain, bp512r1_keygen, bp512r1_scalar, p256_domain, p256_keygen, p256_scalar,
    p256k1_domain, p256k1_keygen, p256k1_scalar, p384_domain, p384_keygen, p384_scalar,
    p521_domain, p521_keygen, p521_scalar,
};
use bouncycastle_ec::{Bp256r1, Bp384r1, Bp512r1, P256, P384, P521, Secp256K1};
use bouncycastle_rng::FixedSeedRNG;
use bouncycastle_utils::secret::ZeroizablePrimitive;

/// A curve's hazmat keygen at some draw length, for the comparison with the trait's.
type HazmatKeygen<C> =
    fn(
        &mut dyn RNG,
    ) -> Result<(<C as Curve>::Scalar, (<C as Curve>::Fe, <C as Curve>::Fe)), RNGError>;

fn seed() -> [u8; 96] {
    core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
}

fn limbs_of<const L: usize>(low: u64) -> [u64; L] {
    let mut l = [0u64; L];
    l[0] = low;
    l
}

fn affine<C: Curve>(p: &C::Point) -> (C::Fe, C::Fe) {
    p.to_affine().expect("not the identity")
}

/// The whole suite for one curve: `n`, `G` and the keygen are the hazmat module's, handed in so
/// the trait's answers can be compared with them.
fn check<C, const L: usize, const N: usize, const DRAW: usize>(
    n: [u64; L],
    g: ([u64; L], [u64; L]),
    hazmat_keygen: HazmatKeygen<C>,
) where
    C: Curve<Limbs = [u64; L], ScalarBytes = [u8; N]>,
{
    // The table: the run-time twin of `check_lengths`, so a wrong entry is a test failure as
    // well as a compile error.
    assert!(!C::NAME.is_empty());
    assert_eq!(C::STRENGTH, C::RNG_STRENGTH);
    assert_eq!(C::FE_LEN, <C::FeBytes as Array<u8>>::LEN);
    assert_eq!(C::SCALAR_LEN, N);
    assert_eq!(C::SCALAR_LEN, C::ORDER_BITS.div_ceil(8));
    assert_eq!(C::PK_UNCOMPRESSED_LEN, 1 + 2 * C::FE_LEN);
    assert_eq!(C::PK_UNCOMPRESSED_LEN, <C::PkUncompressed as Array<u8>>::LEN);
    assert_eq!(C::PK_COMPRESSED_LEN, 1 + C::FE_LEN);
    assert_eq!(C::PK_COMPRESSED_LEN, <C::PkCompressed as Array<u8>>::LEN);
    assert_eq!(C::SIG_LEN, 2 * C::SCALAR_LEN);
    assert_eq!(C::SIG_LEN, <C::Signature as Array<u8>>::LEN);
    assert!(C::EXTRA_BITS_DRAW_LEN >= C::SCALAR_LEN + 8);
    assert_eq!(C::EXTRA_BITS_DRAW_LEN, DRAW);
    assert_eq!(C::EXTRA_BITS_DRAW_LEN, <C::ExtraBitsDraw as Array<u8>>::LEN);
    assert!(C::MAX_DRBG_OUTPUT_LEN >= C::EXTRA_BITS_DRAW_LEN);
    assert_eq!(<C::Limbs as Array<u64>>::LEN, L);
    assert_eq!(C::N, n);
    let top_bits = 64 - n[L - 1].leading_zeros() as usize;
    assert_eq!(64 * (L - 1) + top_bits, C::ORDER_BITS, "ORDER_BITS is n's bit length");
    assert!(C::MAX_DRBG_OUTPUT_LEN >= C::SCALAR_LEN + 8);

    // The generator and the three multiplications.
    let base = C::base_point();
    assert!(!base.is_infinity().to_bool());
    assert_eq!(affine::<C>(&base), (C::Fe::from_limbs(g.0), C::Fe::from_limbs(g.1)));
    let one = C::Scalar::from_limbs(limbs_of::<L>(1));
    assert_eq!(affine::<C>(&C::multiply_base_point(&one)), affine::<C>(&base));
    for low in [2u64, 3, 0x1234_5678_9abc_def0] {
        let k = C::Scalar::from_limbs(limbs_of::<L>(low));
        let comb = C::multiply_base_point(&k);
        let ladder = C::multiply_point(&k, &base);
        assert_eq!(affine::<C>(&comb), affine::<C>(&ladder));
        assert_eq!(C::public_point(&k), affine::<C>(&comb));
        assert_eq!(comb.affine_x_of_nonidentity(), affine::<C>(&comb).0);
    }
    let u = C::PublicScalar::from_limbs(limbs_of::<L>(5));
    let v = C::PublicScalar::from_limbs(limbs_of::<L>(9));
    let q = C::multiply_base_point(&C::Scalar::from_limbs(limbs_of::<L>(2)));
    // [5]G + [9]([2]G) = [23]G
    let shamir = C::shamir_multiply(&u, &v, &q);
    let expected = C::multiply_base_point(&C::Scalar::from_limbs(limbs_of::<L>(23)));
    assert_eq!(affine::<C>(&shamir), affine::<C>(&expected));
    assert_eq!(affine::<C>(&base.double()), affine::<C>(&base.add(&base)));
    assert!(base.add(&base.negate()).is_infinity().to_bool());
    assert!(C::Point::INFINITY.is_infinity().to_bool());
    assert!(C::Point::INFINITY.to_affine().is_none());
    assert_eq!(
        affine::<C>(&C::Point::from_affine(C::Fe::from_limbs(g.0), C::Fe::from_limbs(g.1))),
        affine::<C>(&base)
    );
    let mut p = base;
    p.zeroize();
    assert_eq!(p.x().to_limbs(), [0; L]);
    assert_eq!(p.y().to_limbs(), [0; L]);
    assert_eq!(p.z().to_limbs(), [0; L]);

    // Field identities through the trait.
    let a = C::Fe::from_limbs(g.0);
    let b = C::Fe::from_limbs(g.1);
    assert_eq!(a.add(&b).sub(&b), a);
    assert_eq!(a.negate().add(&a), C::Fe::ZERO);
    assert_eq!(a.mul(&a.invert()), C::Fe::ONE);
    assert_eq!(a.square(), a.mul(&a));
    assert!(C::Fe::ZERO.is_zero().to_bool());
    assert!(!a.is_zero().to_bool());
    assert_eq!(C::Fe::from_limbs(a.to_limbs()), a);
    let mut limbs = [0u64; L];
    a.to_limbs_into(&mut limbs);
    assert_eq!(limbs, a.to_limbs());
    let mut z = a;
    z.zeroize();
    assert_eq!(z, C::Fe::ZERO);

    // Scalar field identities, and the public scalar's inverse against the constant-time one.
    let k = C::Scalar::from_limbs(limbs_of::<L>(0x1234_5678_9abc_def0));
    let kf = C::ScalarField::from_secret(&k);
    assert_eq!(kf.mul(&kf.invert()), C::ScalarField::ONE);
    assert_eq!(kf.square(), kf.mul(&kf));
    assert_eq!(kf.add(&kf).sub(&kf), kf);
    assert_eq!(kf.negate().add(&kf), C::ScalarField::ZERO);
    assert!(C::ScalarField::ZERO.is_zero().to_bool());
    assert!(!kf.is_zero().to_bool());
    assert_eq!(C::ScalarField::from_limbs(kf.to_limbs()), kf);
    assert_eq!(C::PublicScalar::from_limbs(kf.to_limbs()).invert_vartime(), kf.invert());
    assert_eq!(C::PublicScalar::from_limbs(kf.to_limbs()).to_limbs(), kf.to_limbs());
    let mut zf = kf;
    zf.zeroize();
    assert_eq!(zf, C::ScalarField::ZERO);

    // The secret scalar's two constructors and its encoding.
    let k_limbs = limbs_of::<L>(0x1234_5678_9abc_def0);
    assert_eq!(C::Scalar::from_borrowed_limbs(&k_limbs), C::Scalar::from_limbs(k_limbs));
    let k_bytes = k.to_be_bytes();
    assert_eq!(C::Scalar::from_be_bytes(&k_bytes), k);
    assert_eq!(C::limbs_from_be_bytes(&k_bytes), k_limbs);
    assert_eq!(C::be_bytes_from_limbs(&k_limbs), k_bytes);
    let mut out_limbs = [0u64; L];
    C::limbs_from_be_bytes_into(&k_bytes, &mut out_limbs);
    assert_eq!(out_limbs, k_limbs);
    let mut out_bytes = [0u8; N];
    C::be_bytes_from_limbs_into(&k_limbs, &mut out_bytes);
    assert_eq!(out_bytes, k_bytes);
    // The field element codec is the same bytes on these curves (FE_LEN == SCALAR_LEN).
    assert_eq!(C::fe_be_bytes_from_limbs(&k_limbs).as_ref(), &k_bytes[..]);
    let mut fe_bytes = C::FeBytes::ZEROED;
    C::fe_be_bytes_from_limbs_into(&k_limbs, &mut fe_bytes);
    assert_eq!(fe_bytes.as_ref(), &k_bytes[..]);

    // The range test and the checked private-key load at the edges of [1, n-1].
    let n_minus_1 = {
        let mut l = n;
        l[0] -= 1; // n is odd, so no borrow
        l
    };
    assert!(!C::scalar_in_range(&[0; L]).to_bool());
    assert!(C::scalar_in_range(&limbs_of::<L>(1)).to_bool());
    assert!(C::scalar_in_range(&n_minus_1).to_bool());
    assert!(!C::scalar_in_range(&n).to_bool());
    assert!(!C::scalar_in_range(&[u64::MAX; L]).to_bool());
    assert!(private_scalar_from_be_bytes::<C>(&[0u8; N]).is_none());
    assert_eq!(
        private_scalar_from_be_bytes::<C>(&C::be_bytes_from_limbs(&limbs_of::<L>(1))),
        Some(one.clone())
    );
    assert_eq!(
        private_scalar_from_be_bytes::<C>(&C::be_bytes_from_limbs(&n_minus_1)),
        Some(C::Scalar::from_limbs(n_minus_1))
    );
    assert!(private_scalar_from_be_bytes::<C>(&C::be_bytes_from_limbs(&n)).is_none());
    assert!(private_scalar_from_be_bytes::<C>(&[0xFF; N]).is_none());

    // SEC 1 through the trait: both encodings of G decode to G; a wrong length is refused.
    let (gx, gy) = affine::<C>(&base);
    let uncompressed = C::encode_uncompressed(&gx, &gy);
    assert_eq!(uncompressed.as_ref()[0], 0x04);
    assert_eq!(C::decode(uncompressed.as_ref()), Some((gx, gy)));
    let compressed = C::encode_compressed(&gx, &gy);
    assert!(matches!(compressed.as_ref()[0], 0x02 | 0x03));
    assert_eq!(C::decode(compressed.as_ref()), Some((gx, gy)));
    assert!(C::decode(&uncompressed.as_ref()[..C::PK_UNCOMPRESSED_LEN - 1]).is_none());
    assert!(C::decode(&[]).is_none());

    // Key generation through the trait is the hazmat module's, and applies its strength gate.
    let (d, (x, y)) = C::keygen::<N>(&mut FixedSeedRNG::new(seed())).unwrap();
    let (d2, (x2, y2)) = hazmat_keygen(&mut FixedSeedRNG::new(seed())).unwrap();
    assert_eq!((&d, x, y), (&d2, x2, y2));
    assert!(C::scalar_in_range(&C::limbs_from_be_bytes(&d.to_be_bytes())).to_bool());
    assert_eq!(C::public_point(&d), (x, y));
    // The N + 64 draw is keygen at EXTRA_BITS_DRAW_LEN: compared through the hazmat keygen the
    // caller handed in only where that is its draw length, and against the trait's generic form
    // on every curve.
    let (d3, (x3, y3)) = C::keygen_extra_bits(&mut FixedSeedRNG::new(seed())).unwrap();
    let (d4, (x4, y4)) = C::keygen::<DRAW>(&mut FixedSeedRNG::new(seed())).unwrap();
    assert_eq!((&d3, x3, y3), (&d4, x4, y4));
    assert_eq!(C::public_point(&d3), (x3, y3));
    let mut weak = FixedSeedRNG::new(seed());
    weak.set_security_strength(SecurityStrength::_112bit);
    assert!(matches!(
        C::keygen::<N>(&mut weak),
        Err(RNGError::SecurityStrengthInsufficientForAlgorithm)
    ));
    // The reduction into [1, n-1] of an all-zero and an all-one draw.
    assert_eq!(C::reduce_wide_bits_mod_n_minus_1(&[0u8; 132][..C::MAX_DRBG_OUTPUT_LEN]), one);
    let top = C::reduce_wide_bits_mod_n_minus_1(&[0xFF; N]);
    assert!(C::scalar_in_range(&C::limbs_from_be_bytes(&top.to_be_bytes())).to_bool());
}

#[test]
fn p256() {
    check::<P256, 4, 32, 44>(
        p256_scalar::N_LIMBS,
        (p256_domain::G_X_LIMBS, p256_domain::G_Y_LIMBS),
        p256_keygen::keygen::<32>,
    );
}

#[test]
fn p384() {
    check::<P384, 6, 48, 56>(
        p384_scalar::N_LIMBS,
        (p384_domain::G_X_LIMBS, p384_domain::G_Y_LIMBS),
        p384_keygen::keygen::<48>,
    );
}

#[test]
fn p521() {
    check::<P521, 9, 66, 74>(
        p521_scalar::N_LIMBS,
        (p521_domain::G_X_LIMBS, p521_domain::G_Y_LIMBS),
        p521_keygen::keygen::<66>,
    );
}

#[test]
fn secp256k1() {
    check::<Secp256K1, 4, 32, 40>(
        p256k1_scalar::N_LIMBS,
        (p256k1_domain::G_X_LIMBS, p256k1_domain::G_Y_LIMBS),
        p256k1_keygen::keygen::<32>,
    );
}

#[test]
fn bp256r1() {
    check::<Bp256r1, 4, 32, 40>(
        bp256r1_scalar::N_LIMBS,
        (bp256r1_domain::G_X_LIMBS, bp256r1_domain::G_Y_LIMBS),
        bp256r1_keygen::keygen::<32>,
    );
}

#[test]
fn bp384r1() {
    check::<Bp384r1, 6, 48, 56>(
        bp384r1_scalar::N_LIMBS,
        (bp384r1_domain::G_X_LIMBS, bp384r1_domain::G_Y_LIMBS),
        bp384r1_keygen::keygen::<48>,
    );
}

#[test]
fn bp512r1() {
    check::<Bp512r1, 8, 64, 72>(
        bp512r1_scalar::N_LIMBS,
        (bp512r1_domain::G_X_LIMBS, bp512r1_domain::G_Y_LIMBS),
        bp512r1_keygen::keygen::<64>,
    );
}
