//! `ZA` computation: `draft-shen-sm2-ecdsa-02` §5.1.2, `ZA = SM3(ENTLA || IDA || a || b || xG || yG
//! || xA || yA)` -- the identity-and-domain-parameter digest that binds an SM2 signature to a
//! specific signer's identity `IDA` and public key `(xA, yA)`, distinct from §5.1.3's `e = SM3(ZA ||
//! M)` hash of the actual message. `ENTLA` is `IDA`'s bit length as a 2-byte big-endian integer; `a`,
//! `b`, `xG`, `yG`, `xA`, `yA` are each encoded as fixed-width 32-byte big-endian octets, matching
//! this curve's field size.
//!
//! Verified (in Python, not checked in) against the draft's own Appendix A.2 worked example before
//! any of this was written: `IDA = "ALICE123@YAHOO.COM"` (18 ASCII bytes) gives `ENTLA = 0x0090`
//! (144 bits), and every intermediate byte string this module builds -- `ENTLA || IDA`, then each
//! domain/key coordinate appended -- was checked against the draft's own printed values, as was the
//! resulting `ZA`. That worked example uses a different (illustrative) curve than the "recommended
//! parameters" curve `bouncycastle_ec::sm2` implements, so this only validates the algorithm and
//! byte-encoding, not this crate's own domain constants -- those are separately validated in
//! `bouncycastle-ec`'s own SM2 tests.

use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::Hash;
use bouncycastle_ec::nat;
use bouncycastle_ec::sm2::{P_LIMBS, Sm2FieldElement};
use bouncycastle_ec::sm2_domain::{B_LIMBS, G_X_LIMBS, G_Y_LIMBS};
use bouncycastle_ec::sm2_sec1::be_bytes_from_limbs;
use bouncycastle_sm3::SM3;

/// `a = p - 3` (`draft-shen-sm2-ecdsa-02` Appendix D), computed here rather than exposed by
/// [`bouncycastle_ec::sm2_domain`]: SM2's own curve arithmetic never needs the literal value of `a`
/// (it bakes the `a = -3` shortcut directly into its doubling formula -- see
/// `bouncycastle_ec::sm2_point`'s docs), but `ZA`'s definition below does.
fn a_limbs() -> [u64; 4] {
    let (diff, borrow) = nat::sub(&P_LIMBS, &[3, 0, 0, 0]);
    debug_assert_eq!(borrow, 0, "p > 3, so p - 3 never borrows");
    diff
}

/// Computes `ZA` for the given identity `id` and public key affine coordinates
/// (`draft-shen-sm2-ecdsa-02` §5.1.2). Returns [`SignatureError::GenericError`] if `id`'s bit length
/// doesn't fit in 16 bits, the limit `ENTLA`'s 2-byte encoding imposes.
pub fn compute(
    id: &[u8],
    x: &Sm2FieldElement,
    y: &Sm2FieldElement,
) -> Result<[u8; 32], SignatureError> {
    let bit_len = id
        .len()
        .checked_mul(8)
        .ok_or(SignatureError::GenericError("SM2 identity too long: bit length overflows usize"))?;
    let entla: u16 = bit_len.try_into().map_err(|_| {
        SignatureError::GenericError("SM2 identity too long: ENTLA must fit in 16 bits")
    })?;

    let mut hash = SM3::new();
    hash.do_update(&entla.to_be_bytes());
    hash.do_update(id);
    hash.do_update(&be_bytes_from_limbs(&a_limbs()));
    hash.do_update(&be_bytes_from_limbs(&B_LIMBS));
    hash.do_update(&be_bytes_from_limbs(&G_X_LIMBS));
    hash.do_update(&be_bytes_from_limbs(&G_Y_LIMBS));
    hash.do_update(&be_bytes_from_limbs(&x.to_limbs()));
    hash.do_update(&be_bytes_from_limbs(&y.to_limbs()));

    let mut za = [0u8; 32];
    hash.do_final_out(&mut za);
    Ok(za)
}
