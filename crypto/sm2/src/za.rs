//! `ZA` computation: GB/T 32918.2-2016 §5.5 (the draft's §5.1.4.4), `ZA = SM3(ENTLA || IDA || a ||
//! b || xG || yG || xA || yA)` -- the identity-and-domain-parameter digest that binds an SM2
//! signature to a specific signer's identity `IDA` and public key `(xA, yA)`, distinct from §6.1
//! steps A1-A2's `e = SM3(ZA || M)` hash of the actual message. `ENTLA` is `IDA`'s bit length as a
//! 2-byte big-endian integer; `a`,
//! `b`, `xG`, `yG`, `xA`, `yA` are each encoded as fixed-width 32-byte big-endian octets, matching
//! this curve's field size.
//!
//! Verified (in Python, not checked in) against the draft's own Appendix A.2 worked example before
//! any of this was written: `IDA = "ALICE123@YAHOO.COM"` (18 ASCII bytes) gives `ENTLA = 0x0090`
//! (144 bits), and every intermediate byte string this module builds -- `ENTLA || IDA`, then each
//! domain/key coordinate appended -- was checked against the draft's own printed values, as was the
//! resulting `ZA`. That worked example uses a different (illustrative) curve than the "recommended
//! parameters" curve `bouncycastle_ec::hazmat::sm2` implements, so this only validates the
//! algorithm and byte-encoding, not this crate's own domain constants -- those are separately
//! validated in `bouncycastle-ec`'s own SM2 tests.

use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::Hash;
use bouncycastle_ec::hazmat::sm2::{P_LIMBS, Sm2FieldElement};
use bouncycastle_ec::hazmat::sm2_domain::{B_LIMBS, G_X_LIMBS, G_Y_LIMBS};
use bouncycastle_ec::hazmat::sm2_sec1::be_bytes_from_limbs;
use bouncycastle_ec::nat;
use bouncycastle_sm3::SM3;

/// `a = p - 3` (`draft-shen-sm2-ecdsa-02` Appendix D), computed here rather than exposed by
/// [`bouncycastle_ec::hazmat::sm2_domain`]: SM2's own curve arithmetic never needs the literal
/// value of `a` (it bakes the `a = -3` shortcut directly into its doubling formula -- see
/// `bouncycastle_ec::hazmat::sm2_point`'s docs), but `ZA`'s definition below does.
fn a_limbs() -> [u64; 4] {
    let (diff, borrow) = nat::sub(&P_LIMBS, &[3, 0, 0, 0]);
    debug_assert_eq!(borrow, 0, "p > 3, so p - 3 never borrows");
    diff
}

/// Computes `ZA` for the given identity `id` and public key affine coordinates
/// (GB/T 32918.2-2016 §5.5). Returns [`SignatureError::GenericError`] if `id`'s bit length
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

// `ZA` is an intermediate the public API never exposes -- only its effect on `e`, and so on the
// signature, is observable -- so these known answers for `compute` itself are a unit test under
// the QUALITY_AND_STYLE.md private-function, known-answer exception. The first three are from an
// independent Python computation of GB/T 32918.2-2016 S5.5 over the public keys of the
// `sm2_kat_tests.rs` vectors; the fourth is BouncyCastle Java's `SM2SignerTest` vector.
#[cfg(test)]
mod tests {
    use super::*;
    use bouncycastle_ec::hazmat::sm2_sec1::limbs_from_be_bytes;

    fn fe(hex: &str) -> Sm2FieldElement {
        Sm2FieldElement::from_limbs(limbs_from_be_bytes(
            &bouncycastle_hex::decode(hex).unwrap().try_into().unwrap(),
        ))
    }

    #[test]
    fn compute_matches_known_answers() {
        let cases: [(&str, &str, &[u8], &str); 4] = [
            (
                "17b937e7b5d2d00ceaec4ff25c6b74eaa57c8b67518fb630ec28ac04faf97f24",
                "71fa5c9eb79214b79568b2597a3c87fe8d3c0fb9a96b3cc36594bff402218fb1",
                b"ALICE123@YAHOO.COM",
                "bab69c9204aadd3d49ff244e8fdffb204e1d4249e36855f06a912abd81ddf167",
            ),
            (
                "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
                "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0",
                b"",
                "c13adcc1829f563f2a01ef3c4e0685647bf32a650a35273443150d44f5809ff8",
            ),
            (
                "6d06baebf91d46e720c2a37f59ae6a070efdc56aa79be2c992e9bed2af4706bf",
                "8a8c2b9d86f05a6fb94ba694cf0ea5bcaf48020fcd22cdef90c118b522b3a9d1",
                b"user@example.com",
                "65052e995e872be0fb904d14ba6c2550a70d751e4dccf3c7a700c4588852e215",
            ),
            (
                "d03d30dd01ca3422aeaccf9b88043b554659d3092b0a9e8cce3e8c4530a98cb7",
                "9d705e6213eee145b748e36e274e5f101dc10d7bbc9dab9a04022e73b76e02cd",
                b"sm2test@example.com",
                "ad1c1335ec4bd951cbb4a2144b8247b78fbe47efce2203086f968be8b730393d",
            ),
        ];
        for (qx, qy, id, za_hex) in cases {
            let za = compute(id, &fe(qx), &fe(qy)).unwrap();
            assert_eq!(bouncycastle_hex::encode(za), za_hex);
        }
    }
}
