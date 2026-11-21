//! `hazmat::WithoutCollisionResistance<H>`: `H` in everything it computes and reports, with the
//! `CollisionResistantHash` marker `H` lacks.

use bouncycastle_core::errors::HashError;
use bouncycastle_core::hazmat::{WithoutCollisionResistance, waive_pre_hash_strength_rule};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::{PreHash, PreHashStrengthRule};
use bouncycastle_core::traits::{
    Algorithm, AlgorithmInfo, AlgorithmOID, CollisionResistantHash, FinishToken, Hash,
    HashAlgParams, HashOneShot,
};

/// A stand-in for a hash, with every reported value distinct so that a swapped delegation shows:
/// the digest is the XOR of the input bytes, then their count, and a partial byte's bits are
/// folded into the first.
#[derive(Clone, Default)]
struct Toy<const WAIVED: bool> {
    xor: u8,
    count: u8,
}

impl<const WAIVED: bool> Algorithm for Toy<WAIVED> {
    const ALG_NAME: &'static str = "Toy";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_112bit;
}

impl<const WAIVED: bool> HashAlgParams for Toy<WAIVED> {
    const OUTPUT_LEN: usize = 2;
    const BLOCK_LEN: usize = 7;
    const PRE_HASH_STRENGTH_RULE: PreHashStrengthRule =
        if WAIVED { waive_pre_hash_strength_rule() } else { PreHashStrengthRule::ENFORCED };
}

impl<const WAIVED: bool> AlgorithmOID for Toy<WAIVED> {
    const OID: &'static [u32] = &[1, 2, 3];
    const OID_DER: &'static [u8] = &[0x06, 0x02, 0x2a, 0x03];
}

impl<const WAIVED: bool> Hash for Toy<WAIVED> {
    fn block_bitlen(&self) -> usize {
        56
    }

    fn output_len(&self) -> usize {
        2
    }

    fn do_update(&mut self, data: &[u8]) {
        for b in data {
            self.xor ^= b;
            self.count = self.count.wrapping_add(1);
        }
    }

    fn finish_into(&mut self, _token: &FinishToken, output: &mut [u8]) -> usize {
        output.fill(0);
        output[..2].copy_from_slice(&[self.xor, self.count]);
        2
    }

    fn finish_partial_bits_into(
        &mut self,
        token: &FinishToken,
        partial_byte: u8,
        num_bits: usize,
        output: &mut [u8],
    ) -> Result<usize, HashError> {
        if num_bits > 7 {
            return Err(HashError::InvalidLength("num_bits must be in 0..=7"));
        }
        self.xor ^= partial_byte >> (8 - num_bits as u32).min(7);
        Ok(self.finish_into(token, output))
    }
}

impl<const WAIVED: bool> HashOneShot for Toy<WAIVED> {}

type Wrapped<const WAIVED: bool> = WithoutCollisionResistance<Toy<WAIVED>>;

fn is_collision_resistant<H: CollisionResistantHash>() {}
fn is_pre_hash<H: PreHash>() {}

#[test]
fn the_wrapper_carries_the_marker() {
    is_collision_resistant::<Wrapped<false>>();
    is_collision_resistant::<WithoutCollisionResistance<Wrapped<false>>>();
    is_pre_hash::<Wrapped<false>>();
}

#[test]
fn the_wrapper_reports_the_hash_it_wraps() {
    assert_eq!(Wrapped::<false>::ALG_NAME, "Toy");
    assert_eq!(Wrapped::<false>::MAX_SECURITY_STRENGTH, SecurityStrength::_112bit);
    assert_eq!(Wrapped::<false>::OUTPUT_LEN, 2);
    assert_eq!(Wrapped::<false>::BLOCK_LEN, 7);
    assert_eq!(Wrapped::<false>::OID, &[1, 2, 3]);
    assert_eq!(Wrapped::<false>::OID_DER, &[0x06, 0x02, 0x2a, 0x03]);

    let h = Wrapped::<false>::default();
    assert_eq!(h.alg_name(), "Toy");
    assert_eq!(h.max_security_strength(), SecurityStrength::_112bit);
    assert_eq!(h.block_bitlen(), 56);
    assert_eq!(h.output_len(), 2);
}

#[test]
fn the_wrapper_passes_the_strength_rule_through() {
    assert!(!Wrapped::<false>::PRE_HASH_STRENGTH_RULE.is_waived());
    assert!(Wrapped::<true>::PRE_HASH_STRENGTH_RULE.is_waived());
}

#[test]
fn the_wrapper_computes_what_the_hash_does() {
    let msg = b"\x01\x02\x04\x10 and the rest";
    let expected = Toy::<false>::hash(msg);
    assert_eq!(expected.len(), 2);
    assert_ne!(expected, [0, 0]);
    assert_eq!(Wrapped::<false>::hash(msg), expected);

    // streamed, into a buffer
    let mut h = Wrapped::<false>::default();
    h.do_update(&msg[..3]);
    h.do_update(&msg[3..]);
    let mut out = [0xffu8; 4];
    assert_eq!(h.do_final_out(&mut out), 2);
    assert_eq!(out[..2], expected[..]);
    assert_eq!(out[2..], [0, 0]);

    // a clone carries the absorbed prefix
    let mut h = Wrapped::<false>::default();
    h.do_update(&msg[..5]);
    let mut fork = h.clone();
    h.do_update(&msg[5..]);
    fork.do_update(&msg[5..]);
    assert_eq!(h.do_final(), expected);
    assert_eq!(fork.do_final(), expected);
}

#[test]
fn the_wrapper_passes_partial_bits_and_their_error_through() {
    let mut bare = Toy::<false>::default();
    bare.do_update(b"abc");
    let expected = bare.do_final_partial_bits(0b1010_0000, 3).unwrap();
    assert_ne!(expected, Toy::<false>::hash(b"abc"));

    let mut h = Wrapped::<false>::default();
    h.do_update(b"abc");
    assert_eq!(h.do_final_partial_bits(0b1010_0000, 3).unwrap(), expected);

    let mut out = [0u8; 2];
    assert!(matches!(
        Wrapped::<false>::default().do_final_partial_bits_out(0, 8, &mut out),
        Err(HashError::InvalidLength(_))
    ));
}
