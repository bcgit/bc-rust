//! The candidate form of `DeriveKeyPair` (RFC 9180 Section 7.1.3), driven through a test group
//! that says which candidates it accepts, so that the rejection loop is exercised: the NIST
//! curves refuse a candidate too rarely for a vector to reach `counter > 0`.
//!
//! ```text
//! while sk == 0 or sk >= order:
//!   if counter > 255:
//!     raise DeriveKeyPairError
//!   bytes = LabeledExpand(dkp_prk, "candidate", I2OSP(counter, 1), Nsk)
//!   bytes[0] = bytes[0] & bitmask
//!   sk = OS2IP(bytes)
//!   counter = counter + 1
//! ```

use bouncycastle_core::errors::{KEMError, KeyAgreementError};
use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, RNG};
use bouncycastle_dhkem::{DHKEM, DHKEMParams, DeriveKeyPairForm};
use bouncycastle_ed::x25519::X25519;
use bouncycastle_utils::secret::Secret;
use std::cell::RefCell;

thread_local! {
    /// Every candidate the group under test has been offered, in order.
    static OFFERED: RefCell<Vec<[u8; 32]>> = const { RefCell::new(Vec::new()) };
}

/// A group whose private keys are 32 bytes, that refuses its first `REFUSE` candidates and
/// records all of them. Only `DeriveKeyPair` is exercised.
struct Picky<const REFUSE: usize>;

impl<const REFUSE: usize> Algorithm for Picky<REFUSE> {
    const ALG_NAME: &'static str = "test group";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

const BITMASK: u8 = 0x0F;

impl<const REFUSE: usize> DHKEMParams<32, 32, 32> for Picky<REFUSE> {
    type PublicKey = [u8; 32];
    type PrivateKey = [u8; 32];
    type KDFHash = <X25519 as DHKEMParams<32, 32, 32>>::KDFHash;
    const KEM_ID: u16 = 0xFFFE;
    const DERIVE_KEY_PAIR: DeriveKeyPairForm = DeriveKeyPairForm::Candidate { bitmask: BITMASK };

    fn private_key_from_bytes(sk: &[u8; 32]) -> Option<[u8; 32]> {
        OFFERED.with_borrow_mut(|offered| {
            offered.push(*sk);
            (offered.len() > REFUSE).then_some(*sk)
        })
    }

    fn pk(sk: &[u8; 32]) -> [u8; 32] {
        sk.map(|b| !b)
    }

    fn with_generated_key_pair<R>(
        _: &mut dyn RNG,
        _: impl FnOnce(&[u8; 32], &[u8; 32]) -> R,
    ) -> Result<R, KEMError> {
        unimplemented!("only DeriveKeyPair is exercised")
    }

    fn dh_into(
        _: &[u8; 32],
        _: &[u8; 32],
        _: &mut Secret<[u8; 32]>,
    ) -> Result<(), KeyAgreementError> {
        unimplemented!("only DeriveKeyPair is exercised")
    }

    fn serialize_public_key(pk: &[u8; 32]) -> [u8; 32] {
        *pk
    }

    fn deserialize_public_key(pkm: &[u8; 32]) -> Result<[u8; 32], KEMError> {
        Ok(*pkm)
    }
}

fn ikm() -> KeyMaterial256 {
    KeyMaterial256::from_bytes_as_type(&[0x5A; 32], KeyType::Seed).unwrap()
}

/// The candidates offered to `Picky<REFUSE>` by one `derive_key_pair`, and its result.
fn derive<const REFUSE: usize>() -> (Vec<[u8; 32]>, Result<([u8; 32], [u8; 32]), KEMError>) {
    OFFERED.with_borrow_mut(Vec::clear);
    let result = DHKEM::<Picky<REFUSE>, 32, 32, 32, 32>::derive_key_pair(&ikm());
    (OFFERED.with_borrow(Vec::clone), result)
}

/// A group that accepts its first candidate is offered exactly one, and that candidate is the
/// key; `pk(sk)` is the group's.
#[test]
fn the_first_accepted_candidate_is_the_key() {
    let (offered, result) = derive::<0>();
    let (pk, sk) = result.unwrap();
    assert_eq!(offered.len(), 1);
    assert_eq!(sk, offered[0]);
    assert_eq!(pk, sk.map(|b| !b));
}

/// Refused candidates are passed over: the loop moves to the next counter, each candidate is a
/// different expansion, and every one has had the bitmask applied to its first byte.
#[test]
fn refused_candidates_are_passed_over() {
    let (first, _) = derive::<0>();
    let (offered, result) = derive::<5>();
    let (_, sk) = result.unwrap();
    assert_eq!(offered.len(), 6, "five refused, the sixth accepted");
    assert_eq!(sk, offered[5]);
    assert_eq!(offered[0], first[0], "counter 0 gives the same candidate whoever asks");
    for (i, candidate) in offered.iter().enumerate() {
        assert_eq!(candidate[0] & !BITMASK, 0, "candidate {i}: the bitmask is applied");
        assert!(candidate[1..].iter().any(|&b| b != 0), "candidate {i} is an expansion");
        assert!(!offered[..i].contains(candidate), "candidate {i} differs from those before it");
    }
}

/// The counter is one byte: the 256th candidate (counter 255) is still tried, and when it too is
/// refused the derivation fails with the RFC's `DeriveKeyPairError`.
#[test]
fn the_256th_candidate_is_the_last() {
    let (offered, result) = derive::<255>();
    assert_eq!(offered.len(), 256);
    assert_eq!(result.unwrap().1, offered[255]);

    let (offered, result) = derive::<256>();
    assert_eq!(offered.len(), 256, "no 257th candidate is drawn");
    assert!(matches!(result, Err(KEMError::KeyGenError(_))));
}
