//! `RNGExt::next_array`: `N` bytes off any `RNG`, a trait object included, as the caller-buffer
//! draw would give them, and an error rather than a partly filled array.

use bouncycastle_core::errors::RNGError;
use bouncycastle_core::hazmat::FixedSeedRNG;
use bouncycastle_core::key_material::{KeyMaterial0, KeyMaterial256, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{RNG, RNGExt};
use bouncycastle_rng::hazmat::NewUninitialized;
use bouncycastle_rng::{HashDRBG_SHA256, Sp80090ADrbg};

/// A counting pattern longer than the draws below, so that consecutive draws differ:
/// `FixedSeedRNG` repeats its bytes.
const SEED: [u8; 200] = {
    let mut seed = [0u8; 200];
    let mut i = 0;
    while i < seed.len() {
        seed[i] = i as u8;
        i += 1;
    }
    seed
};

fn drbg() -> HashDRBG_SHA256 {
    let mut drbg = HashDRBG_SHA256::new_uninitialized();
    let seed = KeyMaterial256::from_bytes_as_type(&SEED[..32], KeyType::Seed).unwrap();
    drbg.instantiate(false, seed, &KeyMaterial0::new(), &[], SecurityStrength::_128bit).unwrap();
    drbg
}

/// What `next_bytes_out` delivers on each call, for an RNG that fails or delivers short.
enum Delivers {
    Error,
    OneByteShort,
    Nothing,
}

struct FaultyRNG(Delivers);

impl RNG for FaultyRNG {
    fn add_seed_keymaterial(&mut self, _: &dyn KeyMaterialTrait) -> Result<(), RNGError> {
        Ok(())
    }

    fn next_int(&mut self) -> Result<u32, RNGError> {
        Err(RNGError::Uninitialized)
    }

    fn next_bytes_out(&mut self, out: &mut [u8]) -> Result<usize, RNGError> {
        match self.0 {
            Delivers::Error => {
                // Bytes left behind by a draw that then fails.
                out.fill(0xEE);
                Err(RNGError::ReseedRequired)
            }
            Delivers::OneByteShort => {
                let delivered = out.len().saturating_sub(1);
                out[..delivered].fill(0xEE);
                Ok(delivered)
            }
            Delivers::Nothing => Ok(0),
        }
    }

    fn fill_keymaterial_out(&mut self, _: &mut dyn KeyMaterialTrait) -> Result<usize, RNGError> {
        Err(RNGError::Uninitialized)
    }

    fn security_strength(&self) -> SecurityStrength {
        SecurityStrength::None
    }
}

/// The array holds the bytes `next_bytes_out` gives an identically seeded RNG, draw after draw.
#[test]
fn the_array_is_the_caller_buffer_draw() {
    let (mut by_value, mut by_buffer) = (FixedSeedRNG::new(SEED), FixedSeedRNG::new(SEED));
    let first: [u8; 32] = by_value.next_array().unwrap();
    let second = by_value.next_array::<48>().unwrap();
    let (mut expected_first, mut expected_second) = ([0u8; 32], [0u8; 48]);
    assert_eq!(by_buffer.next_bytes_out(&mut expected_first).unwrap(), 32);
    assert_eq!(by_buffer.next_bytes_out(&mut expected_second).unwrap(), 48);
    assert_eq!(first, expected_first);
    assert_eq!(second, expected_second);
    assert_eq!(first, SEED[..32]);
    assert_eq!(second, SEED[32..80]);
}

#[test]
fn consecutive_draws_differ() {
    let mut rng = FixedSeedRNG::new(SEED);
    let first: [u8; 32] = rng.next_array().unwrap();
    let second: [u8; 32] = rng.next_array().unwrap();
    assert_ne!(first, second);

    let mut rng = drbg();
    let first: [u8; 32] = rng.next_array().unwrap();
    let second: [u8; 32] = rng.next_array().unwrap();
    assert_ne!(first, second);
}

/// A draw of no bytes succeeds and takes nothing from the stream.
#[test]
fn an_empty_array_is_drawn() {
    let mut rng = FixedSeedRNG::new(SEED);
    assert_eq!(rng.next_array::<0>(), Ok([]));
    assert_eq!(rng.next_array::<4>(), Ok([0, 1, 2, 3]));
}

/// The blanket impl covers `dyn RNG`, so the method is there on a trait object, which `RNG`
/// can still be.
#[test]
fn it_is_callable_on_a_trait_object() {
    fn draw(rng: &mut dyn RNG) -> [u8; 16] {
        rng.next_array().unwrap()
    }
    assert_eq!(draw(&mut FixedSeedRNG::new(SEED)), SEED[..16]);

    let (mut by_value, mut by_buffer) = (drbg(), drbg());
    let mut expected = [0u8; 16];
    by_buffer.next_bytes_out(&mut expected).unwrap();
    assert_eq!(draw(&mut by_value), expected);
}

/// A concrete DRBG, at a length over one hash block.
#[test]
fn a_drbg_draws_an_array() {
    let (mut by_value, mut by_buffer) = (drbg(), drbg());
    let drawn: [u8; 100] = by_value.next_array().unwrap();
    let mut expected = [0u8; 100];
    assert_eq!(by_buffer.next_bytes_out(&mut expected).unwrap(), 100);
    assert_eq!(drawn, expected);
    assert_ne!(drawn, [0u8; 100]);
}

/// The RNG's own error is passed on.
#[test]
fn a_failed_draw_is_the_rngs_error() {
    let mut rng = FaultyRNG(Delivers::Error);
    assert_eq!(rng.next_array::<32>(), Err(RNGError::ReseedRequired));
    let mut uninstantiated = HashDRBG_SHA256::new_uninitialized();
    assert_eq!(uninstantiated.next_array::<32>(), Err(RNGError::Uninitialized));
}

/// An RNG that reports fewer bytes than the array holds has not filled it: that is an error,
/// whether it is one byte short or delivered nothing, and through a trait object as well.
#[test]
fn a_short_draw_is_an_error() {
    let mut rng = FaultyRNG(Delivers::OneByteShort);
    assert!(matches!(rng.next_array::<32>(), Err(RNGError::GenericError(_))));
    assert!(matches!(rng.next_array::<1>(), Err(RNGError::GenericError(_))));
    let mut rng = FaultyRNG(Delivers::Nothing);
    assert!(matches!(rng.next_array::<32>(), Err(RNGError::GenericError(_))));
    let rng: &mut dyn RNG = &mut rng;
    assert!(matches!(rng.next_array::<32>(), Err(RNGError::GenericError(_))));
    // No bytes were asked for, so none are missing.
    assert_eq!(rng.next_array::<0>(), Ok([]));
}
