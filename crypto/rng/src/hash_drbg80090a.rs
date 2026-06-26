//! Implements Hash_DRBG (Deterministic Random Bit Generator) from NIST SP 800-90Ar1.

// This is here cause HashDRBG80090AParams is private on purpose so that people can't instantiate new parameter sets other than the ones prescribed by NIST.
#![allow(private_bounds)]

use crate::Sp80090ADrbg;

use bouncycastle_core::errors::{KeyMaterialError, RNGError};
use bouncycastle_core::key_material::{
    KeyMaterial512, KeyMaterialTrait, KeyType, do_hazardous_operations,
};
use bouncycastle_core::traits::{Hash, HashAlgParams, RNG, SecurityStrength};
use bouncycastle_sha2::{SHA256, SHA512};
use bouncycastle_utils::min;

use std::fmt::{Display, Formatter};

enum SupportedHash {
    SHA256,
    SHA512,
}

// By not making this pub, nobody else should be able to impl it;
// ie the structs defined below will be the only allowed ones.
trait HashDRBG80090AParams {
    const HASH: SupportedHash;
    // const OUT_LEN: usize;
    const MAX_SECURITY_STRENGTH: SecurityStrength;
    // const SEED_LEN: usize;
    const MAX_LENGTH: u64;
    const MAX_PERSONALIZATION_STRING_LENGTH: u64;
    const MAX_ADDITIONAL_INPUT_LENGTH: u64;
    const MAX_NUMBER_OF_BITS_PER_REQUEST: u64;
    const RESEED_INTERVAL: u64;
}

#[allow(non_camel_case_types)]
pub struct HashDRBG80090AParams_SHA256 {}

impl HashDRBG80090AParams for HashDRBG80090AParams_SHA256 {
    const HASH: SupportedHash = SupportedHash::SHA256;
    // const OUT_LEN: usize = 64;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
    // const SEED_LEN: usize = 440 / 8;
    const MAX_LENGTH: u64 = (1u64 << 35) / 8; // 2^35 bits
    const MAX_PERSONALIZATION_STRING_LENGTH: u64 = (1u64 << 35) / 8; // 2^35 bits
    const MAX_ADDITIONAL_INPUT_LENGTH: u64 = (1u64 << 35) / 8; // 2^35 bits
    const MAX_NUMBER_OF_BITS_PER_REQUEST: u64 = (1u64 << 19) / 8; // 2^19 bits
    const RESEED_INTERVAL: u64 = 1u64 << 48; // 2^48 requests
}

#[allow(non_camel_case_types)]
pub struct HashDRBG80090AParams_SHA512 {}
impl HashDRBG80090AParams for HashDRBG80090AParams_SHA512 {
    const HASH: SupportedHash = SupportedHash::SHA512;
    // const OUT_LEN: usize = 64;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
    // const SEED_LEN: usize = 888 / 8;
    const MAX_LENGTH: u64 = (1u64 << 35) / 8; // 2^35 bits
    const MAX_PERSONALIZATION_STRING_LENGTH: u64 = (1u64 << 35) / 8; // 2^35 bits
    const MAX_ADDITIONAL_INPUT_LENGTH: u64 = (1u64 << 35) / 8; // 2^35 bits
    const MAX_NUMBER_OF_BITS_PER_REQUEST: u64 = (1u64 << 19) / 8; // 2^19 bits
    const RESEED_INTERVAL: u64 = 1u64 << 48; // 2^48 requests
}

// TODO: is there a rustacious way to extract this from HASH?
const LARGEST_HASHER_OUTPUT_LEN: usize = 64;

#[allow(private_bounds)]
/// Implementation of the Hash_DRBG algorithm as specified in NIST SP 800-90Ar1.
pub struct HashDRBG80090A<H: HashDRBG80090AParams> {
    _phantom: core::marker::PhantomData<H>,
    // Rust is stupid. What's the point of having a generic parameter if we can't use constants inside it?
    // state: WorkingState<H::SEED_LEN>,
    state: WorkingState<LARGEST_HASHER_OUTPUT_LEN>,
    admin_info: AdministrativeInfo,
}

struct WorkingState<const SEED_LEN: usize> {
    v: [u8; SEED_LEN],
    c: [u8; SEED_LEN],

    /// s 8.3: "A count of the number of requests produced since the instantiation was seeded or reseeded."
    reseed_counter: u64,
}

struct AdministrativeInfo {
    strength: SecurityStrength,
    prediction_resistance: bool,
    instantiated: bool,
}

impl<const SEED_LEN: usize> Drop for WorkingState<SEED_LEN> {
    fn drop(&mut self) {
        // zeroize
        self.v.fill(0u8);
        self.c.fill(0u8);
        self.reseed_counter = 0;
    }
}

/// Explicit implementation of Display that prevents auto-generated ones from accidentally leaking secrets.
impl<const SEED_LEN: usize> Display for WorkingState<SEED_LEN> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "HashDRBG80090A::WorkingState::<{}>", SEED_LEN)
    }
}

#[test]
/// impl Display to not print the state data.
fn test_working_state_display() {
    let ws = WorkingState::<32> { v: [0u8; 32], c: [0u8; 32], reseed_counter: 0 };
    assert_eq!(format!("{}", ws), "HashDRBG80090A::WorkingState::<32>");
}

impl<H: HashDRBG80090AParams> HashDRBG80090A<H> {
    /// Creates a new instance using the local OS RNG as a source of seed entropy.
    /// Alias for [HashDRBG80090A::new_from_os].
    pub fn new() -> Self {
        Self::new_from_os()
    }

    /// Creates a new, uninstantiated instance. After creating it, you must call instantiate() to seed it.
    ///
    /// **WARNING: Dangerous! This constructor does not initialize the DRBG from any entropy source,
    /// and relies on you to provide a strong seed.**
    pub fn new_unititialized() -> Self {
        Self {
            _phantom: core::marker::PhantomData,
            state: WorkingState::<LARGEST_HASHER_OUTPUT_LEN> {
                v: [0u8; LARGEST_HASHER_OUTPUT_LEN],
                c: [0u8; LARGEST_HASHER_OUTPUT_LEN],
                reseed_counter: 0,
            },
            admin_info: AdministrativeInfo {
                strength: H::MAX_SECURITY_STRENGTH,
                prediction_resistance: false,
                instantiated: false,
            },
        }
    }

    /// Creates a new instance using the local OS RNG as a source of seed entropy.
    pub fn new_from_os() -> Self {
        let mut seed = KeyMaterial512::new();
        do_hazardous_operations(&mut seed, |seed| {
            seed.set_key_type(KeyType::Seed).unwrap();
            match H::HASH {
                SupportedHash::SHA256 => {
                    getrandom::fill(&mut seed.ref_to_bytes_mut().unwrap()[..32]).unwrap();
                    seed.set_key_len(32).unwrap();
                    seed.set_security_strength(SecurityStrength::_128bit).unwrap();
                }
                SupportedHash::SHA512 => {
                    getrandom::fill(&mut seed.ref_to_bytes_mut().unwrap()).unwrap();
                    seed.set_key_len(64).unwrap();
                    seed.set_security_strength(SecurityStrength::_256bit).unwrap();
                }
            }
            Ok(())
        })
        .unwrap();

        let mut rng = Self::new_unititialized();
        let ss = seed.security_strength().clone();
        rng.instantiate(false, seed, &KeyMaterial512::new(), "new_from_os".as_bytes(), ss).unwrap();
        rng
    }
}

impl<H: HashDRBG80090AParams> Default for HashDRBG80090A<H> {
    /// Creates a new instance using the local OS RNG as a source of seed entropy.
    /// Alias for [HashDRBG80090A::new_from_os].
    fn default() -> Self {
        Self::new_from_os()
    }
}

impl<H: HashDRBG80090AParams> Sp80090ADrbg for HashDRBG80090A<H> {
    /// Output:
    /// 1. initial_working_state: The initial values for V, C, and reseed_counter (see Section 10.1.1.1).
    fn instantiate(
        &mut self,
        prediction_resistance: bool,
        seed: impl KeyMaterialTrait,
        nonce: &impl KeyMaterialTrait,
        personalization_string: &[u8],
        security_strength: SecurityStrength,
    ) -> Result<(), RNGError> {
        // Hash_DRBG Instantiate Process:
        // 1. seed_material = entropy_input || nonce || personalization_string.
        // 2. seed = Hash_df (seed_material, seedlen).
        // 3. V = seed.
        // 4. C = Hash_df ((0x00 || V), seedlen). Comment: Precede V with a byte of zeros.
        // 5. reseed_counter = 1.
        // 6. Return (V, C, reseed_counter).

        if self.admin_info.instantiated {
            return Err(RNGError::GenericError(
                "This DRBG instance has already been instantiated.",
            ));
        }

        // todo: take this out once supported
        if prediction_resistance {
            todo!("Prediction resistance is not yet supported by Hash_DRBG80090A.")
        }

        if personalization_string.len() as u64 > H::MAX_PERSONALIZATION_STRING_LENGTH {
            return Err(RNGError::GenericError(
                "Personalization string exceeds the maximum length allowed by the DRBG instance",
            ));
        }

        if seed.key_type() != KeyType::Seed {
            return Err(KeyMaterialError::InvalidKeyType("RNG seed must be KeyType::Seed"))?;
        }

        if (seed.key_len() as u32) < security_strength.as_int() / 8 {
            return Err(KeyMaterialError::SecurityStrength(
                "Provided seed must have a length that matches or exceeds the DRBG security strength.",
            ))?;
        }
        if (seed.key_len() as u64) > H::MAX_LENGTH {
            return Err(KeyMaterialError::SecurityStrength(
                "Provided seed exceeds the maximum seed length.",
            ))?;
        }
        // On purpose not checking the SecurityStrength field of the seed, because we assume it's pure entropy and hasn't been touched by any actual algoritms yet.
        if security_strength > H::MAX_SECURITY_STRENGTH {
            return Err(KeyMaterialError::SecurityStrength(
                "Requested security strength exceeds the maximum strength that this DRBG instance can provide.",
            ))?;
        }

        // 1. seed_material = entropy_input || nonce || personalization_string.
        // 2. seed = Hash_df (seed_material, seedlen).
        // 3. V = seed.
        match H::HASH {
            SupportedHash::SHA256 => hash_df::<SHA256>(
                seed.ref_to_bytes(),
                nonce.ref_to_bytes(),
                personalization_string,
                &[0u8; 0],
                &mut self.state.v,
            ),
            SupportedHash::SHA512 => hash_df::<SHA512>(
                seed.ref_to_bytes(),
                nonce.ref_to_bytes(),
                personalization_string,
                &[0u8; 0],
                &mut self.state.v,
            ),
        }

        // 4. C = Hash_df ((0x00 || V), seedlen). Comment: Precede V with a byte of zeros.
        match H::HASH {
            SupportedHash::SHA256 => {
                hash_df::<SHA256>(&[0u8], &self.state.v, &[0u8; 0], &[0u8; 0], &mut self.state.c)
            }
            SupportedHash::SHA512 => {
                hash_df::<SHA512>(&[0u8], &self.state.v, &[0u8; 0], &[0u8; 0], &mut self.state.c)
            }
        }

        // 5. reseed_counter = 1.
        self.state.reseed_counter = 1;
        self.admin_info.strength = min(&security_strength, &H::MAX_SECURITY_STRENGTH).clone();
        self.admin_info.prediction_resistance = prediction_resistance;
        self.admin_info.instantiated = true;

        // 6. Return (V, C, reseed_counter).
        Ok(())
    }

    fn reseed(
        &mut self,
        seed: &impl KeyMaterialTrait,
        additional_input: &[u8],
    ) -> Result<(), RNGError> {
        // Hash_DRBG Reseed Process:
        // 1. seed_material = 0x01 || V || entropy_input || additional_input.
        // 2. seed = Hash_df (seed_material, seedlen).
        // 3. V = seed.
        // 4. C = Hash_df ((0x00 || V), seedlen). Comment: Preceed with a byte of all zeros.
        // 5. reseed_counter = 1.
        // 6. Return (V, C, and reseed_counter).

        if !self.admin_info.instantiated {
            return Err(RNGError::Uninitialized);
        }

        if additional_input.len() as u64 > H::MAX_ADDITIONAL_INPUT_LENGTH {
            return Err(RNGError::GenericError(
                "Additional input exceeds the maximum length allowed by the DRBG instance",
            ));
        }

        if seed.key_type() != KeyType::Seed {
            return Err(KeyMaterialError::InvalidKeyType("RNG seed must be KeyType::Seed"))?;
        }

        // On purpose not checking the SecurityStrength field of the seed, because we assume it's pure entropy and hasn't been touched by any actual algoritms yet.

        if (seed.key_len() as u32) < self.admin_info.strength.as_int() / 8 {
            return Err(KeyMaterialError::SecurityStrength(
                "Provided seed must have a length that matches or exceeds the DRBG security strength.",
            ))?;
        }
        if (seed.key_len() as u64) > H::MAX_LENGTH {
            return Err(KeyMaterialError::SecurityStrength(
                "Provided seed exceeds the maximum seed length.",
            ))?;
        }

        // 1. seed_material = 0x01 || V || entropy_input || additional_input.
        // 2. seed = Hash_df (seed_material, seedlen).
        // 3. V = seed.
        match H::HASH {
            SupportedHash::SHA256 => hash_df::<SHA256>(
                &[0x01],
                &self.state.v.clone(),
                seed.ref_to_bytes(),
                additional_input,
                &mut self.state.v,
            ),
            SupportedHash::SHA512 => hash_df::<SHA512>(
                &[0x01],
                &self.state.v.clone(),
                seed.ref_to_bytes(),
                additional_input,
                &mut self.state.v,
            ),
        }

        // 4. C = Hash_df ((0x00 || V), seedlen). Comment: Preceed with a byte of all zeros.
        match H::HASH {
            SupportedHash::SHA256 => {
                hash_df::<SHA256>(&[0u8], &self.state.v, &[0u8; 0], &[0u8; 0], &mut self.state.c)
            }
            SupportedHash::SHA512 => {
                hash_df::<SHA512>(&[0u8], &self.state.v, &[0u8; 0], &[0u8; 0], &mut self.state.c)
            }
        }

        // 5. reseed_counter = 1.
        self.state.reseed_counter = 1;

        // 6. Return (V, C, and reseed_counter).
        Ok(())
    }

    fn generate(&mut self, additional_input: &[u8], len: usize) -> Result<Vec<u8>, RNGError> {
        let mut out = vec![0u8; len];
        self.generate_out(additional_input, &mut out)?;
        Ok(out)
    }

    fn generate_out(&mut self, additional_input: &[u8], out: &mut [u8]) -> Result<usize, RNGError> {
        // Hash_DRBG_Generate Process:
        // 1. If reseed_counter > reseed_interval, then return an indication that a reseed is required.
        // 2. If (additional_input ≠ Null), then do
        //   2.1 w = Hash (0x02 || V || additional_input).
        //   2.2 V = (V + w) mod 2^seedlen.
        // 3. (returned_bits) = Hashgen (requested_number_of_bits, V).
        // 4. H = Hash (0x03 || V).
        // 5. V = (V + H + C + reseed_counter) mod 2^seedlen.
        // 6. reseed_counter = reseed_counter + 1.
        // 7. Return (SUCCESS, returned_bits, V, C, reseed_counter).

        if !self.admin_info.instantiated {
            return Err(RNGError::Uninitialized);
        }
        if out.len() as u64 > H::MAX_NUMBER_OF_BITS_PER_REQUEST {
            return Err(RNGError::GenericError(
                "Requested number of bits exceeds the maximum number of bits per request allowed by the DRBG instance",
            ));
        }
        if additional_input.len() as u64 > H::MAX_ADDITIONAL_INPUT_LENGTH {
            return Err(RNGError::GenericError(
                "Additional input exceeds the maximum length allowed by the DRBG instance",
            ));
        }

        // 1. If reseed_counter > reseed_interval, then return an indication that a reseed is required.
        if self.state.reseed_counter > H::RESEED_INTERVAL {
            return Err(RNGError::ReseedRequired);
        }

        out.fill(0);

        // 2. If (additional_input ≠ Null), then do
        //   2.1 w = Hash (0x02 || V || additional_input).
        //   2.2 V = (V + w) mod 2^seedlen.
        if additional_input.len() > 0 {
            match H::HASH {
                SupportedHash::SHA256 => {
                    let mut h = SHA256::new();
                    h.do_update(&[0x02]);
                    h.do_update(&self.state.v);
                    h.do_update(additional_input);

                    let mut w = [0u8; SHA256::OUTPUT_LEN];
                    h.do_final_out(&mut w);
                    add_to_array(&mut self.state.v, &w);
                }
                SupportedHash::SHA512 => {
                    let mut h = SHA512::new();
                    h.do_update(&[0x02]);
                    h.do_update(&self.state.v);
                    h.do_update(additional_input);

                    let mut w = [0u8; SHA512::OUTPUT_LEN];
                    h.do_final_out(&mut w);
                    add_to_array(&mut self.state.v, &w);
                }
            }
        }

        // 3. (returned_bits) = Hashgen (requested_number_of_bits, V).
        if out.len() > 0 {
            // If zero bytes of output is requested, we can skip the hashgen step because this step
            // is purely producing output and has no side-effect on the state.
            // But we do want to continue below to roll the state and increment the request counter.
            match H::HASH {
                SupportedHash::SHA256 => {
                    hashgen::<SHA256>(&self.state.v, out);
                }
                SupportedHash::SHA512 => {
                    hashgen::<SHA512>(&self.state.v, out);
                }
            }
        }

        // 4. H = Hash (0x03 || V).
        // let mut h = [0u8; H::OUT_LEN];
        let mut h = [0u8; 64];
        match H::HASH {
            SupportedHash::SHA256 => {
                let mut sha = SHA256::default();
                sha.do_update(&[0x03]);
                sha.do_update(&self.state.v);
                sha.do_final_out(&mut h);
            }
            SupportedHash::SHA512 => {
                let mut sha = SHA512::default();
                sha.do_update(&[0x03]);
                sha.do_update(&self.state.v);
                sha.do_final_out(&mut h);
            }
        };

        // 5. V = (V + H + C + reseed_counter) mod 2^seedlen.
        add_to_array(&mut self.state.v, &h);
        add_to_array(&mut self.state.v, &self.state.c);
        add_to_array(&mut self.state.v, &self.state.reseed_counter.to_le_bytes());

        // 6. reseed_counter = reseed_counter + 1.
        self.state.reseed_counter += 1;

        // 7. Return (SUCCESS, returned_bits, V, C, reseed_counter).
        Ok(out.len())
    }

    fn generate_keymaterial_out(
        &mut self,
        additional_input: &[u8],
        out: &mut impl KeyMaterialTrait,
    ) -> Result<usize, RNGError> {
        let mut ret: Result<usize, RNGError> = Ok(0);
        do_hazardous_operations(out, |out| {
            let out_ref = out.ref_to_bytes_mut()?;
            ret = self.generate_out(additional_input, out_ref);
            Ok(())
        })?;

        let bytes_written = match ret {
            Err(e) => return Err(e),
            Ok(bytes_written) => bytes_written,
        };

        do_hazardous_operations(out, |out| {
            out.set_key_len(bytes_written)?;
            out.set_key_type(KeyType::BytesFullEntropy)?;
            let new_security_strength =
                min(&self.admin_info.strength, &SecurityStrength::from_bits(bytes_written * 8))
                    .clone();
            out.set_security_strength(new_security_strength)?;
            Ok(())
        })?;
        Ok(bytes_written)
    }
}

impl<H: HashDRBG80090AParams> RNG for HashDRBG80090A<H> {
    // TODO: add this back once we figure out how to handle a streaming-style reseed.
    // fn add_seed_bytes(&mut self, additional_seed: &[u8]) -> Result<(), RNGError> {
    //     if !self.admin_info.instantiated { return Err(RNGError::Uninitialized) }
    //
    //     todo!()
    // }

    fn add_seed_keymaterial(
        &mut self,
        additional_seed: impl KeyMaterialTrait,
    ) -> Result<(), RNGError> {
        self.reseed(&additional_seed, "add_seed_keymaterial".as_bytes())
    }

    fn next_int(&mut self) -> Result<u32, RNGError> {
        let mut out = [0u8; 4];
        self.generate_out("next_int".as_bytes(), &mut out)?;
        Ok(u32::from_le_bytes(out))
    }

    fn next_bytes(&mut self, len: usize) -> Result<Vec<u8>, RNGError> {
        self.generate("next_bytes".as_bytes(), len)
    }

    fn next_bytes_out(&mut self, out: &mut [u8]) -> Result<usize, RNGError> {
        out.fill(0);

        self.generate_out("next_bytes_out".as_bytes(), out)
    }

    fn fill_keymaterial_out(&mut self, out: &mut impl KeyMaterialTrait) -> Result<usize, RNGError> {
        self.generate_keymaterial_out("fill_keymaterial".as_bytes(), out)
    }

    fn security_strength(&self) -> SecurityStrength {
        self.admin_info.strength.clone()
    }
}

/*** Internal Helper Functions ***/

/// the hash_df function as defined in SP 800-90Ar1 section 10.3.1.
/// no_of_bits_to_return is the length of the provided output buffer.
/// Because array concatenation is not available in a no_std / no_alloc build, this takes many input parameters. To leave a parameter unused, simply provide an empty array &[0u8;0]
fn hash_df<H: Hash + HashAlgParams + Default>(
    in1: &[u8],
    in2: &[u8],
    in3: &[u8],
    in4: &[u8],
    out: &mut [u8],
) {
    // Note: all lengths here are in bytes, whereas the spec uses bits.

    // // I'm gonna panic! here because this is private and shouldn't get into weird inputs.
    if out.len() > 255 * H::OUTPUT_LEN {
        panic!("hash_df can't produce that much output!")
    }

    out.fill(0);

    // out is "temp" in SP 800-90Ar1
    let no_of_bits_to_return: u32 = (out.len() * 8) as u32;
    let len = u32::div_ceil(out.len() as u32, H::OUTPUT_LEN as u32);
    let mut counter: u8 = 0x01;

    // note: this could probably be performance optimized a tiny bit by pulling no_of_bits_to_return.to_le_bytes() out of the loop
    // and by merging i and counter into the same variable.
    for i in 1..len {
        let mut h = H::default();
        h.do_update(&counter.to_le_bytes());
        h.do_update(&no_of_bits_to_return.to_le_bytes());
        h.do_update(in1);
        h.do_update(in2);
        h.do_update(in3);
        h.do_update(in4);
        h.do_final_out(&mut out[((i - 1) as usize) * H::OUTPUT_LEN..(i as usize) * H::OUTPUT_LEN]);

        counter += 1;
    }

    // Handle the last block separately since not all of it will fit in the output buffer.
    // First, do we even need to do a last block, or was the requested number of bits already a multiple of the output length?
    let bytes_written = (len - 1) as usize * H::OUTPUT_LEN;
    let remainder = out.len() - bytes_written;
    if remainder != 0 {
        let mut h = H::default();
        h.do_update(&counter.to_le_bytes());
        h.do_update(&no_of_bits_to_return.to_le_bytes());
        h.do_update(in1);
        h.do_update(in2);
        h.do_update(in3);
        h.do_update(in4);

        // I don't understand rust
        // let mut temp = [0u8; H::OUTPUT_LEN];
        let mut temp = [0u8; 64];
        h.do_final_out(&mut temp);

        // Copy only what we need from the last block.
        out[bytes_written..].copy_from_slice(&temp[..remainder]);
    }
}

#[test]
fn test_hash_df() {
    // success case
    let mut out = [0u8; 100];
    hash_df::<SHA256>(&[0x01, 0x02, 0x03], &[0x04, 0x05], &[0x06, 0x07], &[0x08, 0x09], &mut out);
    assert_ne!(out, [0u8; 100]);
    // repeatability test
    // println!("out: {:?}", out);
    assert_eq!(
        out,
        [
            150u8, 177u8, 87u8, 145u8, 138u8, 4u8, 164u8, 14u8, 162u8, 43u8, 159u8, 152u8, 121u8,
            117u8, 6u8, 18u8, 253u8, 84u8, 41u8, 64u8, 40u8, 209u8, 16u8, 176u8, 106u8, 115u8,
            172u8, 193u8, 246u8, 228u8, 208u8, 79u8, 37u8, 31u8, 134u8, 141u8, 200u8, 7u8, 42u8,
            199u8, 229u8, 236u8, 236u8, 186u8, 28u8, 87u8, 200u8, 14u8, 127u8, 36u8, 132u8, 23u8,
            36u8, 150u8, 23u8, 215u8, 247u8, 121u8, 175u8, 82u8, 99u8, 187u8, 235u8, 25u8, 213u8,
            18u8, 106u8, 22u8, 4u8, 99u8, 1u8, 184u8, 211u8, 160u8, 177u8, 67u8, 78u8, 181u8, 69u8,
            51u8, 117u8, 2u8, 72u8, 36u8, 134u8, 72u8, 2u8, 9u8, 105u8, 149u8, 136u8, 35u8, 81u8,
            114u8, 142u8, 80u8, 94u8, 42u8, 85u8, 155
        ]
    );

    // Test success with out.len() at the maximum allowed for SHA256 (255 * 32 = 8160)
    let mut out_max_sha256 = vec![0u8; 255 * 32];
    hash_df::<SHA256>(&[0x01], &[0x02], &[0x03], &[0x04], &mut out_max_sha256);
    assert_ne!(out_max_sha256, vec![0u8; 255 * 32]);

    // Test panic with out.len() exceeding the maximum for SHA256
    let mut out_too_large_sha256 = vec![0u8; 255 * 32 + 1];
    let result_sha256 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        hash_df::<SHA256>(&[0x01], &[0x02], &[0x03], &[0x04], &mut out_too_large_sha256);
    }));
    assert!(result_sha256.is_err());

    // Test success with out.len() at the maximum allowed for SHA512 (255 * 64 = 16320)
    let mut out_max_sha512 = vec![0u8; 255 * 64];
    hash_df::<SHA512>(&[0x01], &[0x02], &[0x03], &[0x04], &mut out_max_sha512);
    assert_ne!(out_max_sha512, vec![0u8; 255 * 64]);
    // make sure the last block got written to
    assert_ne!(out_max_sha512[254 * 64..], [0u8; 64]);

    // Test panic with out.len() exceeding the maximum for SHA512
    let mut out_too_large_sha512 = vec![0u8; 255 * 64 + 1];
    let result_sha512 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        hash_df::<SHA512>(&[0x01], &[0x02], &[0x03], &[0x04], &mut out_too_large_sha512);
    }));
    assert!(result_sha512.is_err());
}

fn hashgen<H: Hash + HashAlgParams + Default>(v: &[u8], out: &mut [u8]) {
    // Hashgen Process:
    // 1. m = ceil(requested_no_of_bits / outlen)
    // 2. data = V.
    // 3. W = the Null string.
    // 4. For i = 1 to m
    //   4.1 w = Hash (data).
    //   4.2 W = W || w.
    //   4.3 data = (data + 1) mod 2^seedlen.
    // 5. returned_bits = leftmost (W, requested_no_of_bits).
    // 6. Return (returned_bits).

    // 1. m = ceil(requested_no_of_bits / outlen)
    out.fill(0);

    let m = u32::div_ceil(out.len() as u32, H::OUTPUT_LEN as u32);

    // requested_no_of_bits = out.len()
    // let mut data= [0u8; H::OUTPUT_LEN];
    let mut data = [0u8; 64];
    data.copy_from_slice(v);
    // W = out

    // 4. For i = 1 to m
    //   4.1 w = Hash (data).
    //   4.2 W = W || w.
    //   4.3 data = (data + 1) mod 2^seedlen.
    for i in 1..m {
        H::default().hash_out(
            &data,
            &mut out[((i - 1) as usize) * H::OUTPUT_LEN..(i as usize) * H::OUTPUT_LEN],
        );
        add_to_array(&mut data, &[0x01]);
    }

    // Handle the last block separately since not all of it will fit in the output buffer.
    // First, do we even need to do a last block, or was the requested number of bits already a multiple of the output length?
    let bytes_written = (m - 1) as usize * H::OUTPUT_LEN;
    let remainder = out.len() - bytes_written;
    if remainder != 0 {
        // I don't understand rust
        // let mut temp = [0u8; H::OUTPUT_LEN];
        let mut temp = [0u8; 64];
        H::default().hash_out(&data, &mut temp);

        // Copy only what we need from the last block.
        out[bytes_written..].copy_from_slice(&temp[..remainder as usize]);
    }
}

/// This will always add the shorter length byte array mathematically to the
/// longer length byte array.
/// Mathematically, this is
///   longer + shorter (mod longer.len())
/// Be careful....
fn add_to_array(longer: &mut [u8], shorter: &[u8]) {
    if shorter.len() > longer.len() {
        panic!("add_to_array: shorter array is longer than longer array!")
    }

    let mut carry: u8 = 0;

    // Add the overlapping portion
    for i in 1..=shorter.len() {
        let res = (longer[longer.len() - i] as u16)
            + (shorter[shorter.len() - i] as u16)
            + (carry as u16);
        carry = if res > 0xFF { 1 } else { 0 };
        longer[longer.len() - i] = res as u8;
    }

    // Propagate carry through the remaining bytes
    for i in (shorter.len() + 1)..=longer.len() {
        let res = (longer[longer.len() - i] as u16) + (carry as u16);
        carry = if res > 0xFF { 1 } else { 0 };
        longer[longer.len() - i] = res as u8;
    }
}

#[test]
fn test_add_to_array() {
    let mut longer = [0x0F, 0xFF, 0xFF, 0xFF];
    let shorter = [0x01];
    add_to_array(&mut longer, &shorter);
    assert_eq!(longer, [0x10, 0x00, 0x00, 0x00]);

    let mut longer = [0x0F, 0xFF, 0xFE, 0xFE];
    let shorter = [0x01];
    add_to_array(&mut longer, &shorter);
    assert_eq!(longer, [0x0F, 0xFF, 0xFE, 0xFF]);

    let mut longer = [0x0F, 0xFF, 0xFE, 0xFF];
    let shorter = [0x01];
    add_to_array(&mut longer, &shorter);
    assert_eq!(longer, [0x0F, 0xFF, 0xFF, 0x00]);

    let mut longer = [0x1F, 0xFF, 0xFF, 0xFF];
    let shorter = [0xE0, 0x00, 0x00, 0x02];
    add_to_array(&mut longer, &shorter);
    assert_eq!(longer, [0x00, 0x00, 0x00, 0x01]);

    let mut longer = [0xFF];
    let shorter = [0x01];
    add_to_array(&mut longer, &shorter);
    assert_eq!(longer, [0x00]);

    let mut longer = [0x00, 0x01];
    let shorter = [0xFF];
    add_to_array(&mut longer, &shorter);
    assert_eq!(longer, [0x01, 0x00]);

    let mut longer = [0x00, 0x00, 0xFF];
    let shorter = [0x00, 0x01];
    add_to_array(&mut longer, &shorter);
    assert_eq!(longer, [0x00, 0x01, 0x00]);

    let mut longer = [0x00, 0x00, 0xFF];
    let shorter = [0x0C, 0x01];
    add_to_array(&mut longer, &shorter);
    assert_eq!(longer, [0x00, 0x0D, 0x00]);

    let mut longer = [0x00, 0xFF];
    let shorter = [0x00, 0x01];
    add_to_array(&mut longer, &shorter);
    assert_eq!(longer, [0x01, 0x00]);

    let mut longer = [0x00, 0x00, 0xFF];
    let shorter = [0x00, 0x0C, 0x01];
    add_to_array(&mut longer, &shorter);
    assert_eq!(longer, [0x00, 0x0D, 0x00]);

    let mut longer = [0x00, 0x00, 0xFF];
    let shorter = [0x00, 0x0F, 0x01];
    add_to_array(&mut longer, &shorter);
    assert_eq!(longer, [0x00, 0x10, 0x00]);

    let mut longer = [0x00, 0x00, 0xFC];
    let shorter = [0x00, 0x0F, 0x01];
    add_to_array(&mut longer, &shorter);
    assert_eq!(longer, [0x00, 0x0F, 0xFD]);

    let mut longer = [0x00, 0x0F, 0xFC];
    let shorter = [0x00, 0x1F, 0x01];
    add_to_array(&mut longer, &shorter);
    assert_eq!(longer, [0x00, 0x2E, 0xFD]);
}
