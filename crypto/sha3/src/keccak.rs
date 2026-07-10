use bouncycastle_core::errors::{HashError, SuspendableError};
use bouncycastle_core::key_material::KeyType;
use bouncycastle_core::traits::SecurityStrength;

const KECCAK_ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

#[derive(Clone)]
pub(crate) struct KeccakState {
    buf: [u64; 25],
    rate: usize,
}

impl KeccakState {
    fn new(rate: usize) -> Self {
        Self { buf: [0u64; 25], rate }
    }

    fn absorb(&mut self, data: &[u8]) {
        let count = self.rate >> 6;
        for i in 0..count {
            let mut tmp = [0u8; 8];
            tmp.copy_from_slice(&data[i * 8..(i + 1) * 8]);
            self.buf[i] ^= u64::from_le_bytes(tmp);
        }

        Self::permute(self);
    }

    pub fn permute(a: &mut Self) {
        let [
            mut a00,
            mut a01,
            mut a02,
            mut a03,
            mut a04,
            mut a05,
            mut a06,
            mut a07,
            mut a08,
            mut a09,
            mut a10,
            mut a11,
            mut a12,
            mut a13,
            mut a14,
            mut a15,
            mut a16,
            mut a17,
            mut a18,
            mut a19,
            mut a20,
            mut a21,
            mut a22,
            mut a23,
            mut a24,
        ] = a.buf;

        for round_constant in KECCAK_ROUND_CONSTANTS {
            // theta
            let mut c0 = a00 ^ a05 ^ a10 ^ a15 ^ a20;
            let mut c1 = a01 ^ a06 ^ a11 ^ a16 ^ a21;
            let c2 = a02 ^ a07 ^ a12 ^ a17 ^ a22;
            let c3 = a03 ^ a08 ^ a13 ^ a18 ^ a23;
            let c4 = a04 ^ a09 ^ a14 ^ a19 ^ a24;

            let d0 = c0.rotate_left(1) ^ c3;
            let d1 = c1.rotate_left(1) ^ c4;
            let d2 = c2.rotate_left(1) ^ c0;
            let d3 = c3.rotate_left(1) ^ c1;
            let d4 = c4.rotate_left(1) ^ c2;

            a00 ^= d1;
            a05 ^= d1;
            a10 ^= d1;
            a15 ^= d1;
            a20 ^= d1;
            a01 ^= d2;
            a06 ^= d2;
            a11 ^= d2;
            a16 ^= d2;
            a21 ^= d2;
            a02 ^= d3;
            a07 ^= d3;
            a12 ^= d3;
            a17 ^= d3;
            a22 ^= d3;
            a03 ^= d4;
            a08 ^= d4;
            a13 ^= d4;
            a18 ^= d4;
            a23 ^= d4;
            a04 ^= d0;
            a09 ^= d0;
            a14 ^= d0;
            a19 ^= d0;
            a24 ^= d0;

            // rho/pi
            c1 = a01.rotate_left(1);
            a01 = a06.rotate_left(44);
            a06 = a09.rotate_left(20);
            a09 = a22.rotate_left(61);
            a22 = a14.rotate_left(39);
            a14 = a20.rotate_left(18);
            a20 = a02.rotate_left(62);
            a02 = a12.rotate_left(43);
            a12 = a13.rotate_left(25);
            a13 = a19.rotate_left(8);
            a19 = a23.rotate_left(56);
            a23 = a15.rotate_left(41);
            a15 = a04.rotate_left(27);
            a04 = a24.rotate_left(14);
            a24 = a21.rotate_left(2);
            a21 = a08.rotate_left(55);
            a08 = a16.rotate_left(45);
            a16 = a05.rotate_left(36);
            a05 = a03.rotate_left(28);
            a03 = a18.rotate_left(21);
            a18 = a17.rotate_left(15);
            a17 = a11.rotate_left(10);
            a11 = a07.rotate_left(6);
            a07 = a10.rotate_left(3);
            a10 = c1;

            // chi
            c0 = a00 ^ (!a01 & a02);
            c1 = a01 ^ (!a02 & a03);
            a02 ^= !a03 & a04;
            a03 ^= !a04 & a00;
            a04 ^= !a00 & a01;
            a00 = c0;
            a01 = c1;

            c0 = a05 ^ (!a06 & a07);
            c1 = a06 ^ (!a07 & a08);
            a07 ^= !a08 & a09;
            a08 ^= !a09 & a05;
            a09 ^= !a05 & a06;
            a05 = c0;
            a06 = c1;

            c0 = a10 ^ (!a11 & a12);
            c1 = a11 ^ (!a12 & a13);
            a12 ^= !a13 & a14;
            a13 ^= !a14 & a10;
            a14 ^= !a10 & a11;
            a10 = c0;
            a11 = c1;

            c0 = a15 ^ (!a16 & a17);
            c1 = a16 ^ (!a17 & a18);
            a17 ^= !a18 & a19;
            a18 ^= !a19 & a15;
            a19 ^= !a15 & a16;
            a15 = c0;
            a16 = c1;

            c0 = a20 ^ (!a21 & a22);
            c1 = a21 ^ (!a22 & a23);
            a22 ^= !a23 & a24;
            a23 ^= !a24 & a20;
            a24 ^= !a20 & a21;
            a20 = c0;
            a21 = c1;

            // iota
            a00 ^= round_constant;
        }

        a.buf = [
            a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10, a11, a12, a13, a14, a15, a16,
            a17, a18, a19, a20, a21, a22, a23, a24,
        ];
    }
}

// Mutants note: this fails because you can't write unit tests for drop()
impl Drop for KeccakState {
    fn drop(&mut self) {
        // Zeroize the contents before returning the memory to the OS.
        self.buf.fill(0u64);
    }
}

// This is pub(crate) so that the SerializableState handlers can unpack it.
#[derive(Clone)]
pub(crate) struct KeccakDigest {
    state: KeccakState,
    pub data_queue: [u8; 192],
    rate: usize,
    pub bits_in_queue: usize,
    pub squeezing: bool,
}

#[derive(Clone)]
pub(crate) enum KeccakSize {
    _128 = 128,
    _224 = 224,
    _256 = 256,
    _288 = 288,
    _384 = 384,
    _512 = 512,
}

impl KeccakDigest {
    pub(super) fn new(size: KeccakSize) -> Self {
        let rate = 1600 - ((size as usize) << 1);

        Self {
            state: KeccakState::new(rate),
            data_queue: [0u8; 192],
            rate,
            bits_in_queue: 0,
            squeezing: false,
        }
    }

    pub(super) fn absorb(&mut self, data: &[u8]) {
        if (self.bits_in_queue & 7) != 0 {
            panic!("attempt to absorb with odd length queue");
        }
        if self.squeezing {
            // Maybe this should be an error rather than a panic?
            // But, like, don't write your code to absorb after squeezing.
            panic!("attempt to absorb while squeezing");
        }

        for byte in data {
            self.data_queue[self.bits_in_queue >> 3] = *byte;
            self.bits_in_queue += 8;

            if self.bits_in_queue == self.rate {
                self.state.absorb(&self.data_queue);
                self.bits_in_queue = 0;
            }
        }
    }

    pub(super) fn absorb_bits(&mut self, data: u8, bits: usize) -> Result<(), HashError> {
        if bits == 0 {
            return Ok(());
        }
        if !(1..=7).contains(&bits) {
            return Err(HashError::InvalidLength("bits must be in the range 1 to 7"));
        }
        if (self.bits_in_queue & 7) != 0 {
            return Err(HashError::InvalidState("attempt to absorb with odd length queue"));
        }
        if self.squeezing {
            return Err(HashError::InvalidState("attempt to absorb while squeezing"));
        }

        let mask = (1 << bits) - 1;
        self.data_queue[self.bits_in_queue >> 3] = data & mask;

        // NOTE: After this, bits_in_queue is no longer a multiple of 8, so no more absorbs will work
        self.bits_in_queue += bits;
        self.pad_and_switch_to_squeezing_phase();
        Ok(())
    }

    /// Panics if the output buffer is too small.
    /// Returns the number of bytes written.
    pub(super) fn squeeze(&mut self, out: &mut [u8]) -> usize {
        out.fill(0);

        if !self.squeezing {
            self.pad_and_switch_to_squeezing_phase();
        }
        let output_length = out.len() << 3;

        let mut i = 0;
        while i < output_length {
            if self.bits_in_queue == 0 {
                self.keccak_extract();
            }
            let partial_block = self.bits_in_queue.min(output_length - i);

            let length = partial_block >> 3;
            let start_data_queue = (self.rate - self.bits_in_queue) >> 3;
            let start_output = i >> 3;
            out[start_output..(start_output + length)]
                .copy_from_slice(&self.data_queue[start_data_queue..(start_data_queue + length)]);

            self.bits_in_queue -= partial_block;
            i += partial_block;
        }
        output_length >> 3
    }

    #[inline(always)]
    fn keccak_extract(&mut self) {
        KeccakState::permute(&mut self.state);

        let (chunks, _) = self.data_queue.as_chunks_mut::<8>();

        for (i, chunk) in chunks.iter_mut().enumerate() {
            *chunk = self.state.buf[i].to_le_bytes();
        }

        self.bits_in_queue = self.rate;
    }

    pub(super) fn pad_and_switch_to_squeezing_phase(&mut self) {
        debug_assert!(self.bits_in_queue < self.rate);
        self.data_queue[self.bits_in_queue >> 3] |= (1 << (self.bits_in_queue & 7)) as u8;

        self.bits_in_queue += 1;
        if self.bits_in_queue == self.rate {
            self.state.absorb(&self.data_queue);
        } else {
            let full = self.bits_in_queue >> 6;
            let partial = self.bits_in_queue & 63;
            let mut off = 0;

            for i in 0..full {
                let mut tmp = [0u8; 8];
                tmp.copy_from_slice(&self.data_queue[off..off + 8]);
                self.state.buf[i] ^= u64::from_le_bytes(tmp);
                off += 8;
            }

            let mask = (1 << partial) - 1;

            let mut tmp = [0u8; 8];
            tmp.copy_from_slice(&self.data_queue[off..off + 8]);
            self.state.buf[full] ^= u64::from_le_bytes(tmp) & mask;
        }

        self.state.buf[(self.rate - 1) >> 6] ^= 1 << 63;

        self.bits_in_queue = 0;
        self.squeezing = true;
    }
}

/*** State serialization ***/
//
// The SHA3 and SHAKE public objects have identical state: a [KeccakDigest] plus three pieces of
// KDF metadata. The helpers below serialize that shared state so the `SerializableState` impls in
// `sha3.rs` and `shake.rs` are just thin wrappers that add/check the library version header.

/// Number of bytes needed to serialize a [KeccakDigest]'s mutable state.
///
/// The `rate` is intentionally NOT serialized: it is fully determined by the SHA3/SHAKE variant and
/// is re-supplied at deserialization time (see [KeccakDigest::from_serialized_state]).
///
/// Layout (all integers little-endian):
///   [0   .. 200)  state.buf     [u64; 25]
///   [200 .. 392)  data_queue    [u8; 192]
///   [392 .. 400)  bits_in_queue usize serialized as u64
///   [400 .. 401)  squeezing     bool  (0 or 1)
const KECCAK_SERIALIZED_LEN: usize = 200 + 192 + 8 + 1;

/// Number of bytes needed to serialize the shared SHA3-family state (a variant tag, a [KeccakDigest],
/// plus the three KDF metadata fields), excluding the library version header.
///
/// The leading variant tag distinguishes every SHA3/SHAKE variant — crucially including same-rate
/// pairs such as SHA3-256 and SHAKE256 — so a serialized state can never be deserialized into a
/// different algorithm (which would silently apply the wrong domain separation).
///
/// Layout (all integers little-endian):
///   [0 .. 1)                              variant tag           (see `STATE_TAG` on the param traits)
///   [1 .. 1 + KECCAK_SERIALIZED_LEN)      keccak digest state
///   [.. + 1)                              kdf_key_type          (1 byte enum tag)
///   [.. + 1)                              kdf_security_strength (1 byte enum tag)
///   [.. + 8)                              kdf_entropy           usize serialized as u64
pub(crate) const SHA3_FAMILY_STATE_LEN: usize = 1 + KECCAK_SERIALIZED_LEN + 10;

/// Length in bytes of the serialized state of a SHA3 or SHAKE instance.
pub const SUSPENDED_SHA3_STATE_LEN: usize = 3 + SHA3_FAMILY_STATE_LEN;

impl KeccakDigest {
    /// Serializes this digest's mutable state into `out`. The `rate` is deliberately omitted; see
    /// [KECCAK_SERIALIZED_LEN].
    fn serialize_state(&self, out: &mut [u8; KECCAK_SERIALIZED_LEN]) {
        // state.buf: [u64; 25]
        for i in 0..25 {
            out[i * 8..(i * 8) + 8].copy_from_slice(&self.state.buf[i].to_le_bytes());
        }

        // data_queue: [u8; 192]
        out[200..392].copy_from_slice(&self.data_queue);

        // bits_in_queue: usize
        out[392..400].copy_from_slice(&(self.bits_in_queue as u64).to_le_bytes());

        // squeezing: bool
        out[400] = self.squeezing as u8;
    }

    /// Reconstructs a [KeccakDigest] from a state produced by [KeccakDigest::serialize_state].
    ///
    /// `rate` is supplied by the caller (derived from its algorithm parameters) rather than read
    /// from the serialized bytes, since the rate is fully determined by the SHA3/SHAKE variant. The
    /// caller is responsible for having already verified the variant tag so that this `rate` is the
    /// correct one for the serialized state.
    fn from_serialized_state(
        input: &[u8; KECCAK_SERIALIZED_LEN],
        rate: usize,
    ) -> Result<Self, SuspendableError> {
        // state.buf: [u64; 25]
        let mut buf = [0u64; 25];
        for i in 0..25 {
            buf[i] = u64::from_le_bytes(input[i * 8..(i * 8) + 8].try_into().unwrap());
        }

        // data_queue: [u8; 192]
        let data_queue: [u8; 192] = input[200..392].try_into().unwrap();

        // squeezing: bool
        let squeezing = match input[400] {
            0 => false,
            1 => true,
            _ => return Err(SuspendableError::InvalidData),
        };

        // bits_in_queue: usize. It can never legitimately exceed the rate.
        // Reject it here as InvalidData rather than deferring to a downstream panic.
        let bits_in_queue = u64::from_le_bytes(input[392..400].try_into().unwrap()) as usize;
        if bits_in_queue > rate || (!squeezing && (bits_in_queue % 8 != 0 || bits_in_queue == rate))
        {
            return Err(SuspendableError::InvalidData);
        }

        Ok(Self { state: KeccakState { buf, rate }, data_queue, rate, bits_in_queue, squeezing })
    }
}

/// Serializes the state shared by all SHA3-family objects (the `variant_tag`, a [KeccakDigest], plus
/// the three KDF metadata fields) into `out`. See [SHA3_FAMILY_STATE_LEN] for the layout.
pub(crate) fn serialize_sha3_family_state(
    out: &mut [u8; SHA3_FAMILY_STATE_LEN],
    variant_tag: u8,
    keccak: &KeccakDigest,
    kdf_key_type: KeyType,
    kdf_security_strength: SecurityStrength,
    kdf_entropy: usize,
) {
    out[0] = variant_tag;

    let keccak_out: &mut [u8; KECCAK_SERIALIZED_LEN] =
        (&mut out[1..1 + KECCAK_SERIALIZED_LEN]).try_into().unwrap();
    keccak.serialize_state(keccak_out);

    out[1 + KECCAK_SERIALIZED_LEN] = kdf_key_type as u8;
    out[1 + KECCAK_SERIALIZED_LEN + 1] = kdf_security_strength as u8;
    out[1 + KECCAK_SERIALIZED_LEN + 2..1 + KECCAK_SERIALIZED_LEN + 10]
        .copy_from_slice(&(kdf_entropy as u64).to_le_bytes());
}

/// Reconstructs the shared SHA3-family state from a buffer produced by [serialize_sha3_family_state].
///
/// `expected_variant_tag` and `rate` are both derived from the caller's algorithm parameters. The
/// tag is checked against the serialized one first: this is what prevents a state from one variant
/// being loaded into another (e.g. SHA3-256 vs SHAKE256, which share a rate but differ in domain
/// separation). Only once the tag matches is `rate` guaranteed to be the correct one to rebuild with.
pub(crate) fn deserialize_sha3_family_state(
    input: &[u8; SHA3_FAMILY_STATE_LEN],
    expected_variant_tag: u8,
    rate: usize,
) -> Result<(KeccakDigest, KeyType, SecurityStrength, usize), SuspendableError> {
    if input[0] != expected_variant_tag {
        return Err(SuspendableError::InvalidData);
    }

    let keccak_in: &[u8; KECCAK_SERIALIZED_LEN] =
        input[1..1 + KECCAK_SERIALIZED_LEN].try_into().unwrap();
    let keccak = KeccakDigest::from_serialized_state(keccak_in, rate)?;

    // KeyType and SecurityStrength each own their canonical 1-byte encoding (`as u8` / `TryFrom<u8>`).
    let kdf_key_type = KeyType::try_from(input[1 + KECCAK_SERIALIZED_LEN])?;
    let kdf_security_strength = SecurityStrength::try_from(input[1 + KECCAK_SERIALIZED_LEN + 1])?;
    let kdf_entropy = u64::from_le_bytes(
        input[1 + KECCAK_SERIALIZED_LEN + 2..1 + KECCAK_SERIALIZED_LEN + 10].try_into().unwrap(),
    ) as usize;

    Ok((keccak, kdf_key_type, kdf_security_strength, kdf_entropy))
}

#[cfg(test)]
mod keccak_tests {
    use super::*;
    use bouncycastle_hex as hex;

    #[test]
    fn test_keccak() {
        let mut d = KeccakDigest::new(KeccakSize::_256);
        let m_vec = hex::decode("6d657373616765").unwrap();
        d.absorb(&m_vec);

        let mut out = [0u8; 32];
        d.squeeze(&mut out);
        println!("n1: {:x?}", &out);

        d.squeeze(&mut out);
        println!("n2: {:x?}", &out);
    }

    /// Regression test for from_serialized_state's validation of a not-yet-squeezing queue: a corrupt
    /// state whose bits_in_queue is not byte-aligned, or equals the rate, must be rejected as
    /// InvalidData rather than deserialized into a value that later panics in absorb() /
    /// pad_and_switch_to_squeezing_phase().
    #[test]
    fn from_serialized_state_rejects_corrupt_bits_in_queue() {
        let rate = 1600 - ((KeccakSize::_256 as usize) << 1);

        // A valid, mid-absorb (not squeezing) serialized state.
        let mut d = KeccakDigest::new(KeccakSize::_256);
        d.absorb(b"message");
        assert!(!d.squeezing);
        let mut good = [0u8; KECCAK_SERIALIZED_LEN];
        d.serialize_state(&mut good);
        assert!(KeccakDigest::from_serialized_state(&good, rate).is_ok());

        // bits_in_queue lives at [392..400) as a little-endian u64 with squeezing at [400].
        assert_eq!(good[400], 0, "test setup expects a non-squeezing state");
        let set_biq = |state: &mut [u8; KECCAK_SERIALIZED_LEN], v: u64| {
            state[392..400].copy_from_slice(&v.to_le_bytes());
        };

        // > rate -> rejected.
        let mut corrupt = good;
        set_biq(&mut corrupt, rate as u64 + 8);
        assert!(matches!(
            KeccakDigest::from_serialized_state(&corrupt, rate),
            Err(SuspendableError::InvalidData)
        ));

        // == rate while not squeezing -> rejected (would trip the pad_and_switch debug_assert).
        let mut corrupt = good;
        set_biq(&mut corrupt, rate as u64);
        assert!(matches!(
            KeccakDigest::from_serialized_state(&corrupt, rate),
            Err(SuspendableError::InvalidData)
        ));

        // Not byte-aligned while not squeezing -> rejected (would panic in absorb()).
        let mut corrupt = good;
        set_biq(&mut corrupt, 9);
        assert!(matches!(
            KeccakDigest::from_serialized_state(&corrupt, rate),
            Err(SuspendableError::InvalidData)
        ));
    }
}
