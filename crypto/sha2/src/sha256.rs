use crate::SHA2Params;
use bouncycastle_core::errors::{HashError, SuspendableError};
use bouncycastle_core::suspendable_state::{add_lib_ver, check_lib_ver};
use bouncycastle_core::traits::{Algorithm, Hash, SecurityStrength, Suspendable};
use bouncycastle_utils::min;
use core::slice;

const SHA256_K: [u32; 64] = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
];

#[inline]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

#[inline]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (z & (x ^ y))
}

#[inline]
fn sum0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

#[inline]
fn sum1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

#[inline]
fn theta0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

#[inline]
fn theta1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

#[derive(Clone)]
pub(crate) struct Sha256State<PARAMS: SHA2Params> {
    _params: core::marker::PhantomData<PARAMS>,
    h: [u32; 8],
}

impl<PARAMS: SHA2Params> Drop for Sha256State<PARAMS> {
    fn drop(&mut self) {
        self.h.fill(0);
    }
}

impl<PARAMS: SHA2Params> Sha256State<PARAMS> {
    pub(crate) fn new() -> Self {
        match PARAMS::OUTPUT_LEN * 8 {
            224 => Self {
                _params: core::marker::PhantomData,
                h: [
                    0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939, 0xFFC00B31, 0x68581511,
                    0x64F98FA7, 0xBEFA4FA4,
                ],
            },
            256 => Self {
                _params: std::marker::PhantomData,
                h: [
                    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C,
                    0x1F83D9AB, 0x5BE0CD19,
                ],
            },
            _ => panic!("Invalid SHA-2 bit size: {}", PARAMS::OUTPUT_LEN),
        }
    }

    fn compress(&mut self, blocks: &[[u8; 64]]) {
        let mut x = [0u32; 64];

        let s = &mut self.h;
        let &mut [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = s;

        for block in blocks {
            let (chunks, _remainder) = block.as_chunks::<4>();
            for (i, w) in x[..16].iter_mut().zip(chunks) {
                *i = u32::from_be_bytes(*w);
            }

            for i in 16..64 {
                x[i] = theta1(x[i - 2])
                    .wrapping_add(x[i - 7])
                    .wrapping_add(theta0(x[i - 15]))
                    .wrapping_add(x[i - 16]);
            }

            macro_rules! sha256_round {
                ($a:ident,$b:ident,$c:ident,$d:ident,$e:ident,$f:ident,$g:ident,$h:ident,$t:ident,$K:ident,$x:ident) => {
                    $h = $h
                        .wrapping_add(sum1($e))
                        .wrapping_add(ch($e, $f, $g))
                        .wrapping_add($K[$t])
                        .wrapping_add($x[$t]);
                    $d = $d.wrapping_add($h);
                    $h = $h.wrapping_add(sum0($a)).wrapping_add(maj($a, $b, $c));
                    $t += 1;
                };
            }

            let mut t: usize = 0;
            for _ in 0..8 {
                sha256_round!(a, b, c, d, e, f, g, h, t, SHA256_K, x);
                sha256_round!(h, a, b, c, d, e, f, g, t, SHA256_K, x);
                sha256_round!(g, h, a, b, c, d, e, f, t, SHA256_K, x);
                sha256_round!(f, g, h, a, b, c, d, e, t, SHA256_K, x);
                sha256_round!(e, f, g, h, a, b, c, d, t, SHA256_K, x);
                sha256_round!(d, e, f, g, h, a, b, c, t, SHA256_K, x);
                sha256_round!(c, d, e, f, g, h, a, b, t, SHA256_K, x);
                sha256_round!(b, c, d, e, f, g, h, a, t, SHA256_K, x);
            }

            a = a.wrapping_add(s[0]);
            b = b.wrapping_add(s[1]);
            c = c.wrapping_add(s[2]);
            d = d.wrapping_add(s[3]);
            e = e.wrapping_add(s[4]);
            f = f.wrapping_add(s[5]);
            g = g.wrapping_add(s[6]);
            h = h.wrapping_add(s[7]);

            s[0] = a;
            s[1] = b;
            s[2] = c;
            s[3] = d;
            s[4] = e;
            s[5] = f;
            s[6] = g;
            s[7] = h;
        }
    }
}

#[derive(Clone)]
pub struct SHA256Internal<PARAMS: SHA2Params> {
    _params: core::marker::PhantomData<PARAMS>,
    state: Sha256State<PARAMS>,
    byte_count: u64,
    x_buf: [u8; 64],
    x_buf_off: usize,
    // TODO: should we add a maximum message size according to FIPS 180-4? (2^64 for SHA256 and 2^128 for SHA512)
}

impl<PARAMS: SHA2Params> Drop for SHA256Internal<PARAMS> {
    fn drop(&mut self) {
        self.x_buf.fill(0);
    }
}

impl<PARAMS: SHA2Params> SHA256Internal<PARAMS> {
    pub fn new() -> Self {
        Self {
            _params: core::marker::PhantomData,
            state: Sha256State::<PARAMS>::new(),
            byte_count: 0,
            x_buf: [0; 64],
            x_buf_off: 0,
        }
    }
}

impl<PARAMS: SHA2Params> Default for SHA256Internal<PARAMS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<PARAMS: SHA2Params> Algorithm for SHA256Internal<PARAMS> {
    const ALG_NAME: &'static str = PARAMS::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = PARAMS::MAX_SECURITY_STRENGTH;
}

impl<PARAMS: SHA2Params> Hash for SHA256Internal<PARAMS> {
    /// As per FIPS 180-4 Figure 1
    fn block_bitlen(&self) -> usize {
        512
    }

    fn output_len(&self) -> usize {
        PARAMS::OUTPUT_LEN
    }

    fn hash(self, data: &[u8]) -> Vec<u8> {
        let mut output = vec![0u8; PARAMS::OUTPUT_LEN];
        self.hash_out(data, &mut output);
        output
    }

    fn hash_out(mut self, data: &[u8], output: &mut [u8]) -> usize {
        output.fill(0);

        self.do_update(data);
        self.do_final_out(output)
    }

    fn do_update(&mut self, block: &[u8]) {
        let len = block.len();

        // TODO: Check there is enough space left in 'byte_count' to allow this operation,
        // TODO: although overflowing a u64 is unlikely to happen in practice, and rust will throw an error anyway.
        self.byte_count += len as u64;

        let available = 64 - self.x_buf_off;

        // TODO: mutants thinks you can replace < with <= without changing behaviour
        if len < available {
            self.x_buf[self.x_buf_off..self.x_buf_off + len].copy_from_slice(block);
            self.x_buf_off += len;
            return;
        }

        let mut block = block;
        if self.x_buf_off != 0 {
            self.x_buf[self.x_buf_off..].copy_from_slice(&block[..available]);
            block = &block[available..];

            self.state.compress(slice::from_ref(&self.x_buf));
        }

        let (chunks, remainder) = block.as_chunks::<64>();

        self.state.compress(chunks);

        let remaining = remainder.len();
        self.x_buf[..remaining].copy_from_slice(remainder);
        self.x_buf_off = remaining;
    }

    fn do_final(self) -> Vec<u8> {
        let mut output = vec![0u8; PARAMS::OUTPUT_LEN];
        self.do_final_out(&mut output);
        output
    }

    fn do_final_out(mut self, output: &mut [u8]) -> usize {
        output.fill(0);

        let n = *min(&output.len(), &PARAMS::OUTPUT_LEN);

        let bit_len: u64 = self.byte_count << 3;

        self.x_buf[self.x_buf_off] = 0x80;
        self.x_buf_off += 1;

        if self.x_buf_off > 56 {
            self.x_buf[self.x_buf_off..].fill(0x00);
            self.state.compress(slice::from_ref(&self.x_buf));
            self.x_buf_off = 0;
        }

        self.x_buf[self.x_buf_off..56].fill(0x00);
        self.x_buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        self.state.compress(slice::from_ref(&self.x_buf));

        let h = &self.state.h;

        // let n = output.len();
        for i in 0..(n / 4) {
            output[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
        }
        if !n.is_multiple_of(4) {
            output[((n / 4) * 4)..((n / 4) * 4) + (n % 4)]
                .copy_from_slice(&h[n / 4].to_be_bytes()[0..(n % 4)]);
        }

        n
    }

    /// TODO: This is defined in FIPS 180-4 s. 5.1.2
    /// TODO: <https://pages.nist.gov/ACVP/draft-celi-acvp-sha.html>
    /// TODO: Could implement if there is demand.
    #[allow(unused)]
    fn do_final_partial_bits(
        self,
        partial_byte: u8,
        num_partial_bits: usize,
    ) -> Result<Vec<u8>, HashError> {
        unimplemented!()
    }

    /// TODO: This is defined in FIPS 180-4 s. 5.1.2
    /// TODO: <https://pages.nist.gov/ACVP/draft-celi-acvp-sha.html>
    /// TODO: Could implement if there is demand.
    #[allow(unused)]
    fn do_final_partial_bits_out(
        self,
        partial_byte: u8,
        num_partial_bits: usize,
        output: &mut [u8],
    ) -> Result<usize, HashError> {
        unimplemented!()
    }

    fn max_security_strength(&self) -> SecurityStrength {
        SecurityStrength::from_bytes(PARAMS::OUTPUT_LEN / 2)
    }
}

/// Length in bytes of the serialized state of SHA224 and SHA256.
pub const SUSPENDED_SHA256_STATE_LEN: usize = 108;

impl<PARAMS: SHA2Params> Suspendable<SUSPENDED_SHA256_STATE_LEN> for SHA256Internal<PARAMS> {
    fn suspend(self) -> [u8; SUSPENDED_SHA256_STATE_LEN] {
        debug_assert_eq!(SUSPENDED_SHA256_STATE_LEN, 108);

        let mut out_to_return = [0u8; SUSPENDED_SHA256_STATE_LEN];

        // insert the version tag
        // infallible: add_lib_ver returns a slice of exactly SUSPENDED_SHA256_STATE_LEN - 3 = 105 bytes.
        let out: &mut [u8; 105] = add_lib_ver(&mut out_to_return).try_into().unwrap();

        // state.h: [u32; 8]
        // 4 * 8 = 32
        for i in 0..8 {
            out[i * 4..(i * 4) + 4].copy_from_slice(&self.state.h[i].to_le_bytes());
        }

        // byte_count: u64
        out[32..40].copy_from_slice(&self.byte_count.to_le_bytes());

        // x_buf: [u8; 64]
        out[40..104].copy_from_slice(&self.x_buf);

        // x_buf_off: usize
        // in general, a usize should be serialized into a u64, but in this case, it can't ever be larger than 64
        debug_assert!(self.x_buf_off < 64);
        out[104] = self.x_buf_off as u8;

        out_to_return
    }

    fn from_suspended(
        serialized_state: [u8; SUSPENDED_SHA256_STATE_LEN],
    ) -> Result<Self, SuspendableError> {
        debug_assert_eq!(SUSPENDED_SHA256_STATE_LEN, 108);

        // check the version tag
        // At the moment, we have no not_before version to specify.
        // infallible: check_lib_ver returns a slice of exactly SUSPENDED_SHA256_STATE_LEN - 3 = 105 bytes.
        let input: &[u8; 105] = check_lib_ver(&serialized_state, None)?.try_into().unwrap();

        // state.h: [u32; 8]
        // 4 * 8 = 32
        let mut h = [0u32; 8];
        for i in 0..8 {
            h[i] = u32::from_le_bytes(input[i * 4..(i * 4) + 4].try_into().unwrap());
        }

        // byte_count: u64
        let byte_count: u64 = u64::from_le_bytes(input[32..40].try_into().unwrap());

        // x_buf: [u8; 64]
        let x_buf: [u8; 64] = input[40..104].try_into().unwrap();

        // x_buf_off: usize
        // in general, a usize should be serialized into a u64, but in this case, it can't ever be larger than 64
        let x_buf_off: usize = input[104] as usize;
        if x_buf_off >= 64 {
            return Err(SuspendableError::InvalidData);
        }

        // Construct the object
        let state = Sha256State { _params: core::marker::PhantomData, h };
        Ok(SHA256Internal {
            _params: core::marker::PhantomData,
            state,
            byte_count,
            x_buf,
            x_buf_off,
        })
    }
}
