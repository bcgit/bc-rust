use crate::SHA2Params;
use bouncycastle_core::errors::HashError;
use bouncycastle_core::traits::{Hash, SecurityStrength};
use bouncycastle_utils::min;
use core::slice;

const SHA512_K: [u64; 80] = [
    0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
    0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
    0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
    0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
    0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
    0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
    0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
    0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
    0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
    0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
    0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
    0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
    0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
    0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
    0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
    0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817,
];

#[inline]
fn ch(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}

#[inline]
fn maj(x: u64, y: u64, z: u64) -> u64 {
    (x & y) | (z & (x ^ y))
}

#[inline]
fn sum0(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}

#[inline]
fn sum1(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}

#[inline]
fn theta0(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}

#[inline]
fn theta1(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
}

// todo -- cleanup
// #[derive(Clone, Copy)]
#[derive(Clone)]
pub(crate) struct Sha512State<PARAMS: SHA2Params> {
    _params: std::marker::PhantomData<PARAMS>,
    h: [u64; 8],
}

impl<PARAMS: SHA2Params> Drop for Sha512State<PARAMS> {
    fn drop(&mut self) {
        self.h.fill(0);
    }
}

impl<PARAMS: SHA2Params> Sha512State<PARAMS> {
    pub(crate) fn new() -> Self {
        match PARAMS::OUTPUT_LEN * 8 {
            384 => Self {
                _params: std::marker::PhantomData,
                h: [
                    0xCBBB9D5DC1059ED8, 0x629A292A367CD507, 0x9159015A3070DD17, 0x152FECD8F70E5939,
                    0x67332667FFC00B31, 0x8EB44A8768581511, 0xDB0C2E0D64F98FA7, 0x47B5481DBEFA4FA4,
                ],
            },
            512 => Self {
                _params: std::marker::PhantomData,
                h: [
                    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
                    0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
                ],
            },
            _ => panic!("Invalid SHA-2 bit size"),
        }
    }

    fn compress(&mut self, blocks: &[[u8; 128]]) {
        let mut x = [0u64; 80];

        let s = &mut self.h;
        let &mut [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = s;

        for block in blocks {
            let (chunks, _remainder) = block.as_chunks::<8>();
            for (i, w) in x[..16].iter_mut().zip(chunks) {
                *i = u64::from_be_bytes(*w);
            }

            for i in 16..80 {
                x[i] = theta1(x[i - 2])
                    .wrapping_add(x[i - 7])
                    .wrapping_add(theta0(x[i - 15]))
                    .wrapping_add(x[i - 16]);
            }

            macro_rules! sha512_round {
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
            for _ in 0..10 {
                sha512_round!(a, b, c, d, e, f, g, h, t, SHA512_K, x);
                sha512_round!(h, a, b, c, d, e, f, g, t, SHA512_K, x);
                sha512_round!(g, h, a, b, c, d, e, f, t, SHA512_K, x);
                sha512_round!(f, g, h, a, b, c, d, e, t, SHA512_K, x);
                sha512_round!(e, f, g, h, a, b, c, d, t, SHA512_K, x);
                sha512_round!(d, e, f, g, h, a, b, c, t, SHA512_K, x);
                sha512_round!(c, d, e, f, g, h, a, b, t, SHA512_K, x);
                sha512_round!(b, c, d, e, f, g, h, a, t, SHA512_K, x);
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

// todo -- cleanup
// #[derive(Clone, Copy)]
#[derive(Clone)]
pub struct Sha512Internal<PARAMS: SHA2Params> {
    _params: std::marker::PhantomData<PARAMS>,
    state: Sha512State<PARAMS>,
    byte_count: u64, // NOTE We only support 2^67 bits, not the full 2^128
    x_buf: [u8; 128],
    x_buf_off: usize,
}

impl<PARAMS: SHA2Params> Drop for Sha512Internal<PARAMS> {
    fn drop(&mut self) {
        self.x_buf.fill(0);
    }
}

impl<PARAMS: SHA2Params> Sha512Internal<PARAMS> {
    pub fn new() -> Self {
        Self {
            _params: std::marker::PhantomData,
            state: Sha512State::<PARAMS>::new(),
            byte_count: 0,
            x_buf: [0; 128],
            x_buf_off: 0_usize,
        }
    }
}

impl<PARAMS: SHA2Params> Default for Sha512Internal<PARAMS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<PARAMS: SHA2Params> Hash for Sha512Internal<PARAMS> {
    /// As per FIPS 180-4 Figure 1
    fn block_bitlen(&self) -> usize {
        1024
    }

    fn output_len(&self) -> usize {
        PARAMS::OUTPUT_LEN
    }

    fn hash(self, data: &[u8]) -> Vec<u8> {
        let mut output = vec![0u8; self.output_len()];
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

        let available = 128 - self.x_buf_off;
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
            //self.x_buf_off = 0;
        }

        let (chunks, remainder) = block.as_chunks::<128>();

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

        let bit_len_hi: u64 = self.byte_count >> 61;
        let bit_len_lo: u64 = self.byte_count << 3;

        self.x_buf[self.x_buf_off] = 0x80;
        self.x_buf_off += 1;

        if self.x_buf_off > 112 {
            self.x_buf[self.x_buf_off..].fill(0x00);
            self.state.compress(slice::from_ref(&self.x_buf));
            self.x_buf_off = 0;
        }

        self.x_buf[self.x_buf_off..112].fill(0x00);
        self.x_buf[112..120].copy_from_slice(&bit_len_hi.to_be_bytes());
        self.x_buf[120..128].copy_from_slice(&bit_len_lo.to_be_bytes());
        self.state.compress(slice::from_ref(&self.x_buf));

        let h = &self.state.h;

        for i in 0..(n / 8) {
            output[i * 8..i * 8 + 8].copy_from_slice(&h[i].to_be_bytes());
        }
        if !n.is_multiple_of(8) {
            output[((n / 8) * 8)..((n / 8) * 8) + (n % 8)]
                .copy_from_slice(&h[n / 8].to_be_bytes()[0..(n % 8)]);
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
