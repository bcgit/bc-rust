use bouncycastle_core_interface::traits::{Hash, XOF};
use bouncycastle_sha3::{SHAKE128Params, SHAKE, SHAKE128, SHAKE256};

// TODO -- I think this file can be deleted at the end

#[derive(Clone)]
pub(crate) struct Symmetric {
    pub(crate) stream_128_block_bytes: usize,
    pub(crate) stream_256_block_bytes: usize,
    digest128: SHAKE128,
    digest256: SHAKE256,
}

impl Symmetric {
    pub(crate) fn new() -> Self {
        Self {
            stream_128_block_bytes: 168,
            stream_256_block_bytes: 136,
            digest128: SHAKE128::new(),
            digest256: SHAKE256::new(),
        }
    }

    fn stream_init(digest: &mut impl XOF, seed: &[u8], nonce: u16) {
        // digest.keccak.reset();
        let mut tmp: [u8; 2] = [0; 2];
        tmp[0] = nonce as u8;
        tmp[1] = (nonce >> 8) as u8;

        digest.absorb(seed);
        digest.absorb(&tmp);
    }

    // pub(crate) fn stream128_init(&mut self, seed: &[u8], nonce: u16) {
    //     Symmetric::stream_init(&mut self.digest128, seed, nonce);
    // }
    //
    // pub(crate) fn stream256_init(&mut self, seed: &[u8], nonce: u16) {
    //     Symmetric::stream_init(&mut self.digest256, seed, nonce);
    // }

    pub(crate) fn stream128_squeeze_blocks(&mut self, output: &mut [u8], off: usize, len: usize) {
        self.digest128.do_output(&mut output[off..off + len]);
    }

    pub(crate) fn stream256_squeeze_blocks(&mut self, output: &mut [u8], off: usize, len: usize) {
        self.digest256.do_output(&mut output[off..off + len]);
    }
}
