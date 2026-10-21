use bouncycastle_core::errors::MACError;
use bouncycastle_core::traits::MAC;
use bouncycastle_core_test_framework::mac::TestFrameworkMAC;
use bouncycastle_poly1305::hazmat::key_from_bytes;
use bouncycastle_poly1305::{Poly1305, Poly1305Key};

/// A public test key, so these tests make as many keys from it as they like; a real one-time key
/// authenticates one message.
const KEY: [u8; 32] = [0x42; 32];

fn generator() -> Poly1305 {
    key_from_bytes(&KEY).into_generator()
}

fn verify(msg: &[u8], tag: &[u8]) -> bool {
    key_from_bytes(&KEY).into_verifier().verify(msg, tag)
}

/// The framework's API-contract checks, which need no external data. The tag's correctness is
/// pinned by the RFC 8439 vectors in poly1305_bc-test-data.rs, which run the same suite.
#[test]
fn core_mac_contract() {
    let msg = b"framework message spanning more than one 16-byte block";
    let tag = generator().mac(msg);
    TestFrameworkMAC::new().test_one_time_mac(generator, msg, &tag);
}

#[test]
fn empty_message_returns_the_additive_key_half() {
    assert_eq!(generator().finalize(), KEY[16..]);
}

/// The two ways to consume a key make the same worker.
#[test]
fn the_verifier_computes_the_generators_tag() {
    let msg = b"message";
    assert_eq!(key_from_bytes(&KEY).into_verifier().mac(msg), generator().mac(msg));
}

#[test]
fn streaming_and_output_buffer_contract() {
    for len in [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 1025] {
        let msg: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(7)).collect();
        let expected = generator().mac(&msg);
        for chunk in [1, 3, 15, 16, 17, 64, 129] {
            let mut mac = generator();
            assert_eq!(mac.output_len(), 16);
            mac.do_update(&[]);
            for bytes in msg.chunks(chunk) {
                mac.do_update(bytes);
                mac.do_update(&[]);
            }
            let mut out = [0xa5; 32];
            assert_eq!(mac.do_final_out(&mut out).unwrap(), 16);
            assert_eq!(&out[..16], expected);
            assert_eq!(&out[16..], &[0; 16]);
        }
        assert!(verify(&msg, &expected));
        for bit in 0..128 {
            let mut bad = expected.clone();
            bad[bit / 8] ^= 1 << (bit % 8);
            assert!(!verify(&msg, &bad));
        }
        assert!(!verify(&msg, &expected[..15]));
        assert!(!verify(&msg, &[0; 17]));
    }
}

#[test]
fn full_tags_are_required() {
    for len in 0..16 {
        let mut out = vec![0xa5; len];
        assert!(matches!(
            generator().mac_out(b"message", &mut out),
            Err(MACError::InvalidLength(_))
        ));
        assert!(out.iter().all(|&b| b == 0));
    }
}

/// The all-zero key, which RFC 8439 accepts and only the caller can refuse: with `r = 0` and
/// `s = 0` every tag is zero.
#[test]
fn the_all_zero_key_is_accepted() {
    assert_eq!(key_from_bytes(&[0; 32]).into_generator().mac(b"zero-key test"), [0; 16]);
}

/// One full block under a key whose clamped `r` is the single limb `r0 < 2^26` and whose `s` is
/// zero, chosen (by an offline search) so that the block's product carries out of the top limb
/// and leaves `h0` within 5 of 2^26. Those are the only inputs that reach finalize's last
/// `h1 += h0 >> 26` with a non-zero carry, which no RFC or Wycheproof vector does.
///
/// The expected tag is computed by `reference_tag`, an independent big-integer evaluation of
/// RFC 8439 Sec 2.5's `acc = ((acc + block) * r) % p`, `tag = (acc + s) mod 2^128`.
#[test]
fn final_carry_out_of_h0() {
    for (r0, block) in [
        (0x3fffffe_u32, "eb25b4d74b68af97d05e2fa1bd5e427b"),
        (0x3ffffff_u32, "01000005000014000050000040010000"),
    ] {
        let block: [u8; 16] = bouncycastle_hex::decode(block).unwrap().try_into().unwrap();
        let mut key = [0u8; 32];
        key[..4].copy_from_slice(&r0.to_le_bytes());
        assert_eq!(
            key_from_bytes(&key).into_generator().mac(&block),
            reference_tag(r0, &block),
            "r0 = {r0:#x}"
        );
    }
}

/// RFC 8439 Sec 2.5 for one full block, `r = r0 < 2^26` and `s = 0`, over little-endian 32-bit
/// limbs: `acc = ((block + 2^128) * r0) mod (2^130 - 5)`, `tag = acc mod 2^128`.
fn reference_tag(r0: u32, block: &[u8; 16]) -> [u8; 16] {
    // x = block + 2^128: the block with the 0x01 byte appended.
    let mut x = [0u64; 5];
    for (limb, bytes) in x.iter_mut().zip(block.chunks_exact(4)) {
        *limb = u64::from(u32::from_le_bytes(bytes.try_into().unwrap()));
    }
    x[4] = 1;
    // v = x * r0, in six limbs.
    let mut v = [0u64; 6];
    let mut carry = 0;
    for (out, limb) in v.iter_mut().zip(x) {
        let t = limb * u64::from(r0) + carry;
        *out = t & 0xffff_ffff;
        carry = t >> 32;
    }
    v[5] = carry;
    // v = hi * 2^130 + lo, and 2^130 = 5 (mod p): v becomes lo + 5 * hi, below 2^131.
    let hi = (v[4] >> 2) | (v[5] << 30);
    v[4] &= 3;
    let mut carry = 5 * hi;
    for limb in &mut v[..5] {
        let t = *limb + carry;
        *limb = t & 0xffff_ffff;
        carry = t >> 32;
    }
    // Subtract p = 2^130 - 5 while v >= p.
    const P: [u64; 5] = [0xffff_fffb, 0xffff_ffff, 0xffff_ffff, 0xffff_ffff, 3];
    while (0..5).rev().find(|&i| v[i] != P[i]).is_none_or(|i| v[i] > P[i]) {
        let mut borrow = 0;
        for i in 0..5 {
            let t = (v[i] + (1 << 32)) - P[i] - borrow;
            v[i] = t & 0xffff_ffff;
            borrow = 1 - (t >> 32);
        }
    }
    let mut tag = [0u8; 16];
    for (bytes, limb) in tag.chunks_exact_mut(4).zip(v) {
        bytes.copy_from_slice(&(limb as u32).to_le_bytes());
    }
    tag
}

/// The figures in the crate docs' Memory Usage table.
#[cfg(target_pointer_width = "64")]
#[test]
fn sizes_match_the_documented_memory_table() {
    assert_eq!(core::mem::size_of::<Poly1305Key>(), 88);
    assert_eq!(core::mem::size_of::<Poly1305>(), 192);
}
