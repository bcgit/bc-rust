//! `hazmat::AnyStrength<H>` is the hash `H` in everything it reports and computes; what it
//! changes, HashML-DSA's strength check, is tested in the two ML-DSA crates.

use bouncycastle_core::signature_key::PreHash;
use bouncycastle_core::traits::{
    Algorithm, AlgorithmInfo, AlgorithmOID, Hash, HashAlgParams, HashOneShot,
};
use bouncycastle_mldsa_common::hazmat::AnyStrength;
use bouncycastle_sha2::{SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256};
use bouncycastle_sha3::{SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256};

/// Everything the wrapper reports and computes is `H`'s, the strength included; the rule is the
/// one difference.
fn is_the_hash_it_wraps<H: PreHash + Clone>() {
    assert_eq!(<AnyStrength<H> as Algorithm>::ALG_NAME, H::ALG_NAME);
    assert_eq!(<AnyStrength<H> as Algorithm>::MAX_SECURITY_STRENGTH, H::MAX_SECURITY_STRENGTH);
    assert_eq!(<AnyStrength<H> as HashAlgParams>::OUTPUT_LEN, H::OUTPUT_LEN);
    assert_eq!(<AnyStrength<H> as HashAlgParams>::BLOCK_LEN, H::BLOCK_LEN);
    assert_eq!(<AnyStrength<H> as AlgorithmOID>::OID, H::OID);
    assert_eq!(<AnyStrength<H> as AlgorithmOID>::OID_DER, H::OID_DER);
    assert!(!H::PRE_HASH_STRENGTH_RULE.is_waived());
    assert!(<AnyStrength<H> as HashAlgParams>::PRE_HASH_STRENGTH_RULE.is_waived());

    let (h, w) = (H::default(), AnyStrength::<H>::default());
    assert_eq!(w.alg_name(), h.alg_name());
    assert_eq!(w.max_security_strength(), h.max_security_strength());
    assert_eq!(w.output_len(), h.output_len());
    assert_eq!(w.block_bitlen(), h.block_bitlen());

    // the one-shots, and the streaming form over uneven chunks
    let msg: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
    let digest = H::hash(&msg);
    assert_eq!(AnyStrength::<H>::hash(&msg), digest);
    let mut w = AnyStrength::<H>::default();
    for chunk in msg.chunks(77) {
        w.do_update(chunk);
    }
    assert_eq!(w.do_final(), digest);

    // a short buffer takes a truncated digest and a long one zeros after it, as `H` does
    for len in [1, H::OUTPUT_LEN - 1, H::OUTPUT_LEN, H::OUTPUT_LEN + 9] {
        let (mut out_h, mut out_w) = (vec![0xAAu8; len], vec![0x55u8; len]);
        assert_eq!(AnyStrength::<H>::hash_out(&msg, &mut out_w), H::hash_out(&msg, &mut out_h));
        assert_eq!(out_w, out_h);
    }

    // a trailing partial byte, and its refusal of more than seven bits
    for num_bits in [0, 3, 7, 8] {
        let (mut h, mut w) = (H::default(), AnyStrength::<H>::default());
        h.do_update(&msg);
        w.do_update(&msg);
        let expected = h.do_final_partial_bits(0xA0, num_bits);
        assert_eq!(expected.is_err(), num_bits == 8);
        assert_eq!(w.do_final_partial_bits(0xA0, num_bits), expected);
    }

    // a clone carries the absorbed prefix and then goes its own way
    let mut w = AnyStrength::<H>::default();
    w.do_update(&msg[..500]);
    let mut fork = w.clone();
    w.do_update(&msg[500..]);
    fork.do_update(b"something else");
    assert_eq!(w.do_final(), digest);
    assert_eq!(fork.do_final(), H::hash(&[&msg[..500], b"something else"].concat()));
}

#[test]
fn any_strength_is_the_hash_it_wraps() {
    is_the_hash_it_wraps::<SHA224>();
    is_the_hash_it_wraps::<SHA256>();
    is_the_hash_it_wraps::<SHA384>();
    is_the_hash_it_wraps::<SHA512>();
    is_the_hash_it_wraps::<SHA512_224>();
    is_the_hash_it_wraps::<SHA512_256>();
    is_the_hash_it_wraps::<SHA3_224>();
    is_the_hash_it_wraps::<SHA3_256>();
    is_the_hash_it_wraps::<SHA3_384>();
    is_the_hash_it_wraps::<SHA3_512>();
    is_the_hash_it_wraps::<SHAKE128>();
    is_the_hash_it_wraps::<SHAKE256>();
}
