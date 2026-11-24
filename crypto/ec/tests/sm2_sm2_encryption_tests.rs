//! SM2 public key encryption (GB/T 32918.4-2016) through the public API of
//! `bouncycastle_ec::sm2::encryption`.
//!
//! The known answers are in this file. QUALITY_AND_STYLE.md asks for tests against bc-test-data
//! and Wycheproof, and neither has a vector for SM2 encryption: no file in either is named for
//! SM2, and a search of their contents for `SM2`, `sm2p256v1`, `sm2encrypt` and the OID arc
//! `1.2.156.10197` finds one line, a public key in bc-test-data's C509 README. Bouncy Castle
//! Java's own (`SM2EngineTest` and `SM2CipherTest`) are the examples of GM/T 0003.4-2012 Annex
//! A, over that annex's curves, a 256-bit prime curve and a 257-bit binary one, which this
//! module does not implement, so none of them is here.
//!
//! Where the constants come from:
//!
//! * `ANNEX_C_*`: GM/T 0003.5-2012 Annex C.2, from the English translation published at
//!   gmbz.org.cn. The annex prints `dB`, `M`, `C1`, `C2` and `C3` and then a ciphertext that it
//!   labels `C1 || C2 || C3` but prints as `x1 || y1 || C3 || C2`, without `C1`'s leading `04`;
//!   the two orders here are assembled from the parts. Every part was recomputed from `dB`,
//!   the annex's `k` and `M` by a Python model written from GB/T 32918.4-2016 Sections 5.4.3,
//!   6.1 and 7.1 (affine integer arithmetic, OpenSSL's SM3) and agreed with the print.
//! * `ZERO_T_*`, `MODEL_*`, `SMALL_X_*`, `OFF_CURVE_*`: computed by that Python model.
//!   `ZERO_T` is `C1 = [470]G` under the annex's key, the smallest `k` whose key stream for a
//!   one-byte message is `00`. The `MODEL` ciphertexts use scalars that are SHA-256 of a label,
//!   reduced into `[1, n-2]`. `SMALL_X` is the point with `x = 1`; `OFF_CURVE` is the base
//!   point with `y + 1`. For those two `C2` and `C3` were computed from `[dB]C1` by formulas
//!   that never use the curve's `b`, so they are what a decryption that did not check `C1`
//!   would accept.
//! * `EQUAL_T_*`: computed by that Python model. `C1 = [130]G` under the annex's key, `k = 130`
//!   being the smallest for which the first two bytes of the key stream are equal and not
//!   zero (`5e 5e`), found by trying `k = 1, 2, ..`: a key stream whose bytes XOR to zero
//!   without being zero.
//! * `X2_ZERO_*`: computed by that Python model. The curve has two points with `x = 0`,
//!   `(0, y)` and `(0, p - y)` for `y = b^((p+1)/4) mod p`; `C1` is `[dB^-1 mod n]` of each
//!   under `MODEL_D`, so that the shared point `[dB]C1` is that point, and `C2` and `C3` are
//!   what GB/T 32918.4-2016 Section 7.1 gives the message `x2 is zero` for it.
//! * `KEYGEN_*`: the private key that `(seed mod (n - 2)) + 1` gives for the 40 bytes
//!   `00 01 .. 27` read as a big-endian integer, which is what
//!   `bouncycastle_ec::sm2::extra_bits` documents, and its public key, both computed in Python
//!   with integer arithmetic. Reduced modulo `n - 1` the same seed gives
//!   `..84e6988e28fb8ad4`.
//! * `OPENSSL_*`: a key generated and a message encrypted by OpenSSL 3.0.13
//!   (`openssl genpkey -algorithm SM2`, `openssl pkeyutl -encrypt`), the four fields of its
//!   DER `SM2Cipher` laid out as `C1 || C3 || C2`.

use bouncycastle_core::errors::{
    KeyDecodingError, KeyMaterialError, PublicKeyEncryptionError, RNGError, SignatureError,
};
use bouncycastle_core::hazmat::FixedSeedRNG;
use bouncycastle_core::key_material::KeyMaterialTrait;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{PrivateKey, PublicKey, RNG};
use bouncycastle_core_test_framework::signature::TestFrameworkSignatureKeys;
use bouncycastle_ec::hazmat::sm2_scalar::N_LIMBS;
use bouncycastle_ec::hazmat::sm2_sec1::be_bytes_from_limbs;
use bouncycastle_ec::sm2::encryption::{
    C1_LEN, OVERHEAD_LEN, SM2EncryptionPrivateKey, SM2EncryptionPublicKey, keygen,
};
use bouncycastle_ec::sm2::keys::{SM2PrivateKey, SM2PublicKey};
use bouncycastle_rng::DefaultRNG;

const ANNEX_C_DB: &str = "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8";
const ANNEX_C_PB: &str = "0409f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020\
                          ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13";
const ANNEX_C_M: &[u8] = b"encryption standard";
const ANNEX_C_C1: &str = "0404ebfc718e8d1798620432268e77feb6415e2ede0e073c0f4f640ecd2e149a73\
                          e858f9d81e5430a57b36daab8f950a3c64e6ee6a63094d99283aff767e124df0";
const ANNEX_C_C2: &str = "21886ca989ca9c7d58087307ca93092d651efa";
const ANNEX_C_C3: &str = "59983c18f809e262923c53aec295d30383b54e39d609d160afcb1908d0bd8766";

const ZERO_T_C1: &str = "0417a8dbf0e9d5ce427a04c8800bef14de5e22e24c5cee027d8f71fe0bf8a909\
                         b10bc9ed977244bf069fa0e9163a353597134cf54a2747957945678515b49265e8";
const ZERO_T_C3: &str = "ae0472e858ff7f757df1d97567fd4889d0f340ed959cf70756029aaeff7d5f6e";
const ZERO_T_M: u8 = 0x4d;

const EQUAL_T_C1: &str = "0473fd021127db200837fb5e89e4ade4a103c3310096cbfdfd2aff1d698b3e9596\
                          6eac311bf6f3a5af2230ad7167d0a7ee884aa70a81db42e61e56cc63984cbbdf";
const EQUAL_T_C3: &str = "279155a3632ecd600f9e521c2ef34a7bdb912e382f3411297051e8d17662a51a";
const EQUAL_T_C2: [u8; 2] = [0x13, 0x6c];
const EQUAL_T_M: [u8; 2] = [0x4d, 0x32];
const EQUAL_T_K: u8 = 130;

const MODEL_D: &str = "62a67a18707cd9d597d8fed50d8edeb3c0c58a1f606b8b14b0aa0086c58f79f3";
const MODEL_PB: &str = "044ece01154170b0176a91f9b0e06522ce18d5c18557bbedb095db972700d04e\
                        f193f6b50f59a8c79fa9dcfee84a5e3e5841201ac949b4466bee09caf777396e70";
/// Message lengths 1, 33 and 100; byte `i` of the message of length `L` is `7 i + L mod 256`.
const MODEL_C1C3C2: [&str; 3] = [
    "044f178d82aafb0bbf491d384aa43bb967c20d78d70ab9414dd96a1fb7ba76e8\
     b39059463a7023c8122f541f9778e2b703fdf9ffb0998aceeefbad050359325a\
     5a0a492c56960602c70d28e5548006d0168f03266715e84d516c319e34f9d95f\
     07fe",
    "0420983e67501ad22f0fe3efb4e0df4c732e3ff5e7abd988da55d23d740c6722\
     43541792418752a04954a2d9404fe65504389bf266bcd7c41c03ac1f37c34c31\
     1cfb5d362f73b90bc2ccbb3b255281f5bc7b5b64c956eb9521ba858d80be4c70\
     334e95fa869f8015ec4598b73535fe25b01c886fbb556a9073004cfb7f321a8b\
     ec16",
    "042c740eff4533efd7106e3264201b9fd469def2b6c33a64159375f6cc2bc8d5\
     60f663fb442ef67d46639ce96ceb3358857208a8b3c927bcd05a4150eace57c0\
     71b8f6f2824558e795d947e4773baddd6de92e453b265366c726f593064d9348\
     f00826ea0bd519f1e626b87f1b2465a636c30dda4d53f24f3ee9ebab3bd0373e\
     4676963ce04ac05d0db4aefe0abcabb2ab022dca395d145303b80a6aa08aa747\
     4e2ce6ad66ca1111db3e6bc7c301aea239dc45bd3de9b860c34af1a564172b3f\
     6cf9a915c6",
];

/// Under `MODEL_D`, the message `range check`.
const SMALL_X_C1: &str = "040000000000000000000000000000000000000000000000000000000000000001\
                          9f7a091433a81e3f218f405f792355bf2aa98b5ffa95982f03870800065279a3";
/// The same point with `x + p` for `x`.
const SMALL_X_C1_PLUS_P: &str = "04fffffffeffffffffffffffffffffffffffffffff000000010000000000000000\
                                 9f7a091433a81e3f218f405f792355bf2aa98b5ffa95982f03870800065279a3";
const SMALL_X_C3: &str = "3e7ce9572a0628eb0f760c4ac2784b371f9adf0279ed5f399b56aaa0892ab7da";
const SMALL_X_C2: &str = "f802d3e6dd1dacdc9ee754";

const OFF_CURVE_C1: &str = "0432c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7\
                            bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a1";
const OFF_CURVE_C3: &str = "b56ae41252bdd8f6f1ee345db10787ac496ec72a1f072e396e189c36b95f1b11";
const OFF_CURVE_C2: &str = "4852561618e8bf8e68e800";

/// Under `MODEL_D`, the message `x2 is zero`: `(C1, C3, C2)` for the shared points `(0, y)`
/// and `(0, p - y)`.
const X2_ZERO: [(&str, &str, &str); 2] = [
    (
        "041a9263245eb163584e07ce5fd2974c0a679796585de823bffd216ec5c44b9deb\
         4c84f6f2735ad51d6920bfe52962c18eefd58f70f905afe685b2cca58516de7f",
        "3f253e22cabb137bc0b5782c273c5641a6d552754a1cba5cf9fb1ea146dbcf5e",
        "c8f5cfd7a4e5c46fbe51",
    ),
    (
        "041a9263245eb163584e07ce5fd2974c0a679796585de823bffd216ec5c44b9deb\
         b37b090c8ca52ae296df401ad69d3e71102a708e06fa501a7a4d335a7ae92180",
        "380912a7bf7581fd7fff6dfd0db71775b0bb70f72127246be2738b9df4d0bdd9",
        "966a5e15c0d57c86b3e0",
    ),
];

const KEYGEN_D: &str = "0c0f12150c0d0e0f1011a12cd91ac8aca5656a3f66bf813384e79a912d0192de";
const KEYGEN_PB: &str = "04c81d8138505a19655861f7440740db65ece3aa042364bdf47c8396cedc0993ea\
                         11f519f6bc80084587d58f3d22955ddf108db6510f23d24f97b66b98068dcb2b";

const OPENSSL_D: &str = "8527f34dbaf88d2f24a10d468b8a85d349f7aea6cb9a3f9066d458b312a334bf";
const OPENSSL_M: &str = "0b6afd74296c688903ff01454bea4f96909dd2";
const OPENSSL_C1C3C2: &str = "04c97d997041439eb58b82e28f35ed14784b6690c4285925b61789f7b609e8c3a8\
                              c9def7d2e74055bb3072a604cfe863b6d8260a9e655686972c38c3a8262344ff\
                              1ba513dba6b6f58adc1ac4af4a3ff722bec07fbea41261412272dbc7267ba79b\
                              de917ab1bfccdf7d7dbdbbb89048b3960621f3";

const FAILED: Result<usize, PublicKeyEncryptionError> =
    Err(PublicKeyEncryptionError::DecryptionFailed);

fn hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

fn sk(d: &str) -> SM2EncryptionPrivateKey {
    SM2EncryptionPrivateKey::from_bytes(&hex(d)).unwrap()
}

/// `C1 || C3 || C2` rearranged as `C1 || C2 || C3`.
fn as_c1c2c3(c1c3c2: &[u8]) -> Vec<u8> {
    let mut out = c1c3c2[..C1_LEN].to_vec();
    out.extend_from_slice(&c1c3c2[OVERHEAD_LEN..]);
    out.extend_from_slice(&c1c3c2[C1_LEN..OVERHEAD_LEN]);
    out
}

/// A message of `len` bytes that no two lengths share a prefix of.
fn message(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 + len) as u8).collect()
}

/// Decrypts `c1c3c2` in both orders into buffers full of `0xaa`, and returns what the standard
/// order gave, having checked that the other order gave the same and that a failure left both
/// buffers zeroized.
fn decrypt_both_orders(
    sk: &SM2EncryptionPrivateKey,
    c1c3c2: &[u8],
) -> Result<Vec<u8>, PublicKeyEncryptionError> {
    let mut out = vec![0xaa; c1c3c2.len()];
    let mut out_other = vec![0xaa; c1c3c2.len()];
    let result = sk.decrypt_out(c1c3c2, &mut out);
    let other = sk.decrypt_c1c2c3_out(&as_c1c2c3(c1c3c2), &mut out_other);
    assert_eq!(result, other);
    assert_eq!(out, out_other);
    match result {
        Ok(len) => {
            assert_eq!(len, c1c3c2.len() - OVERHEAD_LEN);
            assert!(out[len..].iter().all(|b| *b == 0), "the rest of the buffer is zeroized");
            out.truncate(len);
            Ok(out)
        }
        Err(e) => {
            assert!(out.iter().all(|b| *b == 0), "a failure leaves the buffer zeroized");
            Err(e)
        }
    }
}

/// An RNG that fails, or delivers one byte fewer than asked, at 128-bit strength.
struct BrokenRng {
    short: bool,
}

impl RNG for BrokenRng {
    fn add_seed_keymaterial(&mut self, _seed: &dyn KeyMaterialTrait) -> Result<(), RNGError> {
        Ok(())
    }

    fn next_int(&mut self) -> Result<u32, RNGError> {
        Err(RNGError::Uninitialized)
    }

    fn next_bytes_out(&mut self, out: &mut [u8]) -> Result<usize, RNGError> {
        out.fill(0);
        if self.short {
            let len = out.len() - 1;
            out[..len].fill(0x5a);
            Ok(len)
        } else {
            Err(RNGError::Uninitialized)
        }
    }

    fn fill_keymaterial_out(&mut self, _out: &mut dyn KeyMaterialTrait) -> Result<usize, RNGError> {
        Err(RNGError::KeyMaterialError(KeyMaterialError::InvalidLength))
    }

    fn security_strength(&self) -> SecurityStrength {
        SecurityStrength::_128bit
    }
}

/// A seed whose consecutive 40-byte draws differ: `FixedSeedRNG` repeats its seed, and a seed
/// of one draw's length would hand every encryption the same `k`.
fn counting_seed() -> [u8; 251] {
    core::array::from_fn(|i| i as u8)
}

#[test]
fn annex_c_ciphertext_decrypts_in_both_orders() {
    let sk = sk(ANNEX_C_DB);
    assert_eq!(sk.derive_pk().encode().to_vec(), hex(ANNEX_C_PB));

    let c1c3c2 = [hex(ANNEX_C_C1), hex(ANNEX_C_C3), hex(ANNEX_C_C2)].concat();
    assert_eq!(decrypt_both_orders(&sk, &c1c3c2).unwrap(), ANNEX_C_M);

    // The parts in the other order, read as C1 || C3 || C2, are not a ciphertext.
    let mut out = [0xaa; 19];
    assert_eq!(sk.decrypt_out(&as_c1c2c3(&c1c3c2), &mut out), FAILED);
    assert_eq!(out, [0; 19]);

    let mut buf = hex(ANNEX_C_C2);
    sk.decrypt_detached_inplace(
        &hex(ANNEX_C_C1).try_into().unwrap(),
        &hex(ANNEX_C_C3).try_into().unwrap(),
        &mut buf,
    )
    .unwrap();
    assert_eq!(buf, ANNEX_C_M);
}

#[test]
fn ciphertexts_from_the_model_and_from_openssl_decrypt() {
    let model_sk = sk(MODEL_D);
    assert_eq!(model_sk.derive_pk().encode().to_vec(), hex(MODEL_PB));
    for (ciphertext, len) in MODEL_C1C3C2.iter().zip([1usize, 33, 100]) {
        let expected: Vec<u8> = (0..len).map(|i| (7 * i + len) as u8).collect();
        assert_eq!(decrypt_both_orders(&model_sk, &hex(ciphertext)).unwrap(), expected);
    }

    assert_eq!(decrypt_both_orders(&sk(OPENSSL_D), &hex(OPENSSL_C1C3C2)).unwrap(), hex(OPENSSL_M));
}

/// GB/T 32918.4-2016 Section 7.1 step B4: a ciphertext whose key stream is all zero is refused,
/// although its `C3` is the hash decryption computes.
#[test]
fn a_ciphertext_with_an_all_zero_key_stream_is_refused() {
    let sk = sk(ANNEX_C_DB);
    let c1c3c2 = [hex(ZERO_T_C1), hex(ZERO_T_C3), vec![ZERO_T_M]].concat();
    assert_eq!(decrypt_both_orders(&sk, &c1c3c2), Err(PublicKeyEncryptionError::DecryptionFailed));

    let mut buf = [ZERO_T_M];
    assert_eq!(
        sk.decrypt_detached_inplace(
            &hex(ZERO_T_C1).try_into().unwrap(),
            &hex(ZERO_T_C3).try_into().unwrap(),
            &mut buf
        ),
        Err(PublicKeyEncryptionError::DecryptionFailed)
    );
    assert_eq!(buf, [0]);
}

/// Steps A5 and B4 test whether every byte of the key stream is zero. Here its two bytes are
/// equal, so a test that combined them any other way than by OR would take it for all zero:
/// encryption would draw again, and with this RNG give up, and decryption would refuse.
#[test]
fn a_key_stream_of_equal_bytes_is_not_all_zero() {
    let sk = sk(ANNEX_C_DB);
    let c1c3c2 = [hex(EQUAL_T_C1), hex(EQUAL_T_C3), EQUAL_T_C2.to_vec()].concat();
    assert_eq!(decrypt_both_orders(&sk, &c1c3c2).unwrap(), EQUAL_T_M);

    // The RNG's 40 bytes are k - 1: encryption takes k as that integer mod (n - 1), plus 1.
    let mut k_minus_1 = [0u8; 40];
    k_minus_1[39] = EQUAL_T_K - 1;
    let mut buf = EQUAL_T_M;
    let (c1, c3) = sk
        .derive_pk()
        .encrypt_detached_inplace(&mut FixedSeedRNG::new(k_minus_1), &mut buf)
        .unwrap();
    assert_eq!((c1.to_vec(), c3.to_vec(), buf), (hex(EQUAL_T_C1), hex(EQUAL_T_C3), EQUAL_T_C2));
}

/// The shared point `[dB]C1` is not the point at infinity when one of its coordinates is zero.
#[test]
fn a_shared_point_with_a_zero_x_coordinate_decrypts() {
    let model_sk = sk(MODEL_D);
    for (c1, c3, c2) in X2_ZERO {
        let c1c3c2 = [hex(c1), hex(c3), hex(c2)].concat();
        assert_eq!(decrypt_both_orders(&model_sk, &c1c3c2).unwrap(), b"x2 is zero");
    }
}

#[test]
fn round_trips_over_message_lengths() {
    let (pk, sk) = keygen(&mut DefaultRNG::default()).unwrap();
    let mut rng = DefaultRNG::default();
    for len in [1, 2, 31, 32, 33, 63, 64, 65, 127, 128, 129, 4096, 5000] {
        let msg = message(len);

        // Detached, in place.
        let mut buf = msg.clone();
        let (c1, c3) = pk.encrypt_detached_inplace(&mut rng, &mut buf).unwrap();
        assert_eq!(c1[0], 0x04);
        assert_ne!(buf, msg);
        let c2 = buf.clone();
        sk.decrypt_detached_inplace(&c1, &c3, &mut buf).unwrap();
        assert_eq!(buf, msg);

        // The contiguous forms are the same three parts.
        let c1c3c2 = [&c1[..], &c3[..], &c2[..]].concat();
        assert_eq!(decrypt_both_orders(&sk, &c1c3c2).unwrap(), msg);

        // C1 || C3 || C2 into a buffer that is longer than it needs to be.
        assert_eq!(pk.encrypt_out_len(len), len + OVERHEAD_LEN);
        let mut out = vec![0xaa; len + OVERHEAD_LEN + 5];
        assert_eq!(pk.encrypt_out(&mut rng, &msg, &mut out), Ok(len + OVERHEAD_LEN));
        assert_eq!(out[len + OVERHEAD_LEN..], [0; 5]);
        let ciphertext = &out[..len + OVERHEAD_LEN];
        assert_eq!(ciphertext[0], 0x04);
        assert_eq!(sk.decrypt_out_len(ciphertext.len()), len);
        let mut plaintext = vec![0xaa; len + 3];
        assert_eq!(sk.decrypt_out(ciphertext, &mut plaintext), Ok(len));
        assert_eq!(plaintext[..len], msg);
        assert_eq!(plaintext[len..], [0; 3]);

        // C1 || C2 || C3.
        assert_eq!(pk.encrypt_c1c2c3_out_len(len), len + OVERHEAD_LEN);
        let mut out = vec![0xaa; len + OVERHEAD_LEN];
        assert_eq!(pk.encrypt_c1c2c3_out(&mut rng, &msg, &mut out), Ok(len + OVERHEAD_LEN));
        assert_eq!(sk.decrypt_c1c2c3_out_len(out.len()), len);
        let mut plaintext = vec![0xaa; len];
        assert_eq!(sk.decrypt_c1c2c3_out(&out, &mut plaintext), Ok(len));
        assert_eq!(plaintext, msg);
        // And it is that order: C3 is the last 32 bytes, so moving it decrypts the other way.
        let mut moved = out[..C1_LEN].to_vec();
        moved.extend_from_slice(&out[C1_LEN + len..]);
        moved.extend_from_slice(&out[C1_LEN..C1_LEN + len]);
        assert_eq!(sk.decrypt_out(&moved, &mut plaintext), Ok(len));
        assert_eq!(plaintext, msg);
    }
}

#[test]
fn out_len_helpers_saturate() {
    let (pk, sk) = keygen(&mut DefaultRNG::default()).unwrap();
    assert_eq!(pk.encrypt_out_len(0), 97);
    assert_eq!(pk.encrypt_out_len(usize::MAX), usize::MAX);
    assert_eq!(pk.encrypt_c1c2c3_out_len(usize::MAX - 96), usize::MAX);
    assert_eq!(sk.decrypt_out_len(98), 1);
    assert_eq!(sk.decrypt_out_len(97), 0);
    assert_eq!(sk.decrypt_out_len(0), 0);
    assert_eq!(sk.decrypt_c1c2c3_out_len(96), 0);
}

#[test]
fn every_byte_of_a_ciphertext_is_covered() {
    let (pk, sk) = keygen(&mut DefaultRNG::default()).unwrap();
    let msg = message(40);
    let mut ciphertext = vec![0u8; 40 + OVERHEAD_LEN];
    pk.encrypt_out(&mut DefaultRNG::default(), &msg, &mut ciphertext).unwrap();
    assert_eq!(decrypt_both_orders(&sk, &ciphertext).unwrap(), msg);

    // C1 is bytes 0 to 64, C3 bytes 65 to 96, C2 the rest.
    for i in 0..ciphertext.len() {
        for bit in [0x01, 0x80] {
            let mut tampered = ciphertext.clone();
            tampered[i] ^= bit;
            assert_eq!(
                decrypt_both_orders(&sk, &tampered),
                Err(PublicKeyEncryptionError::DecryptionFailed),
                "byte {i}"
            );
        }
    }

    // A byte more or a byte less of C2.
    let mut longer = ciphertext.clone();
    longer.push(0);
    assert_eq!(decrypt_both_orders(&sk, &longer), Err(PublicKeyEncryptionError::DecryptionFailed));
    assert_eq!(
        decrypt_both_orders(&sk, &ciphertext[..ciphertext.len() - 1]),
        Err(PublicKeyEncryptionError::DecryptionFailed)
    );
}

#[test]
fn a_failed_detached_decryption_leaves_the_buffer_zeroized() {
    let (pk, sk) = keygen(&mut DefaultRNG::default()).unwrap();
    let mut buf = message(70);
    let (c1, c3) = pk.encrypt_detached_inplace(&mut DefaultRNG::default(), &mut buf).unwrap();
    let c2 = buf.clone();

    let mut bad_c3 = c3;
    bad_c3[0] ^= 1;
    let mut bad_c1 = c1;
    bad_c1[40] ^= 1;
    let mut bad_c2 = c2.clone();
    bad_c2[69] ^= 1;
    for (c1, c3, c2) in [(&c1, &bad_c3, &c2), (&bad_c1, &c3, &c2), (&c1, &c3, &bad_c2)] {
        let mut buf = c2.clone();
        assert_eq!(
            sk.decrypt_detached_inplace(c1, c3, &mut buf),
            Err(PublicKeyEncryptionError::DecryptionFailed)
        );
        assert_eq!(buf, [0; 70]);
    }
}

/// `C1` with its tag set to `tag`.
fn retagged(c1: &[u8], tag: u8) -> Vec<u8> {
    [&[tag][..], &c1[1..]].concat()
}

/// The hybrid tag that matches the parity of `c1`'s `y`.
fn hybrid_tag(c1: &[u8]) -> u8 {
    0x06 | (c1[64] & 1)
}

/// Step B1 converts `C1` from the uncompressed or the hybrid form (GB/T 32918.1-2016 Section
/// 4.2.10), and a ciphertext decrypts the same in either. The two `X2_ZERO` points have one `x`
/// and the two parities of `y`; the annex's `y` is even.
#[test]
fn c1_in_the_hybrid_form_decrypts() {
    let model_sk = sk(MODEL_D);
    let mut tags = Vec::new();
    for (c1, c3, c2) in X2_ZERO {
        let tag = hybrid_tag(&hex(c1));
        tags.push(tag);
        let hybrid = retagged(&hex(c1), tag);
        let c1c3c2 = [hybrid.clone(), hex(c3), hex(c2)].concat();
        assert_eq!(decrypt_both_orders(&model_sk, &c1c3c2).unwrap(), b"x2 is zero");

        let mut buf = hex(c2);
        model_sk
            .decrypt_detached_inplace(
                &hybrid.try_into().unwrap(),
                &hex(c3).try_into().unwrap(),
                &mut buf,
            )
            .unwrap();
        assert_eq!(buf, b"x2 is zero");
    }
    assert_eq!(tags, [0x07, 0x06]);

    let annex = [retagged(&hex(ANNEX_C_C1), 0x06), hex(ANNEX_C_C3), hex(ANNEX_C_C2)].concat();
    assert_eq!(decrypt_both_orders(&sk(ANNEX_C_DB), &annex).unwrap(), ANNEX_C_M);
}

/// A hybrid tag is refused when it disagrees with the parity of `y` (GB/T 32918.1-2016 Section
/// 4.2.9 d) 3) and 4.2.10 e)), in both APIs, with the buffer zeroized.
#[test]
fn c1_in_the_hybrid_form_with_the_wrong_parity_is_refused() {
    let model_sk = sk(MODEL_D);
    for (c1, c3, c2) in X2_ZERO {
        let wrong = retagged(&hex(c1), hybrid_tag(&hex(c1)) ^ 1);
        let c1c3c2 = [wrong.clone(), hex(c3), hex(c2)].concat();
        assert_eq!(
            decrypt_both_orders(&model_sk, &c1c3c2),
            Err(PublicKeyEncryptionError::DecryptionFailed)
        );

        let mut buf = hex(c2);
        assert_eq!(
            model_sk.decrypt_detached_inplace(
                &wrong.try_into().unwrap(),
                &hex(c3).try_into().unwrap(),
                &mut buf,
            ),
            Err(PublicKeyEncryptionError::DecryptionFailed)
        );
        assert_eq!(buf, [0; 10]);
    }
}

/// Step B1: `C1` is a point on the curve in the uncompressed or hybrid form with both
/// coordinates below `p`, or the ciphertext is refused, whatever the rest of it is.
#[test]
fn c1_that_is_not_a_point_in_the_uncompressed_or_hybrid_form_is_refused() {
    let model_sk = sk(MODEL_D);

    // The control: a valid point whose x is 1, in both forms.
    let small_x = [hex(SMALL_X_C1), hex(SMALL_X_C3), hex(SMALL_X_C2)].concat();
    assert_eq!(decrypt_both_orders(&model_sk, &small_x).unwrap(), b"range check");
    let small_x_hybrid = retagged(&hex(SMALL_X_C1), hybrid_tag(&hex(SMALL_X_C1)));
    let small_x = [small_x_hybrid, hex(SMALL_X_C3), hex(SMALL_X_C2)].concat();
    assert_eq!(decrypt_both_orders(&model_sk, &small_x).unwrap(), b"range check");

    // The same point with x + p for x: a coordinate that is not below p, in both forms.
    let plus_p = hex(SMALL_X_C1_PLUS_P);
    for c1 in [plus_p.clone(), retagged(&plus_p, hybrid_tag(&plus_p))] {
        let out_of_range = [c1, hex(SMALL_X_C3), hex(SMALL_X_C2)].concat();
        assert_eq!(
            decrypt_both_orders(&model_sk, &out_of_range),
            Err(PublicKeyEncryptionError::DecryptionFailed)
        );
    }

    // A point off the curve, with the C2 and C3 that go with it, in both forms.
    let off = hex(OFF_CURVE_C1);
    for c1 in [off.clone(), retagged(&off, hybrid_tag(&off))] {
        let off_curve = [c1, hex(OFF_CURVE_C3), hex(OFF_CURVE_C2)].concat();
        assert_eq!(
            decrypt_both_orders(&model_sk, &off_curve),
            Err(PublicKeyEncryptionError::DecryptionFailed)
        );
    }

    // The annex's ciphertext with C1 in the compressed form of GB/T 32918.1-2016 Section 4.2.9,
    // which no 65-byte C1 holds, and under tags of no form.
    let annex_sk = sk(ANNEX_C_DB);
    let (c1, c3, c2) = (hex(ANNEX_C_C1), hex(ANNEX_C_C3), hex(ANNEX_C_C2));
    for tag in [0x01, 0x05, 0x08, 0x84, 0x86] {
        let ciphertext = [retagged(&c1, tag), c3.clone(), c2.clone()].concat();
        assert_eq!(
            decrypt_both_orders(&annex_sk, &ciphertext),
            Err(PublicKeyEncryptionError::DecryptionFailed)
        );
    }
    // Compressed: 02 or 03 by the parity of y, then x; 33 bytes, and also with y left in.
    for prefix in [0x02, 0x03] {
        let compressed = [vec![prefix], c1[1..33].to_vec()].concat();
        // 33 bytes of C1 leave this short of C1 and C3 for a 19-byte C2, so C2 is made longer.
        let ciphertext = [compressed.clone(), c3.clone(), c2.clone(), vec![0; 32]].concat();
        assert_eq!(
            decrypt_both_orders(&annex_sk, &ciphertext),
            Err(PublicKeyEncryptionError::DecryptionFailed)
        );
        let mut same_length = c1.clone();
        same_length[0] = prefix;
        let ciphertext = [same_length, c3.clone(), c2.clone()].concat();
        assert_eq!(
            decrypt_both_orders(&annex_sk, &ciphertext),
            Err(PublicKeyEncryptionError::DecryptionFailed)
        );
    }
    // The point at infinity: the single byte 00, alone and padded to 65, and (0, 0).
    let mut zero_point = vec![0u8; 65];
    for first in [0x00, 0x04] {
        zero_point[0] = first;
        let ciphertext = [zero_point.clone(), c3.clone(), c2.clone()].concat();
        assert_eq!(
            decrypt_both_orders(&annex_sk, &ciphertext),
            Err(PublicKeyEncryptionError::DecryptionFailed)
        );
    }
    let ciphertext = [vec![0u8], c3.clone(), [c2.clone(), vec![0; 64]].concat()].concat();
    assert_eq!(
        decrypt_both_orders(&annex_sk, &ciphertext),
        Err(PublicKeyEncryptionError::DecryptionFailed)
    );
}

#[test]
fn the_wrong_private_key_does_not_decrypt() {
    let (pk, _) = keygen(&mut DefaultRNG::default()).unwrap();
    let (_, other_sk) = keygen(&mut DefaultRNG::default()).unwrap();
    let mut ciphertext = vec![0u8; 50 + OVERHEAD_LEN];
    pk.encrypt_out(&mut DefaultRNG::default(), &message(50), &mut ciphertext).unwrap();
    assert_eq!(
        decrypt_both_orders(&other_sk, &ciphertext),
        Err(PublicKeyEncryptionError::DecryptionFailed)
    );
}

#[test]
fn an_empty_message_is_refused_both_ways() {
    let (pk, sk) = keygen(&mut DefaultRNG::default()).unwrap();
    let mut rng = DefaultRNG::default();
    let invalid_length =
        |r: Result<usize, _>| matches!(r, Err(PublicKeyEncryptionError::InvalidInputLength(_)));

    assert!(matches!(
        pk.encrypt_detached_inplace(&mut rng, &mut []),
        Err(PublicKeyEncryptionError::InvalidInputLength(_))
    ));
    let mut out = [0xaa; 200];
    assert!(invalid_length(pk.encrypt_out(&mut rng, &[], &mut out)));
    assert_eq!(out, [0; 200]);
    let mut out = [0xaa; 200];
    assert!(invalid_length(pk.encrypt_c1c2c3_out(&mut rng, &[], &mut out)));
    assert_eq!(out, [0; 200]);
    // The message is at fault before the buffer is.
    assert!(invalid_length(pk.encrypt_out(&mut rng, &[], &mut [])));

    // A real C1 and C3 with no C2, and everything shorter.
    let mut buf = [1u8];
    let (c1, c3) = pk.encrypt_detached_inplace(&mut rng, &mut buf).unwrap();
    assert!(matches!(
        sk.decrypt_detached_inplace(&c1, &c3, &mut []),
        Err(PublicKeyEncryptionError::InvalidInputLength(_))
    ));
    let c1c3 = [&c1[..], &c3[..]].concat();
    for len in [0, 1, 65, 96, 97] {
        let mut out = [0xaa; 200];
        assert!(invalid_length(sk.decrypt_out(&c1c3[..len], &mut out)), "length {len}");
        assert_eq!(out, [0; 200]);
        let mut out = [0xaa; 200];
        assert!(invalid_length(sk.decrypt_c1c2c3_out(&c1c3[..len], &mut out)), "length {len}");
        assert_eq!(out, [0; 200]);
    }
}

#[test]
fn an_output_buffer_that_is_too_short_is_zeroized_and_refused() {
    let (pk, sk) = keygen(&mut DefaultRNG::default()).unwrap();
    let mut rng = DefaultRNG::default();
    let msg = message(20);
    let mut ciphertext = vec![0u8; 20 + OVERHEAD_LEN];
    pk.encrypt_out(&mut rng, &msg, &mut ciphertext).unwrap();

    let too_small = Err(PublicKeyEncryptionError::OutputBufferTooSmall(20 + OVERHEAD_LEN));
    let mut out = vec![0xaa; 20 + OVERHEAD_LEN - 1];
    assert_eq!(pk.encrypt_out(&mut rng, &msg, &mut out), too_small);
    assert!(out.iter().all(|b| *b == 0));
    out.fill(0xaa);
    assert_eq!(pk.encrypt_c1c2c3_out(&mut rng, &msg, &mut out), too_small);
    assert!(out.iter().all(|b| *b == 0));
    assert_eq!(pk.encrypt_out(&mut rng, &msg, &mut []), too_small);

    let too_small = Err(PublicKeyEncryptionError::OutputBufferTooSmall(20));
    let mut out = [0xaa; 19];
    assert_eq!(sk.decrypt_out(&ciphertext, &mut out), too_small);
    assert_eq!(out, [0; 19]);
    out.fill(0xaa);
    assert_eq!(sk.decrypt_c1c2c3_out(&as_c1c2c3(&ciphertext), &mut out), too_small);
    assert_eq!(out, [0; 19]);
}

#[test]
fn two_encryptions_of_one_message_differ() {
    let (pk, sk) = keygen(&mut DefaultRNG::default()).unwrap();
    let msg = message(48);

    // One RNG, drawn from twice.
    let mut rng = FixedSeedRNG::new(counting_seed());
    let mut first = msg.clone();
    let mut second = msg.clone();
    let (c1_a, c3_a) = pk.encrypt_detached_inplace(&mut rng, &mut first).unwrap();
    let (c1_b, c3_b) = pk.encrypt_detached_inplace(&mut rng, &mut second).unwrap();
    assert_ne!(c1_a, c1_b);
    assert_ne!(c3_a, c3_b);
    assert_ne!(first, second);
    sk.decrypt_detached_inplace(&c1_a, &c3_a, &mut first).unwrap();
    sk.decrypt_detached_inplace(&c1_b, &c3_b, &mut second).unwrap();
    assert_eq!((first, second), (msg.clone(), msg.clone()));

    // And the randomness is all that distinguishes them: the same draws give the same result.
    let mut rng = FixedSeedRNG::new(counting_seed());
    let mut again = msg.clone();
    assert_eq!(pk.encrypt_detached_inplace(&mut rng, &mut again).unwrap(), (c1_a, c3_a));
}

#[test]
fn an_rng_below_128_bits_is_refused() {
    let (pk, _) = keygen(&mut DefaultRNG::default()).unwrap();
    let weak =
        Err(PublicKeyEncryptionError::RNGError(RNGError::SecurityStrengthInsufficientForAlgorithm));
    let mut rng = FixedSeedRNG::new(counting_seed());
    rng.set_security_strength(SecurityStrength::_112bit);

    let msg = message(10);
    let mut buf = msg.clone();
    assert_eq!(pk.encrypt_detached_inplace(&mut rng, &mut buf).map(|_| ()), weak);
    assert_eq!(buf, msg, "the message is left as it was");
    let mut out = [0xaa; 200];
    assert_eq!(pk.encrypt_out(&mut rng, &msg, &mut out).map(|_| ()), weak);
    assert_eq!(out, [0; 200]);
    assert_eq!(keygen(&mut rng).map(|_| ()), weak);

    rng.set_security_strength(SecurityStrength::_128bit);
    pk.encrypt_detached_inplace(&mut rng, &mut buf).unwrap();
    keygen(&mut rng).unwrap();
}

#[test]
fn an_rng_that_fails_or_delivers_short_is_an_error() {
    let (pk, _) = keygen(&mut DefaultRNG::default()).unwrap();
    let msg = message(10);
    for (short, expected) in [(false, RNGError::Uninitialized), (true, RNGError::GenericError(""))]
    {
        let mut rng = BrokenRng { short };
        let same_kind = |r: Result<(), PublicKeyEncryptionError>| match (r, &expected) {
            (
                Err(PublicKeyEncryptionError::RNGError(RNGError::GenericError(_))),
                RNGError::GenericError(_),
            ) => true,
            (Err(PublicKeyEncryptionError::RNGError(e)), expected) => e == *expected,
            _ => false,
        };

        let mut buf = msg.clone();
        assert!(same_kind(pk.encrypt_detached_inplace(&mut rng, &mut buf).map(|_| ())));
        assert_eq!(buf, msg, "the message is left as it was");
        let mut out = [0xaa; 200];
        assert!(same_kind(pk.encrypt_out(&mut rng, &msg, &mut out).map(|_| ())));
        assert_eq!(out, [0; 200], "and the copy of it in the output buffer is not");
        assert!(same_kind(keygen(&mut rng).map(|_| ())));
    }
}

#[test]
fn key_encodings_round_trip() {
    TestFrameworkSignatureKeys::new()
        .test_keys::<SM2EncryptionPublicKey, SM2EncryptionPrivateKey, 65, 32>(|| {
            keygen(&mut DefaultRNG::default()).map_err(|_| SignatureError::GenericError("keygen"))
        });

    let (pk, sk) = keygen(&mut DefaultRNG::default()).unwrap();
    assert_eq!(sk.derive_pk(), pk);
    assert_eq!(SM2EncryptionPublicKey::from_bytes(&pk.encode()).unwrap(), pk);
    assert_eq!(SM2EncryptionPrivateKey::from_bytes(&sk.encode()).unwrap(), sk);

    let mut pk_out = [0xaa; 65];
    assert_eq!(pk.encode_out(&mut pk_out), 65);
    assert_eq!(pk_out, pk.encode());
    assert_eq!(pk_out[0], 0x04);
    let mut sk_out = [0xaa; 32];
    assert_eq!(sk.encode_out(&mut sk_out), 32);
    assert_eq!(sk_out, sk.encode());

    // The compressed form of a public key is accepted, and is the same key.
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02 | (pk_out[64] & 1);
    compressed[1..].copy_from_slice(&pk_out[1..33]);
    assert_eq!(SM2EncryptionPublicKey::from_bytes(&compressed).unwrap(), pk);

    // The encodings are the signature keys': the same bytes load as either.
    assert_eq!(SM2PublicKey::from_bytes(&pk_out).unwrap().encode(), pk_out);
    assert_eq!(SM2PrivateKey::from_bytes(&sk_out).unwrap().encode(), sk_out);
    assert_eq!(SM2PrivateKey::from_bytes(&sk_out).unwrap().derive_pk().encode(), pk_out);

    let (other_pk, other_sk) = keygen(&mut DefaultRNG::default()).unwrap();
    assert_ne!(pk, other_pk);
    assert_ne!(sk, other_sk);
    assert_ne!(format!("{pk}"), format!("{other_pk}"));
    assert!(format!("{pk}").starts_with("SM2EncryptionPublicKey"));
    // The private scalar is not what Debug prints.
    let debug = format!("{sk:?}");
    let low_limb = u64::from_be_bytes(sk_out[24..].try_into().unwrap());
    assert!(!debug.contains(&format!("{low_limb}")) && !debug.contains(&format!("{low_limb:x}")));
}

#[test]
fn keys_out_of_range_or_off_the_curve_are_refused() {
    let invalid = |r: Result<SM2EncryptionPrivateKey, KeyDecodingError>| r.is_err();
    // dB is in [1, n-2].
    let n = be_bytes_from_limbs(&N_LIMBS);
    let n_minus = |k: u8| {
        let mut bytes = n;
        bytes[31] -= k;
        bytes
    };
    assert!(invalid(SM2EncryptionPrivateKey::from_bytes(&[0; 32])));
    assert!(invalid(SM2EncryptionPrivateKey::from_bytes(&n)));
    assert!(invalid(SM2EncryptionPrivateKey::from_bytes(&n_minus(1))));
    assert!(invalid(SM2EncryptionPrivateKey::from_bytes(&[0xff; 32])));
    assert!(invalid(SM2EncryptionPrivateKey::from_bytes(&[1; 31])));
    assert!(invalid(SM2EncryptionPrivateKey::from_bytes(&[1; 33])));
    let mut one = [0u8; 32];
    one[31] = 1;
    assert_eq!(SM2EncryptionPrivateKey::from_bytes(&one).unwrap().encode(), one);
    assert_eq!(SM2EncryptionPrivateKey::from_bytes(&n_minus(2)).unwrap().encode(), n_minus(2));
    // Zero is every limb being zero: keys whose 64-bit limbs are equal, in pairs or all four,
    // are in range, although their limbs XOR to zero.
    for limbs in [[0u64, 0, 1, 1], [1, 1, 1, 1], [u64::MAX, u64::MAX, 0, 0]] {
        let equal_limbs: [u8; 32] = be_bytes_from_limbs(&limbs);
        let sk = SM2EncryptionPrivateKey::from_bytes(&equal_limbs).unwrap();
        assert_eq!(sk.encode(), equal_limbs);
        assert_eq!(
            sk.derive_pk().encode(),
            SM2PrivateKey::from_bytes(&equal_limbs).unwrap().derive_pk().encode()
        );
    }

    assert!(SM2EncryptionPublicKey::from_bytes(&hex(SMALL_X_C1)).is_ok());
    assert!(SM2EncryptionPublicKey::from_bytes(&hex(SMALL_X_C1_PLUS_P)).is_err());
    assert!(SM2EncryptionPublicKey::from_bytes(&hex(OFF_CURVE_C1)).is_err());
    assert!(SM2EncryptionPublicKey::from_bytes(&[0u8; 65]).is_err());
    assert!(SM2EncryptionPublicKey::from_bytes(&[0u8]).is_err());
    let mut hybrid = hex(ANNEX_C_PB);
    hybrid[0] = 0x06 | (hybrid[64] & 1);
    assert!(SM2EncryptionPublicKey::from_bytes(&hybrid).is_err());
}

#[test]
fn keygen_is_determined_by_the_rng_and_gives_a_working_pair() {
    let (pk_a, sk_a) = keygen(&mut FixedSeedRNG::new(counting_seed())).unwrap();
    let (pk_b, sk_b) = keygen(&mut FixedSeedRNG::new(counting_seed())).unwrap();
    assert_eq!((pk_a, &sk_a), (pk_b, &sk_b));
    let mut other_seed = counting_seed();
    other_seed[39] ^= 1;
    let (pk_c, sk_c) = keygen(&mut FixedSeedRNG::new(other_seed)).unwrap();
    assert_ne!(pk_a, pk_c);

    // The pair works, and it is a pair: the other private key does not decrypt.
    assert_eq!(sk_a.derive_pk(), pk_a);
    let msg = message(45);
    let mut ciphertext = vec![0u8; 45 + OVERHEAD_LEN];
    pk_a.encrypt_out(&mut DefaultRNG::default(), &msg, &mut ciphertext).unwrap();
    assert_eq!(decrypt_both_orders(&sk_a, &ciphertext).unwrap(), msg);
    assert_eq!(
        decrypt_both_orders(&sk_c, &ciphertext),
        Err(PublicKeyEncryptionError::DecryptionFailed)
    );
}

/// `dB` is the RNG's 40 bytes, as a big-endian integer, mod `n - 2`, plus 1: a value in
/// `[1, n-2]` (GB/T 32918.1-2016 Section 6.1 a)).
#[test]
fn keygen_known_answer_and_the_ends_of_its_range() {
    let (pk, sk) = keygen(&mut FixedSeedRNG::new(counting_seed())).unwrap();
    assert_eq!(sk.encode().to_vec(), hex(KEYGEN_D));
    assert_eq!(pk.encode().to_vec(), hex(KEYGEN_PB));

    let n = be_bytes_from_limbs(&N_LIMBS);
    let generated_from = |n_minus: u8| {
        let mut seed = [0u8; 40];
        seed[8..].copy_from_slice(&n);
        seed[39] -= n_minus;
        keygen(&mut FixedSeedRNG::new(seed)).unwrap().1.encode()
    };
    let mut n_minus_2 = n;
    n_minus_2[31] -= 2;
    let mut one = [0u8; 32];
    one[31] = 1;
    // n - 3 is the largest value below the modulus, and gives the largest key.
    assert_eq!(generated_from(3), n_minus_2);
    // n - 2 is the modulus, and wraps to the smallest: reduced mod n - 1 it would give n - 1.
    assert_eq!(generated_from(2), one);
    assert_eq!(keygen(&mut FixedSeedRNG::new([0u8; 40])).unwrap().1.encode(), one);
}

/// The smallest and the largest private key, 1 and `n - 2`, encrypt and decrypt.
#[test]
fn the_keys_at_the_ends_of_the_range_round_trip() {
    let mut one = [0u8; 32];
    one[31] = 1;
    let mut n_minus_2 = be_bytes_from_limbs(&N_LIMBS);
    n_minus_2[31] -= 2;
    for d in [one, n_minus_2] {
        let sk = SM2EncryptionPrivateKey::from_bytes(&d).unwrap();
        let pk = sk.derive_pk();
        let mut ciphertext = vec![0u8; 50 + OVERHEAD_LEN];
        pk.encrypt_out(&mut DefaultRNG::default(), &message(50), &mut ciphertext).unwrap();
        assert_eq!(decrypt_both_orders(&sk, &ciphertext), Ok(message(50)));
    }
}
