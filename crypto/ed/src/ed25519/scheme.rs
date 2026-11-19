//! Ed25519 and Ed25519ph as RFC 8032 Sections 5.1.5 to 5.1.7 give them: the public key of a
//! private key, signing and verification, over octet arrays and [`PublicPoint`].
//!
//! Ed25519ctx is not provided, so where `dom2(F, C)` is present its flag F is always 1.
//! Verification is cofactored: it checks the first of the two equations of Section 5.1.7,
//! step 3, so a signature that differs from a valid one by points of small order is accepted
//! (Section 8.8).
//!
//! Signing is constant time in the private key and in everything derived from it; the
//! message, the context, the public key and the signature are public. Verification is
//! variable time throughout.

use super::point::{self, PointAffine, PublicPoint};
use super::scalar;
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::hazmat::finish_token;
use bouncycastle_core::traits::Hash;
use bouncycastle_sha2::SHA512;
use bouncycastle_utils::secret::Secret;

/// Octets in an Ed25519 private key (RFC 8032 Section 5.1.5).
pub const PRIVATE_KEY_LEN: usize = 32;
/// Octets in an Ed25519 public key (RFC 8032 Section 5.1.5).
pub const PUBLIC_KEY_LEN: usize = 32;
/// Octets in an Ed25519 or Ed25519ph signature (RFC 8032 Section 5.1.6).
pub const SIGNATURE_LEN: usize = 64;
/// Octets in the SHA-512 pre-hash of Ed25519ph.
pub(crate) const PREHASH_LEN: usize = 64;
/// The longest Ed25519ph context, in octets (RFC 8032 Section 5.1: "maximum of 255 octets").
pub const CONTEXT_MAX_LEN: usize = 255;

/// The fixed part of `dom2` (RFC 8032 Section 2), "in ASCII (32 octets)".
const DOM2_PREFIX: &[u8; 32] = b"SigEd25519 no Ed25519 collisions";

/// The one error of the two fault paths, key expansion and signing: a fixed-base multiplication
/// whose result failed its own check (FIPS 186-5 Section 7.1 asks implementations to "verify
/// the correctness of group arithmetic computations"), which no input causes.
fn computation_fault() -> SignatureError {
    SignatureError::ComputationFault
}

/// The private key after RFC 8032 Section 5.1.6, step 1, with its public key: the secret
/// scalar `s` and `prefix`, the two halves of its SHA-512 digest, and `A`, the encoding of
/// `[s]B`. The scalar and the prefix are wiped when the value is dropped.
///
/// `A` is computed here, once, and signing reads it from here: a signature made with any
/// other value in its place exposes the private scalar to whoever also holds a correct
/// signature on the same message, so no caller is given the chance to supply one.
#[allow(non_snake_case)]
pub(crate) struct ExpandedKey {
    /// The pruned first half of the digest: the scalar, in 32 little-endian octets.
    s: Secret<[u8; 32]>,
    /// The second half of the digest.
    prefix: Secret<[u8; 32]>,
    /// The public key. All zero exactly while the key is unfilled: an all-zero encoding is
    /// y = 0, which no multiple of B has, and the result check refuses.
    A: [u8; PUBLIC_KEY_LEN],
}

impl ExpandedKey {
    /// An all-zero, unfilled value for [`Self::expand`] to fill where it will live.
    pub(crate) const fn zeroized() -> Self {
        Self { s: Secret::new(), prefix: Secret::new(), A: [0; PUBLIC_KEY_LEN] }
    }

    /// Back to the unfilled value, the scalar and the prefix wiped.
    pub(crate) fn clear(&mut self) {
        self.s.zeroize();
        self.prefix.zeroize();
        self.A = [0; PUBLIC_KEY_LEN];
    }

    /// Makes `self` a copy of `source`, field by field, with nothing staged on the way.
    pub(crate) fn copy_from(&mut self, source: &Self) {
        self.s.copy_from_slice(&*source.s);
        self.prefix.copy_from_slice(&*source.prefix);
        self.A = source.A;
    }

    /// Whether [`Self::expand`] has filled the key.
    pub(crate) fn is_filled(&self) -> bool {
        self.A != [0; PUBLIC_KEY_LEN]
    }

    /// Fills `self` from the private key `sk` (RFC 8032 Section 5.1.5, steps 1 to 4).
    /// Constant time; the digest is wiped on return. The only error is the multiplication
    /// failing its own result check, when `self` is left unfilled.
    pub(crate) fn expand(&mut self, sk: &[u8; PRIVATE_KEY_LEN]) -> Result<(), SignatureError> {
        // Step 1: "Hash the 32-byte private key using SHA-512, storing the digest in a
        // 64-octet large buffer, denoted h."
        // The hash is finished where it sits, so that its state, which has absorbed the
        // key, is wiped in place when it drops and not left behind by a move.
        let mut h = Secret::<[u8; 64]>::new();
        let mut hash = SHA512::new();
        hash.do_update(sk);
        hash.finish_into(&finish_token(), &mut *h);
        self.s.copy_from_slice(&h[..32]);
        self.prefix.copy_from_slice(&h[32..]);

        // Step 2: "The lowest three bits of the first octet are cleared, the highest bit of
        // the last octet is cleared, and the second highest bit of the last octet is set."
        self.s[0] &= 0xF8;
        self.s[31] &= 0x7F;
        self.s[31] |= 0x40;

        // Steps 3 and 4: "Interpret the buffer as the little-endian integer, forming a
        // secret scalar s. Perform a fixed-base scalar multiplication [s]B." "The public key
        // A is the encoding of the point [s]B."
        // The multiplication wants a scalar below 2^256 - L (`scalar::to_signed_digits`):
        // step 2 cleared bit 255, so s < 2^255, and L < 2^253.
        if point::scalar_mult_base_encoded(&self.s, &mut self.A).is_err() {
            self.clear();
            return Err(computation_fault());
        }
        Ok(())
    }

    /// The public key, the encoding of `[s]B`; all zero for an unfilled key.
    pub(crate) fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.A
    }

    /// The public key as a point, or `None` for an unfilled key. Costs a square root, and no
    /// scalar multiplication: see [`PublicPoint::decode_base_multiple_var`], whose two
    /// conditions hold here. `A` is the checked encoding of `[s]B`, and `[s]B` is not the
    /// neutral element, because the pruned `s` is a multiple of 8 below `8 L` and not zero,
    /// so not a multiple of the odd `L`.
    pub(crate) fn public_point(&self) -> Option<PublicPoint> {
        if !self.is_filled() {
            return None;
        }
        PublicPoint::decode_base_multiple_var(&self.A)
    }
}

/// Signs the message `M` with Ed25519 (RFC 8032 Section 5.1.6), writing `R || S` to `sig`.
/// `key` must be filled. The only error is the multiplication failing its own result check,
/// when `sig` is left zero.
#[allow(non_snake_case)]
pub(crate) fn sign(
    key: &ExpandedKey,
    M: &[u8],
    sig: &mut [u8; SIGNATURE_LEN],
) -> Result<(), SignatureError> {
    sign_core(key, None, M, sig)
}

/// Signs with Ed25519ph (RFC 8032 Section 5.1.6): `prehash` is `PH(M)`, the SHA-512 digest of
/// the message, and `context` is at most [`CONTEXT_MAX_LEN`] octets, or the call fails with
/// a `LengthError`. Otherwise as [`sign`].
pub(crate) fn sign_ph(
    key: &ExpandedKey,
    context: &[u8],
    prehash: &[u8; PREHASH_LEN],
    sig: &mut [u8; SIGNATURE_LEN],
) -> Result<(), SignatureError> {
    sign_core(key, Some(context), prehash, sig)
}

/// Verifies an Ed25519 signature on the message `M` (RFC 8032 Section 5.1.7).
/// `SignatureVerificationFailed` is the only error.
#[allow(non_snake_case)]
pub(crate) fn verify(
    sig: &[u8; SIGNATURE_LEN],
    A: &PublicPoint,
    M: &[u8],
) -> Result<(), SignatureError> {
    verify_core(sig, A, None, M)
}

/// Verifies an Ed25519ph signature (RFC 8032 Section 5.1.7): `prehash` and `context` as for
/// [`sign_ph`], with a `LengthError` for a context that is too long and
/// `SignatureVerificationFailed` otherwise.
#[allow(non_snake_case)]
pub(crate) fn verify_ph(
    sig: &[u8; SIGNATURE_LEN],
    A: &PublicPoint,
    context: &[u8],
    prehash: &[u8; PREHASH_LEN],
) -> Result<(), SignatureError> {
    verify_core(sig, A, Some(context), prehash)
}

/// Whether `context` fits Ed25519ph's `dom2`.
pub(crate) fn check_context(context: Option<&[u8]>) -> Result<(), SignatureError> {
    match context {
        Some(context) if context.len() > CONTEXT_MAX_LEN => {
            Err(SignatureError::LengthError("an Ed25519ph context is at most 255 octets"))
        }
        _ => Ok(()),
    }
}

/// Absorbs `dom2(F, C)` (RFC 8032 Section 2): nothing for Ed25519 (`None`), and for
/// Ed25519ph the prefix, `octet(F)` with F = 1, `octet(OLEN(C))` and C. The context has
/// passed [`check_context`], so its length fits the octet.
fn absorb_dom2(hash: &mut SHA512, context: Option<&[u8]>) {
    if let Some(context) = context {
        hash.do_update(DOM2_PREFIX);
        hash.do_update(&[1, context.len() as u8]);
        hash.do_update(context);
    }
}

/// RFC 8032 Section 5.1.6, steps 2 to 6; step 1 is [`ExpandedKey::expand`]. `PH_M` is the
/// message for Ed25519 and its pre-hash for Ed25519ph.
///
/// The digest of step 2, `r` and the working values of `[r]B` and of `S` are secret: the
/// first two are held in [`Secret`]s here, the rest by the functions that compute them.
#[allow(non_snake_case)]
fn sign_core(
    key: &ExpandedKey,
    context: Option<&[u8]>,
    PH_M: &[u8],
    sig: &mut [u8; SIGNATURE_LEN],
) -> Result<(), SignatureError> {
    sig.fill(0);
    check_context(context)?;

    // Step 2: "Compute SHA-512(dom2(F, C) || prefix || PH(M)) [..] Interpret the 64-octet
    // digest as a little-endian integer r."
    // Finished where it sits, as in `expand`: this hash has absorbed the prefix.
    let mut r_digest = Secret::<[u8; 64]>::new();
    let mut hash = SHA512::new();
    absorb_dom2(&mut hash, context);
    hash.do_update(&*key.prefix);
    hash.do_update(PH_M);
    hash.finish_into(&finish_token(), &mut *r_digest);

    // Step 3: "Compute the point [r]B. For efficiency, do this by first reducing r modulo L
    // [..] Let the string R be the encoding of this point."
    let mut r = Secret::<[u8; 32]>::new();
    scalar::reduce_512(&r_digest, &mut r);
    // The multiplication wants a scalar below 2^256 - L (`scalar::to_signed_digits`), and
    // `reduce_512` leaves r < L.
    let mut R = [0_u8; 32];
    point::scalar_mult_base_encoded(&r, &mut R).map_err(|_| computation_fault())?;

    // Step 4: "Compute SHA512(dom2(F, C) || R || A || PH(M)), and interpret the 64-octet
    // digest as a little-endian integer k."
    let mut k_digest = [0_u8; 64];
    let mut hash = SHA512::new();
    absorb_dom2(&mut hash, context);
    hash.do_update(&R);
    hash.do_update(&key.A);
    hash.do_update(PH_M);
    hash.do_final_out(&mut k_digest);

    // Step 5: "Compute S = (r + k * s) mod L. For efficiency, again reduce k modulo L first."
    let mut k = [0_u8; 32];
    scalar::reduce_512(&k_digest, &mut k);
    let mut S = [0_u8; 32];
    scalar::calculate_S(&r, &k, &key.s, &mut S);

    // Step 6: "the concatenation of R (32 octets) and the little-endian encoding of S"
    sig[..32].copy_from_slice(&R);
    sig[32..].copy_from_slice(&S);
    Ok(())
}

/// RFC 8032 Section 5.1.7. The public key was decoded, and fully validated, when `A` was
/// made.
#[allow(non_snake_case)]
fn verify_core(
    sig: &[u8; SIGNATURE_LEN],
    A: &PublicPoint,
    context: Option<&[u8]>,
    PH_M: &[u8],
) -> Result<(), SignatureError> {
    check_context(context)?;

    // Step 1: "first split the signature into two 32-octet halves. Decode the first half as
    // a point R, and the second half as an integer S, in the range 0 <= s < L. [..] If any
    // of the decodings fail (including S being out of range), the signature is invalid."
    let (halves, _) = sig.as_chunks::<32>();
    let (R, S) = (&halves[0], &halves[1]);
    let R_point = PointAffine::decode_var(R).ok_or(SignatureError::SignatureVerificationFailed)?;
    let S = scalar::decode_canonical_var(S).ok_or(SignatureError::SignatureVerificationFailed)?;

    // Step 2: "Compute SHA512(dom2(F, C) || R || A || PH(M)), and interpret the 64-octet
    // digest as a little-endian integer k."
    let mut A_encoded = [0_u8; 32];
    A.encode(&mut A_encoded);
    let mut k_digest = [0_u8; 64];
    let mut hash = SHA512::new();
    absorb_dom2(&mut hash, context);
    hash.do_update(R);
    hash.do_update(&A_encoded);
    hash.do_update(PH_M);
    hash.do_final_out(&mut k_digest);
    let mut k_octets = [0_u8; 32];
    scalar::reduce_512(&k_digest, &mut k_octets);
    let mut k = [0_u64; 4];
    scalar::decode_into(&k_octets, &mut k);

    // Step 3: "Check the group equation [8][S]B = [8]R + [8][k]A'."
    // With v1 k = v0 (mod L) and v1 not zero, multiplying through by v1 gives the equivalent
    //   [8]([v1 S]B - [v0]A' - [v1]R) = 0
    // in which v0 and v1 are half the length of k. (Should the reduction ever give up, the
    // signature is refused rather than checked the long way.)
    let (v0, v1) =
        scalar::reduce_basis_var(&k).ok_or(SignatureError::SignatureVerificationFailed)?;
    // Straus wants its base-point scalar below 2^253: `multiply_128_var` ends in a reduction
    // mod L, and L < 2^253.
    let v1_S = scalar::multiply_128_var(&S, &v1);
    let Z =
        point::scalar_mult_straus_128_var(&v1_S, &v0, &A.point().negate(), &v1, &R_point.negate());
    if Z.normalizes_to_neutral_var() {
        Ok(())
    } else {
        Err(SignatureError::SignatureVerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    // RFC 8032 Section 7.1 (Ed25519) and Section 7.3 (Ed25519ph, whose context is empty),
    // lifted from the RFC text by script.

    // (test name, secret key, public key, message, signature)
    const RFC8032_ED25519: &[(&str, &str, &str, &str, &str)] = &[
        (
            "1",
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            concat!(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bac",
                "c61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
        ),
        (
            "2",
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            concat!(
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e",
                "458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
        ),
        (
            "3",
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            concat!(
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290",
                "ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
        ),
        (
            "1024",
            "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
            "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
            concat!(
                "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12",
                "ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe57",
                "38829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338b",
                "bd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe",
                "ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b8",
                "32f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc10",
                "3b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53",
                "f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2",
                "d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6",
                "079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553",
                "878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2",
                "cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba",
                "b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae078",
                "4504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8",
                "fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301",
                "651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8",
                "ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd9",
                "04b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7",
                "984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a",
                "3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3",
                "2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a4",
                "3dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041",
                "e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d9",
                "0d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d",
                "b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef",
                "68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0",
            ),
            concat!(
                "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f45",
                "28ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03",
            ),
        ),
        (
            "SHA(abc)",
            "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
            "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
            concat!(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a8",
                "36ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            ),
            concat!(
                "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ec",
                "fdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
            ),
        ),
    ];

    // (test name, secret key, public key, message, signature)
    const RFC8032_ED25519PH: &[(&str, &str, &str, &str, &str)] = &[(
        "abc",
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        "616263",
        concat!(
            "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a35",
            "5a2003d062adf5aaa10b8c61e636062aaad11c2a26083406",
        ),
    )];

    // Known answers from the prototype this was ported from (bc-rust-nursery,
    // crates/ed25519): `generate_public_key` with `sign`, and with `sign_prehash` over the
    // SHA-512 of the message, on keys, contexts and messages from splitmix64 with a fixed
    // seed. Printed by the scratch program described in `nat.rs` (`kat-gen sign`, not in
    // this repository).

    // (private key, message, public key, signature)
    const ED25519_KATS: &[(&str, &str, &str, &str)] = &[
        (
            "f797ff14e069655b17be5b59c0bb8ee7d5ff7041d640106632630014002cf3f2",
            "",
            "047ed0c1c0f683b3e73d79145c1d6e4e9780bc79583f7f9412bcdaeef0ed1b5c",
            "64cfc5b27d98263d5af8feabe06df0509fbf1274682fbab081a5f34c3ba8f5fdd8ad20a10fec6bc97371d3232e737965ee72e08509a3b14bd4cce35bb8a7960c",
        ),
        (
            "02f89d945de107a93df1f4651f2cbea2b4f66645c29ab76c5446b620199f01b1",
            "7c",
            "fa4bf871791d3d7b051bf7712e8d1f5bd8a48be64c29716a46bc35a3df4d3bdd",
            "9a7a99a52bca9059f20dab4ab36886811869641295e0699088ac6fe610abcb26d8046bf3d555729d1d27e9eb6c4bf85a644d389f03c3f37795b9dc5182f8a906",
        ),
        (
            "0add170f936060d188c6cb675f7c9d9c1ba51b8f0ebbe1c5833fc35e75f66928",
            "6776",
            "f6bdc3c6c1c8d8718e4fc541dfb7a4a366ccd0bac7ad7aaad0f58dd1771727d9",
            "1e6fed2873eef00c58434ceb9a7d424f8923d8f80fa19bc4f43cbf54da879a771ff4f062c33128b7547eb5e3a91d9681c9779df6a9335a68c006457298d54d06",
        ),
        (
            "ef68aecbf273f388a52fde389b0e9a44ac91f749b35dcba404b391b8745aa9e0",
            "6ef845c85064f7afed4a8a62f3b1f4a324fd0bd20c1750a4b6315474167d7b",
            "70f802fa1f77ae967db4508ccac9ac57d27e33b53084819c08873f2a10bb0532",
            "1a273a17b9895b049ba5b9e44b46aa25c312457e596745329775563199c566ca133c8fcca738a07ff261c6920cc14831d17f890f48c25ac29ec0a4b999a2fc0c",
        ),
        (
            "1c6d8dd956d7eb5d0f1f91d32efc9c663c0f539e6807dcfafd93c5898b29c4f1",
            "deab87027a642c757387acc2835912a624b099a4507a2491f020306d9a400b26",
            "ad43763accfed0d89c16a6f033ac5c4d9b9f24ba783b480a6667478559ea35cf",
            "7e0a01579266e0f5a4aee6b3b6a786e4fe3700fde212e9d17eb79b73d2a5ea57775631fa073132f0b899c6b027d78e9af36864cc96761333174f6102b323310b",
        ),
        (
            "84bc3a3c5c2a10e2ddb374514b7c956615d4f6eb630119fa16a73f8d3fdbbb21",
            "46325b16ffdabe4ef67d297e5e53da0b5ea95192608cbc1fd298d753128eb57b267823ac77f37221d6a07423cf5f660596d337367f1029d0c4b321d836248c",
            "2a0ccb06371885d58101acd475106bb6e60a86b7a1ad21216f59784222ca85c0",
            "6a2904a68ebb5726eef0bd52425ef10962536409fcac506819512f85edf31c5f4ff67922dca2e4cc7d834417e5ab4e441ca2300b03eeff2c9619a00a3bc0350d",
        ),
        (
            "12e8e75e992490eaa17029ce14f19a22c21a1f3471bc8340b794a3dee171ecc1",
            "e63715c3828af7038d0825816aad4fbb5589cb16ca3d3cfe38d1ff821a6db903d255a649690451239d060bb92228aa7e986e770148d589efdafa9e30d0cc11dc",
            "338ae27aff45563e0d80f23f041b6ffbbbba451d7f60f1ca682d75efa4f3cb59",
            "61ccedb0135bb59231c56f42008ab2177d9e20d9dc9f49c4b7272b3aa624af4d1d1884aec25b716ca37d20f58abe194e01d003403b3a9fb82a4560fc1193e90c",
        ),
        (
            "cff7c848f8ebfb10539e019506c9f0c1d62a1081773f9735c496e76d42c0c10e",
            "8d86d8befefb4d3cfff83633768a652c81cce7fc477ca314b25a4fd2b8c85ca95e79adbf8ed5c86d9bbd7e60187298508f157c3d047318ab9012d077a40621d4d6",
            "07ecd1bd3378cf6e5c280b7fad2920d6eca8b509a76f59e3014dcc5026c9cb7f",
            "b5249d9d59aee3893a9c1d87125e3436233bca49d193b67f0370aa0ab31f404b0fe24d28bfb5ca7023d19a435fd95fe0471709d3a1788af675ad404c0dbb2e0d",
        ),
        (
            "4cbbeb61352dbf3e0959d26741d4eeaec34b53fa3193db9bda980d7fc0384771",
            "f51a7921d8030312e465a5cb01c02fe53e2e1f5f6f94660d21064344d5bf06467c7febf539d6380825660d50eab8c3c797afbb50484deb16fbef0cd60b9a77278541e6243a5e9d348cd523b3cd63d9d5ff26af2081c1442e7daaf9d7a054718eea2dd0fa5e3f1ef99e35bf59c24527",
            "92181dc4b7687abe33f1001a66ef905dec3f7d6c0e229f8121a95143ea057afb",
            "ca973c964d802cfd6d3f6d6970e2eb32521e6d7b8e5a7bf9af2159fc2b6ba9611d1c8b4734438080e91e47f60bc1d262d74e7f2ae712be0be3070bd881a80407",
        ),
        (
            "e3a67d77aae50d54383d9913e60cfad3082f78269b60baed3686283db35478ac",
            "e3e294f364941ffce03d53471680bde85af289b8757b4a8efc53cbc7d5117dac821fd3eaf18f87d68578d6d91085602476999e2ec4d7eb302f1cee999656a80447c4d5d1415cfa43e0db4c9a4979f5180a08efc2becf9745cda266aea24aecc8622cc0fbee88273635663793702014e6",
            "d9d83b0dfbbcf9b8b8cb93ed728bc8342b7369acfdae6d9a55d3341e002ba7b5",
            "ae9ae5a64585f292547d94ac7bf2b6221e9d5d536c6ab95ed8f1b5a62e9689659c02804865ae285eb21d28bf164ac7d58bbdc2ecd30ac56ecae87dfe7ac3bf04",
        ),
        (
            "3694e8fdb58df01274cb0227f96332a8ec1bf02743d325dce96adeef032b35ac",
            "b347b4590dcda7ec94d19c9c4beffc72d1dd6c7a18b64683e78d84bb794d9328e4e0cb694f4db7263666ee73dddc8068703f197c62e11fe229e393bfc1c70e0d8d6fd51bbe1cff9cba802adc19e48814c88ae34199aa8f37f6f3b27a0b4dee82d93cc948af5657f7f3ba289c965fa37bb7933eb351486724559292e8c25c52",
            "fee54ce0ee92c7304f05e93d218c54f2fbf172d57f05217d2b63a34919c8dd92",
            "ebb7ff4aeaf290b995c9621549f40c5755d360210c3e61fbc1c5067fbf75223b30940d72e9d30ebf4d8a1819fa55b818020468e227f8c0f95197fb634a22570e",
        ),
        (
            "474114b4c4e8d90c2d051fd633fb2973ff1ec6e670d269e7caa9436958cc7cfe",
            "0bf6c38bbf374097f1afd53d4aca2dbb0626a0725e604d56851ad17660fb43453d841e1435e3294f16680b526a4bda7e45de029166a237d0616a26897c3bd196d7aa5fe99433b1e1b95b7684b12a8c0c960518e12cb847b8381c08aae64d95f1c52d2cff94e0398c6277d755371a78e77b9a24023d9ccc9ed9d753d5bc09dbb2",
            "c1d295eee29edd31e5f8dde40a711021cdec1a2adc311222d25a85f91f38c694",
            "e0528587637bd9ba8dc7244fb11cd8f65726938caaf999d40183f44097df5157b691c69e7bd99259634703abd2f38411a9be63dd705f4c2f2ce9a82888b3fb0a",
        ),
        (
            "55d39e781506da446f05056afb5a62734ca3545493f5e804c53126fd48348115",
            "6d48c4cf96922e5ad803b26c287086db5cc25383f4ec65c1ddea342f0887613422d826cc023fa4767e7ff5940c5cdc1469a1a2e87eabda6d3051ba401c4ec238bf87e7252ca78d2b58aa3a65781e1e74aed6726f3c12785526d83d7cc96670db85efc46e6203eb5cd2280f00a5e95243d868cb3fba7eac31964c7d3e09cce60aab",
            "a2235f768d2652cec419581cdbb88099d72a172431d98a6cd047759eac8ecaba",
            "57ce78d02e11f076b95c05cce66c543f13897dd957c4e94b0f12fad39dddb6e3a053425616e2b725994c6e2d213cc815f722d497d106b12b8c6cb87d64673608",
        ),
        (
            "363b7a4189467cf4e1b1985de42900299af448bb0761d81899aaa3804279726e",
            "05cee762f07c469fb4c52ee6e2e9a386b5d493db687cfd61c4b45f9d4c95b3fd92d9e139a6233b3ed261832364dc980571628d672f72065fc422df822437979d2e7b3b65cdf21ddb13e5debbf6c00f714f04dd1a9f3373604d3894b4da1df35599a749f6899a695ca12d4d21fd622df928635594a718b4fcf3c277e147d838a79c67b63447d8045cf2c1f2b603d7efe5d535244dd8d3c403ed731a2b86d23dd6e4977d08a5908b8b72a853e5a12bc05ebce853d1f076f0a169704303c1f929db72380a111a53d6af",
            "9c7de6ab06ee7e3db3cfd6245dff64918de36b4f8d4875c943c55247015d95f3",
            "b2a9795b2a91f824f369657e2ac4ce773fb9c2a81ad7b5e789e3f712fe9ad5914ba5ee54314ad3ba8463e0e9d76a57a523510349e70877e5ce2582263a0adb06",
        ),
        (
            "b929f1fd63f998da12fb5dcf6bb52f8e3df48b77d70561d56063ed34902a860b",
            "7e9371bf54cff95145cacb3be0d0a53c677753f84907948cf0e6ba5bd22d0029f1c9382d99626c4e13e1c2cc223883f1f4bb323f6b365a89913ecd59fb9edf79ee6474bc36a491954cb90a68adb0dc82dffeb5737eae57bd578e06029899a8e84124492d218d0ece08029f27ff0e82614ee52fcd93b4b026f3e015531d7f90e24c9e64aba9b99df73626cb34dca2a8da49dc7bdbf5babbdf8de1e348eb6c6af09700e5e7b13ff5f6141b04995270067902bbf4f68bf85fad73f92c245f1687a95cd4153e853ab0a8cadd6b35f099f064247b10b43d6c3fbcfacdaebec025901423a446addae29e7f4585a190339f51ce11b5676e26d282bce2ebbbf2fb92b71d0f",
            "c2d2e28ea907c7847e1a1605e05543e385a9e80a20b63f6edf553a83d0d39527",
            "c271cfb93a03f0b5e70998f8c5549453bdc59266e9649791a49938ba5273778e4363b124eb27cce04129eac3afa1103cae9a8fcc5fc719f6c3a950e3f1536708",
        ),
        (
            "5d7f24d29c33ee2bc117636ab70b7c807431c710f3c2f601719782681aac0a0a",
            "8dbd3522e5fcd600bdab26b8ea93458d1023c733361af484f00f8d464a438a88b571fdb68f842c361ab6cc9169445cd9ddcf18ce9ffa5e73cea5074c81c4e854d5ece6572367fca04ebf605ba743427308c786521d3551fb07986a2616c9b5e86e9e970e51f78a12cd897afec0094af9970624afb7cadf1c6aa9aafbecc61cad60ae98d47e411feb689475c24297996ba706f0cb824275b9259a421678b7794db9fb9caf850d7083e0bd9bb0ffdf775f5687341a4ab0923b25b1dcc1a32eb1830cd004e284948998380e0a4fa069f60bfc911d989a9395e517b1ba8d9894390c2848400becdb37aaa292bb3d20d5239832947f0a64fd6b1127095929bee797304b9cb9ef34d104ea6a2aeb4881cf3172e9ef44fa5faecb0aa4ae6974265445717a51311edaffe07e9d75ba6cffc80ee8d2c9cae2b0cedaec90ffc425ea554136670231ff07bae608dc4d9fe683cfd08134e1a0313c43a58addb2dfc9fa441d77a3fd073a18e2cb88979ba768c39202bff15b6684f2a272301a3c8fb413cc1886b52c9e37ff0fbadd1ae659919a0333d1802e6a255a72ca14ed844e46535ab9d7e97a75cc60453e1986e713410e821ad712e129d645f36a156a10fb3759f3b114be2fbd2bab1c1661f8397a4b1db851dd899fd0d3cb1c50251af6cd7ebb048dc5625efb19083fa049962bba5fda40f52f6f7ba46c7d99d434c146edff8019101c8a42cbe7a2c474d1daafa8d7bfc15169716c6a5f3f6a762ae634678b8184a4255cf35fccaa1a3c03e3e871d96c45633849568efe155fe25e6f718ea890d88895accedd8b6f73bc170c18cedb6ba3f555761912b42d0b71cf1ee547f2f8a4e339078ee12ddf012dde023f260724c34e13366c288ecfa35ffaf256ef71c21df927431453aa9131d7d2518554842569d40282c6e11deb3849c221fec392848dbd29a17fee37dd3bff1fac34db6ebc283a317d92f6704a49e90d8d82f21f086fe2641342b4c934dbdf649f718ed8e6899f62e909c3f9a7a026e3ed0ff10eb38575a00669223dc6017c5accdfe126b201440c5da959c855ff702e5a420f113c0801b42c9858aa5ac046ebb03fc78b03abd37916be746c4f6ac46098f4a0d52c329e80ab162c3364d7442cd19b11ca41a4e41d320566a87b882996a332f9b7930bebc1449755fe057ef262855e86d7ee5ac5cbafa3d16e9beae0d64191f2db97fe0070efb173707eda0d87ce4410b43778329558471718baf1d26d6c8b143c1bdb4f885c00f04ca1438c9802e1189026e4748b0b19fef5a63a6ddafbde3fce8e0bc13571588c26f3b7992b15cb5f5ecf1c3394f506b57f1377c8741b5f0c63e406aeda8bd76aece5a4925f4924604101d09891c1d5a597a507fcb744ac0916a633a6b5e9fa83a0f82c1d30",
            "ca93dda556a0ff3e018122ea0a1c4573985e347f5db2ae6c5cd3debbd9421823",
            "4a2c95ac5075186a8c5120316c2355d82d2162e9fa92eab8a4a009e10c39e71648b90bf6c86a1a2f2548fbf1bf85ee4cb92fb7d02e53f415196d9ebf439aef0f",
        ),
    ];

    // (private key, context, message, public key, signature over SHA-512(message))
    const ED25519PH_KATS: &[(&str, &str, &str, &str, &str)] = &[
        (
            "58275f1444bfc735fea6dafdd11e6d3f529ae3b69c9b29545791a559e0d66607",
            "",
            "",
            "d872a98ea83bc37ddc3bcf8d2e330b1a1b3f70a089b21d3ff5388a237664b87f",
            "d4eb5ec8da18a508a0f3c1c47e90c042cd1c467523f22c97ae159309a25372b443a18ca584d32c07f8d69774ff28e5b8ce2fe7f28ba37199e0f3bd35dc91a005",
        ),
        (
            "1ffb3130be69e27c874440224534bfb31c5693b7e207fa94773142bb0e5631e0",
            "",
            "e1ee14",
            "c372cd992f5ffb6dbac532d826cfbb7aa9480df1be8d3ff3da667f7fbb79129e",
            "b8ab04b9b88ee94e681e0b40e0b2f60b393dc55307640574ca75239d55cf3b319eb1ef10594438a200d705792553527be992a738bac88a231e8d6de51d3d9202",
        ),
        (
            "a3065a7d4b9da84f53d221c6cd8f017a7d6968e6442dacff727a4143855e7bb8",
            "e3",
            "1d",
            "e06ab483f54bec162051d629a21942dc590cea735a9f452faa265d0ae874638e",
            "6e64a8b6d26cddfb542d848a116128df77d70c573e1ac0ef0fa95d3bca7e6be7e4e7647e7dd6eb9ace7de9b1a5fa75cca3d202606237b8b4ffadaa1417a31303",
        ),
        (
            "abb657efcbd59e87b1713ee07c35ebb4b2a64de8e4fb9325125825e297f4721a",
            "66a93d48b410126c6e1275fdcbfa3fb1fe4a103ed46d554003a62bb8a4533640",
            "a2474ff7f42a76d622c7bf037d3c26f79c4814a5d56313dba078cd08f953eb1092068a58667ad39792ef58aec35a4966637c647aa2eb06e06e0ea7f0aa5db2a6",
            "7a520ff5eabac47601cd2f28b043cd8c7077d0de0daf66d534470b389621a296",
            "6b169aef43686a71db919629bbc542c76a7947074c1719131a4aae5b6b1619482679e6cbc49dad8aaed94cd0647d54951f4a68fdf3eda6332a19cf3fb60d480a",
        ),
        (
            "912d1cb1f256de0feeb944eae854899e8ff8d4168a3ed348c6bbc18d573c7b72",
            "4b39190d0cf8b63b740b960647b87a8919486791feedd72e0e9b2c770f8bb5dde3",
            "cd93e3054b3460662a485737ff5a0c7ba5042235880f013d6b7bfe393c3e7f8cf298fe07a2ee85b4cab06149d793bd41ceda82ce47fb295e8b34b133b0ee216dd2de14f2e8615f4ffea152858220abe98e25e4cb555cbcd028c4ba36f3a354ec151c701378985d4765d22b7933bb692bc9ea6f31c02abc783df3b2d9ac30fd154bbcb5f6416a2b93eb8081db5e64f844494fea928763dcf7d2e626185710600033a7e48982ce8e7291b2ef4e67b98f22770b37a2a593a78a82f1704e8aff2bbf017d99f05860f829",
            "9437b211f1c492aa64e4c3d71940a0dfa91e6255afd91320403731b761584744",
            "1c3e38ae8b69def5df69e0b45b49f150a202c2ccafb980d6e5fa32a7e0f80dd91a548e9e3000cbe4d66150074c561ccc1bcbaf05aa70f1c195fabe42842a7e06",
        ),
        (
            "aed10a6714fd2a672fc50e68859ac2d9cfaa5cf1876830af9caedacbfa31481e",
            "597e8b448abe1b985d20ed7fe397e2f4caf4efd1918fc7b912e9d0fd27b48780a6ca6b2d0e9f09266d5d90a276f4bb3ad0fcc8eb8693321c5b5d470f99e00856eccfa7d63e3a91e1ba1f30b17c3d5db1d4b6644e3637a498321ed5dde98acaf6a92a905b",
            "1f1838a819370ff7062dbf5b2311d720eb02dce3c267d7a2f07f1bbda31db2d4777910ed8618e4068a297641e242c16ad4d8fc850a5f620fc6526829d02d0c316558d6e1438e84c8b35803825c9b2d78b1908d035f57cc7743271e0bfd862f82719b18f5a4f3db8a821cbba30388fc5e16c7eb1afdfd05f557a9af0fc01173",
            "47289831762be3994e3242224be14695a7c22e49d0b5994b8cf16e5881e0944d",
            "f8090346871b31f487b85fe9ef13b0abbf7c924cfc9078db7a9d9ac54dfac0eae66863a23a6ced5e82ce29f9bf043842674f0bcdc542e8037f710263edd23d0a",
        ),
        (
            "44759360bda3c0ea0a64bf48960938d9793cb601948e4336d3a81229778aca75",
            "197a83497b9631f694b7229af732f5493d1b795af48247d7f5c71624d3da5321647399ac37011c00711b19e52f0af7bf3d16f41c85993ffc0502e6a8824ccc3d6f2ab6073f1949c7b6fbc4f5e21638e82184fba3e1a2f01b251add413b7c60d8ab9a50656f092564597d676329cf70f4f3adac3db15936136a3a656aedbbf697467158f657be9689d0d3f2f55544abb65e62064fc90b0a81b518ae64548a45b30bc089ab01bbbdc8fa024003423062f6fdbbf32538a3ab3c84f994110a4a928636e56348bca3eac43d43c3a2e983ad8fe97a35bd2f48811d4214bc481c0116745969debfe1b3b166cd94818ba584b5a5b18ce604ffdea2185ef88c727ac9",
            "e23021ac7df37231fc8956945b7d949b8adeb6194aa92d1fe607ce66ab6b995a8c29d06b9c9810ffcb650cf72fe81b922e918843f15f7304d9e941744dcf5be3bde420b5edd869602d44dbf4bb4fe5eeded91e19431d5ec55039af7a813aed992c6c28cdfb5a40279ba3f3ee2fa7d9ea76183ed323896280f24da7f9f52ba274",
            "8dda5ece96693d6895163488d98b9006cb5a21a265ee31fc2c6c31b47144426a",
            "88cb1d31fb556ceaf5700dbc87b98ae87afd8e7bc7ed378aea7e10535b0a7e3038bc1f107832ca560931eabfc7737d410206e109ec5c40bbf63782d4589fc702",
        ),
        (
            "b98f9d3aab12bb740b4a1d2d5286dfedab3fbbdb6d20d400a431c3f66c5fd50a",
            "8850a9e659313ec7beb254badb6986551fd239d4ca2db73b1049f095def06bab29af005f00ae6002cff2567eb77947f246d067abec96fe1e79ac5ab1a7d2d13d345554150ca20353d83a37221c18c1f66c73029242bd2c02bbf337734c9f9170f660bd92cd1210dfc0de91b6af2ec6f5388dea10d31421145f6cf80024a8faa047732335f3cf4c109c94f57a658f17eaa0a562d9b8154fd77f1a84c9035e31a22acd8cf10f9a274eb257bcdcc46315faf3786f27533318c1218a5fdf31f265ba0738850510a5476c3c9f6b02c6028c8aef7e33956d82fff3a6ad2b60c0181691db8ac30fa214cd99f309f2fd70dc492bfe34d81e81135699cb4d14274c50d9",
            "e6567a97b10c03c26b739f7ed1f8749cfd6c9df61e0cdd0ca6c140fa10b6772b0208628a473e2240c1c9ae6cf1a2ff0062ff95f70254b3190713ca87592f11239da8fe461525dd459802c812ce11280c7fd4fa6c1ec1445a2c6be21d6e3c35445d16f942362424ee8893d1ba07a18113b9467057a52984a08f3aa8bf7b7ebe161c",
            "5cfc3b172a1270b9b634d10a30d7ba8599b8d25d45734044848f6e07bbadcd42",
            "438c4d57bd38727b761e5f979246f0e348629566d9da976356ac791db9387e4145f7d68784e6ff8d7d93aebfe238c7afbf45f416093e92e0c1ee59262816750a",
        ),
        (
            "f626ad9dc8ee418631229d330be10c84b3fbd69c9990cc7ddd75901a426d5843",
            "93a5f4f3f45e1fd38456d2ae754108ab5159cde3b82283dbb51fda06d6086fb3541d71e75608223bedb5a682862a70ef355543bd57c626fee399eb29aa5bdf2f1d2569c21996e17f9a44336be06da0b67f92b63ea90dfa0a1eb2d0ffb511b48b119e1d708df6feb7d7cde61b3518355ff6d842a9b09841bdfabcbabdf95731cf98d968415ed862b1b9c7a531c586ab9918aee17e1516a9914c196e4d507462224780ab91395b1e8849117dd95889615c62a466e792c3ac62fabde232575d0f2c0dccfd9893e21731abea852e676da53b0e0e3cf101b6c3a87b2e70c80e1c202218480dd87bea9b601fb817af1ecffaada6c476fd9ad1af417fb7ef1d5c8dfe",
            "",
            "476c0de2e2a91d291a7f75b4bedfcd4cf551bb8af795737236ef6e7e6fce4861",
            "d1f891c9fd82d39d363d3c6c890763b8abfb0814e56a1f5445fa3302bf6c6639bf943a353daab27f2b92d8bff2379aba1683fb48f4a629d2f8e9e3cd64e37204",
        ),
        (
            "30b05d56f8851fb86d23a24840651111bdd3b85a1ac949074453f271546e9468",
            "a14f8ec89e7e87",
            "965e8e8a292778ad16666f205bef24bc5b0b1f28705c5bf6cd7a4e21814cd5acfb358388de681562e5a0cec835f5fbc8eb14565b5ddabeaa42cca0c02d3b6ead3b7e5290ab05e5accd24048d2b9834d25475687ff268fce2f98729ffc227a925fb405fbe9ef63f5490ed7d0c590c385beb224b74733f60fefb4bb13d09ebe2f4e412d6ffd9d6dc0e4424478d6caac17e2aad0e147253dbac811e396e05d8a7c51577229d46caa1ed836d34e392d33b050c1afb2cce0cce3615a47c9c0efd7840aff4e65fc657d877c7e8c2541d926c2c04aab6c1b2fb59e7b3333853058ed6c926c48882df2251f5f304dc1e35f44347200291052d72cd92bfd4e81bb6f672baa05d13e839a457e5e78f0bd52c607827c3f0ef01b0ea837a1b68dd84328e1568c04d1a45eef399ae1674f7185f19620392e0f66f949ce1b1bcadcac0814a56ab7de8a0a2d11294eb89b7ea42baf2c00e1585302c447b28ca1f8998503799dd834477957325606007d394e95fe3fa645c8194331d6eab7929b346ec60176ee6488fde4334920aa00b92a6d002ce93bbce1099381bf3dc125e4042db2688028d4b686ccd3349eea6111505da485e3f4f9e9aae158aef735c6055431921d6141fb82944960b3bd0712d2be5601c8f8f9978b629a49be02e0e517d9d49ed1605879464064cb0660b56041730347afd8b54c49491f62017514cf2fadba63be5d4f06a51ab1ca1621b07b506df4138539d2efa4b553f1065479ad3729edb8e01987aeea37a40c8e43ee9b9a45e51e4974fe5728a62bf9dc1359cbd16448848102a02f0d7b223c428d5ba937c15bd28a42989785d0e3ff0abcb337ee74905a61aefa11c9f1a73b15ec976c66d66ad3c008c1c6bb9d68e0e01843594a387a61ca8fdfabd68543434dc070741e05bbb341187d5507bc64fecd56220a30c6a79df7a32a416c8c27852a8cce43bda29cb1d65cfbc70dfe070e2d95dc2bfa4b4fdc12585c3b7ff76dfd247419548a2cfb06cf85a721806e133304208a5bd66abe00211b1efd69ce1ebaff889d36e7adf6c3437e27bc9691e3aaecc7bdd61c6edbdae1d7c704faed1ed0f633b9d54f0e54f40a94a0691c6d80b015d4c85f8b39aec5fb808662d945381107e8c9b1ccaff52cdf37274562102b3c1e1900e4e1e3370724052fcea81aaf08e3d173fb15c5e5fea5e9e07220a1f80478f8cf8bb618abac311a9049a5c97571fea3be5e63a8bfac521b6314859240496e051173baa7f94ae8a5b394ac865cb8c274466218a22b82b30b7e630ce5fa019bda2d642f0e9b3b263f0f6f1dd5f2c2ecaedb37c0ceac52080fd5366e487a0bfce0ccfaee8471a7aca1ff797cc2cf8701c4f79343180ad0ada6d6ad740a624b9aaab0f1f7cae94ab5fd946e5650561bd591f63d7",
            "0867e807992fb4a21107d68b863aeb4f094cfb47b36e7045fafce4d6a69d687f",
            "6b0de6a3421a25f0703d2a1c91fcb8d75f3654b5f9068fa86b7d2ffa5fa01e72670976fd1c33eaaf6384fc073466229a16d0aa8c6cc2b2ff8fbf2388b7a3a108",
        ),
    ];

    // The vectors of "Taming the many EdDSAs" (https://ia.cr/2020/1244) as the prototype's
    // tests carry them, with the prototype's verdicts (`kat-gen taming`). Vector 7 is left
    // out: its signature there is not 64 octets.

    // (number, message, public key, signature, whether the prototype's full validation
    // accepts the key, whether its verification accepts the signature)
    const TAMING_KATS: &[(usize, &str, &str, &str, bool, bool)] = &[
        (
            0,
            "8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
            concat!(
                "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            false,
            false,
        ),
        (
            1,
            "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
            concat!(
                "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
                "a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
            ),
            false,
            false,
        ),
        (
            2,
            "aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab",
            "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
            concat!(
                "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
                "8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e",
            ),
            false,
            true,
        ),
        (
            3,
            "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
            "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
            concat!(
                "9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f",
                "87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009",
            ),
            false,
            true,
        ),
        (
            4,
            "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
            "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
            concat!(
                "160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed512",
                "5ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09",
            ),
            false,
            true,
        ),
        (
            5,
            "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
            "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
            concat!(
                "21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7",
                "e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405",
            ),
            false,
            true,
        ),
        (
            6,
            "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
            "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
            concat!(
                "e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e",
                "547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514",
            ),
            true,
            false,
        ),
        (
            8,
            "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
            "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
            concat!(
                "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f",
            ),
            false,
            false,
        ),
        (
            9,
            "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
            "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
            concat!(
                "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "ca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908",
            ),
            false,
            false,
        ),
        (
            10,
            "e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            concat!(
                "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dc",
                "a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
            ),
            false,
            false,
        ),
        (
            11,
            "39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            concat!(
                "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dc",
                "a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
            ),
            false,
            false,
        ),
    ];

    fn octets<const N: usize>(hex: &str) -> [u8; N] {
        bouncycastle_hex::decode(hex).unwrap().try_into().unwrap()
    }

    fn bytes(hex: &str) -> Vec<u8> {
        bouncycastle_hex::decode(hex).unwrap()
    }

    fn sha512(m: &[u8]) -> [u8; PREHASH_LEN] {
        let mut digest = [0_u8; PREHASH_LEN];
        let mut hash = SHA512::new();
        hash.do_update(m);
        hash.do_final_out(&mut digest);
        digest
    }

    /// The expanded key and the public key of a private key.
    fn key_pair(sk: &[u8; PRIVATE_KEY_LEN]) -> (ExpandedKey, [u8; PUBLIC_KEY_LEN]) {
        let mut key = ExpandedKey::zeroized();
        key.expand(sk).unwrap();
        let pk = *key.public_key();
        (key, pk)
    }

    const FAILED: Result<(), SignatureError> = Err(SignatureError::SignatureVerificationFailed);

    /// Key generation, signing and verification on one Ed25519 vector.
    fn check_ed25519(name: &str, sk: &str, pk: &str, m: &str, sig: &str) {
        let (key, public) = key_pair(&octets(sk));
        assert_eq!(public, octets::<32>(pk), "{name}");
        let m = bytes(m);
        let mut signature = [0xA5_u8; SIGNATURE_LEN];
        sign(&key, &m, &mut signature).unwrap();
        assert_eq!(signature, octets::<64>(sig), "{name}");

        let point = PublicPoint::decode_var(&public).unwrap();
        assert_eq!(verify(&signature, &point, &m), Ok(()), "{name}");
    }

    /// The same on one Ed25519ph vector.
    fn check_ed25519ph(name: &str, sk: &str, context: &str, pk: &str, m: &str, sig: &str) {
        let (key, public) = key_pair(&octets(sk));
        assert_eq!(public, octets::<32>(pk), "{name}");
        let (context, prehash) = (bytes(context), sha512(&bytes(m)));
        let mut signature = [0xA5_u8; SIGNATURE_LEN];
        sign_ph(&key, &context, &prehash, &mut signature).unwrap();
        assert_eq!(signature, octets::<64>(sig), "{name}");

        let point = PublicPoint::decode_var(&public).unwrap();
        assert_eq!(verify_ph(&signature, &point, &context, &prehash), Ok(()), "{name}");
    }

    #[test]
    fn rfc_8032_vectors() {
        assert_eq!((RFC8032_ED25519.len(), RFC8032_ED25519PH.len()), (5, 1));
        for (name, sk, pk, m, sig) in RFC8032_ED25519 {
            check_ed25519(name, sk, pk, m, sig);
        }
        for (name, sk, pk, m, sig) in RFC8032_ED25519PH {
            check_ed25519ph(name, sk, "", pk, m, sig);
        }
    }

    #[test]
    fn signatures_match_the_prototype() {
        for (sk, m, pk, sig) in ED25519_KATS {
            check_ed25519(sk, sk, pk, m, sig);
        }
        for (sk, context, m, pk, sig) in ED25519PH_KATS {
            check_ed25519ph(sk, sk, context, pk, m, sig);
        }
    }

    /// Every key the prototype's full validation refuses is refused here when it is
    /// decoded, which is before any signature is looked at (so vectors 2 to 5, which the
    /// prototype's verification accepts under keys of mixed order, cannot be verified at
    /// all); under the one key that is valid the verdict is the prototype's.
    #[test]
    fn taming_vectors_get_the_prototype_s_verdicts() {
        for (number, m, pk, sig, key_valid, accepted) in TAMING_KATS {
            let point = PublicPoint::decode_var(&octets(pk));
            assert_eq!(point.is_some(), *key_valid, "vector {number}");
            if let Some(point) = point {
                let verdict = verify(&octets(sig), &point, &bytes(m));
                assert_eq!(verdict.is_ok(), *accepted, "vector {number}");
            }
        }
    }

    /// RFC 8032 Section 5.1.5, step 2, on a digest that has every pruned bit the wrong way
    /// round is not available, so check the three masks on the scalars of the vectors: among
    /// them the unpruned digests differ in each of the five bits.
    #[test]
    fn the_secret_scalar_is_pruned() {
        let mut seen_clear = [0xFF_u8; 2];
        let mut seen_set = [0_u8; 2];
        for (sk, ..) in ED25519_KATS {
            let digest = sha512(&octets::<32>(sk));
            seen_clear[0] &= digest[0];
            seen_clear[1] &= digest[31];
            seen_set[0] |= digest[0];
            seen_set[1] |= digest[31];

            let (key, _) = key_pair(&octets(sk));
            assert_eq!(key.s[0], digest[0] & 0xF8);
            assert_eq!(key.s[1..31], digest[1..31]);
            assert_eq!(key.s[31], (digest[31] & 0x7F) | 0x40);
            assert_eq!(*key.prefix, digest[32..]);
        }
        // Each pruned bit was seen both set and clear before pruning.
        assert_eq!((seen_clear[0] & 0x07, seen_clear[1] & 0xC0), (0, 0));
        assert_eq!((seen_set[0] & 0x07, seen_set[1] & 0xC0), (0x07, 0xC0));
    }

    /// Any one bit changed in the signature, the message or the key makes verification fail,
    /// as does the right signature under the other instance or another context.
    #[test]
    fn verification_fails_on_any_change() {
        let (sk, m, ..) = ED25519_KATS[5];
        let (key, public) = key_pair(&octets(sk));
        let point = PublicPoint::decode_var(&public).unwrap();
        let m = bytes(m);
        let mut signature = [0_u8; SIGNATURE_LEN];
        sign(&key, &m, &mut signature).unwrap();
        assert_eq!(verify(&signature, &point, &m), Ok(()));

        for bit in 0..8 * SIGNATURE_LEN {
            let mut changed = signature;
            changed[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(verify(&changed, &point, &m), FAILED, "signature bit {bit}");
        }
        for bit in 0..8 * m.len() {
            let mut changed = m.clone();
            changed[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(verify(&signature, &point, &changed), FAILED, "message bit {bit}");
        }
        assert_eq!(verify(&signature, &point, &m[..m.len() - 1]), FAILED);

        // Another key.
        let (_, other) = key_pair(&octets(ED25519_KATS[6].0));
        let other = PublicPoint::decode_var(&other).unwrap();
        assert_eq!(verify(&signature, &other, &m), FAILED);

        // Ed25519ph: the context and the instance are bound.
        let prehash = sha512(&m);
        sign_ph(&key, b"context", &prehash, &mut signature).unwrap();
        assert_eq!(verify_ph(&signature, &point, b"context", &prehash), Ok(()));
        assert_eq!(verify_ph(&signature, &point, b"contexu", &prehash), FAILED);
        assert_eq!(verify_ph(&signature, &point, b"", &prehash), FAILED);
        assert_eq!(verify_ph(&signature, &point, b"context\0", &prehash), FAILED);
        assert_eq!(verify(&signature, &point, &prehash), FAILED);
        sign_ph(&key, b"", &prehash, &mut signature).unwrap();
        assert_eq!(verify(&signature, &point, &prehash), FAILED);
        sign(&key, &prehash, &mut signature).unwrap();
        assert_eq!(verify_ph(&signature, &point, b"", &prehash), FAILED);
    }

    /// RFC 8032 Section 5.1: a context of 255 octets is the longest; one more is refused by
    /// both operations before anything else, and the signature buffer is cleared.
    #[test]
    fn the_context_is_at_most_255_octets() {
        let (key, public) = key_pair(&[7; PRIVATE_KEY_LEN]);
        let point = PublicPoint::decode_var(&public).unwrap();
        let prehash = sha512(b"message");
        let context = [0x5A_u8; CONTEXT_MAX_LEN + 1];

        let mut signature = [0xA5_u8; SIGNATURE_LEN];
        sign_ph(&key, &context[..CONTEXT_MAX_LEN], &prehash, &mut signature).unwrap();
        assert_eq!(verify_ph(&signature, &point, &context[..CONTEXT_MAX_LEN], &prehash), Ok(()));
        assert_eq!(
            verify_ph(&signature, &point, &context[..CONTEXT_MAX_LEN - 1], &prehash),
            FAILED
        );

        let too_long = |result: Result<(), SignatureError>| {
            matches!(result, Err(SignatureError::LengthError(_)))
        };
        assert!(too_long(verify_ph(&signature, &point, &context, &prehash)));
        assert!(too_long(sign_ph(&key, &context, &prehash, &mut signature)));
        assert_eq!(signature, [0; SIGNATURE_LEN]);
    }

    /// A signature built by hand from a chosen `R` encoding: `S = k s mod L` for the `k` of
    /// that encoding, so that `[S]B = [k]A` and the signature is right exactly if `R` counts
    /// as the neutral element.
    fn signature_with_r(
        key: &ExpandedKey,
        public: &[u8; PUBLIC_KEY_LEN],
        r_encoding: &[u8; 32],
        m: &[u8],
    ) -> [u8; SIGNATURE_LEN] {
        let mut k_digest = [0_u8; 64];
        let mut hash = SHA512::new();
        hash.do_update(r_encoding);
        hash.do_update(public);
        hash.do_update(m);
        hash.do_final_out(&mut k_digest);
        let mut k = [0_u8; 32];
        scalar::reduce_512(&k_digest, &mut k);
        let mut s_part = [0_u8; 32];
        scalar::calculate_S(&[0; 32], &k, &key.s, &mut s_part);

        let mut signature = [0_u8; SIGNATURE_LEN];
        signature[..32].copy_from_slice(r_encoding);
        signature[32..].copy_from_slice(&s_part);
        signature
    }

    /// RFC 8032 Section 5.1.7, step 1: "If any of the decodings fail (including S being out
    /// of range), the signature is invalid", for an `S` and an `R` that would satisfy the
    /// group equation if they were reduced first.
    #[test]
    fn verification_rejects_non_canonical_s_and_r() {
        let (key, public) = key_pair(&[9; PRIVATE_KEY_LEN]);
        let point = PublicPoint::decode_var(&public).unwrap();
        let m = b"message";
        let mut signature = [0_u8; SIGNATURE_LEN];
        sign(&key, m, &mut signature).unwrap();

        // S + L, which is S mod L and still fits 32 octets.
        let mut s_plus_l = [0_u8; 32];
        let mut carry = 0_u16;
        let l = scalar::L.iter().flat_map(|limb| limb.to_le_bytes());
        for ((out, s), l) in s_plus_l.iter_mut().zip(&signature[32..]).zip(l) {
            carry += *s as u16 + l as u16;
            *out = carry as u8;
            carry >>= 8;
        }
        assert_eq!(carry, 0);
        let mut malleated = signature;
        malleated[32..].copy_from_slice(&s_plus_l);
        assert_eq!(verify(&malleated, &point, m), FAILED);

        // R the neutral element, (0, 1): accepted in its canonical encoding, and refused as
        // y = p + 1, which a decoder that reduced y would take for the same point.
        let mut neutral = [0_u8; 32];
        neutral[0] = 1;
        assert_eq!(verify(&signature_with_r(&key, &public, &neutral, m), &point, m), Ok(()));
        let mut p_plus_1 = [0xFF_u8; 32];
        (p_plus_1[0], p_plus_1[31]) = (0xEE, 0x7F);
        assert_eq!(verify(&signature_with_r(&key, &public, &p_plus_1, m), &point, m), FAILED);
        // x = 0 with the sign bit set (step 4 of Section 5.1.3).
        neutral[31] = 0x80;
        assert_eq!(verify(&signature_with_r(&key, &public, &neutral, m), &point, m), FAILED);
    }

    /// Verification is cofactored (RFC 8032 Section 5.1.7, step 3, the first equation): a
    /// signature whose `R` is off by a point of small order satisfies
    /// `[8][S]B = [8]R + [8][k]A'` and not `[S]B = R + [k]A'`, and is accepted. Here `R` is
    /// each of the small-order points itself, with `S = k s`.
    #[test]
    fn verification_is_cofactored() {
        // The canonical encodings of the eight points of small order; shown to be so below.
        const SMALL_ORDER: [&str; 8] = [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000080",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        ];
        let (key, public) = key_pair(&[11; PRIVATE_KEY_LEN]);
        let point = PublicPoint::decode_var(&public).unwrap();
        let m = b"message";

        for encoding in SMALL_ORDER {
            let encoding: [u8; 32] = octets(encoding);
            // [8]T is the neutral element: [8]([0]B + [1]T + [0]T).
            let t = PointAffine::decode_var(&encoding).unwrap();
            let eight_t = point::scalar_mult_straus_128_var(&[0; 4], &[1, 0], &t, &[0, 0], &t);
            assert!(eight_t.normalizes_to_neutral_var());

            let signature = signature_with_r(&key, &public, &encoding, m);
            assert_eq!(verify(&signature, &point, m), Ok(()));
            // It is still a signature on this message only.
            assert_eq!(verify(&signature, &point, b"massage"), FAILED);
        }
    }
}
