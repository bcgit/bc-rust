//! Ed448 and Ed448ph as RFC 8032 Sections 5.2.5 to 5.2.7 give them: the public key of a
//! private key, signing and verification, over octet arrays and [`PublicPoint`].
//!
//! Both algorithms take a context, bound through `dom4(F, C)` with F = 0 for Ed448 and 1 for
//! Ed448ph. Verification is cofactored: it checks the first of the two equations of Section
//! 5.2.7, step 3, so a signature that differs from a valid one by points of small order is
//! accepted (Section 8.8).
//!
//! Signing is constant time in the private key and in everything derived from it; the
//! message, the context, the public key and the signature are public. Verification is
//! variable time throughout.

use super::point::{self, POINT_LEN, PointAffine, PublicPoint};
use super::scalar::{self, SCALAR_LEN};
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::hazmat::finish_token;
use bouncycastle_core::traits::{Hash, XOFSqueezer};
use bouncycastle_digest::sha3::SHAKE256;
use bouncycastle_utils::secret::Secret;

/// Octets in an Ed448 private key (RFC 8032 Section 5.2.5).
pub const PRIVATE_KEY_LEN: usize = 57;
/// Octets in an Ed448 public key (RFC 8032 Section 5.2.5).
pub const PUBLIC_KEY_LEN: usize = POINT_LEN;
/// Octets in an Ed448 or Ed448ph signature (RFC 8032 Section 5.2.6).
pub const SIGNATURE_LEN: usize = POINT_LEN + SCALAR_LEN;
/// Octets in the pre-hash of Ed448ph, `SHAKE256(x, 64)` (RFC 8032 Section 5.2).
pub(in crate::ed) const PREHASH_LEN: usize = 64;
/// The longest context, in octets (RFC 8032 Section 5.2: "maximum of 255 octets").
pub const CONTEXT_MAX_LEN: usize = 255;

/// Octets in a digest `SHAKE256(x, 114)` (RFC 8032 Section 5.2, Table 2).
const DIGEST_LEN: usize = 114;

/// The encoding of the neutral element, (0, 1) (RFC 8032 Section 5.2.2).
const NEUTRAL_ELEMENT: [u8; PUBLIC_KEY_LEN] = {
    let mut encoding = [0; PUBLIC_KEY_LEN];
    encoding[0] = 1;
    encoding
};

/// The fixed part of `dom4` (RFC 8032 Section 2), "in ASCII (8 octets)".
const DOM4_PREFIX: &[u8; 8] = b"SigEd448";

/// The one error of the two fault paths, key expansion and signing: a fixed-base multiplication
/// whose result failed its own check (FIPS 186-5 Section 7.1 asks implementations to "verify
/// the correctness of group arithmetic computations"), which no input causes.
fn computation_fault() -> SignatureError {
    SignatureError::ComputationFault
}

/// Ends absorbing where the sponge sits and writes the 114 octets of `SHAKE256(x, 114)` to
/// `digest`.
fn squeeze_digest(hash: &mut SHAKE256, digest: &mut [u8; DIGEST_LEN]) {
    let mut squeezer = hash.finish_squeezer(&finish_token());
    squeezer.do_output_out(digest);
}

/// `SHAKE256(parts[0] || parts[1] || .., 114)` for an input that holds a secret, the private
/// key or the prefix.
///
/// The sponge is finished where it sits and wiped when it drops, here. `XOF::into_squeezer`
/// would move it, and a sponge that is moved leaves its old bytes where they were: a release
/// build was seen to leave the private key (still in the sponge's input buffer) and whole
/// Keccak states of the prefix's hash, from which the prefix can be computed back, on the dead
/// stack that way.
fn secret_digest(parts: &[&[u8]], digest: &mut [u8; DIGEST_LEN]) {
    let mut hash = SHAKE256::new();
    for part in parts {
        hash.do_update(part);
    }
    squeeze_digest(&mut hash, digest);
}

/// The private key after RFC 8032 Section 5.2.6, step 1, with its public key: the secret
/// scalar `s` and `prefix`, the two halves of its SHAKE256 digest, and `A`, the encoding of
/// `[s]B`. The scalar and the prefix are wiped when the value is dropped.
///
/// `A` is computed here, once, and signing reads it from here: a signature made with any
/// other value in its place exposes the private scalar to whoever also holds a correct
/// signature on the same message, so no caller is given the chance to supply one.
#[allow(non_snake_case)]
pub(in crate::ed) struct ExpandedKey {
    /// The pruned first half of the digest: the scalar, in 57 little-endian octets.
    s: Secret<[u8; SCALAR_LEN]>,
    /// The second half of the digest.
    prefix: Secret<[u8; 57]>,
    /// The public key. All zero exactly while the key is unfilled: an all-zero encoding is
    /// y = 0, which no multiple of B has, and the result check refuses.
    A: [u8; PUBLIC_KEY_LEN],
}

impl ExpandedKey {
    /// An all-zero, unfilled value for [`Self::expand`] to fill where it will live.
    pub(in crate::ed) const fn zeroized() -> Self {
        Self { s: Secret::new(), prefix: Secret::new(), A: [0; PUBLIC_KEY_LEN] }
    }

    /// Back to the unfilled value, the scalar and the prefix wiped.
    pub(in crate::ed) fn clear(&mut self) {
        self.s.zeroize();
        self.prefix.zeroize();
        self.A = [0; PUBLIC_KEY_LEN];
    }

    /// Makes `self` a copy of `source`, field by field, with nothing staged on the way.
    pub(in crate::ed) fn copy_from(&mut self, source: &Self) {
        self.s.copy_from_slice(&*source.s);
        self.prefix.copy_from_slice(&*source.prefix);
        self.A = source.A;
    }

    /// Whether [`Self::expand`] has filled the key.
    pub(in crate::ed) fn is_filled(&self) -> bool {
        self.A != [0; PUBLIC_KEY_LEN]
    }

    /// Fills `self` from the private key `sk` (RFC 8032 Section 5.2.5, steps 1 to 4).
    /// Constant time; the digest is wiped on return.
    ///
    /// The errors, on either of which `self` is left unfilled: `ComputationFault` if the
    /// multiplication fails its own result check, which no input causes, and `KeyGenError`
    /// for a private key whose public key is the neutral element (see
    /// [`Self::fill_public_key`]).
    pub(in crate::ed) fn expand(
        &mut self,
        sk: &[u8; PRIVATE_KEY_LEN],
    ) -> Result<(), SignatureError> {
        // Step 1: "Hash the 57-byte private key using SHAKE256(x, 114), storing the digest in
        // a 114-octet large buffer, denoted h. Only the lower 57 bytes are used for
        // generating the public key."
        let mut h = Secret::<[u8; DIGEST_LEN]>::new();
        secret_digest(&[sk], &mut h);
        self.s.copy_from_slice(&h[..57]);
        // Section 5.2.6, step 1: "Let prefix denote the second half of the hash digest,
        // h[57],...,h[113]."
        self.prefix.copy_from_slice(&h[57..]);

        // Step 2: "Prune the buffer: The two least significant bits of the first octet are
        // cleared, all eight bits the last octet are cleared, and the highest bit of the
        // second to last octet is set."
        self.s[0] &= 0xFC;
        self.s[56] = 0;
        self.s[55] |= 0x80;

        self.fill_public_key()
    }

    /// RFC 8032 Section 5.2.5, steps 3 and 4, for the scalar already in `self.s`: "Interpret
    /// the buffer as the little-endian integer, forming a secret scalar s. Perform a
    /// known-base-point scalar multiplication [s]B." "The public key A is the encoding of the
    /// point [s]B."
    ///
    /// A key whose `A` is the neutral element is refused, which the RFC does not ask for. A
    /// pruned Ed448 scalar is a multiple of 4 from `2^447` up to `2^448`, and `4 L` is one:
    /// the one private scalar that is a multiple of L, under which anyone can sign. (Ed25519
    /// has none: `8 L` is above `2^255`.) A private key that prunes to it is a SHAKE256
    /// preimage, and none is known. The test is on the public key, which is public.
    fn fill_public_key(&mut self) -> Result<(), SignatureError> {
        // The multiplication wants a scalar below 2^448, which clearing the last octet made
        // it.
        if point::scalar_mult_base_encoded(&self.s, &mut self.A).is_err() {
            self.clear();
            return Err(computation_fault());
        }
        if self.A == NEUTRAL_ELEMENT {
            self.clear();
            return Err(SignatureError::KeyGenError(
                "Ed448: the private key's public key is the neutral element",
            ));
        }
        Ok(())
    }

    /// The public key, the encoding of `[s]B`; all zero for an unfilled key.
    pub(in crate::ed) fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.A
    }

    /// The public key as a point, or `None` for an unfilled key. Costs a square root, and no
    /// scalar multiplication: see [`PublicPoint::decode_base_multiple_var`], which takes `A`
    /// as the checked encoding of `[s]B`, not the neutral element.
    pub(in crate::ed) fn public_point(&self) -> Option<PublicPoint> {
        if !self.is_filled() {
            return None;
        }
        PublicPoint::decode_base_multiple_var(&self.A)
    }
}

/// Signs the message `M` with Ed448 (RFC 8032 Section 5.2.6) under `context`, writing
/// `R || S` to `sig`. `key` must be filled. A context of more than [`CONTEXT_MAX_LEN`] octets
/// fails with a `LengthError`; the only other error is the multiplication failing its own
/// result check. On either, `sig` is left zero.
#[allow(non_snake_case)]
pub(in crate::ed) fn sign(
    key: &ExpandedKey,
    context: &[u8],
    M: &[u8],
    sig: &mut [u8; SIGNATURE_LEN],
) -> Result<(), SignatureError> {
    sign_core(key, 0, context, M, sig)
}

/// Signs with Ed448ph (RFC 8032 Section 5.2.6): `prehash` is `PH(M)`, `SHAKE256(M, 64)`.
/// Otherwise as [`sign`].
pub(in crate::ed) fn sign_ph(
    key: &ExpandedKey,
    context: &[u8],
    prehash: &[u8; PREHASH_LEN],
    sig: &mut [u8; SIGNATURE_LEN],
) -> Result<(), SignatureError> {
    sign_core(key, 1, context, prehash, sig)
}

/// Verifies an Ed448 signature on the message `M` under `context` (RFC 8032 Section 5.2.7),
/// with a `LengthError` for a context that is too long and `SignatureVerificationFailed`
/// otherwise.
#[allow(non_snake_case)]
pub(in crate::ed) fn verify(
    sig: &[u8; SIGNATURE_LEN],
    A: &PublicPoint,
    context: &[u8],
    M: &[u8],
) -> Result<(), SignatureError> {
    verify_core(sig, A, 0, context, M)
}

/// Verifies an Ed448ph signature (RFC 8032 Section 5.2.7): `prehash` as for [`sign_ph`].
/// Otherwise as [`verify`].
#[allow(non_snake_case)]
pub(in crate::ed) fn verify_ph(
    sig: &[u8; SIGNATURE_LEN],
    A: &PublicPoint,
    context: &[u8],
    prehash: &[u8; PREHASH_LEN],
) -> Result<(), SignatureError> {
    verify_core(sig, A, 1, context, prehash)
}

/// Whether `context` fits `dom4`.
pub(in crate::ed) fn check_context(context: &[u8]) -> Result<(), SignatureError> {
    if context.len() > CONTEXT_MAX_LEN {
        return Err(SignatureError::LengthError("an Ed448 context is at most 255 octets"));
    }
    Ok(())
}

/// Absorbs `dom4(F, C)` (RFC 8032 Section 2): "SigEd448" || octet(F) || octet(OLEN(C)) || C.
/// The context has passed [`check_context`], so its length fits the octet.
#[allow(non_snake_case)]
fn absorb_dom4(hash: &mut SHAKE256, F: u8, context: &[u8]) {
    hash.do_update(DOM4_PREFIX);
    hash.do_update(&[F, context.len() as u8]);
    hash.do_update(context);
}

/// RFC 8032 Section 5.2.6, steps 2 to 6; step 1 is [`ExpandedKey::expand`]. `F` is 0 for
/// Ed448 and 1 for Ed448ph, and `PH_M` the message or its pre-hash.
///
/// The digest of step 2, `r` and the working values of `[r]B` and of `S` are secret: the
/// first two are held in [`Secret`]s here, the rest by the functions that compute them.
#[allow(non_snake_case)]
fn sign_core(
    key: &ExpandedKey,
    F: u8,
    context: &[u8],
    PH_M: &[u8],
    sig: &mut [u8; SIGNATURE_LEN],
) -> Result<(), SignatureError> {
    sig.fill(0);
    check_context(context)?;

    // Step 2: "Compute SHAKE256(dom4(F, C) || prefix || PH(M), 114) [..] Interpret the
    // 114-octet digest as a little-endian integer r."
    let mut r_digest = Secret::<[u8; DIGEST_LEN]>::new();
    // dom4(F, C), as `absorb_dom4` has it; the context has passed `check_context`.
    let dom4_octets = [F, context.len() as u8];
    secret_digest(&[DOM4_PREFIX, &dom4_octets, context, &*key.prefix, PH_M], &mut r_digest);

    // Step 3: "Compute the point [r]B. For efficiency, do this by first reducing r modulo L,
    // the group order of B. Let the string R be the encoding of this point."
    let mut r = Secret::<[u8; SCALAR_LEN]>::new();
    scalar::reduce_912(&r_digest, &mut r);
    // The multiplication wants a scalar below 2^448, and `reduce_912` leaves r < L.
    let mut R = [0_u8; POINT_LEN];
    point::scalar_mult_base_encoded(&r, &mut R).map_err(|_| computation_fault())?;

    // Step 4: "Compute SHAKE256(dom4(F, C) || R || A || PH(M), 114), and interpret the
    // 114-octet digest as a little-endian integer k."
    let mut k_digest = [0_u8; DIGEST_LEN];
    let mut hash = SHAKE256::new();
    absorb_dom4(&mut hash, F, context);
    hash.do_update(&R);
    hash.do_update(&key.A);
    hash.do_update(PH_M);
    squeeze_digest(&mut hash, &mut k_digest);

    // Step 5: "Compute S = (r + k * s) mod L. For efficiency, again reduce k modulo L first."
    let mut k = [0_u8; SCALAR_LEN];
    scalar::reduce_912(&k_digest, &mut k);
    let mut S = [0_u8; SCALAR_LEN];
    scalar::calculate_S(&r, &k, &key.s, &mut S);

    // Step 6: "the concatenation of R (57 octets) and the little-endian encoding of S (57
    // octets; the ten most significant bits of the final octets are always zero)"
    sig[..POINT_LEN].copy_from_slice(&R);
    sig[POINT_LEN..].copy_from_slice(&S);
    Ok(())
}

/// RFC 8032 Section 5.2.7. The public key was decoded, and fully validated, when `A` was
/// made.
#[allow(non_snake_case)]
fn verify_core(
    sig: &[u8; SIGNATURE_LEN],
    A: &PublicPoint,
    F: u8,
    context: &[u8],
    PH_M: &[u8],
) -> Result<(), SignatureError> {
    check_context(context)?;

    // Step 1: "first split the signature into two 57-octet halves. Decode the first half as
    // a point R, and the second half as an integer S, in the range 0 <= s < L. [..] If any
    // of the decodings fail (including S being out of range), the signature is invalid."
    let (halves, _) = sig.as_chunks::<57>();
    let (R, S) = (&halves[0], &halves[1]);
    let R_point = PointAffine::decode_var(R).ok_or(SignatureError::SignatureVerificationFailed)?;
    let S = scalar::decode_canonical_var(S).ok_or(SignatureError::SignatureVerificationFailed)?;

    // Step 2: "Compute SHAKE256(dom4(F, C) || R || A || PH(M), 114), and interpret the
    // 114-octet digest as a little-endian integer k."
    let mut A_encoded = [0_u8; PUBLIC_KEY_LEN];
    A.encode(&mut A_encoded);
    let mut k_digest = [0_u8; DIGEST_LEN];
    let mut hash = SHAKE256::new();
    absorb_dom4(&mut hash, F, context);
    hash.do_update(R);
    hash.do_update(&A_encoded);
    hash.do_update(PH_M);
    squeeze_digest(&mut hash, &mut k_digest);
    let mut k_octets = [0_u8; SCALAR_LEN];
    scalar::reduce_912(&k_digest, &mut k_octets);
    let mut k = [0_u64; 7];
    scalar::decode_into(&k_octets, &mut k);

    // Step 3: "Check the group equation [4][S]B = [4]R + [4][k]A'."
    // With v1 k = v0 (mod L) and v1 not zero, multiplying through by v1 gives the equivalent
    //   [4]([v1 S]B - [v0]A' - [v1]R) = 0
    // in which v0 and v1 are half the length of k. (Should the reduction ever give up, the
    // signature is refused rather than checked the long way.)
    let (v0, v1) =
        scalar::reduce_basis_var(&k).ok_or(SignatureError::SignatureVerificationFailed)?;
    // Straus wants its base-point scalar below 2^446: `multiply_225_var` ends in a reduction
    // mod L, and L < 2^446.
    let v1_S = scalar::multiply_225_var(&S, &v1);
    let Z =
        point::scalar_mult_straus_225_var(&v1_S, &v0, &A.point().negate(), &v1, &R_point.negate());
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
    use bouncycastle_core::traits::XOF;
    use std::vec::Vec;

    // RFC 8032 Section 7.4 (Ed448) and Section 7.5 (Ed448ph), lifted from the RFC text by
    // script, and further vectors made by the same script with the Python library of the
    // RFC's Appendix A.

    // (test name, secret key, public key, message, context, signature)
    const RFC8032_ED448: &[(&str, &str, &str, &str, &str, &str)] = &[
        (
            "Blank",
            concat!(
                "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e",
                "39a3fc5b94492f8f032e7549a20098f95b",
            ),
            concat!(
                "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c706",
                "1bd6783df1e50f6cd1fa1abeafe8256180",
            ),
            "",
            "",
            concat!(
                "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281",
                "f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b41",
                "04852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600",
            ),
        ),
        (
            "1 octet",
            concat!(
                "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c",
                "5e3bc397a659949ef8021e954e0a12274e",
            ),
            concat!(
                "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802",
                "b8438ea4cb82169c235160627b4c3a9480",
            ),
            "03",
            "",
            concat!(
                "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7",
                "e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336",
                "c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00",
            ),
        ),
        (
            "1 octet (with context)",
            concat!(
                "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c",
                "5e3bc397a659949ef8021e954e0a12274e",
            ),
            concat!(
                "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802",
                "b8438ea4cb82169c235160627b4c3a9480",
            ),
            "03",
            "666f6f",
            concat!(
                "d4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2151f7647f11d8ca2",
                "ae279fb842d607217fce6e042f6815ea000c85741de5c8da1144a6a1aba7f96de42505d7a7298524",
                "fda538fccbbb754f578c1cad10d54d0d5428407e85dcbc98a49155c13764e66c3c00",
            ),
        ),
        (
            "11 octets",
            concat!(
                "cd23d24f714274e744343237b93290f511f6425f98e64459ff203e8985083ffdf60500553abc0e05",
                "cd02184bdb89c4ccd67e187951267eb328",
            ),
            concat!(
                "dcea9e78f35a1bf3499a831b10b86c90aac01cd84b67a0109b55a36e9328b1e365fce161d71ce713",
                "1a543ea4cb5f7e9f1d8b00696447001400",
            ),
            "0c3e544074ec63b0265e0c",
            "",
            concat!(
                "1f0a8888ce25e8d458a21130879b840a9089d999aaba039eaf3e3afa090a09d389dba82c4ff2ae8a",
                "c5cdfb7c55e94d5d961a29fe0109941e00b8dbdeea6d3b051068df7254c0cdc129cbe62db2dc957d",
                "bb47b51fd3f213fb8698f064774250a5028961c9bf8ffd973fe5d5c206492b140e00",
            ),
        ),
        (
            "12 octets",
            concat!(
                "258cdd4ada32ed9c9ff54e63756ae582fb8fab2ac721f2c8e676a72768513d939f63dddb55609133",
                "f29adf86ec9929dccb52c1c5fd2ff7e21b",
            ),
            concat!(
                "3ba16da0c6f2cc1f30187740756f5e798d6bc5fc015d7c63cc9510ee3fd44adc24d8e968b6e46e6f",
                "94d19b945361726bd75e149ef09817f580",
            ),
            "64a65f3cdedcdd66811e2915",
            "",
            concat!(
                "7eeeab7c4e50fb799b418ee5e3197ff6bf15d43a14c34389b59dd1a7b1b85b4ae90438aca634bea4",
                "5e3a2695f1270f07fdcdf7c62b8efeaf00b45c2c96ba457eb1a8bf075a3db28e5c24f6b923ed4ad7",
                "47c3c9e03c7079efb87cb110d3a99861e72003cbae6d6b8b827e4e6c143064ff3c00",
            ),
        ),
        (
            "13 octets",
            concat!(
                "7ef4e84544236752fbb56b8f31a23a10e42814f5f55ca037cdcc11c64c9a3b2949c1bb6070031461",
                "1732a6c2fea98eebc0266a11a93970100e",
            ),
            concat!(
                "b3da079b0aa493a5772029f0467baebee5a8112d9d3a22532361da294f7bb3815c5dc59e176b4d9f",
                "381ca0938e13c6c07b174be65dfa578e80",
            ),
            "64a65f3cdedcdd66811e2915e7",
            "",
            concat!(
                "6a12066f55331b6c22acd5d5bfc5d71228fbda80ae8dec26bdd306743c5027cb4890810c162c0274",
                "68675ecf645a83176c0d7323a2ccde2d80efe5a1268e8aca1d6fbc194d3f77c44986eb4ab4177919",
                "ad8bec33eb47bbb5fc6e28196fd1caf56b4e7e0ba5519234d047155ac727a1053100",
            ),
        ),
        (
            "64 octets",
            concat!(
                "d65df341ad13e008567688baedda8e9dcdc17dc024974ea5b4227b6530e339bff21f99e68ca6968f",
                "3cca6dfe0fb9f4fab4fa135d5542ea3f01",
            ),
            concat!(
                "df9705f58edbab802c7f8363cfe5560ab1c6132c20a9f1dd163483a26f8ac53a39d6808bf4a1dfbd",
                "261b099bb03b3fb50906cb28bd8a081f00",
            ),
            concat!(
                "bd0f6a3747cd561bdddf4640a332461a4a30a12a434cd0bf40d766d9c6d458e5512204a30c17d1f5",
                "0b5079631f64eb3112182da3005835461113718d1a5ef944",
            ),
            "",
            concat!(
                "554bc2480860b49eab8532d2a533b7d578ef473eeb58c98bb2d0e1ce488a98b18dfde9b9b90775e6",
                "7f47d4a1c3482058efc9f40d2ca033a0801b63d45b3b722ef552bad3b4ccb667da350192b61c508c",
                "f7b6b5adadc2c8d9a446ef003fb05cba5f30e88e36ec2703b349ca229c2670833900",
            ),
        ),
        (
            "256 octets",
            concat!(
                "2ec5fe3c17045abdb136a5e6a913e32ab75ae68b53d2fc149b77e504132d37569b7e766ba74a19bd",
                "6162343a21c8590aa9cebca9014c636df5",
            ),
            concat!(
                "79756f014dcfe2079f5dd9e718be4171e2ef2486a08f25186f6bff43a9936b9bfe12402b08ae6579",
                "8a3d81e22e9ec80e7690862ef3d4ed3a00",
            ),
            concat!(
                "15777532b0bdd0d1389f636c5f6b9ba734c90af572877e2d272dd078aa1e567cfa80e12928bb5423",
                "30e8409f3174504107ecd5efac61ae7504dabe2a602ede89e5cca6257a7c77e27a702b3ae39fc769",
                "fc54f2395ae6a1178cab4738e543072fc1c177fe71e92e25bf03e4ecb72f47b64d0465aaea4c7fad",
                "372536c8ba516a6039c3c2a39f0e4d832be432dfa9a706a6e5c7e19f397964ca4258002f7c0541b5",
                "90316dbc5622b6b2a6fe7a4abffd96105eca76ea7b98816af0748c10df048ce012d901015a51f189",
                "f3888145c03650aa23ce894c3bd889e030d565071c59f409a9981b51878fd6fc110624dcbcde0bf7",
                "a69ccce38fabdf86f3bef6044819de11",
            ),
            "",
            concat!(
                "c650ddbb0601c19ca11439e1640dd931f43c518ea5bea70d3dcde5f4191fe53f00cf966546b72bcc",
                "7d58be2b9badef28743954e3a44a23f880e8d4f1cfce2d7a61452d26da05896f0a50da66a239a8a1",
                "88b6d825b3305ad77b73fbac0836ecc60987fd08527c1a8e80d5823e65cafe2a3d00",
            ),
        ),
        (
            "1023 octets",
            concat!(
                "872d093780f5d3730df7c212664b37b8a0f24f56810daa8382cd4fa3f77634ec44dc54f1c2ed9bea",
                "86fafb7632d8be199ea165f5ad55dd9ce8",
            ),
            concat!(
                "a81b2e8a70a5ac94ffdbcc9badfc3feb0801f258578bb114ad44ece1ec0e799da08effb81c5d685c",
                "0c56f64eecaef8cdf11cc38737838cf400",
            ),
            concat!(
                "6ddf802e1aae4986935f7f981ba3f0351d6273c0a0c22c9c0e8339168e675412a3debfaf435ed651",
                "558007db4384b650fcc07e3b586a27a4f7a00ac8a6fec2cd86ae4bf1570c41e6a40c931db27b2faa",
                "15a8cedd52cff7362c4e6e23daec0fbc3a79b6806e316efcc7b68119bf46bc76a26067a53f296daf",
                "dbdc11c77f7777e972660cf4b6a9b369a6665f02e0cc9b6edfad136b4fabe723d2813db3136cfde9",
                "b6d044322fee2947952e031b73ab5c603349b307bdc27bc6cb8b8bbd7bd323219b8033a581b59ead",
                "ebb09b3c4f3d2277d4f0343624acc817804728b25ab797172b4c5c21a22f9c7839d64300232eb66e",
                "53f31c723fa37fe387c7d3e50bdf9813a30e5bb12cf4cd930c40cfb4e1fc622592a49588794494d5",
                "6d24ea4b40c89fc0596cc9ebb961c8cb10adde976a5d602b1c3f85b9b9a001ed3c6a4d3b1437f520",
                "96cd1956d042a597d561a596ecd3d1735a8d570ea0ec27225a2c4aaff26306d1526c1af3ca6d9cf5",
                "a2c98f47e1c46db9a33234cfd4d81f2c98538a09ebe76998d0d8fd25997c7d255c6d66ece6fa56f1",
                "1144950f027795e653008f4bd7ca2dee85d8e90f3dc315130ce2a00375a318c7c3d97be2c8ce5b6d",
                "b41a6254ff264fa6155baee3b0773c0f497c573f19bb4f4240281f0b1f4f7be857a4e59d416c06b4",
                "c50fa09e1810ddc6b1467baeac5a3668d11b6ecaa901440016f389f80acc4db977025e7f5924388c",
                "7e340a732e554440e76570f8dd71b7d640b3450d1fd5f0410a18f9a3494f707c717b79b4bf75c984",
                "00b096b21653b5d217cf3565c9597456f70703497a078763829bc01bb1cbc8fa04eadc9a6e3f6699",
                "587a9e75c94e5bab0036e0b2e711392cff0047d0d6b05bd2a588bc109718954259f1d86678a579a3",
                "120f19cfb2963f177aeb70f2d4844826262e51b80271272068ef5b3856fa8535aa2a88b2d41f2a0e",
                "2fda7624c2850272ac4a2f561f8f2f7a318bfd5caf9696149e4ac824ad3460538fdc25421beec2cc",
                "6818162d06bbed0c40a387192349db67a118bada6cd5ab0140ee273204f628aad1c135f770279a65",
                "1e24d8c14d75a6059d76b96a6fd857def5e0b354b27ab937a5815d16b5fae407ff18222c6d1ed263",
                "be68c95f32d908bd895cd76207ae726487567f9a67dad79abec316f683b17f2d02bf07e0ac8b5bc6",
                "162cf94697b3c27cd1fea49b27f23ba2901871962506520c392da8b6ad0d99f7013fbc06c2c17a56",
                "9500c8a7696481c1cd33e9b14e40b82e79a5f5db82571ba97bae3ad3e0479515bb0e2b0f3bfcd1fd",
                "33034efc6245eddd7ee2086ddae2600d8ca73e214e8c2b0bdb2b047c6a464a562ed77b73d2d841c4",
                "b34973551257713b753632efba348169abc90a68f42611a40126d7cb21b58695568186f7e569d2ff",
                "0f9e745d0487dd2eb997cafc5abf9dd102e62ff66cba87",
            ),
            "",
            concat!(
                "e301345a41a39a4d72fff8df69c98075a0cc082b802fc9b2b6bc503f926b65bddf7f4c8f1cb49f63",
                "96afc8a70abe6d8aef0db478d4c6b2970076c6a0484fe76d76b3a97625d79f1ce240e7c576750d29",
                "5528286f719b413de9ada3e8eb78ed573603ce30d8bb761785dc30dbc320869e1a00",
            ),
        ),
    ];

    // (test name, secret key, public key, message, context, signature)
    const RFC8032_ED448PH: &[(&str, &str, &str, &str, &str, &str)] = &[
        (
            "TEST abc",
            concat!(
                "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42ef7822e0d5104127",
                "dc05d6dbefde69e3ab2cec7c867c6e2c49",
            ),
            concat!(
                "259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743c09428a131d6b1b5",
                "7303d90d8132c276d5ed3d5d01c0f53880",
            ),
            "616263",
            "",
            concat!(
                "822f6901f7480f3d5f562c592994d9693602875614483256505600bbc281ae381f54d6bce2ea9115",
                "74932f52a4e6cadd78769375ec3ffd1b801a0d9b3f4030cd433964b6457ea39476511214f97469b5",
                "7dd32dbc560a9a94d00bff07620464a3ad203df7dc7ce360c3cd3696d9d9fab90f00",
            ),
        ),
        (
            "TEST abc (with context)",
            concat!(
                "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42ef7822e0d5104127",
                "dc05d6dbefde69e3ab2cec7c867c6e2c49",
            ),
            concat!(
                "259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743c09428a131d6b1b5",
                "7303d90d8132c276d5ed3d5d01c0f53880",
            ),
            "616263",
            "666f6f",
            concat!(
                "c32299d46ec8ff02b54540982814dce9a05812f81962b649d528095916a2aa481065b1580423ef92",
                "7ecf0af5888f90da0f6a9a85ad5dc3f280d91224ba9911a3653d00e484e2ce232521481c8658df30",
                "4bb7745a73514cdb9bf3e15784ab71284f8d0704a608c54a6b62d97beb511d132100",
            ),
        ),
    ];

    /// The private key of the first vector of RFC 8032 Section 7.4, which the generated
    /// vectors below are under.
    const GENERATED_SK: &str = concat!(
        "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e",
        "39a3fc5b94492f8f032e7549a20098f95b",
    );

    /// Its public key.
    const GENERATED_PK: &str = concat!(
        "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c706",
        "1bd6783df1e50f6cd1fa1abeafe8256180",
    );

    // (whether Ed448ph, context, signature on "abc"), by the Python library of RFC 8032
    // Appendix A
    const CONTEXT_KATS: &[(bool, &str, &str)] = &[
        (
            false,
            "",
            concat!(
                "50cf9c9532d4f906bc05eee0e6a35c47b539e66b47f7e9229e43b35bde4c2c9dddab4329de8e73ac",
                "7754d958bfdb4cbb3bc960ffbee8835e0026a993fccde9232465f1ad394ff14ad37e77ad38824259",
                "942d2884d671b7a8d1ac92c7c9841b1c0a4fd3adee3574ee1368f07988088d543100",
            ),
        ),
        (
            false,
            "00",
            concat!(
                "3ef478d25cf315f69a6d40d09bb4396960ebacf80bd0fa1afca71fabd7cfcd66672898618d167c79",
                "3c89e31d8b88ba129ce6c6526025215880b1c6407c796777dc06c197da55bf6c35d3a60686c2fb6b",
                "72f77b2e87fc2d08700dffdf43655a02cc2d064d4814ad6452cfa9eb78f03eb21800",
            ),
        ),
        (
            false,
            concat!(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627",
                "28292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
                "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f7071727374757677",
                "78797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7",
                "c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef",
                "f0f1f2f3f4f5f6f7f8f9fafbfcfdfe",
            ),
            concat!(
                "ef900ed044a11e1e757bff530e638a97d76ea7fa888336be5fc510ddf629cdcde97949305691ae78",
                "07bf217ff323eb43d79c4347c8006dbd806effac5725b9725cae9ed75359c54010c853c16ef493bf",
                "0b255d7e239cb3286b6fc453b04a1736830ea8c6c3be2d843e49bd8bfba26b0a0a00",
            ),
        ),
        (
            true,
            "",
            concat!(
                "62a8fc722f705b0436c3528e6fc75c9347ceafe71ca6d70aaa9e62a9110ed2d01a5f353ba5b87961",
                "e6bc2a5789a58a3fd9384c4106e49f0a80b8705befd1054ee77231775340449868a7c4ef7d2e2531",
                "5f63873702eb33ac8a552a37b3e4bb670dcc4d945476cf094b5d28e944beeab81200",
            ),
        ),
        (
            true,
            "00",
            concat!(
                "41f8cb2f71623df358939809437efff4761969661aecc7bebcc8cfc17793e315f1ed9344fd855981",
                "3197852ca7d6ea9137152265c8f7aa7680b9003e27b70f626b2d26140176f3821a6700b96a97b2a1",
                "0b458cc756489fb92a4b4927ef80a6c65d646db3cf865f6c62eddb175bde9c742500",
            ),
        ),
        (
            true,
            concat!(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627",
                "28292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
                "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f7071727374757677",
                "78797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7",
                "c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef",
                "f0f1f2f3f4f5f6f7f8f9fafbfcfdfe",
            ),
            concat!(
                "41ed3b313521d9b1b6f05c09f2e0a147fd811503553a04724b015708889e119b0226038e13535e96",
                "d2de5bcc17d5ab60d04d020768a0190380ee982d0f4886d48cf5521f531451afd8134fe836634604",
                "81437ff62970903282931c643a2f64e325e3a08f244b847cf763c68740b7b3ee2e00",
            ),
        ),
    ];

    // (what R is, signature on "cofactored" with the empty context): each satisfies
    // [4][S]B = [4]R + [4][k]A and, but for the last, not [S]B = R + [k]A; made and checked
    // with the Python library of RFC 8032 Appendix A
    const COFACTORED_KATS: &[(&str, &str)] = &[
        (
            "[r]B + a point of order 2",
            concat!(
                "68d0c16d1d8cf6cfa2cf3a76f8a33925127f2c22b13df1e57824f6968c8a976b0695be41cff5017f",
                "7344a6c6b1f5699192675323019163fd80ec47264b4c717d7cb4b59c003823a2bfa76cf1b2991d23",
                "047681f093ea189c7ab49cf15a679b9910f5185f2f67c15bd108a609695e995f0500",
            ),
        ),
        (
            "a point of order 2",
            concat!(
                "fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffffff00a84cd7246425c4aed784431358ddbb4ab5df47e6239875",
                "a60b1a41464b3d902b3f2fe2914eddbf2fe9bf7a6eb5cfa3c276fba10f4970410e00",
            ),
        ),
        (
            "[r]B + a point of order 4",
            concat!(
                "b1290a80518ecba63a43376b8fc05e8a92c6d3519dc9541e205370fa1e512ec93edda69cce5d2835",
                "46cc87ce6b190ce66f0f3a455491915680831369fce6f8145bd82014086a8d384871c0726f4fcc36",
                "568e2854a7869fcf7d01742c046686ded68daa71187fdb496fc61f7069c3faab0900",
            ),
        ),
        (
            "a point of order 4",
            concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000080f01af6bfcb571066268ddaf8297ae24cfb2ce5b21f8b1c",
                "094a75d149ebed5b7f4c803869f7e8fb03945c536633312ed80ed8334e21ff2c2900",
            ),
        ),
        (
            "[r]B + a point of order 4, the other",
            concat!(
                "4ed6f57fae713459c5bcc894703fa1756d392cae6236abe1dfac8f05e0aed136c122596331a2d7ca",
                "b933783194e6f31990f0c5baab6e6ea9003ab6731726f94ea139c2c5fa8e1aec0f7ba2b7a04f5b1a",
                "a261c86d81dbb579d53a54739744b115508b5a105d8c90f426bf1c9696fa07ef1500",
            ),
        ),
        (
            "a point of order 4, the other",
            concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000e74d7b455b5f0b5751bd27dc30c7c6009739f1d756f741",
                "fd419cf0795b8cef959d03839d84ac61dbdd61ba93cf3c04a30716285108932d3b00",
            ),
        ),
        (
            "the neutral element",
            concat!(
                "01000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "000000000000000000000000000000000017281c6bbb0203acdb2280f4ed557a8bb789306387987d",
                "d006f33a905d3f49ad5b5ff8de8ed8318e58d8de33893153ebfad5523d53d93b2100",
            ),
        ),
    ];

    // (the encoding of R, signature on "cofactored" with the empty context): the points of
    // small order again, in encodings RFC 8032 Section 5.2.3, step 1, refuses
    const NON_CANONICAL_R_KATS: &[(&str, &str)] = &[
        (
            "y = p for (-1, 0)",
            concat!(
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffffff000432ef1e24ad001261bf5f10e6286f23bb60865db7bc71",
                "d58651d391e70f3f7c29131ca09ae39a41245ccd4ac2722868fa96010108e4480500",
            ),
        ),
        (
            "y = p for (1, 0)",
            concat!(
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffffff8013e4d386d4ce3ef9872be21a2871ad15294c9443bff3bc",
                "0e8b09bdb06aa70f1f643052853f49d6ccd5a6450e91c46b6437bd8c49e16c181000",
            ),
        ),
        (
            "y = p + 1 for (0, 1)",
            concat!(
                "00000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffffff00f12dab1388cf2926542495c4fcbaf0ece1f17f1691ed74",
                "0310186fa3ec8cc66aedf924cadaf4d2bce7043581a8cec11f9e2835048a4a1c1300",
            ),
        ),
        (
            "y = 2^448 for (-1, 0)",
            concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000001062987badae598a4c5955e056cb1132902ea1edbbee331",
                "587b2a8d4c0537c63e8e1651816aed30e9c39eb364c0135d46a2f71b266158233300",
            ),
        ),
        (
            "y = 2^448 + 1 for (0, 1)",
            concat!(
                "01000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000001fdab0bd18f55be4bb40911b393286de615feb8fd7303d5",
                "8f5523f1d78e9c238dc5a4466391cafdc8e7671c5f7be072dc15dbf9484fdd1a0900",
            ),
        ),
    ];

    // Known answers from the prototype this was ported from: `generate_public_key` with
    // `sign_ctx`, and with `sign_prehash` over SHAKE256(message, 64), on keys, contexts and
    // messages from splitmix64 with a fixed seed, and the verdicts of `verify_ctx` on altered
    // signatures. Printed by a scratch program (`kat-gen sign`, not in this repository) and
    // recomputed there with the Python library of RFC 8032 Appendix A.

    // (private key, context, message, public key, signature)
    const ED448_KATS: &[(&str, &str, &str, &str, &str)] = &[
        (
            concat!(
                "f717d532023db4547c0a881b836776efa5ac046ef845c85064f7afed4a8a62f3b1f4a324fd0bd20c",
                "1750a4b6315474167d7b1c0f3cfddeab87",
            ),
            "",
            "",
            concat!(
                "c7e0aa1b8bc4cedbdd3ff578979a196341b024089a8ebc93e5bd5cb8143d3f5ee03321fb0d48794f",
                "11b589739b2050154be2210274b14e6c00",
            ),
            concat!(
                "78cd8fb5ea1e644a1e23dc9ea77acf076a58ffdab4bf9da1998e7d3240c64d2564ec98638e778c5a",
                "17bd9cb30a2c757e401b2c9ea5a8ed50003619f3816a2eee53c1ff1a73eee7411973e62e1ab4f9a4",
                "56fe581e481fc73949f7de0a934dc6605d0fb2bf4fa2018c7c3a704ce0b519fb1b00",
            ),
        ),
        (
            concat!(
                "027a642c757387acc2835912a624b099a4507a2491f020306d9a400b2684dd151646325b16ffdabe",
                "4ef67d297e5e53da0b5ea95192608cbc1f",
            ),
            "",
            "d2",
            concat!(
                "9d1124407262dc2ecafdc2f5915ae796cefde7b03d9824ff6cdcc8c70a40db655d4c428164809829",
                "36d9f27dbd2fd8ab44251cefb17dcf4d00",
            ),
            concat!(
                "a4da4677fb89755c4e617a1095a816a82f3feae947115d62705722bedf5f62730d08b8e8e93c4fc1",
                "faa4529c1f97f3fe382b8cfc77d4ba1d807304f5e65460ba79b6ad8b34fc9d2f111b405890d633a0",
                "53e53bfbc8955e8b2916c2483a9a40af39df0c39fb129e2f503f379e6887f9081f00",
            ),
        ),
        (
            concat!(
                "98d753128eb57b267823ac77f37221d6a07423cf5f660596d337367f1029d0c4b321d836248c12a1",
                "c2b7e63715c3828af7038d0825816aad4f",
            ),
            "bb",
            "5589",
            concat!(
                "6258cbc02a57e17434d5fc9907eb51db150101a4ad17eeb0e2209faa7d8f0b86189a4903e7d03693",
                "dd638b138ad58ddd5a2f6101e521573880",
            ),
            concat!(
                "daef3291f541365bfc87b6f95a06230b42b82ab8f036a9c722fc32f4e03b6926aa7ae4dd329e426f",
                "719e2a0cc7f85949abf0193edc5ab14300e93c4864a7dbd18069f02db1205b8d649cc10f1e55211a",
                "ff23162e34c82296e9d2761aa560bef6cd43fc989230956801af3d550fed4b403a00",
            ),
        ),
        (
            concat!(
                "cb16ca3d3cfe38d1ff821a6db903d255a649690451239d060bb92228aa7e986e770148d589efdafa",
                "9e30d0cc11dccf53d6c48d86d8befefb4d",
            ),
            "3cff",
            "f83633768a652c81cce7fc477ca314b25a4fd2b8c85ca95e79adbf8ed5c86d",
            concat!(
                "923622828388ab125b219e09a464f098add03ce318fbc9d3315cbdd1d4141d21ab5cd32b2979a289",
                "9f6e1c98922601dc0d86994bdf9620d480",
            ),
            concat!(
                "362db12ac9bffe4f8ab69fe90aa86d01324db6a8ed0b1f94f47f8686806cf4bb8cb123cbb322d7c2",
                "e4c16c23fafaa86cd5452a9c44c809d9808fada825b10e4e115f94e758cda33d3f3444c480e64651",
                "8603ec4b04525808359706989a34322e05a3792886f3d726e2288af201b4b2c93700",
            ),
        ),
        (
            concat!(
                "9bbd7e60187298508f157c3d047318ab9012d077a40621d4d64c09c3daf51a7921d8030312e465a5",
                "cb01c02fe53e2e1f5f6f94660d21064344",
            ),
            "d5bf06467c7febf5",
            concat!(
                "39d6380825660d50eab8c3c797afbb50484deb16fbef0cd60b9a77278541e6243a5e9d348cd523b3",
                "cd63d9d5ff26af2081c1442e7daaf9d7",
            ),
            concat!(
                "322f3a37efc75efb54d7ee25e7f28f777efdc232d81530e8ab19da59c81ad54d659e12dd0aa7edc2",
                "94dfc4343a1be92404fc060da0c1590580",
            ),
            concat!(
                "ece345a3504d6d954f2faabb80ba2539b8408ed40a2aafec6875f8bfc2fdf7187a3bc09916197cae",
                "34d9e47bb399434d1d4798e3eb3a1aaa80a1bf331c863fb4f09366c35fa39a109595d68db8c2b730",
                "04597c4639b1790ce1185bfe54e42d76042b9ca662b2d9b21faea46ad99186520300",
            ),
        ),
        (
            concat!(
                "a054718eea2dd0fa5e3f1ef99e35bf59c24527e3380836e3e294f364941ffce03d53471680bde85a",
                "f289b8757b4a8efc53cbc7d5117dac821f",
            ),
            "",
            concat!(
                "d3eaf18f87d68578d6d91085602476999e2ec4d7eb302f1cee999656a80447c4d5d1415cfa43e0db",
                "4c9a4979f5180a08efc2becf9745cda266",
            ),
            concat!(
                "123f6e1f6964197cc7a61f4426abdae1d10f24e276d4bff29671df58a8330d23cbd1236eff445565",
                "8ffc677a7d47694893ebe9ccd985972300",
            ),
            concat!(
                "8c72a6b3f1d632dfc5a3b45cfccd5bb73dc94cbc714c30a7c53fb7a5fc8323626c8fca27f134f193",
                "c8b546b7fb2abb0ed5a538c1717296828039996be433bf1ac1d80c63afaa0194928429e1e97e01b3",
                "21dd4602aa90b88b5bff7b34b9473eede17a99b0afa941302e8a00268d407f351400",
            ),
        ),
        (
            concat!(
                "aea24aecc8622cc0fbee88273635663793702014e63674ece9b347b4590dcda7ec94d19c9c4beffc",
                "72d1dd6c7a18b64683e78d84bb794d9328",
            ),
            "e4e0cb694f4db7263666ee73dddc8068703f197c62e11fe229e393bfc1c70e",
            concat!(
                "0d8d6fd51bbe1cff9cba802adc19e48814c88ae34199aa8f37f6f3b27a0b4dee82d93cc948af5657",
                "f7f3ba289c965fa37bb7933eb351486724559292e8c25c52472dffca0bf6c38bbf374097f1afd53d",
                "4aca2dbb0626a0725e604d56851ad17660fb43453d841e1435e3294f16680b526a4b",
            ),
            concat!(
                "5f103143fa3d60483a623f1521d70b1cfd585a97412849c768b462312a37f583d90ed204fbf882b4",
                "90c1cdfe50f02d0a93c3998a67661ba580",
            ),
            concat!(
                "80c35f5029dcbefd1128436b8c8c18685e90c9769611fec292f44b6d4096f4a1a3ba3feb9c3b663a",
                "7e09e78c57f1b61ebe96081059439115000c736b9fd53ccb24063995a8f2e07cfd0cc20b97ca6526",
                "69c408d52b5bb3bdff5774e992788cfc1a494cc102043da510be2d97b80b063b1700",
            ),
        ),
        (
            concat!(
                "da7e45de029166a237d0616a26897c3bd196d7aa5fe99433b1e1b95b7684b12a8c0c960518e12cb8",
                "47b8381c08aae64d95f1c52d2cff94e039",
            ),
            "8c6277d755371a78e77b9a24023d9ccc9ed9d753d5bc09dbb2556f4cc56d48c4",
            concat!(
                "cf96922e5ad803b26c287086db5cc25383f4ec65c1ddea342f0887613422d826cc023fa4767e7ff5",
                "940c5cdc1469a1a2e87eabda6d3051ba401c4ec238bf87e7252ca78d2b58aa3a65781e1e74aed672",
                "6f3c12785526d83d7cc96670db85efc46e6203eb5cd2280f00a5e95243d868cb3fba7eac31964c7d",
                "3e09cce60aab36e19a9905cee762f0",
            ),
            concat!(
                "87a6f3b6a5f57606af4f87c10d990653e5b899d0b7739a764ef98a1bdadbfb211ac64128f2d42a33",
                "f0069b48699ea50c4d37d50e1df5678780",
            ),
            concat!(
                "f777ccba6e44fbd04c765e2d50457f9bd9c42edb66557d21262a2e3434d774bed63ea9ace66d927b",
                "71853484c357538ea4a570afd993ec610089680060c52e559d01726b89c70b32fab955f48c644bff",
                "3471c8f5829731bcba4fe9ed41656bff95334b0016dae45094fd56ce082d52203a00",
            ),
        ),
        (
            concat!(
                "7c469fb4c52ee6e2e9a386b5d493db687cfd61c4b45f9d4c95b3fd92d9e139a6233b3ed261832364",
                "dc980571628d672f72065fc422df822437",
            ),
            "979d2e7b3b65cdf21ddb13e5debbf6c00f714f04dd1a9f3373604d3894b4da1df3",
            concat!(
                "5599a749f6899a695ca12d4d21fd622df928635594a718b4fcf3c277e147d838a79c67b63447d804",
                "5cf2c1f2b603d7efe5d535244dd8d3c403ed731a2b86d23dd6e4977d08a5908b8b72a853e5a12bc0",
                "5ebce853d1f076f0a169704303c1f929db72380a111a53d6afb9123d607e9371bf54cff95145cacb",
                "3be0d0a53c677753f84907948cf0e6ba",
            ),
            concat!(
                "4e7a4852feaa29ea37e50732b49a102161541c013fbedbe9236d8a77f30dd104c39499b352147386",
                "ba3e8fe8c9373a9e92b7f02669741a8980",
            ),
            concat!(
                "55679c989498bf425214b74ca70b393efe928fb81762789a9f4dfd97575ce71f4c48e17620dae4f5",
                "6894d7bd9aa076a068996e941918aa7280370c5e1a1c57bd2bb821981c248c2e0b22c6998cf12419",
                "4a3bb58aea2b0fbca3f282464d9cd1d6ea204cd0ef745832b5a763fdae1c46111f00",
            ),
        ),
        (
            concat!(
                "5bd22d0029f1c9382d99626c4e13e1c2cc223883f1f4bb323f6b365a89913ecd59fb9edf79ee6474",
                "bc36a491954cb90a68adb0dc82dffeb573",
            ),
            concat!(
                "7eae57bd578e06029899a8e84124492d218d0ece08029f27ff0e82614ee52fcd93b4b026f3e01553",
                "1d7f90e24c9e64aba9b99df73626cb34dca2a8da49dc7bdb",
            ),
            concat!(
                "f5babbdf8de1e348eb6c6af09700e5e7b13ff5f6141b04995270067902bbf4f68bf85fad73f92c24",
                "5f1687a95cd4153e853ab0a8cadd6b35f099f064247b10b43d6c3fbcfacdaebec025901423a446ad",
                "dae29e7f4585a190339f51ce11b5676e26d282bce2ebbbf2fb92b71d0f5dc174718dbd3522e5fcd6",
                "00bdab26b8ea93458d1023c733361af484",
            ),
            concat!(
                "59b288e5d707f96dba2f735a653a68cda9b357511b92ff05339893449df111d45c118cf1dd6a33d6",
                "0a998bfabcf2fde1270c0c0d8fccc72980",
            ),
            concat!(
                "e7ed41b999ca70de4a149816ec029fac47faec85fece542ceec2871ae473f517e0d5e9e11dd76b7c",
                "fa28f6f9b2d5587ff44d408db9735a9580a1bd231d28730e59315c7270bdb3498d1aa784d2a6328e",
                "75a295951434332025b1b1921431980c528978cd2e774f618d6a1c4de8aa41ff1200",
            ),
        ),
        (
            concat!(
                "f00f8d464a438a88b571fdb68f842c361ab6cc9169445cd9ddcf18ce9ffa5e73cea5074c81c4e854",
                "d5ece6572367fca04ebf605ba743427308",
            ),
            concat!(
                "c786521d3551fb07986a2616c9b5e86e9e970e51f78a12cd897afec0094af9970624afb7cadf1c6a",
                "a9aafbecc61cad60ae98d47e411feb689475c24297996ba706f0cb824275b9259a421678b7794db9",
                "fb9caf850d7083e0bd9bb0ffdf775f5687341a4ab0923b25b1dcc1a32eb1830cd004e28494899838",
                "0e0a4fa069f60bfc911d989a9395e517b1ba8d9894390c2848400becdb37aaa292bb3d20d5239832",
                "947f0a64fd6b1127095929bee797304b9cb9ef34d104ea6a2aeb4881cf3172e9ef44fa5faecb0aa4",
                "ae6974265445717a51311edaffe07e9d75ba6cffc80ee8d2c9cae2b0cedaec90ffc425ea55413667",
                "0231ff07bae608dc4d9fe683cfd0",
            ),
            concat!(
                "8134e1a0313c43a58addb2dfc9fa441d77a3fd073a18e2cb88979ba768c39202bff15b6684f2a272",
                "301a3c8fb413cc1886b52c9e37ff0fbadd1ae659919a0333d1802e6a255a72ca14ed844e46535ab9",
                "d7e97a75cc60453e1986e713410e821ad712e129d645f36a156a10fb3759f3b114be2fbd2bab1c16",
                "61f8397a4b1db851dd899fd0d3cb1c50251af6cd7ebb048dc5625efb19083fa049962bba5fda40f5",
                "2f6f7ba46c7d99d434c146edff8019101c8a42cbe7a2c474d1daafa8d7bfc15169716c6a5f3f6a76",
                "2ae634678b8184a4255cf35fccaa1a3c03e3e871d96c45633849568efe155fe25e6f718ea890d888",
                "95accedd8b6f73bc170c18cedb6ba3",
            ),
            concat!(
                "b680a4d7ab94de6c4715d984098b57835130b7093355495a466606b7d6f321145e0f13ac31ff06e5",
                "4f0b3b33ded8ea77db9b2f85f6396c4800",
            ),
            concat!(
                "9e4d881419515eb0918e1863535637056e6c5e33f86e67b4db150145b3a740cade1cb88737bb1351",
                "3b5eaadbf3cf992e72a31e3c26233f3d009934e6796807931fa990869dc51241670c4181ee696875",
                "bbb2956c71f4b73056a69ef81645817732425b32a0b0095f7f65b3f01f471cce0900",
            ),
        ),
        (
            concat!(
                "f555761912b42d0b71cf1ee547f2f8a4e339078ee12ddf012dde023f260724c34e13366c288ecfa3",
                "5ffaf256ef71c21df927431453aa9131d7",
            ),
            concat!(
                "d2518554842569d40282c6e11deb3849c221fec392848dbd29a17fee37dd3bff1fac34db6ebc283a",
                "317d92f6704a49e90d8d82f21f086fe2641342b4c934dbdf649f718ed8e6899f62e909c3f9a7a026",
                "e3ed0ff10eb38575a00669223dc6017c5accdfe126b201440c5da959c855ff702e5a420f113c0801",
                "b42c9858aa5ac046ebb03fc78b03abd37916be746c4f6ac46098f4a0d52c329e80ab162c3364d744",
                "2cd19b11ca41a4e41d320566a87b882996a332f9b7930bebc1449755fe057ef262855e86d7ee5ac5",
                "cbafa3d16e9beae0d64191f2db97fe0070efb173707eda0d87ce4410b43778329558471718baf1d2",
                "6d6c8b143c1bdb4f885c00f04ca143",
            ),
            "",
            concat!(
                "58e43147b1be75692d944961154f58bcd901b071e405af63ba51eb5140fb9aa02a4f877faa1c57e3",
                "356e755c2f238a15e608f95d8d6f721200",
            ),
            concat!(
                "c7a1082e491a28af70e422b47048e6465877bc7259131320d9c8f70d81cac228b1884fe0d1f87e8a",
                "ce402c1ce0d8bde341293074485de23c009246213fbbfb95914918b648ed3fe081a599857248341e",
                "ea55c61a79dd880c62c15f42d646e44b2717af5eb3067c604c73e37c7221662a3e00",
            ),
        ),
        (
            concat!(
                "8c9802e1189026e4748b0b19fef5a63a6ddafbde3fce8e0bc13571588c26f3b7992b15cb5f5ecf1c",
                "3394f506b57f1377c8741b5f0c63e406ae",
            ),
            concat!(
                "da8bd76aece5a4925f4924604101d09891c1d5a597a507fcb744ac0916a633a6b5e9fa83a0f82c1d",
                "3058fe52571f871c77e1ee14a3537d72e31dabb1b21266a93d48b410126c6e1275fdcbfa3fb1fe4a",
                "103ed46d554003a62bb8a4533640a2474ff7f42a76d622c7bf037d3c26f79c4814a5d56313dba078",
                "cd08f953eb1092068a58667ad39792ef58aec35a4966637c647aa2eb06e06e0ea7f0aa5db2a691ee",
                "8fc64b39190d0cf8b63b740b960647b87a8919486791feedd72e0e9b2c770f8bb5dde3cd93e3054b",
                "3460662a485737ff5a0c7ba5042235880f013d6b7bfe393c3e7f8cf298fe07a2ee85b4cab06149d7",
                "93bd41ceda82ce47fb295e8b34b133",
            ),
            concat!(
                "b0ee216dd2de14f2e8615f4ffea152858220abe98e25e4cb555cbcd028c4ba36f3a354ec151c7013",
                "78985d4765d22b7933bb692bc9ea6f31c02abc783df3b2d9ac30fd154bbcb5f6416a2b93eb8081db",
                "5e64f844494fea928763dcf7d2e626185710600033a7e48982ce8e7291b2ef4e67b98f22770b37a2",
                "a593a78a82f1704e8aff2bbf017d99f05860f829ae2fcf9c597e8b448abe1b985d20ed7fe397e2f4",
                "caf4efd1918fc7b912e9d0fd27b48780a6ca6b2d0e9f09266d5d90a276f4bb3ad0fcc8eb8693321c",
                "5b5d470f99e00856eccfa7d63e3a91e1ba1f30b17c3d5db1d4b6644e3637a498321ed5dde98acaf6",
                "a92a905b1f1838a819370ff7062dbf5b2311d720eb02dce3c267d7a2f07f1bbd",
            ),
            concat!(
                "cdf634ef0f9f81f6493251a1a9700efaf73f72418fa4a6d09f4dc10982943f7720cb8c0dccb2411b",
                "6dad0dbfed251d1b4c9bf2357954970980",
            ),
            concat!(
                "b6fcd361dbb468f4f3a87c3ffba2477dbfccebd467ed53341fc8da2bd14a32eae5407926d263eeb3",
                "b4e3671b3d1a582309541c8949978e5480e60d0934429b61f36e0ad6fc16fb41c44b42fc7ca5ddba",
                "c22c91c6efce395bc036556ca253c4a062645bc0ff8faeb990634772e7f1d4fc3c00",
            ),
        ),
    ];

    // (private key, context, message, public key, signature over SHAKE256(message, 64))
    const ED448PH_KATS: &[(&str, &str, &str, &str, &str)] = &[
        (
            concat!(
                "a31db2d4777910ed8618e4068a297641e242c16ad4d8fc850a5f620fc6526829d02d0c316558d6e1",
                "438e84c8b35803825c9b2d78b1908d035f",
            ),
            "",
            "",
            concat!(
                "162796f170a151e11580b833c2303216dd745e6c7dd8c6b543132b3fe8769801d67158d0b4ac727f",
                "22760f281ac930564eaa88939c86da2d00",
            ),
            concat!(
                "ac5fc77bb9dd7e0b879b47ea224195f20192f51846be889335e98293fea8b7a4cf61ce2e1412eca8",
                "1b28239fffb8f54c496e9e9e61abab1100cfe62879f3e9f842c73e4511884a08d8c1cb923f74a6b1",
                "8dba01a5b8d9bf014c9ba899170e48b5be0919aff115f017e9651f7b0d357afa0a00",
            ),
        ),
        (
            concat!(
                "57cc7743271e0bfd862f82719b18f5a4f3db8a821cbba30388fc5e16c7eb1afdfd05f557a9af0fc0",
                "1173440a79d3197a83497b9631f694b722",
            ),
            "",
            "9a",
            concat!(
                "418be874dd38ef29b6ad584355c104bdac00cb2f85486e3e839704eac3cf23a4585d53e1f27e935e",
                "4ef6f4824790e7ecafee3571ca5807a400",
            ),
            concat!(
                "9ef3d2a3acd2d8ad4d166d5a39995653c55978fea741a045577d0f14bf859f8ab0200d7141e69063",
                "446cfd9c6c5b6ae0086cde085aa23082806e1168b8e9f1d24c33551681695810c755b759f29b6d85",
                "ffb7592077a0affd962e715bd8982322c4f3998c93cb8a3aaa33b7d02f0931f60200",
            ),
        ),
        (
            concat!(
                "f732f5493d1b795af48247d7f5c71624d3da5321647399ac37011c00711b19e52f0af7bf3d16f41c",
                "85993ffc0502e6a8824ccc3d6f2ab6073f",
            ),
            "19",
            "49c7",
            concat!(
                "b167a7c6b330750f274b74055a8a49d6b9b51ff6f0fc0cfa8c038a76d487ffa0dd74afb898c9b267",
                "55299267252fded672d98f91a67515d800",
            ),
            concat!(
                "acccfbf1bdc64b9c90ab4957b7936d873e7063575eaabef33848172473c0b4f127ccf85aad6c33a0",
                "a1f009fc7fb8424b248d6e48fa833a41807da759c549c5bfbde9ef4846de6fa9d7442d624fa7fe9b",
                "72150c25387e9077aebe829223979a19285b9df564d46ea71b0ab9967bde223b1200",
            ),
        ),
        (
            concat!(
                "b6fbc4f5e21638e82184fba3e1a2f01b251add413b7c60d8ab9a50656f092564597d676329cf70f4",
                "f3adac3db15936136a3a656aedbbf69746",
            ),
            "7158",
            "f657be9689d0d3f2f55544abb65e62064fc90b0a81b518ae64548a45b30bc0",
            concat!(
                "6a6554569bbd7d01383067e7452b2659709d24fd81985aa2c50080bd5db15b1bfcc247b353d109b5",
                "51cc133c9d4a283db94818532741146c80",
            ),
            concat!(
                "e63ec0e29598c84b63b437fcc70629dd09fba7ddd9adbaf4ffbc3bce9a6f44a8bb8ab081a153e9cf",
                "791f0ded2ae69c6ff1ed7de5e351485580a74f336bf21827814286eaef50f63727e2b8ff154bf1a7",
                "0287ee830883f43539021a08ae7a71381b58e56f17f84196c911a7ba886eee053900",
            ),
        ),
        (
            concat!(
                "89ab01bbbdc8fa024003423062f6fdbbf32538a3ab3c84f994110a4a928636e56348bca3eac43d43",
                "c3a2e983ad8fe97a35bd2f48811d4214bc",
            ),
            "481c0116745969de",
            concat!(
                "bfe1b3b166cd94818ba584b5a5b18ce604ffdea2185ef88c727ac9e23021ac7df37231fc8956945b",
                "7d949b8adeb6194aa92d1fe607ce66ab",
            ),
            concat!(
                "73f794775c722965c1e9e210138fc0e0cf03bac3ebd874bf008c0e0a5e5ecb34b623cb5d34b81409",
                "c5510e6555e460fdc343e551a3346d7b80",
            ),
            concat!(
                "49b181573554b23b3b38cd1589bbf8fff26890624a2d39d4af161eb923544ca2c2660b6ec470c064",
                "fb4d1fbff22807e8a1cee7c1e7f6f75280bf814d4967445ab1b9e66fcba9a6486aa2466c030c266a",
                "24b8d0abfd51261c0155ce6bf0bfd564392c87a27500da57917a322a03f4b5543300",
            ),
        ),
        (
            concat!(
                "6b995a8c29d06b9c9810ffcb650cf72fe81b922e918843f15f7304d9e941744dcf5be3bde420b5ed",
                "d869602d44dbf4bb4fe5eeded91e19431d",
            ),
            "",
            concat!(
                "5ec55039af7a813aed992c6c28cdfb5a40279ba3f3ee2fa7d9ea76183ed323896280f24da7f9f52b",
                "a274b90baba48850a9e659313ec7beb254",
            ),
            concat!(
                "e8ef0ed3b5b478eb781adfd750ab4ce8cd3814f65da1df72883fcab8026f0f0882fdc7c94f22963d",
                "35da447b3bc71d103a9d6035641f0a9900",
            ),
            concat!(
                "e30ddf0cfb10ea43eb7c5933d83fa6a4fd0bf6c146dd5a647a48b3e32a6d5a841ca7eadab6766755",
                "7f05dfd9be93d6c9294ed76215c4c6a90022fadb8327a14dcaba67aae1a10fea48ca81de3bb6dbc6",
                "60b34658f96aaefb173488f9f29cd201a4edb1fc0da424edf08d938b9d7a75f03d00",
            ),
        ),
        (
            concat!(
                "badb6986551fd239d4ca2db73b1049f095def06bab29af005f00ae6002cff2567eb77947f246d067",
                "abec96fe1e79ac5ab1a7d2d13d34555415",
            ),
            "0ca20353d83a37221c18c1f66c73029242bd2c02bbf337734c9f9170f660bd",
            concat!(
                "92cd1210dfc0de91b6af2ec6f5388dea10d31421145f6cf80024a8faa047732335f3cf4c109c94f5",
                "7a658f17eaa0a562d9b8154fd77f1a84c9035e31a22acd8cf10f9a274eb257bcdcc46315faf3786f",
                "27533318c1218a5fdf31f265ba0738850510a5476c3c9f6b02c6028c8aef7e33956d",
            ),
            concat!(
                "3e95acd260ff7d00e113d88461f49a0f3e43e01b99bef25b6e87cb32985d6cf9c62d415ef1f30780",
                "0a40d4e105d7cb0578e864069b20b74700",
            ),
            concat!(
                "ac0816ae00c30009571cb91152fcef52bbc3d6cfd2348605a71197111bd39e5bef3a3574fa6451ae",
                "9872d45a063294080c28f2549da5117c80affaba661f1f1a1679aeb566eefb0d5a755b56b45cf04c",
                "0002ab93e9d0d70b001a85609f9a2f2c7bcc5d36a85ec1d1bc9aaedc4efde4df1300",
            ),
        ),
        (
            concat!(
                "82fff3a6ad2b60c0181691db8ac30fa214cd99f309f2fd70dc492bfe34d81e81135699cb4d14274c",
                "50d9e6567a97b10c03c26b739f7ed1f874",
            ),
            "9cfd6c9df61e0cdd0ca6c140fa10b6772b0208628a473e2240c1c9ae6cf1a2ff",
            concat!(
                "0062ff95f70254b3190713ca87592f11239da8fe461525dd459802c812ce11280c7fd4fa6c1ec144",
                "5a2c6be21d6e3c35445d16f942362424ee8893d1ba07a18113b9467057a52984a08f3aa8bf7b7ebe",
                "161cf631b3dd93a5f4f3f45e1fd38456d2ae754108ab5159cde3b82283dbb51fda06d6086fb3541d",
                "71e75608223bedb5a682862a70ef35",
            ),
            concat!(
                "4be5988e7d1f223a11e234055ea4ab4ab92dcd3988f50057f345bff82482f13b085a85bab2c5219d",
                "046b0296ca6957efdf19ff89a71a234180",
            ),
            concat!(
                "231a89ddea3c1764afeed7550ed5d8ecb96b573dd719f26d5af33980b5922a953c352a8ee646be1a",
                "93645f5141e47a942be814dbef4be9e080546780125ccc9eef941b9f60f49ac8e83ff2887b2b458b",
                "78bd36c8a70a80d54b56041421488c5fffd5321018dc03c0db8d07d7e0c736e11700",
            ),
        ),
        (
            concat!(
                "5543bd57c626fee399eb29aa5bdf2f1d2569c21996e17f9a44336be06da0b67f92b63ea90dfa0a1e",
                "b2d0ffb511b48b119e1d708df6feb7d7cd",
            ),
            "e61b3518355ff6d842a9b09841bdfabcbabdf95731cf98d968415ed862b1b9c7a5",
            concat!(
                "31c586ab9918aee17e1516a9914c196e4d507462224780ab91395b1e8849117dd95889615c62a466",
                "e792c3ac62fabde232575d0f2c0dccfd9893e21731abea852e676da53b0e0e3cf101b6c3a87b2e70",
                "c80e1c202218480dd87bea9b601fb817af1ecffaada6c476fd9ad1af417fb7ef1d5c8dfe306dbd44",
                "a14f8ec89e7e87965e8e8a292778ad16",
            ),
            concat!(
                "8a1790c0023d317d0ee8f9ccb52e3ddaf0b137f0b6ede68c5ebb7373a7e83ba3115aa1ac81f16f48",
                "e34f8dc008b1abb05925922c02640ce400",
            ),
            concat!(
                "d0403caacf04b61f89c3d115798e1d4a39cdadd1622a608c3c8fe2349aafc1c5066c95f25baa1503",
                "5fa0db2bf85753be2a3b7d82c73c8107002b1e4be18d65b4bced3ee552c8c446b4a4030d96cb98c5",
                "a021e55b339f56307f3a948722b89d3e988ebfdc91834235885bfa7c52ec58121400",
            ),
        ),
        (
            concat!(
                "666f205bef24bc5b0b1f28705c5bf6cd7a4e21814cd5acfb358388de681562e5a0cec835f5fbc8eb",
                "14565b5ddabeaa42cca0c02d3b6ead3b7e",
            ),
            concat!(
                "5290ab05e5accd24048d2b9834d25475687ff268fce2f98729ffc227a925fb405fbe9ef63f5490ed",
                "7d0c590c385beb224b74733f60fefb4bb13d09ebe2f4e412",
            ),
            concat!(
                "d6ffd9d6dc0e4424478d6caac17e2aad0e147253dbac811e396e05d8a7c51577229d46caa1ed836d",
                "34e392d33b050c1afb2cce0cce3615a47c9c0efd7840aff4e65fc657d877c7e8c2541d926c2c04aa",
                "b6c1b2fb59e7b3333853058ed6c926c48882df2251f5f304dc1e35f44347200291052d72cd92bfd4",
                "e81bb6f672baa05d13e839a457e5e78f0b",
            ),
            concat!(
                "ea761dfbde59ae791660c5e3a378a392affbd74e3fe533a93498659a84abde3439511de51ee8a8a0",
                "2b04c0827f66df4be7ac0f80e9fbc71380",
            ),
            concat!(
                "bc291a31d6b0c902441a445042bde6314909ecc8cc670dd66197ca8c79e6db359a1cc50aae251401",
                "e8255ff066da0c27a0ccfccbf93c87ea0073e60dfbf4931ca7fe7ccea781455bbd8cc0b0e9263d24",
                "ce4d3dea5f047ecfc099545b4cbb94c7523ba5d821f2038e37519d03b8d843e22300",
            ),
        ),
        (
            concat!(
                "d52c607827c3f0ef01b0ea837a1b68dd84328e1568c04d1a45eef399ae1674f7185f19620392e0f6",
                "6f949ce1b1bcadcac0814a56ab7de8a0a2",
            ),
            concat!(
                "d11294eb89b7ea42baf2c00e1585302c447b28ca1f8998503799dd834477957325606007d394e95f",
                "e3fa645c8194331d6eab7929b346ec60176ee6488fde4334920aa00b92a6d002ce93bbce1099381b",
                "f3dc125e4042db2688028d4b686ccd3349eea6111505da485e3f4f9e9aae158aef735c6055431921",
                "d6141fb82944960b3bd0712d2be5601c8f8f9978b629a49be02e0e517d9d49ed1605879464064cb0",
                "660b56041730347afd8b54c49491f62017514cf2fadba63be5d4f06a51ab1ca1621b07b506df4138",
                "539d2efa4b553f1065479ad3729edb8e01987aeea37a40c8e43ee9b9a45e51e4974fe5728a62bf9d",
                "c1359cbd16448848102a02f0d7b2",
            ),
            concat!(
                "23c428d5ba937c15bd28a42989785d0e3ff0abcb337ee74905a61aefa11c9f1a73b15ec976c66d66",
                "ad3c008c1c6bb9d68e0e01843594a387a61ca8fdfabd68543434dc070741e05bbb341187d5507bc6",
                "4fecd56220a30c6a79df7a32a416c8c27852a8cce43bda29cb1d65cfbc70dfe070e2d95dc2bfa4b4",
                "fdc12585c3b7ff76dfd247419548a2cfb06cf85a721806e133304208a5bd66abe00211b1efd69ce1",
                "ebaff889d36e7adf6c3437e27bc9691e3aaecc7bdd61c6edbdae1d7c704faed1ed0f633b9d54f0e5",
                "4f40a94a0691c6d80b015d4c85f8b39aec5fb808662d945381107e8c9b1ccaff52cdf37274562102",
                "b3c1e1900e4e1e3370724052fcea81",
            ),
            concat!(
                "681a49e848f47fe8f07977eea2f6a4d66cf04a294ae554c25a239af3c2fd6d5f30453e38797cb761",
                "2e79d3265ce28138d394e5ffbce864d300",
            ),
            concat!(
                "f61cd0db86afcdb879b21caab2158daba7cf6fe041cc94c379af7abfac67dc85eae62076180c010b",
                "7882670a9979391ea7fff3daba1cb1bd80cc74ffd68c11ddbe27f7a3471d0b785959fca76c1bb05e",
                "fab2fddf796150cdb376f7582a895a0a70b42ac226032327d21b252af5b3dc2d1200",
            ),
        ),
        (
            concat!(
                "aaf08e3d173fb15c5e5fea5e9e07220a1f80478f8cf8bb618abac311a9049a5c97571fea3be5e63a",
                "8bfac521b6314859240496e051173baa7f",
            ),
            concat!(
                "94ae8a5b394ac865cb8c274466218a22b82b30b7e630ce5fa019bda2d642f0e9b3b263f0f6f1dd5f",
                "2c2ecaedb37c0ceac52080fd5366e487a0bfce0ccfaee8471a7aca1ff797cc2cf8701c4f79343180",
                "ad0ada6d6ad740a624b9aaab0f1f7cae94ab5fd946e5650561bd591f63d7d1428da0c599c97acef0",
                "7720f93a658a21c9884c4fed8d9150586d3ca17613a452a9108f2a0f321844f9c5df2128fee934e9",
                "f52185d962f1bbfd2e960bb93c8f2575020047e71a49ac9c9ec9f829ccfbabc2b7f9a9819e4beea9",
                "75e89b6ac1077c0ace9e0d1b02f1a8d70856eacbe7d8a78a38fa7f693d0e4a589752f6be8bf46566",
                "80a0705f4a889fded07160eb0c536e",
            ),
            "",
            concat!(
                "7851f8456af1023ed70ab64061668936fe0c4f385c02854771effcc30589899bd91454df2250b08c",
                "163e3e1658e552d83a79dcbce04cf23080",
            ),
            concat!(
                "cfce6e434c14e30350c783236dd13dc5bc1905affa4e7809b875994b3c1a6cfa95a0e2f4bc4143ef",
                "38e56459466baba7c7f810342ab90bfd8041cccb7d33c12ff43964c751266db2cf105e91304d13f4",
                "4e3827918d1778e4dab8efb71a780fb62cb09eff6687e8040a19bf989fea27653700",
            ),
        ),
        (
            concat!(
                "484b18ff4d3a8bf463cff184d78ca5f8f36d723ced78d5bb5845e8b406158345b2946b4ef9253f62",
                "7a49375473114828203165b2d878919305",
            ),
            concat!(
                "5f67289696cc2198caa0fd2335b4625a60efaad98a183c1578688e01a07f520c66f5cc324686f302",
                "493bdf338db2faf4ec29f7b0ca1279d350a697ee957c34cfd086d7dac9432cd41e74f45f2e53fdc0",
                "58d8ac058089296c645a5ed2a8b5bd159252a4ef410807a3754055e59feb480cc45357dae24ebcce",
                "2efe7b923413b4629b69c32f9c579d904ee5a1185afddf8a55c789ac339cc71fa69be8705de98d3e",
                "062638ecb7dbadc66291854e8072a12c912150176e4b4ed65f778a0c9c5e34d2b1c1b80f061b9469",
                "08e5aaeb07342805ecd7fd4e609f9d36c9377e6b4aa309110917c5702340f8faaf0e2530eac45746",
                "6246309be94d1e45d9763879b4a73e",
            ),
            concat!(
                "484ace1a86f8981dd24145fa557ab94b45d8a37fd87172565e5379918d86fa411511b1a9ebd07b64",
                "9bbb678dc155ed78a64a2658f95698db8d382d1f7a228a63feccc953c77d413b8f7ba2a2cae55947",
                "be9548f25f71aad3a0be10a99931b6e06616c5523fa14a553b19bd5d2d7cc84e09eea2997e81f310",
                "e06837ac311fdf6f8ae3b81d265850c748c842587678d17170dbb6252943575e534ba350aab94d99",
                "924dcbebd858bc228bbb543c5ddf04ed2198090dc5d6c9082f885d2abaf6a3225a0bec8ae5cb81ee",
                "9a3eebcb362de83958c359bcf9616cd050023af67ce6bfa39da03f38ca4bce9b625d458a9290c586",
                "dcdc40d0fe285cc8740c7ea3e67f88bae119a7b99f48280a208bff3410f59672",
            ),
            concat!(
                "6f3eecaaa716c8e73a7c8b0b63386ca393f330a4fb261ba8f50c5c306bbb58028e02d646d8dc5386",
                "7e86e0e9ebdc34537b78e525403b5a1500",
            ),
            concat!(
                "e8fc8f1665c580810bad922669e14889932a258a4fff96c04ea32c8c543f5721763892fc8ec1f9ad",
                "87aad900b3dfa301dc1bae2ea9800689802a1dccfb85826bba4069ace6d3f9b9f0eff80c430ad6f0",
                "6af542d1c53a0e9a0653618fd540c46d5c29c3d24226f543606179c9e7afea592000",
            ),
        ),
    ];

    // (row of ED448_KATS, signature, whether the prototype's Ed448 verification accepts it
    // under that row's key, context and message)
    const VERIFY_KATS: &[(usize, &str, bool)] = &[
        (
            0,
            concat!(
                "78cd8fb5ea1e644a1e23dc9ea77acf076a58ffdab4bf9da1998e7d3240c64d2564ec98638e778c5a",
                "17bd9cb30a2c757e401b2c9ea5a8ed50003619f3816a2eee53c1ff1a73eee7411973e62e1ab4f9a4",
                "56fe581e481fc73949f7de0a934dc6605d0fb2bf4fa2018c7c3a704ce0b519fb1b00",
            ),
            true,
        ),
        (
            0,
            concat!(
                "78cd8fb5ea1e644a1e23dc9ea77acf076a58ffdab4bf9da1998e7d3240c66d2564ec98638e778c5a",
                "17bd9cb30a2c757e401b2c9ea5a8ed50003619f3816a2eee53c1ff1a73eee7411973e62e1ab4f9a4",
                "56fe581e481fc73949f7de0a934dc6605d0fb2bf4fa2018c7c3a704ce0b519fb1b00",
            ),
            false,
        ),
        (
            0,
            concat!(
                "78cd8fb5ea1e644a1e23dc9ea77acf076a58ffdab4bf9da1998e7d3240c64d2564ec98638e778c5a",
                "17bd9cb30a2c757e401b2c9ea5a8ed50003619f3816a2eee53c1ff1a73eee7411973e62e1ab4f9a4",
                "56fe581c481fc73949f7de0a934dc6605d0fb2bf4fa2018c7c3a704ce0b519fb1b00",
            ),
            false,
        ),
        (
            0,
            concat!(
                "78cd8fb5ea1e644a1e23dc9ea77acf076a58ffdab4bf9da1998e7d3240c64d2564ec98638e778c5a",
                "17bd9cb30a2c75fe401b2c9ea5a8ed50003619f3816a2eee53c1ff1a73eee7411973e62e1ab4f9a4",
                "56fe581e481fc73949f7de0a934dc6605d0fb2bf4fa2018c7c3a704ce0b519fb1b00",
            ),
            false,
        ),
        (
            0,
            concat!(
                "78cd8fb5ea1e644a1e23dc9ea77acf076a58ffdab4bf9da1998e7d3240c64d2564ec98638e778c5a",
                "17bd9cb30a2c757e401b2c9ea5a8ed5000295e4b2dfdf06677168fe00061aaae3a031d05c9fdd4f3",
                "1ae87ce8c41ec73949f7de0a934dc6605d0fb2bf4fa2018c7c3a704ce0b519fb5b00",
            ),
            false,
        ),
        (
            0,
            concat!(
                "78cd8fb5ea1e644a1e23dc9ea77acf076a58ffdab4bf9da1998e7d3240c64d2564ec98638e778c5a",
                "17bd9cb30a2c757e401b2c9ea5a8ed5000f34458ab92c27823558fc58d72c26c219036d6ae49db4e",
                "c4e923ca7cffffffffffffffffffffffffffffffffffffffffffffffffffffff3f00",
            ),
            false,
        ),
        (
            0,
            concat!(
                "78cd8fb5ea1e644a1e23dc9ea77acf076a58ffdab4bf9da1998e7d3240c64d2564ec98638e778c5a",
                "17bd9cb30a2c757e401b2c9ea5a8ed5000f24458ab92c27823558fc58d72c26c219036d6ae49db4e",
                "c4e923ca7cffffffffffffffffffffffffffffffffffffffffffffffffffffff3f00",
            ),
            false,
        ),
        (
            0,
            concat!(
                "78cd8fb5ea1e644a1e23dc9ea77acf076a58ffdab4bf9da1998e7d3240c64d2564ec98638e778c5a",
                "17bd9cb30a2c757e401b2c9ea5a8ed50003619f3816a2eee53c1ff1a73eee7411973e62e1ab4f9a4",
                "56fe581e481fc73949f7de0a934dc6605d0fb2bf4fa2018c7c3a704ce0b519fb1b01",
            ),
            false,
        ),
        (
            1,
            concat!(
                "a4da4677fb89755c4e617a1095a816a82f3feae947115d62705722bedf5f62730d08b8e8e93c4fc1",
                "faa4529c1f97f3fe382b8cfc77d4ba1d807304f5e65460ba79b6ad8b34fc9d2f111b405890d633a0",
                "53e53bfbc8955e8b2916c2483a9a40af39df0c39fb129e2f503f379e6887f9081f00",
            ),
            true,
        ),
        (
            1,
            concat!(
                "a4da4677fb89755c4e617a1095a816a82f3feae947115d62705722bedf5f62730d08b8e8e93c4fc1",
                "faa4529c1f97f3fe382f8cfc77d4ba1d807304f5e65460ba79b6ad8b34fc9d2f111b405890d633a0",
                "53e53bfbc8955e8b2916c2483a9a40af39df0c39fb129e2f503f379e6887f9081f00",
            ),
            false,
        ),
        (
            1,
            concat!(
                "a4da4677fb89755c4e617a1095a816a82f3feae947115d62705722bedf5f62730d08b8e8e93c4fc1",
                "faa4529c1f97f3fe382b8cfc77d4ba1d807304f5e65460ba79b6ad8b34fc9d2f111b405890d623a0",
                "53e53bfbc8955e8b2916c2483a9a40af39df0c39fb129e2f503f379e6887f9081f00",
            ),
            false,
        ),
        (
            1,
            concat!(
                "a4da4677fb89755c4e617a1095a816a82f3feae947115d62705722bedf5f62730d08b8e8e93c4fc1",
                "faa4529c1f97f3fe382b8cfc77d4ba1d807304f5e65460ba79b6ad8b34fc9d2f111b405810d633a0",
                "53e53bfbc8955e8b2916c2483a9a40af39df0c39fb129e2f503f379e6887f9081f00",
            ),
            false,
        ),
        (
            1,
            concat!(
                "a4da4677fb89755c4e617a1095a816a82f3feae947115d62705722bedf5f62730d08b8e8e93c4fc1",
                "faa4529c1f97f3fe382b8cfc77d4ba1d8066494d92e722339d0b3d51c26e609c32ab762e3f200fef",
                "17cf5fc545955e8b2916c2483a9a40af39df0c39fb129e2f503f379e6887f9085f00",
            ),
            false,
        ),
        (
            1,
            concat!(
                "a4da4677fb89755c4e617a1095a816a82f3feae947115d62705722bedf5f62730d08b8e8e93c4fc1",
                "faa4529c1f97f3fe382b8cfc77d4ba1d80f34458ab92c27823558fc58d72c26c219036d6ae49db4e",
                "c4e923ca7cffffffffffffffffffffffffffffffffffffffffffffffffffffff3f00",
            ),
            false,
        ),
        (
            1,
            concat!(
                "a4da4677fb89755c4e617a1095a816a82f3feae947115d62705722bedf5f62730d08b8e8e93c4fc1",
                "faa4529c1f97f3fe382b8cfc77d4ba1d80f24458ab92c27823558fc58d72c26c219036d6ae49db4e",
                "c4e923ca7cffffffffffffffffffffffffffffffffffffffffffffffffffffff3f00",
            ),
            false,
        ),
        (
            1,
            concat!(
                "a4da4677fb89755c4e617a1095a816a82f3feae947115d62705722bedf5f62730d08b8e8e93c4fc1",
                "faa4529c1f97f3fe382b8cfc77d4ba1d807304f5e65460ba79b6ad8b34fc9d2f111b405890d633a0",
                "53e53bfbc8955e8b2916c2483a9a40af39df0c39fb129e2f503f379e6887f9081f01",
            ),
            false,
        ),
        (
            2,
            concat!(
                "daef3291f541365bfc87b6f95a06230b42b82ab8f036a9c722fc32f4e03b6926aa7ae4dd329e426f",
                "719e2a0cc7f85949abf0193edc5ab14300e93c4864a7dbd18069f02db1205b8d649cc10f1e55211a",
                "ff23162e34c82296e9d2761aa560bef6cd43fc989230956801af3d550fed4b403a00",
            ),
            true,
        ),
        (
            2,
            concat!(
                "daef3291f541265bfc87b6f95a06230b42b82ab8f036a9c722fc32f4e03b6926aa7ae4dd329e426f",
                "719e2a0cc7f85949abf0193edc5ab14300e93c4864a7dbd18069f02db1205b8d649cc10f1e55211a",
                "ff23162e34c82296e9d2761aa560bef6cd43fc989230956801af3d550fed4b403a00",
            ),
            false,
        ),
        (
            2,
            concat!(
                "daef3291f541365bfc87b6f95a06230b42b82ab8f036a9c722fc3274e03b6926aa7ae4dd329e426f",
                "719e2a0cc7f85949abf0193edc5ab14300e93c4864a7dbd18069f02db1205b8d649cc10f1e55211a",
                "ff23162e34c82296e9d2761aa560bef6cd43fc989230956801af3d550fed4b403a00",
            ),
            false,
        ),
        (
            2,
            concat!(
                "daef3291f541365bfc87b6f95a06230b42b82ab8f036a9c722fc32f4e03b6926aa7ae4dd329e426f",
                "711e2a0cc7f85949abf0193edc5ab14300e93c4864a7dbd18069f02db1205b8d649cc10f1e55211a",
                "ff23162e34c82296e9d2761aa560bef6cd43fc989230956801af3d550fed4b403a00",
            ),
            false,
        ),
        (
            2,
            concat!(
                "daef3291f541365bfc87b6f95a06230b42b82ab8f036a9c722fc32f4e03b6926aa7ae4dd329e426f",
                "719e2a0cc7f85949abf0193edc5ab14300dc81a00f3a9e4aa4be7ff33e931dfa852cf8e5cc9efc68",
                "c30d3af8b0c72296e9d2761aa560bef6cd43fc989230956801af3d550fed4b407a00",
            ),
            false,
        ),
        (
            2,
            concat!(
                "daef3291f541365bfc87b6f95a06230b42b82ab8f036a9c722fc32f4e03b6926aa7ae4dd329e426f",
                "719e2a0cc7f85949abf0193edc5ab14300f34458ab92c27823558fc58d72c26c219036d6ae49db4e",
                "c4e923ca7cffffffffffffffffffffffffffffffffffffffffffffffffffffff3f00",
            ),
            false,
        ),
        (
            2,
            concat!(
                "daef3291f541365bfc87b6f95a06230b42b82ab8f036a9c722fc32f4e03b6926aa7ae4dd329e426f",
                "719e2a0cc7f85949abf0193edc5ab14300f24458ab92c27823558fc58d72c26c219036d6ae49db4e",
                "c4e923ca7cffffffffffffffffffffffffffffffffffffffffffffffffffffff3f00",
            ),
            false,
        ),
        (
            2,
            concat!(
                "daef3291f541365bfc87b6f95a06230b42b82ab8f036a9c722fc32f4e03b6926aa7ae4dd329e426f",
                "719e2a0cc7f85949abf0193edc5ab14300e93c4864a7dbd18069f02db1205b8d649cc10f1e55211a",
                "ff23162e34c82296e9d2761aa560bef6cd43fc989230956801af3d550fed4b403a01",
            ),
            false,
        ),
        (
            3,
            concat!(
                "362db12ac9bffe4f8ab69fe90aa86d01324db6a8ed0b1f94f47f8686806cf4bb8cb123cbb322d7c2",
                "e4c16c23fafaa86cd5452a9c44c809d9808fada825b10e4e115f94e758cda33d3f3444c480e64651",
                "8603ec4b04525808359706989a34322e05a3792886f3d726e2288af201b4b2c93700",
            ),
            true,
        ),
        (
            3,
            concat!(
                "362db12ac9bffe4f8ab6bfe90aa86d01324db6a8ed0b1f94f47f8686806cf4bb8cb123cbb322d7c2",
                "e4c16c23fafaa86cd5452a9c44c809d9808fada825b10e4e115f94e758cda33d3f3444c480e64651",
                "8603ec4b04525808359706989a34322e05a3792886f3d726e2288af201b4b2c93700",
            ),
            false,
        ),
        (
            3,
            concat!(
                "362db12ac9bffe4f8ab69fe90aa86d01324db6a8ed0b1f94f47f8686806cf4bb8cb123cbb322d7c2",
                "e4c16c23fafaa86cd5452a9c44c809d9808fada825b10e4e115f94e758cda33d3f3444c480e64651",
                "8603ec4b04525808359706989a34322e05a3792886f3d726e2288af201b4b0c93700",
            ),
            false,
        ),
        (
            3,
            concat!(
                "362db12ac9bffe4f8ab69fe90aa86d01324db6a8ed0b1f94f47f8686806cf4bb8cb123dbb322d7c2",
                "e4c16c23fafaa86cd5452a9c44c809d9808fada825b10e4e115f94e758cda33d3f3444c480e64651",
                "8603ec4b04525808359706989a34322e05a3792886f3d726e2288af201b4b2c93700",
            ),
            false,
        ),
        (
            3,
            concat!(
                "362db12ac9bffe4f8ab69fe90aa86d01324db6a8ed0b1f94f47f8686806cf4bb8cb123cbb322d7c2",
                "e4c16c23fafaa86cd5452a9c44c809d98082f200d143d1c634b423ade63f66aa60c47a9a2f3022a0",
                "4aed0f1681515808359706989a34322e05a3792886f3d726e2288af201b4b2c97700",
            ),
            false,
        ),
        (
            3,
            concat!(
                "362db12ac9bffe4f8ab69fe90aa86d01324db6a8ed0b1f94f47f8686806cf4bb8cb123cbb322d7c2",
                "e4c16c23fafaa86cd5452a9c44c809d980f34458ab92c27823558fc58d72c26c219036d6ae49db4e",
                "c4e923ca7cffffffffffffffffffffffffffffffffffffffffffffffffffffff3f00",
            ),
            false,
        ),
        (
            3,
            concat!(
                "362db12ac9bffe4f8ab69fe90aa86d01324db6a8ed0b1f94f47f8686806cf4bb8cb123cbb322d7c2",
                "e4c16c23fafaa86cd5452a9c44c809d980f24458ab92c27823558fc58d72c26c219036d6ae49db4e",
                "c4e923ca7cffffffffffffffffffffffffffffffffffffffffffffffffffffff3f00",
            ),
            false,
        ),
        (
            3,
            concat!(
                "362db12ac9bffe4f8ab69fe90aa86d01324db6a8ed0b1f94f47f8686806cf4bb8cb123cbb322d7c2",
                "e4c16c23fafaa86cd5452a9c44c809d9808fada825b10e4e115f94e758cda33d3f3444c480e64651",
                "8603ec4b04525808359706989a34322e05a3792886f3d726e2288af201b4b2c93701",
            ),
            false,
        ),
        (
            4,
            concat!(
                "ece345a3504d6d954f2faabb80ba2539b8408ed40a2aafec6875f8bfc2fdf7187a3bc09916197cae",
                "34d9e47bb399434d1d4798e3eb3a1aaa80a1bf331c863fb4f09366c35fa39a109595d68db8c2b730",
                "04597c4639b1790ce1185bfe54e42d76042b9ca662b2d9b21faea46ad99186520300",
            ),
            true,
        ),
        (
            4,
            concat!(
                "ece345a3504d6d954f2faabb80ba2539b8408ed40a2aafec6875f8bfc2fdf7187a3bc09916197cae",
                "34d9e47bb399434d1d4798e3eb3a1aaa80a1bf331c863fb4f09366c35fa39a109595d68db8c2b730",
                "04597c4639b1790ce1185bfe54e42d76042b9ca662b2d9b21faea468d99186520300",
            ),
            false,
        ),
        (
            4,
            concat!(
                "ece345a3504d6d954f2faabb80ba2539b840aed40a2aafec6875f8bfc2fdf7187a3bc09916197cae",
                "34d9e47bb399434d1d4798e3eb3a1aaa80a1bf331c863fb4f09366c35fa39a109595d68db8c2b730",
                "04597c4639b1790ce1185bfe54e42d76042b9ca662b2d9b21faea46ad99186520300",
            ),
            false,
        ),
        (
            4,
            concat!(
                "ece345a3514d6d954f2faabb80ba2539b8408ed40a2aafec6875f8bfc2fdf7187a3bc09916197cae",
                "34d9e47bb399434d1d4798e3eb3a1aaa80a1bf331c863fb4f09366c35fa39a109595d68db8c2b730",
                "04597c4639b1790ce1185bfe54e42d76042b9ca662b2d9b21faea46ad99186520300",
            ),
            false,
        ),
        (
            4,
            concat!(
                "ece345a3504d6d954f2faabb80ba2539b8408ed40a2aafec6875f8bfc2fdf7187a3bc09916197cae",
                "34d9e47bb399434d1d4798e3eb3a1aaa8094048cc718022d14e9f588ed155d7db6250d64670c937f",
                "c842a010b6b0790ce1185bfe54e42d76042b9ca662b2d9b21faea46ad99186524300",
            ),
            false,
        ),
        (
            4,
            concat!(
                "ece345a3504d6d954f2faabb80ba2539b8408ed40a2aafec6875f8bfc2fdf7187a3bc09916197cae",
                "34d9e47bb399434d1d4798e3eb3a1aaa80f34458ab92c27823558fc58d72c26c219036d6ae49db4e",
                "c4e923ca7cffffffffffffffffffffffffffffffffffffffffffffffffffffff3f00",
            ),
            false,
        ),
        (
            4,
            concat!(
                "ece345a3504d6d954f2faabb80ba2539b8408ed40a2aafec6875f8bfc2fdf7187a3bc09916197cae",
                "34d9e47bb399434d1d4798e3eb3a1aaa80f24458ab92c27823558fc58d72c26c219036d6ae49db4e",
                "c4e923ca7cffffffffffffffffffffffffffffffffffffffffffffffffffffff3f00",
            ),
            false,
        ),
        (
            4,
            concat!(
                "ece345a3504d6d954f2faabb80ba2539b8408ed40a2aafec6875f8bfc2fdf7187a3bc09916197cae",
                "34d9e47bb399434d1d4798e3eb3a1aaa80a1bf331c863fb4f09366c35fa39a109595d68db8c2b730",
                "04597c4639b1790ce1185bfe54e42d76042b9ca662b2d9b21faea46ad99186520301",
            ),
            false,
        ),
        (
            5,
            concat!(
                "8c72a6b3f1d632dfc5a3b45cfccd5bb73dc94cbc714c30a7c53fb7a5fc8323626c8fca27f134f193",
                "c8b546b7fb2abb0ed5a538c1717296828039996be433bf1ac1d80c63afaa0194928429e1e97e01b3",
                "21dd4602aa90b88b5bff7b34b9473eede17a99b0afa941302e8a00268d407f351400",
            ),
            true,
        ),
        (
            5,
            concat!(
                "8c72a6b3f1d632dfc5a3b45cfccd5bb73dc94cbc714c30a7c53fb7a5fc8323626c8fca27f134f193",
                "c8b546b7fb2aab0ed5a538c1717296828039996be433bf1ac1d80c63afaa0194928429e1e97e01b3",
                "21dd4602aa90b88b5bff7b34b9473eede17a99b0afa941302e8a00268d407f351400",
            ),
            false,
        ),
        (
            5,
            concat!(
                "8c72a6b3f1d632dfc5a3b45cfccd5bb73dc94cbc714c30a7c53fb7a5fc8323626c8fca27f134f193",
                "c8b546b7fb2abb0ed5a538c1717296828039996be433bf1ac1d81c63afaa0194928429e1e97e01b3",
                "21dd4602aa90b88b5bff7b34b9473eede17a99b0afa941302e8a00268d407f351400",
            ),
            false,
        ),
        (
            5,
            concat!(
                "8c72a6b3f1d632dfc5a3b45cfccd5bb73dc94cbc714c30a7c53fb7a5fc8323626c8fca27f134f193",
                "c8b546b7fb2abb0ed5a538c1717286828039996be433bf1ac1d80c63afaa0194928429e1e97e01b3",
                "21dd4602aa90b88b5bff7b34b9473eede17a99b0afa941302e8a00268d407f351400",
            ),
            false,
        ),
        (
            5,
            concat!(
                "8c72a6b3f1d632dfc5a3b45cfccd5bb73dc94cbc714c30a7c53fb7a5fc8323626c8fca27f134f193",
                "c8b546b7fb2abb0ed5a538c171729682802cdec38fc68193e42d9c283d1dc400b41460b798c8dc01",
                "e6c66acc2690b88b5bff7b34b9473eede17a99b0afa941302e8a00268d407f355400",
            ),
            false,
        ),
        (
            5,
            concat!(
                "8c72a6b3f1d632dfc5a3b45cfccd5bb73dc94cbc714c30a7c53fb7a5fc8323626c8fca27f134f193",
                "c8b546b7fb2abb0ed5a538c17172968280f34458ab92c27823558fc58d72c26c219036d6ae49db4e",
                "c4e923ca7cffffffffffffffffffffffffffffffffffffffffffffffffffffff3f00",
            ),
            false,
        ),
        (
            5,
            concat!(
                "8c72a6b3f1d632dfc5a3b45cfccd5bb73dc94cbc714c30a7c53fb7a5fc8323626c8fca27f134f193",
                "c8b546b7fb2abb0ed5a538c17172968280f24458ab92c27823558fc58d72c26c219036d6ae49db4e",
                "c4e923ca7cffffffffffffffffffffffffffffffffffffffffffffffffffffff3f00",
            ),
            false,
        ),
        (
            5,
            concat!(
                "8c72a6b3f1d632dfc5a3b45cfccd5bb73dc94cbc714c30a7c53fb7a5fc8323626c8fca27f134f193",
                "c8b546b7fb2abb0ed5a538c1717296828039996be433bf1ac1d80c63afaa0194928429e1e97e01b3",
                "21dd4602aa90b88b5bff7b34b9473eede17a99b0afa941302e8a00268d407f351401",
            ),
            false,
        ),
    ];

    fn octets<const N: usize>(hex: &str) -> [u8; N] {
        bouncycastle_core::hex::decode(hex).unwrap().try_into().unwrap()
    }

    fn bytes(hex: &str) -> Vec<u8> {
        bouncycastle_core::hex::decode(hex).unwrap()
    }

    /// PH(M) of Ed448ph: SHAKE256(M, 64).
    fn shake256_64(m: &[u8]) -> [u8; PREHASH_LEN] {
        let mut digest = [0_u8; PREHASH_LEN];
        let mut hash = SHAKE256::new();
        hash.do_update(m);
        hash.into_squeezer().do_output_out(&mut digest);
        digest
    }

    /// The expanded key and the public key of a private key.
    fn key_pair(sk: &[u8; PRIVATE_KEY_LEN]) -> (ExpandedKey, [u8; PUBLIC_KEY_LEN]) {
        let mut key = ExpandedKey::zeroized();
        key.expand(sk).unwrap();
        let pk = *key.public_key();
        (key, pk)
    }

    /// L as an encoded scalar.
    fn order() -> [u8; SCALAR_LEN] {
        let mut l = [0_u8; SCALAR_LEN];
        for (chunk, limb) in l.chunks_mut(8).zip(scalar::L) {
            chunk.copy_from_slice(&limb.to_le_bytes());
        }
        l
    }

    const FAILED: Result<(), SignatureError> = Err(SignatureError::SignatureVerificationFailed);

    /// Key generation, signing and verification on one Ed448 vector.
    fn check_ed448(name: &str, sk: &str, context: &str, pk: &str, m: &str, sig: &str) {
        let (key, public) = key_pair(&octets(sk));
        assert_eq!(public, octets::<PUBLIC_KEY_LEN>(pk), "{name}");
        let (context, m) = (bytes(context), bytes(m));
        let mut signature = [0xA5_u8; SIGNATURE_LEN];
        sign(&key, &context, &m, &mut signature).unwrap();
        assert_eq!(signature, octets::<SIGNATURE_LEN>(sig), "{name}");

        let point = PublicPoint::decode_var(&public).unwrap();
        assert_eq!(verify(&signature, &point, &context, &m), Ok(()), "{name}");
        // The key's own point is the same key.
        let own = key.public_point().unwrap();
        assert_eq!(verify(&signature, &own, &context, &m), Ok(()), "{name}");
    }

    /// The same on one Ed448ph vector.
    fn check_ed448ph(name: &str, sk: &str, context: &str, pk: &str, m: &str, sig: &str) {
        let (key, public) = key_pair(&octets(sk));
        assert_eq!(public, octets::<PUBLIC_KEY_LEN>(pk), "{name}");
        let (context, prehash) = (bytes(context), shake256_64(&bytes(m)));
        let mut signature = [0xA5_u8; SIGNATURE_LEN];
        sign_ph(&key, &context, &prehash, &mut signature).unwrap();
        assert_eq!(signature, octets::<SIGNATURE_LEN>(sig), "{name}");

        let point = PublicPoint::decode_var(&public).unwrap();
        assert_eq!(verify_ph(&signature, &point, &context, &prehash), Ok(()), "{name}");
    }

    #[test]
    fn the_lengths_are_those_of_the_rfc() {
        assert_eq!((PRIVATE_KEY_LEN, PUBLIC_KEY_LEN, SIGNATURE_LEN), (57, 57, 114));
        assert_eq!((PREHASH_LEN, CONTEXT_MAX_LEN, DIGEST_LEN), (64, 255, 114));
    }

    #[test]
    fn rfc_8032_vectors() {
        assert_eq!((RFC8032_ED448.len(), RFC8032_ED448PH.len()), (9, 2));
        for (name, sk, pk, m, context, sig) in RFC8032_ED448 {
            check_ed448(name, sk, context, pk, m, sig);
        }
        for (name, sk, pk, m, context, sig) in RFC8032_ED448PH {
            check_ed448ph(name, sk, context, pk, m, sig);
        }
    }

    #[test]
    fn signatures_match_the_prototype() {
        for (sk, context, m, pk, sig) in ED448_KATS {
            check_ed448(sk, sk, context, pk, m, sig);
        }
        for (sk, context, m, pk, sig) in ED448PH_KATS {
            check_ed448ph(sk, sk, context, pk, m, sig);
        }
    }

    /// Altered signatures get the prototype's verdict: accepted as signed, refused with a bit
    /// changed, with L added to S, and with S replaced by L, by L - 1 or by 2^448 + S.
    #[test]
    fn verification_verdicts_match_the_prototype() {
        let mut accepted = 0;
        for (row, sig, verdict) in VERIFY_KATS {
            let (_, context, m, pk, _) = ED448_KATS[*row];
            let point = PublicPoint::decode_var(&octets(pk)).unwrap();
            let result = verify(&octets(sig), &point, &bytes(context), &bytes(m));
            assert_eq!(result, if *verdict { Ok(()) } else { FAILED }, "{sig}");
            accepted += *verdict as usize;
        }
        assert_eq!((VERIFY_KATS.len(), accepted), (48, 6));
    }

    /// RFC 8032 Section 5.2.5, step 2, on the scalars of the vectors: among them the unpruned
    /// digests differ in each of the two low bits and in the top bit of octet 55, and octet
    /// 56 is not zero.
    #[test]
    fn the_secret_scalar_is_pruned() {
        let mut seen_clear = [0xFF_u8; 2];
        let mut seen_set = [0_u8; 3];
        for (sk, ..) in ED448_KATS {
            let mut digest = [0_u8; DIGEST_LEN];
            let mut hash = SHAKE256::new();
            hash.do_update(&octets::<PRIVATE_KEY_LEN>(sk));
            hash.into_squeezer().do_output_out(&mut digest);
            seen_clear[0] &= digest[0];
            seen_clear[1] &= digest[55];
            seen_set[0] |= digest[0];
            seen_set[1] |= digest[55];
            seen_set[2] |= digest[56];

            let (key, _) = key_pair(&octets(sk));
            assert_eq!(key.s[0], digest[0] & 0xFC);
            assert_eq!(key.s[1..55], digest[1..55]);
            assert_eq!(key.s[55], digest[55] | 0x80);
            assert_eq!(key.s[56], 0);
            assert_eq!(*key.prefix, digest[57..]);
        }
        // Each pruned bit was seen both set and clear before pruning.
        assert_eq!((seen_clear[0] & 0x03, seen_clear[1] & 0x80), (0, 0));
        assert_eq!((seen_set[0] & 0x03, seen_set[1] & 0x80, seen_set[2]), (0x03, 0x80, 0xFF));
    }

    /// An unfilled key is all zero and has no point; `expand` fills it, `copy_from` copies
    /// it and `clear` empties it again.
    #[test]
    fn the_expanded_key_is_filled_copied_and_cleared() {
        let mut key = ExpandedKey::zeroized();
        assert!(!key.is_filled());
        assert!(key.public_point().is_none());
        assert_eq!((*key.s, *key.prefix, key.A), ([0; 57], [0; 57], [0; 57]));

        let (sk, _, _, pk, _) = ED448_KATS[3];
        key.expand(&octets(sk)).unwrap();
        assert!(key.is_filled());
        assert_eq!(*key.public_key(), octets::<PUBLIC_KEY_LEN>(pk));
        let mut encoded = [0_u8; PUBLIC_KEY_LEN];
        key.public_point().unwrap().encode(&mut encoded);
        assert_eq!(encoded, octets::<PUBLIC_KEY_LEN>(pk));

        let mut copy = ExpandedKey::zeroized();
        copy.copy_from(&key);
        assert_eq!((*copy.s, *copy.prefix, copy.A), (*key.s, *key.prefix, key.A));
        assert!(copy.is_filled());

        key.clear();
        assert!(!key.is_filled());
        assert_eq!((*key.s, *key.prefix, key.A), ([0; 57], [0; 57], [0; 57]));
        // The copy is its own.
        assert!(copy.is_filled());
    }

    /// The one pruned scalar that is a multiple of L, 4 L, has the neutral element for its
    /// public key and is refused, the key left unfilled; its neighbours 4 L - 4 and 4 L + 4
    /// are ordinary keys. No private key is known to prune to 4 L, so the scalar is put in
    /// place directly and the public key derived from there.
    #[test]
    fn the_scalar_4l_is_refused() {
        // 4 L, by adding L to itself twice over.
        let mut four_l = order();
        for _ in 0..2 {
            let mut carry = 0_u16;
            for octet in &mut four_l {
                carry += 2 * *octet as u16;
                *octet = carry as u8;
                carry >>= 8;
            }
            assert_eq!(carry, 0);
        }
        // It is a pruned scalar: a multiple of 4 with bit 447 set and nothing above.
        assert_eq!((four_l[0] & 0x03, four_l[55] & 0x80, four_l[56]), (0, 0x80, 0));

        let mut key = ExpandedKey::zeroized();
        key.s.copy_from_slice(&four_l);
        key.prefix.fill(0x11);
        assert!(matches!(key.fill_public_key(), Err(SignatureError::KeyGenError(_))));
        assert!(!key.is_filled());
        assert_eq!((*key.s, *key.prefix, key.A), ([0; 57], [0; 57], [0; 57]));

        for (neighbour, name) in [(four_l[0] - 4, "4 L - 4"), (four_l[0] + 4, "4 L + 4")] {
            let mut key = ExpandedKey::zeroized();
            key.s.copy_from_slice(&four_l);
            key.s[0] = neighbour;
            assert_eq!(key.fill_public_key(), Ok(()), "{name}");
            assert!(key.is_filled() && key.public_point().is_some(), "{name}");
            assert_ne!(key.A, NEUTRAL_ELEMENT, "{name}");
        }
        assert_eq!(NEUTRAL_ELEMENT[0], 1);
        assert_eq!(NEUTRAL_ELEMENT[1..], [0; 56]);
    }

    /// Any one bit changed in the signature, the message, the context or the key makes
    /// verification fail, as does the right signature under the other algorithm.
    #[test]
    fn verification_fails_on_any_change() {
        let (sk, context, m, ..) = ED448_KATS[4];
        let (key, public) = key_pair(&octets(sk));
        let point = PublicPoint::decode_var(&public).unwrap();
        let (context, m) = (bytes(context), bytes(m));
        assert!(!context.is_empty() && !m.is_empty());
        let mut signature = [0_u8; SIGNATURE_LEN];
        sign(&key, &context, &m, &mut signature).unwrap();
        assert_eq!(verify(&signature, &point, &context, &m), Ok(()));

        for bit in 0..8 * SIGNATURE_LEN {
            let mut changed = signature;
            changed[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(verify(&changed, &point, &context, &m), FAILED, "signature bit {bit}");
        }
        for bit in 0..8 * m.len() {
            let mut changed = m.clone();
            changed[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(verify(&signature, &point, &context, &changed), FAILED, "message {bit}");
        }
        assert_eq!(verify(&signature, &point, &context, &m[..m.len() - 1]), FAILED);
        for bit in 0..8 * context.len() {
            let mut changed = context.clone();
            changed[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(verify(&signature, &point, &changed, &m), FAILED, "context bit {bit}");
        }
        assert_eq!(verify(&signature, &point, &context[..context.len() - 1], &m), FAILED);
        assert_eq!(verify(&signature, &point, b"", &m), FAILED);
        // The context is not the start of the message.
        let joined = [&context[..], &m[..]].concat();
        assert_eq!(verify(&signature, &point, b"", &joined), FAILED);

        // Another key.
        let (_, other) = key_pair(&octets(ED448_KATS[5].0));
        let other = PublicPoint::decode_var(&other).unwrap();
        assert_eq!(verify(&signature, &other, &context, &m), FAILED);

        // The algorithm is bound: dom4's flag separates Ed448 on a 64-octet message from
        // Ed448ph on that pre-hash.
        let prehash = shake256_64(&m);
        sign_ph(&key, &context, &prehash, &mut signature).unwrap();
        assert_eq!(verify_ph(&signature, &point, &context, &prehash), Ok(()));
        assert_eq!(verify_ph(&signature, &point, b"", &prehash), FAILED);
        assert_eq!(verify(&signature, &point, &context, &prehash), FAILED);
        sign(&key, &context, &prehash, &mut signature).unwrap();
        assert_eq!(verify(&signature, &point, &context, &prehash), Ok(()));
        assert_eq!(verify_ph(&signature, &point, &context, &prehash), FAILED);
    }

    /// RFC 8032 Section 5.2: contexts of 0, 1 and 255 octets give the signatures of the RFC's
    /// own Python library; 256 octets is refused by both operations of both algorithms before
    /// anything else, and the signature buffer is cleared.
    #[test]
    fn the_context_is_at_most_255_octets() {
        let (key, public) = key_pair(&octets(GENERATED_SK));
        let point = PublicPoint::decode_var(&public).unwrap();
        let prehash = shake256_64(b"abc");
        assert_eq!(public, octets::<PUBLIC_KEY_LEN>(GENERATED_PK));

        let mut lengths = Vec::new();
        for (ph, context, sig) in CONTEXT_KATS {
            let context = bytes(context);
            let mut signature = [0xA5_u8; SIGNATURE_LEN];
            if *ph {
                sign_ph(&key, &context, &prehash, &mut signature).unwrap();
                assert_eq!(verify_ph(&signature, &point, &context, &prehash), Ok(()));
            } else {
                sign(&key, &context, b"abc", &mut signature).unwrap();
                assert_eq!(verify(&signature, &point, &context, b"abc"), Ok(()));
            }
            assert_eq!(signature, octets::<SIGNATURE_LEN>(sig), "{ph} {}", context.len());
            lengths.push((*ph, context.len()));
        }
        assert_eq!(
            lengths,
            [(false, 0), (false, 1), (false, 255), (true, 0), (true, 1), (true, 255)]
        );

        let context = [0x5A_u8; CONTEXT_MAX_LEN + 1];
        assert_eq!(check_context(&context[..CONTEXT_MAX_LEN]), Ok(()));
        let too_long = |result: Result<(), SignatureError>| {
            matches!(result, Err(SignatureError::LengthError(_)))
        };
        assert!(too_long(check_context(&context)));

        let mut signature = [0xA5_u8; SIGNATURE_LEN];
        sign(&key, &context[..CONTEXT_MAX_LEN], b"abc", &mut signature).unwrap();
        let good = signature;
        assert!(too_long(verify(&good, &point, &context, b"abc")));
        assert!(too_long(verify_ph(&good, &point, &context, &prehash)));
        assert!(too_long(sign(&key, &context, b"abc", &mut signature)));
        assert_eq!(signature, [0; SIGNATURE_LEN]);
        signature = [0xA5; SIGNATURE_LEN];
        assert!(too_long(sign_ph(&key, &context, &prehash, &mut signature)));
        assert_eq!(signature, [0; SIGNATURE_LEN]);
    }

    /// RFC 8032 Section 5.2.7, step 1: "If any of the decodings fail (including S being out
    /// of range), the signature is invalid", for values of S that would satisfy the group
    /// equation if they were reduced first.
    #[test]
    fn verification_rejects_s_out_of_range() {
        let (key, public) = key_pair(&[9; PRIVATE_KEY_LEN]);
        let point = PublicPoint::decode_var(&public).unwrap();
        let m = b"message";
        let mut signature = [0_u8; SIGNATURE_LEN];
        sign(&key, b"", m, &mut signature).unwrap();
        assert_eq!(verify(&signature, &point, b"", m), Ok(()));
        let l = order();

        // S + j L for j = 1, 2, 3: each is S mod L and fits the 56 octets the limbs read.
        let mut malleated = signature;
        for j in 1..=3 {
            let mut carry = 0_u16;
            for (s, l) in malleated[POINT_LEN..].iter_mut().zip(l) {
                carry += *s as u16 + l as u16;
                *s = carry as u8;
                carry >>= 8;
            }
            assert_eq!(carry, 0);
            assert_eq!(malleated[SIGNATURE_LEN - 1], 0);
            assert_eq!(verify(&malleated, &point, b"", m), FAILED, "S + {j} L");
        }

        // 2^448 + S: the limbs hold S, and the last octet the rest.
        let mut high = signature;
        high[SIGNATURE_LEN - 1] = 1;
        assert_eq!(verify(&high, &point, b"", m), FAILED);
        high[SIGNATURE_LEN - 1] = 0x80;
        assert_eq!(verify(&high, &point, b"", m), FAILED);

        // S = L, and L - 1, which is in range and wrong.
        let mut s_is_l = signature;
        s_is_l[POINT_LEN..].copy_from_slice(&l);
        assert_eq!(verify(&s_is_l, &point, b"", m), FAILED);
        s_is_l[POINT_LEN] -= 1;
        assert_eq!(verify(&s_is_l, &point, b"", m), FAILED);
    }

    /// Verification is cofactored (RFC 8032 Section 5.2.7, step 3, the first equation): a
    /// signature whose `R` is off by a point of order 2 or 4, or is one, satisfies
    /// `[4][S]B = [4]R + [4][k]A'` and not `[S]B = R + [k]A'`, and is accepted. The same
    /// points in an encoding that is not canonical are refused, with the `S` that would
    /// satisfy the equation had the encoding been reduced.
    #[test]
    fn verification_is_cofactored() {
        let (key, public) = key_pair(&octets(GENERATED_SK));
        let point = PublicPoint::decode_var(&public).unwrap();
        let m = b"cofactored";

        assert_eq!(COFACTORED_KATS.len(), 7);
        for (name, sig) in COFACTORED_KATS {
            let signature: [u8; SIGNATURE_LEN] = octets(sig);
            assert_eq!(verify(&signature, &point, b"", m), Ok(()), "{name}");
            // It is still a signature on this message, under this context, only.
            assert_eq!(verify(&signature, &point, b"", b"cofactorex"), FAILED, "{name}");
            assert_eq!(verify(&signature, &point, b"c", m), FAILED, "{name}");
            // It is not what the signer makes.
            let mut own = [0_u8; SIGNATURE_LEN];
            sign(&key, b"", m, &mut own).unwrap();
            assert_ne!(own, signature, "{name}");
        }

        assert_eq!(NON_CANONICAL_R_KATS.len(), 5);
        for (name, sig) in NON_CANONICAL_R_KATS {
            assert_eq!(verify(&octets(sig), &point, b"", m), FAILED, "{name}");
        }
    }
}
