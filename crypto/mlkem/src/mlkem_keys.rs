use crate::aux_functions::expandA;
use crate::matrix::VectorTrait;
use crate::mlkem::{H, POLY_BYTES, q};
use crate::params::{
    MLKEM512Params, MLKEM768Params, MLKEM1024Params, MLKEMParams, PrivateKeyLen, PublicKeyLen,
};
use bouncycastle_core::errors::KEMError;
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{Hash, KEMPrivateKey, KEMPublicKey};
use bouncycastle_mlkem_common::aux_functions::{byte_decode, byte_encode};
use bouncycastle_utils::ct::ct_eq_bytes;
use bouncycastle_utils::secret::Secret;
use core::fmt;
use core::fmt::{Debug, Display, Formatter};

// imports just for docs
#[allow(unused_imports)]
use crate::mlkem::MLKEMTrait;
#[allow(unused_imports)]
use bouncycastle_mlkem_common::polynomial::Polynomial;

/* Pub Types */

/// ML-KEM-512 Public Key
pub type MLKEM512PublicKey = MLKEMPublicKey<MLKEM512Params>;
/// ML-KEM-512 Private Key
pub type MLKEM512PrivateKey = MLKEMPrivateKey<MLKEM512Params>;
/// ML-KEM-768 Public Key
pub type MLKEM768PublicKey = MLKEMPublicKey<MLKEM768Params>;
/// ML-KEM-768 Private Key
pub type MLKEM768PrivateKey = MLKEMPrivateKey<MLKEM768Params>;
/// ML-KEM-1024 Public Key
pub type MLKEM1024PublicKey = MLKEMPublicKey<MLKEM1024Params>;
/// ML-KEM-1024 Private Key
pub type MLKEM1024PrivateKey = MLKEMPrivateKey<MLKEM1024Params>;

/* Pre-expanded keys for repeated operations */

/// ML-KEM-512 Public Key with a pre-expanded public matrix A for repeated encaps operations.
pub type MLKEM512PublicKeyExpanded = MLKEMPublicKeyExpanded<MLKEM512Params>;
/// ML-KEM-512 Private Key with a pre-expanded public matrix A for repeated decaps operations.
pub type MLKEM512PrivateKeyExpanded = MLKEMPrivateKeyExpanded<MLKEM512Params>;
/// ML-KEM-768 Public Key with a pre-expanded public matrix A for repeated encaps operations.
pub type MLKEM768PublicKeyExpanded = MLKEMPublicKeyExpanded<MLKEM768Params>;
/// ML-KEM-768 Private Key with a pre-expanded public matrix A for repeated decaps operations.
pub type MLKEM768PrivateKeyExpanded = MLKEMPrivateKeyExpanded<MLKEM768Params>;
/// ML-KEM-1024 Public Key with a pre-expanded public matrix A for repeated encaps operations.
pub type MLKEM1024PublicKeyExpanded = MLKEMPublicKeyExpanded<MLKEM1024Params>;
/// ML-KEM-1024 Private Key with a pre-expanded public matrix A for repeated decaps operations.
pub type MLKEM1024PrivateKeyExpanded = MLKEMPrivateKeyExpanded<MLKEM1024Params>;

/// An ML-KEM public key.
///
/// The parameter set fixes every length, so `P` is the only type parameter. [`KEMPublicKey`]
/// takes the encoded length as a const generic, and an associated const of a type parameter may
/// not be used as one, so its impl is generic over the length and bound through the per-length
/// trait (`P: PublicKeyLen<PK_LEN>`), which has one impl per parameter set and so lets the length
/// be inferred from `P`.
pub struct MLKEMPublicKey<P: MLKEMParams> {
    t_hat: P::VecK,
    rho: [u8; 32],
}

// Written out rather than derived: `#[derive(Clone)]` would demand `P: Clone`, and `P` is a
// marker for the parameter set that is never stored, only used to name the field types.
impl<P: MLKEMParams> Clone for MLKEMPublicKey<P> {
    fn clone(&self) -> Self {
        Self { t_hat: self.t_hat, rho: self.rho }
    }
}

/// General trait for all ML-KEM public keys types.
pub trait MLKEMPublicKeyTrait<P: MLKEMParams>: Sized {
    /// Decodes an encapsulation key, FIPS 203 Algorithm 14 (K-PKE.Encrypt) lines 2-3:
    /// 𝐭̂ ← ByteDecode12(ekPKE\[0 ∶ 384𝑘]), 𝜌 ← ekPKE\[384𝑘 ∶ 384𝑘 + 32], with the Section 7.2
    /// modulus check on 𝐭̂.
    /// Input: encapsulation key ek ∈ 𝔹^(384𝑘+32).
    /// Output: 𝐭̂ ∈ (ℤ𝑞^256)^𝑘, 𝜌 ∈ 𝔹^32, or an error if a coefficient is not in \[0, 𝑞 − 1].
    fn pk_decode<const PK_LEN: usize>(pk: &[u8; PK_LEN]) -> Result<Self, KEMError>
    where
        P: PublicKeyLen<PK_LEN>;
    /// Get a copy of the expanded public matrix A_hat
    fn A_hat(&self) -> P::MatrixA;
    /// Get the hash of the public key
    fn compute_hash(&self) -> [u8; 32];
}

pub(crate) trait MLKEMPublicKeyInternalTrait<P: MLKEMParams>:
    MLKEMPublicKeyTrait<P>
{
    /// Not exposing a constructor publicly because you should have to get an instance either by
    /// running a keygen, or by decoding an existing key.
    fn new(t_hat: P::VecK, rho: [u8; 32]) -> Self;

    /// Get a ref to t_hat
    fn t_hat(&self) -> &P::VecK;

    /// The expanded 𝐀̂, if this key holds one; `None` and the caller expands it from 𝜌.
    fn A_hat_cached(&self) -> Option<&P::MatrixA>;
}

impl<P: MLKEMParams> MLKEMPublicKey<P> {
    /// FIPS 203 Algorithm 13 (K-PKE.KeyGen) line 19, ekPKE ← ByteEncode12(𝐭̂) ‖ 𝜌, into a slice
    /// of the encoded length. Shared by the array encoding and the private-key encoding that
    /// embeds ek, so the length is a run-time `debug_assert` here and a type elsewhere.
    pub(crate) fn encode_into(&self, out: &mut [u8]) {
        debug_assert_eq!(POLY_BYTES, 12 * 32);
        debug_assert_eq!(out.len(), P::PK_LEN);

        let (pk_chunks, last_chunk) = out.as_chunks_mut::<POLY_BYTES>();

        // that should divide evenly the remainder of the array, leaving space for rho at the end
        debug_assert_eq!(pk_chunks.len(), P::k);
        debug_assert_eq!(last_chunk.len(), 32);

        for (pk_chunk, t_i) in pk_chunks.iter_mut().zip(self.t_hat.elems()) {
            pk_chunk.copy_from_slice(&byte_encode::<12, POLY_BYTES>(t_i));
        }
        last_chunk.copy_from_slice(&self.rho);
    }

    /// The inverse of [`Self::encode_into`], with the Section 7.2 modulus check; see
    /// [`MLKEMPublicKeyTrait::pk_decode`].
    pub(crate) fn decode_from(pk: &[u8]) -> Result<Self, KEMError> {
        if pk.len() != P::PK_LEN {
            return Err(KEMError::DecodingError("Provided key bytes are the incorrect length"));
        }
        let (pk_chunks, last_chunk) = pk.as_chunks::<POLY_BYTES>();

        // that should divide evenly the remainder of the array, leaving space for rho at the end
        debug_assert_eq!(pk_chunks.len(), P::k);
        debug_assert_eq!(last_chunk.len(), 32);

        let t_hat = {
            let mut t_hat = P::VecK::new();

            for (t_i, pk_chunk) in t_hat.elems_mut().iter_mut().zip(pk_chunks) {
                t_i.coeffs.copy_from_slice(&byte_decode::<12, POLY_BYTES>(pk_chunk).coeffs);

                // FIPS 203 says:
                //      "Specifically, ByteDecode12 converts each 12-bit
                //      segment of its input into an integer modulo 2^{12} = 4096 and then reduces the result
                //      modulo 𝑞. This is no longer a one-to-one operation. Indeed, some 12-bit segments could
                //      correspond to an integer greater than 𝑞 − 1 = 3328 but less than 4096."
                //  Since this concerns to the case d=12, it should be checked that all coeffs are less than q-1
                for coeff in t_i.coeffs.iter() {
                    if *coeff < 0 || *coeff >= q {
                        return Err(KEMError::DecodingError("Invalid or corrupted key"));
                    }
                }
            }

            t_hat
        };
        let rho = last_chunk.try_into().unwrap();

        Ok(Self { t_hat, rho })
    }
}

impl<P: MLKEMParams> MLKEMPublicKeyTrait<P> for MLKEMPublicKey<P> {
    fn pk_decode<const PK_LEN: usize>(pk: &[u8; PK_LEN]) -> Result<Self, KEMError>
    where
        P: PublicKeyLen<PK_LEN>,
    {
        Self::decode_from(pk)
    }

    fn A_hat(&self) -> P::MatrixA {
        expandA::<P>(&self.rho)
    }

    /// H(ek) over the encoding, fed to the hash a polynomial at a time so that no buffer of the
    /// encoded length is needed.
    fn compute_hash(&self) -> [u8; 32] {
        let mut h = H::default();
        for t_i in self.t_hat.elems() {
            h.do_update(&byte_encode::<12, POLY_BYTES>(t_i));
        }
        h.do_update(&self.rho);
        let mut out = [0u8; 32];
        let bytes_written = h.do_final_out(&mut out);
        debug_assert_eq!(bytes_written, 32);
        out
    }
}

impl<P: MLKEMParams> MLKEMPublicKeyInternalTrait<P> for MLKEMPublicKey<P> {
    fn new(t_hat: P::VecK, rho: [u8; 32]) -> Self {
        Self { rho, t_hat }
    }

    fn t_hat(&self) -> &P::VecK {
        &self.t_hat
    }

    fn A_hat_cached(&self) -> Option<&P::MatrixA> {
        None
    }
}

impl<P: MLKEMParams + PublicKeyLen<PK_LEN>, const PK_LEN: usize> KEMPublicKey<PK_LEN>
    for MLKEMPublicKey<P>
{
    /// Encodes the public key as per FIPS 203 Algorithm 13
    /// 19: ekPKE ← ByteEncode12(𝐭)‖𝜌
    fn encode(&self) -> [u8; PK_LEN] {
        let mut pk = [0u8; PK_LEN];
        self.encode_out(&mut pk);

        pk
    }
    /// Encodes the public key as per FIPS 203 Algorithm 13
    /// 19: ekPKE ← ByteEncode12(𝐭)‖𝜌
    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        out.fill(0);
        self.encode_into(out);
        PK_LEN
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, KEMError> {
        if bytes.len() != PK_LEN {
            return Err(KEMError::DecodingError("Provided key bytes are the incorrect length"));
        }
        Self::decode_from(bytes)
    }
}

impl<P: MLKEMParams> Eq for MLKEMPublicKey<P> {}

impl<P: MLKEMParams> PartialEq for MLKEMPublicKey<P> {
    /// Coefficient by coefficient over the encoding, without a buffer of the encoded length.
    fn eq(&self, other: &Self) -> bool {
        let mut equal = ct_eq_bytes(&self.rho, &other.rho);
        for (a, b) in self.t_hat.elems().iter().zip(other.t_hat.elems()) {
            equal &=
                ct_eq_bytes(&byte_encode::<12, POLY_BYTES>(a), &byte_encode::<12, POLY_BYTES>(b));
        }
        equal
    }
}

impl<P: MLKEMParams> Debug for MLKEMPublicKey<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let hash = self.compute_hash();
        write!(f, "MLKEMPublicKey {{ alg: {}, pub_key_hash: {:x?} }}", P::ALG_NAME, hash)
    }
}

impl<P: MLKEMParams> Display for MLKEMPublicKey<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let hash = self.compute_hash();
        write!(f, "MLKEMPublicKey {{ alg: {}, pub_key_hash: {:x?} }}", P::ALG_NAME, hash)
    }
}

/// A fully expanded ML-KEM public key that includes the intermediate values needed for performing multiple encaps operations
/// against the same public key, which causes the MLKEMPublicKey struct to take up more memory, but results
/// in more efficient repeated encaps() operations. It implements the same traits as
/// [`MLKEMPublicKey`], so it is used the same way.
pub struct MLKEMPublicKeyExpanded<P: MLKEMParams> {
    ek: MLKEMPublicKey<P>,
    A_hat: P::MatrixA,
}

/// See the note on [`MLKEMPublicKey`]'s `Clone` for why this is not derived.
impl<P: MLKEMParams> Clone for MLKEMPublicKeyExpanded<P> {
    fn clone(&self) -> Self {
        Self { ek: self.ek.clone(), A_hat: self.A_hat.clone() }
    }
}

impl<P: MLKEMParams> MLKEMPublicKeyInternalTrait<P> for MLKEMPublicKeyExpanded<P> {
    fn new(t_hat: P::VecK, rho: [u8; 32]) -> Self {
        Self::from(&MLKEMPublicKey::new(t_hat, rho))
    }

    fn t_hat(&self) -> &P::VecK {
        self.ek.t_hat()
    }

    fn A_hat_cached(&self) -> Option<&P::MatrixA> {
        Some(&self.A_hat)
    }
}

impl<P: MLKEMParams + PublicKeyLen<PK_LEN>, const PK_LEN: usize> KEMPublicKey<PK_LEN>
    for MLKEMPublicKeyExpanded<P>
{
    fn encode(&self) -> [u8; PK_LEN] {
        self.ek.encode()
    }

    fn encode_out(&self, out: &mut [u8; PK_LEN]) -> usize {
        self.ek.encode_out(out)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, KEMError> {
        Ok(Self::from(&MLKEMPublicKey::from_bytes(bytes)?))
    }
}

impl<P: MLKEMParams> PartialEq for MLKEMPublicKeyExpanded<P> {
    fn eq(&self, other: &Self) -> bool {
        self.ek == other.ek
    }
}

impl<P: MLKEMParams> Eq for MLKEMPublicKeyExpanded<P> {}

impl<P: MLKEMParams> Debug for MLKEMPublicKeyExpanded<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let hash = self.compute_hash();
        write!(f, "MLKEMPublicKeyExpanded {{ alg: {}, pub_key_hash: {:x?} }}", P::ALG_NAME, hash)
    }
}

impl<P: MLKEMParams> Display for MLKEMPublicKeyExpanded<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let hash = self.compute_hash();
        write!(f, "MLKEMPublicKeyExpanded {{ alg: {}, pub_key_hash: {:x?} }}", P::ALG_NAME, hash)
    }
}

impl<P: MLKEMParams> MLKEMPublicKeyTrait<P> for MLKEMPublicKeyExpanded<P> {
    fn pk_decode<const PK_LEN: usize>(pk: &[u8; PK_LEN]) -> Result<Self, KEMError>
    where
        P: PublicKeyLen<PK_LEN>,
    {
        Ok(Self::from(&MLKEMPublicKey::pk_decode(pk)?))
    }

    fn A_hat(&self) -> P::MatrixA {
        self.A_hat.clone()
    }

    fn compute_hash(&self) -> [u8; 32] {
        self.ek.compute_hash()
    }
}

impl<P: MLKEMParams> From<&MLKEMPublicKey<P>> for MLKEMPublicKeyExpanded<P> {
    /// Expands 𝐀̂ from the key's 𝜌 and keeps it alongside a copy of the key, for repeated
    /// encapsulations against the same key.
    fn from(ek: &MLKEMPublicKey<P>) -> Self {
        let A_hat = ek.A_hat();

        Self { ek: ek.clone(), A_hat }
    }
}

/// An ML-KEM private key.
///
/// `P` is its only type parameter, for the reason given on [`MLKEMPublicKey`].
// Dev note: This will automatically inherit the [`Secret`] protections because [`Polynomial`] wraps the underlying data with [`Secret`].
pub struct MLKEMPrivateKey<P: MLKEMParams> {
    s_hat: Secret<P::VecK>,
    ek: MLKEMPublicKey<P>,
    pk_hash: [u8; 32],
    z: Secret<[u8; 32]>,
    seed_d: Option<Secret<[u8; 32]>>,
}

/// See the note on [`MLKEMPublicKey`]'s `Clone` for why this is not derived.
impl<P: MLKEMParams> Clone for MLKEMPrivateKey<P> {
    fn clone(&self) -> Self {
        Self {
            s_hat: self.s_hat.clone(),
            ek: self.ek.clone(),
            pk_hash: self.pk_hash,
            z: self.z.clone(),
            seed_d: self.seed_d.clone(),
        }
    }
}

impl<P: MLKEMParams> MLKEMPrivateKey<P> {
    /// As described on Algorithm 16 line
    ///   3: dk ← (dkPKE ‖ ek ‖ H(ek) ‖ 𝑧)
    fn sk_encode_out<const SK_LEN: usize>(&self, out: &mut [u8; SK_LEN]) -> usize {
        out.fill(0);

        debug_assert_eq!(
            SK_LEN,
            /* dk_pke*/ 12*P::k*32 + /*ek*/P::PK_LEN + /*H(ek)*/32 + /*z*/32
        );

        let mut pos = 0usize;

        /* dk_pke */
        // Alg 13; line 20: dkPKE ← ByteEncode12(𝐬)
        for i in 0..P::k {
            out[i * POLY_BYTES..(i + 1) * POLY_BYTES]
                .copy_from_slice(&byte_encode::<12, POLY_BYTES>(&self.s_hat[i]));
        }
        pos += P::k * POLY_BYTES;

        /* ek */
        // Alg 13; line 19: ekPKE ← ByteEncode12(𝐭)‖𝜌
        self.ek.encode_into(&mut out[pos..pos + P::PK_LEN]);
        pos += P::PK_LEN;

        /* H(ek) */
        out[pos..pos + 32].copy_from_slice(&self.pk_hash);
        pos += 32;

        /* z */
        out[pos..pos + 32].copy_from_slice(&*self.z);

        debug_assert_eq!(pos + 32, SK_LEN);
        SK_LEN
    }

    /// The inverse of [`Self::sk_encode_out`], with the FIPS 203 Section 7.3 decapsulation key
    /// checks 2 and 3; see [`MLKEMPrivateKeyTrait::sk_decode`].
    fn sk_decode_from(sk: &[u8]) -> Result<Self, KEMError> {
        debug_assert_eq!(
            sk.len(),
            /* dk_pke*/ 12*P::k*32 + /*ek*/P::PK_LEN + /*H(ek)*/32 + /*z*/32
        );

        let mut pos = 0usize;

        /* dk_pke */
        let mut s_hat: Secret<P::VecK> = Secret::new();
        for i in 0..P::k {
            s_hat[i] = byte_decode::<12, POLY_BYTES>(
                sk[i * POLY_BYTES..(i + 1) * POLY_BYTES].try_into().unwrap(),
            );

            // FIPS 203 says:
            //      "Specifically, ByteDecode12 converts each 12-bit
            //      segment of its input into an integer modulo 2^{12} = 4096 and then reduces the result
            //      modulo 𝑞. This is no longer a one-to-one operation. Indeed, some 12-bit segments could
            //      correspond to an integer greater than 𝑞 − 1 = 3328 but less than 4096."
            //  Since this concerns to the case d=12, it should be checked that all coeffs are less than q-1
            for coeff in s_hat[i].coeffs.iter() {
                if *coeff < 0 || *coeff >= q {
                    return Err(KEMError::DecodingError("Invalid or corrupted key"));
                }
            }
        }
        pos += P::k * POLY_BYTES;

        /* ek */
        let ek = MLKEMPublicKey::<P>::decode_from(&sk[pos..pos + P::PK_LEN])?;
        pos += P::PK_LEN;

        /* H(ek) */
        let h_pk: [u8; 32] = sk[pos..pos + 32].try_into().unwrap();
        pos += 32;

        // This satisfies the "Decapsulation input check #3) in FIPS 203 section 7.3.
        // It is done here on key load rather than as part of the decapsulation for performance
        // because if multiple decapsulations are being performed, this check needs to be done only once.
        if h_pk != ek.compute_hash() {
            return Err(KEMError::ConsistencyCheckFailed(
                "Corrupted private key: computed hash of ek != h_ek stored in private key",
            ));
        }

        /* z */
        let mut z = Secret::<[u8; 32]>::new();
        z.copy_from_slice(sk[pos..pos + 32].try_into().unwrap());

        Ok(Self::new(s_hat, ek, h_pk, z, None))
    }
}

/// General trait for all ML-KEM private keys types.
pub trait MLKEMPrivateKeyTrait<P: MLKEMParams>: Sized {
    /// Get a ref to the seed, if there is one stored with this private key
    fn seed(&self) -> Option<KeyMaterial<64>>;

    /// The public key, which the private key holds (FIPS 203 Algorithm 16 line 3, dk includes ek).
    fn pk(&self) -> &MLKEMPublicKey<P>;
    /// Get a ref to the stored public key hash.
    fn pk_hash(&self) -> &[u8; 32];
    /// Decode the private key from its FIPS 203 encoding, with the Section 7.3 decapsulation key
    /// checks 2 (coefficient range) and 3 (H(ek) matches the stored hash).
    fn sk_decode<const SK_LEN: usize>(sk: &[u8; SK_LEN]) -> Result<Self, KEMError>
    where
        P: PrivateKeyLen<SK_LEN>;
}

pub(crate) trait MLKEMPrivateKeyInternalTrait<P: MLKEMParams>:
    MLKEMPrivateKeyTrait<P>
{
    /// Not exposing a constructor publicly because you should have to get an instance either by
    /// running a keygen, or by decoding an existing key.
    fn new(
        s_hat: Secret<P::VecK>,
        ek: MLKEMPublicKey<P>,
        h: [u8; 32],
        z: Secret<[u8; 32]>,
        seed_d: Option<Secret<[u8; 32]>>,
    ) -> Self;

    /// Get a ref to s_hat
    fn s_hat(&self) -> &P::VecK;

    fn z(&self) -> &Secret<[u8; 32]>;

    /// The expanded 𝐀̂, if this key holds one; `None` and the caller expands it from 𝜌.
    fn A_hat_cached(&self) -> Option<&P::MatrixA>;
}

impl<P: MLKEMParams> MLKEMPrivateKeyTrait<P> for MLKEMPrivateKey<P> {
    fn seed(&self) -> Option<KeyMaterial<64>> {
        let seed_d = self.seed_d.as_ref()?;

        let mut tmp = Secret::<[u8; 64]>::new();
        tmp[..32].copy_from_slice(seed_d.as_ref());
        tmp[32..].copy_from_slice(&*self.z);

        // `from_bytes` types all-zero input as Zeroized, and `set_security_strength` refuses a
        // strength on a Zeroized key, so the type is set first, inside the hazardous block, where
        // `set_key_type` is unconditional. After that the strength call can only fail on a key
        // shorter than the strength needs, and this one is 64 bytes, so the expect never fires.
        let mut seed =
            KeyMaterial::<64>::from_bytes(&*tmp).expect("64 bytes fit a KeyMaterial<64>");
        do_hazardous_operations(&mut seed, |seed| {
            seed.set_key_type(KeyType::Seed)?;
            seed.set_security_strength(P::MAX_SECURITY_STRENGTH)
        })
        .expect("a 64-byte Seed accepts every ML-KEM security strength");

        Some(seed)
    }

    fn pk(&self) -> &MLKEMPublicKey<P> {
        &self.ek
    }

    fn pk_hash(&self) -> &[u8; 32] {
        &self.pk_hash
    }

    fn sk_decode<const SK_LEN: usize>(sk: &[u8; SK_LEN]) -> Result<Self, KEMError>
    where
        P: PrivateKeyLen<SK_LEN>,
    {
        Self::sk_decode_from(sk)
    }
}

impl<P: MLKEMParams> MLKEMPrivateKeyInternalTrait<P> for MLKEMPrivateKey<P> {
    /// Note to future maintainers: FIPS 203 section 7.3 requires that ek be hashed and compared to pk_hash.
    fn new(
        s_hat: Secret<P::VecK>,
        ek: MLKEMPublicKey<P>,
        pk_hash: [u8; 32],
        z: Secret<[u8; 32]>,
        seed_d: Option<Secret<[u8; 32]>>,
    ) -> Self {
        Self { s_hat, ek, pk_hash, z, seed_d }
    }

    fn s_hat(&self) -> &P::VecK {
        &self.s_hat
    }

    fn z(&self) -> &Secret<[u8; 32]> {
        &self.z
    }

    fn A_hat_cached(&self) -> Option<&P::MatrixA> {
        None
    }
}

impl<P: MLKEMParams + PrivateKeyLen<SK_LEN>, const SK_LEN: usize> KEMPrivateKey<SK_LEN>
    for MLKEMPrivateKey<P>
{
    fn encode(&self) -> [u8; SK_LEN] {
        let mut out = [0u8; SK_LEN];
        self.encode_out(&mut out);

        out
    }

    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        out.fill(0);

        self.sk_encode_out(out)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, KEMError> {
        if bytes.len() != SK_LEN {
            return Err(KEMError::DecodingError("Provided key bytes are the incorrect length"));
        }

        Self::sk_decode_from(bytes)
    }
}

impl<P: MLKEMParams> Eq for MLKEMPrivateKey<P> {}

impl<P: MLKEMParams> PartialEq for MLKEMPrivateKey<P> {
    /// Field by field in constant time: 𝐬̂ coefficient by coefficient over its encoding, then ek,
    /// H(ek) and 𝑧. The seed is not compared, since a decoded key has none and the encoding does
    /// not carry it.
    fn eq(&self, other: &Self) -> bool {
        let mut equal = true;
        for (a, b) in self.s_hat.elems().iter().zip(other.s_hat.elems()) {
            // Encoded 𝐬̂ is private-key material: held in `Secret` buffers for the comparison.
            let mut a_encoded = Secret::<[u8; POLY_BYTES]>::new();
            let mut b_encoded = Secret::<[u8; POLY_BYTES]>::new();
            *a_encoded = byte_encode::<12, POLY_BYTES>(a);
            *b_encoded = byte_encode::<12, POLY_BYTES>(b);
            equal &= ct_eq_bytes(&*a_encoded, &*b_encoded);
        }
        equal &= self.ek == other.ek;
        equal &= ct_eq_bytes(&self.pk_hash, &other.pk_hash);
        equal &= ct_eq_bytes(&*self.z, &*other.z);
        equal
    }
}

/// Debug impl mainly to prevent the secret key from being printed in logs.
impl<P: MLKEMParams> fmt::Debug for MLKEMPrivateKey<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MLKEMPrivateKey {{ alg: {}, pub_key_hash: {:x?}, has_seed: {} }}",
            P::ALG_NAME,
            self.pk_hash,
            self.seed_d.is_some(),
        )
    }
}

/// Display impl mainly to prevent the secret key from being printed in logs.
impl<P: MLKEMParams> Display for MLKEMPrivateKey<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MLKEMPrivateKey {{ alg: {}, pub_key_hash: {:x?}, has_seed: {} }}",
            P::ALG_NAME,
            self.pk_hash,
            self.seed_d.is_some(),
        )
    }
}

/// A fully expanded ML-KEM private key that includes the intermediate values needed for performing
/// multiple decaps operations with the same private key, which causes the private key struct to
/// take up more memory, but results in more efficient repeated decaps() operations. It implements
/// the same traits as [`MLKEMPrivateKey`], so it is used the same way.
pub struct MLKEMPrivateKeyExpanded<P: MLKEMParams> {
    dk: MLKEMPrivateKey<P>,
    A_hat: P::MatrixA,
}

/// See the note on [`MLKEMPublicKey`]'s `Clone` for why this is not derived.
impl<P: MLKEMParams> Clone for MLKEMPrivateKeyExpanded<P> {
    fn clone(&self) -> Self {
        Self { dk: self.dk.clone(), A_hat: self.A_hat.clone() }
    }
}

impl<P: MLKEMParams> From<&MLKEMPrivateKey<P>> for MLKEMPrivateKeyExpanded<P> {
    /// Expands 𝐀̂ from the key's 𝜌 and keeps it alongside a copy of the key, for repeated
    /// decapsulations with the same key.
    fn from(dk: &MLKEMPrivateKey<P>) -> Self {
        let A_hat = dk.pk().A_hat();

        Self { dk: dk.clone(), A_hat }
    }
}

impl<P: MLKEMParams + PrivateKeyLen<SK_LEN>, const SK_LEN: usize> KEMPrivateKey<SK_LEN>
    for MLKEMPrivateKeyExpanded<P>
{
    fn encode(&self) -> [u8; SK_LEN] {
        self.dk.encode()
    }

    fn encode_out(&self, out: &mut [u8; SK_LEN]) -> usize {
        self.dk.encode_out(out)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, KEMError> {
        Ok(Self::from(&MLKEMPrivateKey::from_bytes(bytes)?))
    }
}

impl<P: MLKEMParams> PartialEq for MLKEMPrivateKeyExpanded<P> {
    fn eq(&self, other: &Self) -> bool {
        self.dk.eq(&other.dk)
    }
}

impl<P: MLKEMParams> Eq for MLKEMPrivateKeyExpanded<P> {}

impl<P: MLKEMParams> Debug for MLKEMPrivateKeyExpanded<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MLKEMPrivateKeyExpanded {{ alg: {}, pub_key_hash: {:x?}, has_seed: {} }}",
            P::ALG_NAME,
            self.dk.pk_hash(),
            self.dk.seed_d.is_some(),
        )
    }
}

impl<P: MLKEMParams> Display for MLKEMPrivateKeyExpanded<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MLKEMPrivateKeyExpanded {{ alg: {}, pub_key_hash: {:x?}, has_seed: {} }}",
            P::ALG_NAME,
            self.dk.pk_hash(),
            self.dk.seed_d.is_some(),
        )
    }
}

impl<P: MLKEMParams> MLKEMPrivateKeyTrait<P> for MLKEMPrivateKeyExpanded<P> {
    fn seed(&self) -> Option<KeyMaterial<64>> {
        self.dk.seed()
    }

    fn pk(&self) -> &MLKEMPublicKey<P> {
        self.dk.pk()
    }

    fn pk_hash(&self) -> &[u8; 32] {
        self.dk.pk_hash()
    }

    fn sk_decode<const SK_LEN: usize>(sk: &[u8; SK_LEN]) -> Result<Self, KEMError>
    where
        P: PrivateKeyLen<SK_LEN>,
    {
        Ok(Self::from(&MLKEMPrivateKey::sk_decode(sk)?))
    }
}

impl<P: MLKEMParams> MLKEMPrivateKeyInternalTrait<P> for MLKEMPrivateKeyExpanded<P> {
    fn new(
        s_hat: Secret<P::VecK>,
        ek: MLKEMPublicKey<P>,
        h: [u8; 32],
        z: Secret<[u8; 32]>,
        seed_d: Option<Secret<[u8; 32]>>,
    ) -> Self {
        Self::from(&MLKEMPrivateKey::new(s_hat, ek, h, z, seed_d))
    }

    fn s_hat(&self) -> &P::VecK {
        self.dk.s_hat()
    }

    fn z(&self) -> &Secret<[u8; 32]> {
        self.dk.z()
    }

    fn A_hat_cached(&self) -> Option<&P::MatrixA> {
        Some(&self.A_hat)
    }
}
