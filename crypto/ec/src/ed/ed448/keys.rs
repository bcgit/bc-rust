//! The Ed448 key objects, the algorithm markers, the Ed448ph views of the keys and the
//! signature roles over them.

use super::point::PublicPoint;
use super::scheme::{
    self, CONTEXT_MAX_LEN, ExpandedKey, PREHASH_LEN, PRIVATE_KEY_LEN, PUBLIC_KEY_LEN, SIGNATURE_LEN,
};
use bouncycastle_core::errors::{KeyDecodingError, KeyMaterialError, RNGError, SignatureError};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::{
    DeterministicOneShotSigningKey, DeterministicSigningKey, OneShotVerifyingKey,
    SignatureAlgorithm, VerifyingKey, sign_out_with_signer, verify_with_verifier,
};
use bouncycastle_core::traits::{
    Algorithm, AlgorithmOID, FinishToken, Hash, PrivateKey, PublicKey, RNG, SignatureSigner,
    SignatureVerifier,
};
use bouncycastle_digest::sha3::SHAKE256;
use bouncycastle_utils::ct::ct_eq_bytes;
use bouncycastle_utils::secret::Secret;
use core::fmt::{self, Debug, Display, Formatter};

/// String name of the Ed448 algorithm.
pub const ED448_NAME: &str = "Ed448";
/// String name of the Ed448ph algorithm.
pub const ED448PH_NAME: &str = "Ed448ph";

/// Ed448 (RFC 8032 Section 5.2), the algorithm that signs the message itself, and the
/// algorithm of [`Ed448PrivateKey`] and [`Ed448PublicKey`]. It takes the whole message at
/// once, so the keys implement only the one-shot roles: [`DeterministicOneShotSigningKey`] and
/// [`OneShotVerifyingKey`].
///
/// Unlike Ed25519, it takes a context, of at most [`CONTEXT_MAX_LEN`] octets and empty by
/// default (RFC 8032 Section 5.2: "Value of context is set by signer and verifier (maximum of
/// 255 octets; the default is empty string) and has to match octet by octet for verification
/// to be successful"): `None` is the empty context, and a longer one is a
/// [`SignatureError::LengthError`] from signing and from verification.
pub struct Ed448;

impl Algorithm for Ed448 {
    const ALG_NAME: &'static str = ED448_NAME;
    // RFC 8032 Section 8.5: "Ed448 and Ed448ph have the strength of 224". SecurityStrength
    // has no 224-bit level, so the algorithm is classed at the highest level that does not
    // exceed it, as X448 is.
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}

impl SignatureAlgorithm for Ed448 {}

/// `id-Ed448` (RFC 8410 Section 3), which identifies the public key, the private key and the
/// signature alike. [`Ed448ph`] has none: RFC 8410 Section 1 "does not provide the
/// conventions needed for the prehash versions of the signature algorithm".
impl AlgorithmOID for Ed448 {
    const OID: &'static [u32] = &[1, 3, 101, 113];
    const OID_DER: &'static [u8] = &[0x06, 0x03, 0x2B, 0x65, 0x71];
}

/// Ed448ph (RFC 8032 Section 5.2), the algorithm that signs `SHAKE256(x, 64)`, the first 64
/// octets of SHAKE256 of the message, under a context of at most [`CONTEXT_MAX_LEN`] octets
/// that is empty by default. Its keys are [`Ed448phPrivateKey`] and [`Ed448phPublicKey`], the
/// views [`Ed448PrivateKey::as_prehash`] and [`Ed448PublicKey::as_prehash`] give of an Ed448
/// key. The message can arrive in pieces, so they implement the streaming roles,
/// [`DeterministicSigningKey`] and [`VerifyingKey`], and the one-shot roles with them.
///
/// An Ed448ph signature is not an Ed448 signature of the message or of its digest, and the
/// other way round.
#[allow(non_camel_case_types)]
pub struct Ed448ph;

impl Algorithm for Ed448ph {
    const ALG_NAME: &'static str = ED448PH_NAME;
    // As [`Ed448`]: 224 bits in RFC 8032 Section 8.5, classed at 192.
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}

impl SignatureAlgorithm for Ed448ph {}

/// Generates a key pair from `rng`, which must offer the 192 bits Ed448 is classed at: the 57
/// octets it draws are the private key (RFC 8032 Section 5.2.5).
///
/// [`keygen_out`] into a key you hold, moved out of this frame; a move wipes nothing (the
/// module's Security Considerations).
///
/// # Errors
/// [`SignatureError::RNGError`] if the RNG is weaker than the algorithm or fails to deliver;
/// [`SignatureError::ComputationFault`] if the computed public key fails its check, which no input
/// causes; [`SignatureError::KeyGenError`] if the octets drawn are a private key this module
/// refuses ([`Ed448PrivateKey`]), which is not known to happen. The generation is not retried.
pub fn keygen(rng: &mut dyn RNG) -> Result<(Ed448PublicKey, Ed448PrivateKey), SignatureError> {
    let mut sk = Ed448PrivateKey::zeroized();
    let pk = keygen_out(rng, &mut sk)?;
    Ok((pk, sk))
}

/// Generates a private key into `sk`, a key you hold, and returns its public key: the RNG,
/// which must offer the 192 bits Ed448 is classed at, writes the 57 octets straight into the
/// key, which is expanded where it sits, so no copy of it is staged on the way. `sk` is
/// zeroized first and left so on every error.
///
/// # Errors
/// As [`keygen`].
pub fn keygen_out(
    rng: &mut dyn RNG,
    sk: &mut Ed448PrivateKey,
) -> Result<Ed448PublicKey, SignatureError> {
    sk.clear();
    if rng.security_strength() < Ed448::MAX_SECURITY_STRENGTH {
        return Err(RNGError::SecurityStrengthInsufficientForAlgorithm.into());
    }
    if let Err(e) = rng.next_bytes_out(&mut *sk.private_key) {
        sk.clear();
        return Err(e.into());
    }
    if let Err(e) = sk.expanded.expand(&sk.private_key) {
        sk.clear();
        return Err(e);
    }
    sk.pk()
}

/// Checks that `pk` is the public key of `sk`.
///
/// # Errors
/// [`SignatureError::ConsistencyCheckFailed`] if it is not;
/// [`KeyMaterialError::ActingOnZeroizedKey`] for a private key that was never filled
/// ([`Ed448PrivateKey::zeroized`]).
pub fn keypair_consistency_check(
    pk: &Ed448PublicKey,
    sk: &Ed448PrivateKey,
) -> Result<(), SignatureError> {
    sk.check_filled()?;
    // Both sides are public keys, so the comparison need not be constant time.
    if pk.encode() == *sk.expanded.public_key() {
        Ok(())
    } else {
        Err(SignatureError::ConsistencyCheckFailed)
    }
}

/// An Ed448 private key: the 57 octets of RFC 8032 Section 5.2.5, with the secret scalar, the
/// prefix and the public key derived from them.
///
/// RFC 8032 takes any 57 octets. This module refuses those whose derived scalar is four times
/// the group order, the one scalar the derivation can give whose public key is the neutral
/// element, under which anyone can sign. Finding such octets is finding a SHAKE256 preimage,
/// and none are known.
///
/// The derivation runs once, when the key is generated or decoded, so signing does not repeat
/// it. Everything secret is wiped when the key is dropped, and the type has no `Debug`.
///
/// It is a key of [`Ed448`], the algorithm `id-Ed448` names (RFC 8410 Section 3), and signs a
/// whole message through [`DeterministicOneShotSigningKey`]. The same octets sign with
/// [`Ed448ph`] through the view [`as_prehash`](Self::as_prehash) gives. The key itself has no
/// streaming signer:
///
/// ```compile_fail,E0599
/// use bouncycastle_core::signature_key::DeterministicSigningKey;
/// use bouncycastle_ec::ed::ed448::Ed448PrivateKey;
///
/// fn signer(sk: &Ed448PrivateKey) {
///     let _ = sk.create_signer_deterministic(None);
/// }
/// ```
pub struct Ed448PrivateKey {
    /// The private key as RFC 8032 has it, kept for the encoding.
    private_key: Secret<[u8; PRIVATE_KEY_LEN]>,
    /// What signing uses: RFC 8032 Section 5.2.6, step 1, done ahead, and the public key.
    expanded: ExpandedKey,
}

impl Ed448PrivateKey {
    /// The all-zero key: the key [`keygen_out`] writes into, so that the private key is drawn
    /// where it will live and never moved. It is not a generated key: until `keygen_out` fills
    /// it, it has no public key and signs nothing
    /// ([`KeyMaterialError::ActingOnZeroizedKey`]), and it is equal to no key that was
    /// generated or decoded.
    ///
    /// # 🚨 Security Considerations 🚨
    ///
    /// The encoding of this key is not refused, the encoding methods having no error to give:
    /// it is 57 zero octets, which decode as a working key anyone can compute. Do not store or
    /// send the encoding of a key whose generation failed.
    pub fn zeroized() -> Self {
        Self { private_key: Secret::new(), expanded: ExpandedKey::zeroized() }
    }

    /// Back to the all-zero key, everything secret wiped.
    fn clear(&mut self) {
        self.private_key.zeroize();
        self.expanded.clear();
    }

    /// Refuses a key that was never generated or decoded.
    fn check_filled(&self) -> Result<(), SignatureError> {
        if self.expanded.is_filled() {
            Ok(())
        } else {
            Err(KeyMaterialError::ActingOnZeroizedKey.into())
        }
    }

    /// Decodes the 57 octets of a private key into `sk`, a key you hold: they are copied
    /// straight into the key, which is expanded where it sits, so this module stages no copy
    /// on the way, where the trait's [`from_bytes`](PrivateKey::from_bytes) moves the key it
    /// returns. The SHAKE256 that expands the key is moved once on the way, and may leave
    /// part of what it absorbed behind (the module's Security Considerations).
    /// `sk` is zeroized first and left so on every error.
    ///
    /// # Errors
    /// As [`from_bytes`](PrivateKey::from_bytes).
    pub fn from_bytes_out(bytes: &[u8], sk: &mut Self) -> Result<(), KeyDecodingError> {
        sk.clear();
        if bytes.len() != PRIVATE_KEY_LEN {
            return Err(KeyDecodingError("An Ed448 private key must be 57 bytes"));
        }
        sk.private_key.copy_from_slice(bytes);
        match sk.expanded.expand(&sk.private_key) {
            Ok(()) => Ok(()),
            // The key whose public key is the neutral element.
            Err(SignatureError::KeyGenError(reason)) => {
                sk.clear();
                Err(KeyDecodingError(reason))
            }
            // The fault path of key expansion; this trait's error carries no other kind.
            Err(_) => {
                sk.clear();
                Err(KeyDecodingError("Ed448: a computed point failed its check"))
            }
        }
    }

    /// The public key (RFC 8032 Section 5.2.5). It was computed when this key was made; this
    /// puts it in the form verification uses, at the cost of a square root in the field, with
    /// no scalar multiplication.
    ///
    /// # Errors
    /// [`KeyMaterialError::ActingOnZeroizedKey`] for a key that was never filled
    /// ([`zeroized`](Self::zeroized)).
    pub fn pk(&self) -> Result<Ed448PublicKey, SignatureError> {
        // `None` is the unfilled key: the stored encoding of a filled one always decodes.
        let point = self.expanded.public_point().ok_or(KeyMaterialError::ActingOnZeroizedKey)?;
        Ok(Ed448PublicKey { point })
    }

    /// The pre-hash form of this key, an [`Ed448ph`] signing key. The view borrows the key; no
    /// key material is copied or moved.
    pub fn as_prehash(&self) -> Ed448phPrivateKey<'_> {
        Ed448phPrivateKey { sk: self }
    }
}

/// The encoding is the 57 octets of the private key as RFC 8032 Section 5.2.5 defines it (the
/// "seed" of some other libraries), not the scalar derived from it.
impl PrivateKey<PRIVATE_KEY_LEN> for Ed448PrivateKey {
    /// The private key as a plain array, the trait's contract; prefer `encode_out` into a
    /// buffer you own, since the array is moved out unwiped.
    fn encode(&self) -> [u8; PRIVATE_KEY_LEN] {
        *self.private_key
    }

    fn encode_out(&self, out: &mut [u8; PRIVATE_KEY_LEN]) -> usize {
        *out = *self.private_key;
        PRIVATE_KEY_LEN
    }

    /// Decoding derives the public key, which costs a fixed-base scalar multiplication.
    ///
    /// # Errors
    /// [`KeyDecodingError`] if `bytes` is not 57 octets; if they are a key this module refuses
    /// (see the type), which no known octets are; or if the computed public key fails its
    /// check, which no input causes.
    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyDecodingError> {
        let mut sk = Self::zeroized();
        Self::from_bytes_out(bytes, &mut sk)?;
        Ok(sk)
    }
}

/// `clone` returns the copy by value, and a move wipes nothing (the module's Security
/// Considerations); `clone_from` copies field by field into a key you hold.
impl Clone for Ed448PrivateKey {
    fn clone(&self) -> Self {
        let mut sk = Self::zeroized();
        sk.clone_from(self);
        sk
    }

    fn clone_from(&mut self, source: &Self) {
        self.private_key.copy_from_slice(&*source.private_key);
        self.expanded.copy_from(&source.expanded);
    }
}

/// Constant-time comparison of the private keys. A key that was never filled equals only
/// another such key.
impl PartialEq for Ed448PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        // The public keys add the filled state to the comparison (an unfilled key and the key
        // decoded from 57 zero octets hold the same octets); they are public.
        ct_eq_bytes(&*self.private_key, &*other.private_key)
            & (self.expanded.public_key() == other.expanded.public_key())
    }
}

impl Eq for Ed448PrivateKey {}

/// An Ed448 public key, fully validated: a point of the curve in the prime-order subgroup,
/// and not the neutral element.
///
/// It is a key of [`Ed448`], and verifies over a whole message through
/// [`OneShotVerifyingKey`]; the view [`as_prehash`](Self::as_prehash) gives verifies
/// [`Ed448ph`] signatures. The key itself has no streaming verifier:
///
/// ```compile_fail,E0599
/// use bouncycastle_core::signature_key::VerifyingKey;
/// use bouncycastle_ec::ed::ed448::Ed448PublicKey;
///
/// fn verifier(pk: &Ed448PublicKey) {
///     let _ = pk.create_verifier(None);
/// }
/// ```
///
/// The validation is done once, by [`from_bytes`](PublicKey::from_bytes), and costs about one
/// variable-time scalar multiplication by the group order, comparable to verifying a signature;
/// verification under a key that exists does not repeat it. Keep the key object rather than
/// its encoding where one key verifies many signatures. The key of an
/// [`Ed448PrivateKey`] comes from [`Ed448PrivateKey::pk`] or [`keygen`] without that cost.
#[derive(Clone)]
pub struct Ed448PublicKey {
    point: PublicPoint,
}

impl Ed448PublicKey {
    /// The pre-hash form of this key, an [`Ed448ph`] verifying key. The view borrows the key and
    /// copies nothing.
    pub fn as_prehash(&self) -> Ed448phPublicKey<'_> {
        Ed448phPublicKey { pk: self }
    }
}

/// The encoding is the 57 octets of RFC 8032 Section 5.2.5: the y-coordinate, little-endian,
/// in the first 56, and the sign of x in the top bit of the last.
impl PublicKey<PUBLIC_KEY_LEN> for Ed448PublicKey {
    fn encode(&self) -> [u8; PUBLIC_KEY_LEN] {
        let mut out = [0u8; PUBLIC_KEY_LEN];
        self.point.encode(&mut out);
        out
    }

    fn encode_out(&self, out: &mut [u8; PUBLIC_KEY_LEN]) -> usize {
        self.point.encode(out);
        PUBLIC_KEY_LEN
    }

    /// Decodes and fully validates a public key: the octets must be the canonical encoding of
    /// a point of the curve (RFC 8032 Section 5.2.3), and the point must have the order of the
    /// base point, so a key of small order or of mixed order is refused, as is the neutral
    /// element. See the type for the cost.
    ///
    /// # Errors
    /// [`KeyDecodingError`] if `bytes` is not 57 octets or fails the validation.
    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyDecodingError> {
        let bytes: &[u8; PUBLIC_KEY_LEN] = bytes
            .try_into()
            .map_err(|_| KeyDecodingError("An Ed448 public key must be 57 bytes"))?;
        let point = PublicPoint::decode_var(bytes).ok_or(KeyDecodingError(
            "Not the encoding of an Ed448 public key in the prime-order subgroup",
        ))?;
        Ok(Self { point })
    }
}

/// Two keys are equal when their encodings are; a key has one encoding.
impl PartialEq for Ed448PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.encode() == other.encode()
    }
}

impl Eq for Ed448PublicKey {}

/// The 57 octets of the encoding in hex.
impl Display for Ed448PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Ed448PublicKey {{ ")?;
        for b in &self.encode() {
            write!(f, "{b:02x}")?;
        }
        write!(f, " }}")
    }
}

/// As [`Display`].
impl Debug for Ed448PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(self, f)
    }
}

/*** Ed448, on the keys: the one-shot roles alone ***/

/// Ed448 signing (RFC 8032 Section 5.2.6). The message is hashed twice, the second time
/// after a value computed from the first, so it is taken whole.
///
/// The errors beyond the role's are [`KeyMaterialError::ActingOnZeroizedKey`] for a key that
/// was never filled, and [`SignatureError::ComputationFault`] if a computed point fails its check,
/// which no input causes; `output` holds zeros after any of them.
impl DeterministicOneShotSigningKey<Ed448, SIGNATURE_LEN> for Ed448PrivateKey {
    fn sign_deterministic_out(
        &self,
        msg: &[u8],
        ctx: Option<&[u8]>,
        output: &mut [u8; SIGNATURE_LEN],
    ) -> Result<usize, SignatureError> {
        output.fill(0);
        self.check_filled()?;
        // `sign` checks the length of the context.
        scheme::sign(&self.expanded, ctx.unwrap_or(&[]), msg, output)?;
        Ok(SIGNATURE_LEN)
    }
}

/// Ed448 verification (RFC 8032 Section 5.2.7), by the cofactored equation. The hash covers
/// part of the signature before the message, so the message is taken whole.
impl OneShotVerifyingKey<Ed448, SIGNATURE_LEN> for Ed448PublicKey {
    fn verify(&self, msg: &[u8], ctx: Option<&[u8]>, sig: &[u8]) -> Result<(), SignatureError> {
        // The context first, so that one that is too long is that error whatever the signature.
        let ctx = ctx.unwrap_or(&[]);
        scheme::check_context(ctx)?;
        scheme::verify(signature_octets(sig)?, &self.point, ctx, msg)
    }
}

fn signature_octets(sig: &[u8]) -> Result<&[u8; SIGNATURE_LEN], SignatureError> {
    sig.try_into().map_err(|_| SignatureError::LengthError("An Ed448 signature is 114 bytes"))
}

/*** Ed448ph, on the views: the streaming roles, and the one-shot roles over their workers ***/

/// A context as a worker holds it: checked against [`CONTEXT_MAX_LEN`] and copied, because the
/// worker outlives the caller's borrow of it. It is public data.
struct Context {
    octets: [u8; CONTEXT_MAX_LEN],
    len: u8,
}

impl Context {
    fn new(ctx: Option<&[u8]>) -> Result<Self, SignatureError> {
        let ctx = ctx.unwrap_or(&[]);
        scheme::check_context(ctx)?;
        let mut octets = [0u8; CONTEXT_MAX_LEN];
        octets[..ctx.len()].copy_from_slice(ctx);
        // The check above bounds the length by 255.
        Ok(Self { octets, len: ctx.len() as u8 })
    }

    fn as_slice(&self) -> &[u8] {
        &self.octets[..usize::from(self.len)]
    }
}

/// An Ed448ph signature in progress (RFC 8032 Section 5.2.6 with PH(x) = SHAKE256(x, 64)):
/// the message is hashed as it arrives and the digest signed at the end. Made by
/// [`DeterministicSigningKey::create_signer_deterministic`] on an [`Ed448phPrivateKey`]; it
/// borrows the [`Ed448PrivateKey`] behind the view.
pub struct Ed448phSigner<'k> {
    sk: &'k Ed448PrivateKey,
    prehash: SHAKE256,
    context: Context,
}

impl Algorithm for Ed448phSigner<'_> {
    const ALG_NAME: &'static str = Ed448ph::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = Ed448ph::MAX_SECURITY_STRENGTH;
}

impl SignatureSigner<SIGNATURE_LEN> for Ed448phSigner<'_> {
    fn do_update(&mut self, msg_chunk: &[u8]) {
        self.prehash.do_update(msg_chunk);
    }

    fn finish_signature_into(
        &mut self,
        token: &FinishToken,
        output: &mut [u8; SIGNATURE_LEN],
    ) -> Result<usize, SignatureError> {
        // PH(M); the message is public, and so is its digest. As a hash SHAKE256 gives its
        // first 64 octets, which is PH, and is finished where it sits. `sign_ph` clears
        // `output` first.
        let mut ph = [0u8; PREHASH_LEN];
        self.prehash.finish_into(token, &mut ph);
        scheme::sign_ph(&self.sk.expanded, self.context.as_slice(), &ph, output)?;
        Ok(SIGNATURE_LEN)
    }
}

/// An Ed448ph verification in progress (RFC 8032 Section 5.2.7 with PH(x) = SHAKE256(x, 64)),
/// by the cofactored equation. Made by [`VerifyingKey::create_verifier`] on an
/// [`Ed448phPublicKey`]; it borrows the [`Ed448PublicKey`] behind the view.
pub struct Ed448phVerifier<'k> {
    pk: &'k Ed448PublicKey,
    prehash: SHAKE256,
    context: Context,
}

impl Algorithm for Ed448phVerifier<'_> {
    const ALG_NAME: &'static str = Ed448ph::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = Ed448ph::MAX_SECURITY_STRENGTH;
}

impl SignatureVerifier for Ed448phVerifier<'_> {
    fn do_update(&mut self, msg_chunk: &[u8]) {
        self.prehash.do_update(msg_chunk);
    }

    fn finish_signature_verify(
        &mut self,
        token: &FinishToken,
        sig: &[u8],
    ) -> Result<(), SignatureError> {
        let mut ph = [0u8; PREHASH_LEN];
        self.prehash.finish_into(token, &mut ph);
        scheme::verify_ph(signature_octets(sig)?, &self.pk.point, self.context.as_slice(), &ph)
    }
}

/// An Ed448ph signing key: the view [`Ed448PrivateKey::as_prehash`] gives of an Ed448 private key,
/// which signs with [`Ed448ph`] through [`DeterministicSigningKey`] and its one-shot role. It
/// is a reference to the key and holds no key material, so copying it copies none. A signer it
/// makes borrows the key, not the view:
///
/// ```
/// use bouncycastle_core::signature_key::DeterministicSigningKey;
/// use bouncycastle_ec::ed::ed448::{Ed448PrivateKey, Ed448phSigner};
///
/// fn signer(sk: &Ed448PrivateKey) -> Ed448phSigner<'_> {
///     sk.as_prehash().create_signer_deterministic(None).unwrap()
/// }
/// ```
///
/// It does not sign with [`Ed448`]:
///
/// ```compile_fail,E0277
/// use bouncycastle_core::signature_key::DeterministicOneShotSigningKey;
/// use bouncycastle_ec::ed::ed448::{Ed448, Ed448PrivateKey};
///
/// fn sign(sk: &Ed448PrivateKey) {
///     let _ = DeterministicOneShotSigningKey::<Ed448, 114>::sign_deterministic(
///         &sk.as_prehash(),
///         b"msg",
///         None,
///     );
/// }
/// ```
#[derive(Clone, Copy)]
pub struct Ed448phPrivateKey<'k> {
    sk: &'k Ed448PrivateKey,
}

/// An Ed448ph verifying key: the view [`Ed448PublicKey::as_prehash`] gives of an Ed448 public key,
/// which verifies [`Ed448ph`] signatures through [`VerifyingKey`] and its one-shot role. It is
/// a reference to the key, and a verifier it makes borrows the key, not the view.
///
/// It does not verify [`Ed448`] signatures:
///
/// ```compile_fail,E0277
/// use bouncycastle_core::signature_key::OneShotVerifyingKey;
/// use bouncycastle_ec::ed::ed448::{Ed448, Ed448PublicKey};
///
/// fn verify(pk: &Ed448PublicKey, sig: &[u8]) {
///     let _ = OneShotVerifyingKey::<Ed448, 114>::verify(&pk.as_prehash(), b"msg", None, sig);
/// }
/// ```
#[derive(Clone, Copy)]
pub struct Ed448phPublicKey<'k> {
    pk: &'k Ed448PublicKey,
}

/// Ed448ph signing, the message taken as it arrives.
///
/// The errors beyond the role's are [`KeyMaterialError::ActingOnZeroizedKey`] from the
/// constructor for a key that was never filled, and [`SignatureError::ComputationFault`] from the
/// signer's final if a computed point fails its check, which no input causes.
impl<'a> DeterministicSigningKey<Ed448ph, SIGNATURE_LEN> for Ed448phPrivateKey<'a> {
    // The signer borrows the key the view refers to, for the key's lifetime and not the
    // view's, so it outlives a view that was a temporary.
    type Signer<'k>
        = Ed448phSigner<'a>
    where
        Self: 'k;

    fn create_signer_deterministic<'k>(
        &'k self,
        ctx: Option<&[u8]>,
    ) -> Result<Self::Signer<'k>, SignatureError> {
        self.sk.check_filled()?;
        Ok(Ed448phSigner { sk: self.sk, prehash: SHAKE256::new(), context: Context::new(ctx)? })
    }
}

impl DeterministicOneShotSigningKey<Ed448ph, SIGNATURE_LEN> for Ed448phPrivateKey<'_> {
    fn sign_deterministic_out(
        &self,
        msg: &[u8],
        ctx: Option<&[u8]>,
        output: &mut [u8; SIGNATURE_LEN],
    ) -> Result<usize, SignatureError> {
        sign_out_with_signer(self.create_signer_deterministic(ctx), msg, output)
    }
}

/// Ed448ph verification, the message taken as it arrives.
impl<'a> VerifyingKey<Ed448ph, SIGNATURE_LEN> for Ed448phPublicKey<'a> {
    // As the signer: the verifier borrows the key, not the view.
    type Verifier<'k>
        = Ed448phVerifier<'a>
    where
        Self: 'k;

    fn create_verifier<'k>(
        &'k self,
        ctx: Option<&[u8]>,
    ) -> Result<Self::Verifier<'k>, SignatureError> {
        Ok(Ed448phVerifier { pk: self.pk, prehash: SHAKE256::new(), context: Context::new(ctx)? })
    }
}

impl OneShotVerifyingKey<Ed448ph, SIGNATURE_LEN> for Ed448phPublicKey<'_> {
    fn verify(&self, msg: &[u8], ctx: Option<&[u8]>, sig: &[u8]) -> Result<(), SignatureError> {
        verify_with_verifier(self.create_verifier(ctx)?, msg, sig)
    }
}
