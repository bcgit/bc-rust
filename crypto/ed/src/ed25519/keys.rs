//! The Ed25519 key objects, the algorithm markers and the signature roles over them.

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
    Algorithm, FinishToken, Hash, PrivateKey, PublicKey, RNG, SignatureSigner, SignatureVerifier,
};
use bouncycastle_sha2::SHA512;
use bouncycastle_utils::ct::ct_eq_bytes;
use bouncycastle_utils::secret::Secret;
use core::fmt::{self, Debug, Display, Formatter};

/// String name of the Ed25519 algorithm.
pub const ED25519_NAME: &str = "Ed25519";
/// String name of the Ed25519ph algorithm.
pub const ED25519PH_NAME: &str = "Ed25519ph";

/// Ed25519 (RFC 8032 Section 5.1), the algorithm that signs the message itself. It takes the
/// whole message at once, so the keys implement only the one-shot roles under this marker:
/// [`DeterministicOneShotSigningKey`] and [`OneShotVerifyingKey`].
///
/// It takes no context (RFC 8032 Section 5.1: "The context (if present at all) MUST be
/// empty"): `None` and `Some(&[])` are accepted, and anything else is a
/// [`SignatureError::LengthError`] from signing and from verification.
///
/// There is no streaming signer or verifier to ask for. These compile under [`Ed25519ph`]:
///
/// ```
/// use bouncycastle_core::signature_key::{DeterministicSigningKey, VerifyingKey};
/// use bouncycastle_ed::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519ph};
///
/// fn signer(sk: &Ed25519PrivateKey) {
///     let _ = DeterministicSigningKey::<Ed25519ph, 64>::create_signer_deterministic(sk, None);
/// }
/// fn verifier(pk: &Ed25519PublicKey) {
///     let _ = VerifyingKey::<Ed25519ph, 64>::create_verifier(pk, None);
/// }
/// ```
///
/// and neither does under this marker:
///
/// ```compile_fail,E0277
/// use bouncycastle_core::signature_key::DeterministicSigningKey;
/// use bouncycastle_ed::ed25519::{Ed25519, Ed25519PrivateKey};
///
/// fn signer(sk: &Ed25519PrivateKey) {
///     let _ = DeterministicSigningKey::<Ed25519, 64>::create_signer_deterministic(sk, None);
/// }
/// ```
///
/// ```compile_fail,E0277
/// use bouncycastle_core::signature_key::VerifyingKey;
/// use bouncycastle_ed::ed25519::{Ed25519, Ed25519PublicKey};
///
/// fn verifier(pk: &Ed25519PublicKey) {
///     let _ = VerifyingKey::<Ed25519, 64>::create_verifier(pk, None);
/// }
/// ```
pub struct Ed25519;

impl Algorithm for Ed25519 {
    const ALG_NAME: &'static str = ED25519_NAME;
    // RFC 8032 Section 8.5: "Ed25519 and Ed25519ph have a nominal strength of 128 bits".
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl SignatureAlgorithm for Ed25519 {}

/// Ed25519ph (RFC 8032 Section 5.1), the algorithm that signs the SHA-512 digest of the
/// message, under a context of at most [`CONTEXT_MAX_LEN`] octets that is empty by default. The
/// message can arrive in pieces, so the keys implement the streaming roles under this marker,
/// [`DeterministicSigningKey`] and [`VerifyingKey`], and the one-shot roles with them.
///
/// An Ed25519ph signature is not an Ed25519 signature of the message or of its digest, and the
/// other way round.
#[allow(non_camel_case_types)]
pub struct Ed25519ph;

impl Algorithm for Ed25519ph {
    const ALG_NAME: &'static str = ED25519PH_NAME;
    // RFC 8032 Section 8.5: "Ed25519 and Ed25519ph have a nominal strength of 128 bits".
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl SignatureAlgorithm for Ed25519ph {}

/// Generates a key pair from `rng`, which must offer Ed25519's 128 bits: the 32 octets it
/// draws are the private key (RFC 8032 Section 5.1.5).
///
/// [`keygen_out`] into a key you hold, moved out of this frame; a move wipes nothing (the
/// module's Security Considerations).
///
/// # Errors
/// [`SignatureError::RNGError`] if the RNG is weaker than the algorithm or fails to deliver;
/// [`SignatureError::GenericError`] if the computed public key fails its check, which no input
/// causes.
pub fn keygen(rng: &mut dyn RNG) -> Result<(Ed25519PublicKey, Ed25519PrivateKey), SignatureError> {
    let mut sk = Ed25519PrivateKey::zeroized();
    let pk = keygen_out(rng, &mut sk)?;
    Ok((pk, sk))
}

/// Generates a private key into `sk`, a key you hold, and returns its public key: the RNG,
/// which must offer Ed25519's 128 bits, writes the 32 octets straight into the key, which is
/// expanded where it sits, so no copy of it is staged on the way. `sk` is zeroized first and
/// left so on every error.
///
/// # Errors
/// As [`keygen`].
pub fn keygen_out(
    rng: &mut dyn RNG,
    sk: &mut Ed25519PrivateKey,
) -> Result<Ed25519PublicKey, SignatureError> {
    sk.clear();
    if rng.security_strength() < Ed25519::MAX_SECURITY_STRENGTH {
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
/// ([`Ed25519PrivateKey::zeroized`]).
pub fn keypair_consistency_check(
    pk: &Ed25519PublicKey,
    sk: &Ed25519PrivateKey,
) -> Result<(), SignatureError> {
    sk.check_filled()?;
    // Both sides are public keys, so the comparison need not be constant time.
    if pk.encode() == *sk.expanded.public_key() {
        Ok(())
    } else {
        Err(SignatureError::ConsistencyCheckFailed)
    }
}

/// An Ed25519 private key: the 32 octets of RFC 8032 Section 5.1.5, any value of which is a
/// valid key, with the secret scalar, the prefix and the public key derived from them.
///
/// The derivation runs once, when the key is generated or decoded, so signing does not repeat
/// it. Everything secret is wiped when the key is dropped, and the type has no `Debug`.
/// One key signs with [`Ed25519`] and with [`Ed25519ph`].
#[derive(Clone)]
pub struct Ed25519PrivateKey {
    /// The private key as RFC 8032 has it, kept for the encoding.
    private_key: Secret<[u8; PRIVATE_KEY_LEN]>,
    /// What signing uses: RFC 8032 Section 5.1.6, step 1, done ahead, and the public key.
    expanded: ExpandedKey,
}

impl Ed25519PrivateKey {
    /// The all-zero key: the key [`keygen_out`] writes into, so that the private key is drawn
    /// where it will live and never moved. It is not a generated key: until `keygen_out` fills
    /// it, it has no public key and signs nothing
    /// ([`KeyMaterialError::ActingOnZeroizedKey`]), and it is equal to no key that was
    /// generated or decoded.
    ///
    /// # 🚨 Security Considerations 🚨
    ///
    /// The encoding of this key is not refused, the encoding methods having no error to give:
    /// it is 32 zero octets, which decode as a working key anyone can compute. Do not store or
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

    /// The public key (RFC 8032 Section 5.1.5). It was computed when this key was made; this
    /// puts it in the form verification uses, at the cost of a square root in the field, with
    /// no scalar multiplication.
    ///
    /// # Errors
    /// [`KeyMaterialError::ActingOnZeroizedKey`] for a key that was never filled
    /// ([`zeroized`](Self::zeroized)).
    pub fn pk(&self) -> Result<Ed25519PublicKey, SignatureError> {
        // `None` is the unfilled key: the stored encoding of a filled one always decodes.
        let point = self.expanded.public_point().ok_or(KeyMaterialError::ActingOnZeroizedKey)?;
        Ok(Ed25519PublicKey { point })
    }
}

/// The encoding is the 32 octets of the private key as RFC 8032 Section 5.1.5 defines it (the
/// "seed" of some other libraries), not the scalar derived from it.
impl PrivateKey<PRIVATE_KEY_LEN> for Ed25519PrivateKey {
    /// The private key as a plain array, the trait's contract; prefer `encode_out` into a
    /// buffer you own, since the array is moved out unwiped.
    fn encode(&self) -> [u8; PRIVATE_KEY_LEN] {
        *self.private_key
    }

    fn encode_out(&self, out: &mut [u8; PRIVATE_KEY_LEN]) -> usize {
        *out = *self.private_key;
        PRIVATE_KEY_LEN
    }

    /// Any 32 octets are a valid private key. Decoding derives the public key, which costs a
    /// fixed-base scalar multiplication.
    ///
    /// # Errors
    /// [`KeyDecodingError`] if `bytes` is not 32 octets, or if the computed public key fails
    /// its check, which no input causes.
    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyDecodingError> {
        let bytes: &[u8; PRIVATE_KEY_LEN] = bytes
            .try_into()
            .map_err(|_| KeyDecodingError("An Ed25519 private key must be 32 bytes"))?;
        let mut sk = Self::zeroized();
        *sk.private_key = *bytes;
        if sk.expanded.expand(&sk.private_key).is_err() {
            // The fault path of key expansion; this trait's error carries no other kind.
            sk.clear();
            return Err(KeyDecodingError("Ed25519: a computed point failed its check"));
        }
        Ok(sk)
    }
}

/// Constant-time comparison of the private keys. A key that was never filled equals only
/// another such key.
impl PartialEq for Ed25519PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        // The public keys add the filled state to the comparison (an unfilled key and the key
        // decoded from 32 zero octets hold the same octets); they are public.
        ct_eq_bytes(&*self.private_key, &*other.private_key)
            & (self.expanded.public_key() == other.expanded.public_key())
    }
}

impl Eq for Ed25519PrivateKey {}

/// An Ed25519 public key, fully validated: a point of the curve in the prime-order subgroup,
/// and not the neutral element. One key verifies [`Ed25519`] and [`Ed25519ph`] signatures.
///
/// The validation is done once, by [`from_bytes`](PublicKey::from_bytes), and costs about one
/// variable-time scalar multiplication by the group order, comparable to verifying a signature;
/// verification under a key that exists does not repeat it. Keep the key object rather than
/// its encoding where one key verifies many signatures. The key of an
/// [`Ed25519PrivateKey`] comes from [`Ed25519PrivateKey::pk`] or [`keygen`] without that cost.
#[derive(Clone)]
pub struct Ed25519PublicKey {
    point: PublicPoint,
}

/// The encoding is the 32 octets of RFC 8032 Section 5.1.5: the y-coordinate, little-endian,
/// with the sign of x in the top bit.
impl PublicKey<PUBLIC_KEY_LEN> for Ed25519PublicKey {
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
    /// a point of the curve (RFC 8032 Section 5.1.3), and the point must have the order of the
    /// base point, so a key of small order or of mixed order is refused, as is the neutral
    /// element. See the type for the cost.
    ///
    /// # Errors
    /// [`KeyDecodingError`] if `bytes` is not 32 octets or fails the validation.
    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyDecodingError> {
        let bytes: &[u8; PUBLIC_KEY_LEN] = bytes
            .try_into()
            .map_err(|_| KeyDecodingError("An Ed25519 public key must be 32 bytes"))?;
        let point = PublicPoint::decode_var(bytes).ok_or(KeyDecodingError(
            "Not the encoding of an Ed25519 public key in the prime-order subgroup",
        ))?;
        Ok(Self { point })
    }
}

/// Two keys are equal when their encodings are; a key has one encoding.
impl PartialEq for Ed25519PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.encode() == other.encode()
    }
}

impl Eq for Ed25519PublicKey {}

/// The 32 octets of the encoding in hex.
impl Display for Ed25519PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519PublicKey {{ ")?;
        for b in &self.encode() {
            write!(f, "{b:02x}")?;
        }
        write!(f, " }}")
    }
}

/// As [`Display`].
impl Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(self, f)
    }
}

/*** Ed25519: the one-shot roles alone ***/

/// RFC 8032 Section 5.1, of Ed25519: "The context (if present at all) MUST be empty."
fn refuse_context(ctx: Option<&[u8]>) -> Result<(), SignatureError> {
    match ctx {
        Some(ctx) if !ctx.is_empty() => {
            Err(SignatureError::LengthError("Ed25519 takes no context; Ed25519ph takes one"))
        }
        _ => Ok(()),
    }
}

/// Ed25519 signing (RFC 8032 Section 5.1.6). The message is hashed twice, the second time
/// after a value computed from the first, so it is taken whole.
///
/// The errors beyond the role's are [`KeyMaterialError::ActingOnZeroizedKey`] for a key that
/// was never filled, and [`SignatureError::GenericError`] if a computed point fails its check,
/// which no input causes; `output` holds zeros after any of them.
impl DeterministicOneShotSigningKey<Ed25519, SIGNATURE_LEN> for Ed25519PrivateKey {
    fn sign_deterministic_out(
        &self,
        msg: &[u8],
        ctx: Option<&[u8]>,
        output: &mut [u8; SIGNATURE_LEN],
    ) -> Result<usize, SignatureError> {
        output.fill(0);
        refuse_context(ctx)?;
        self.check_filled()?;
        scheme::sign(&self.expanded, msg, output)?;
        Ok(SIGNATURE_LEN)
    }
}

/// Ed25519 verification (RFC 8032 Section 5.1.7), by the cofactored equation. The hash covers
/// part of the signature before the message, so the message is taken whole.
impl OneShotVerifyingKey<Ed25519, SIGNATURE_LEN> for Ed25519PublicKey {
    fn verify(&self, msg: &[u8], ctx: Option<&[u8]>, sig: &[u8]) -> Result<(), SignatureError> {
        refuse_context(ctx)?;
        scheme::verify(signature_octets(sig)?, &self.point, msg)
    }
}

fn signature_octets(sig: &[u8]) -> Result<&[u8; SIGNATURE_LEN], SignatureError> {
    sig.try_into().map_err(|_| SignatureError::LengthError("An Ed25519 signature is 64 bytes"))
}

/*** Ed25519ph: the streaming roles, and the one-shot roles over their workers ***/

/// A context as a worker holds it: checked against [`CONTEXT_MAX_LEN`] and copied, because the
/// worker outlives the caller's borrow of it. It is public data.
struct Context {
    octets: [u8; CONTEXT_MAX_LEN],
    len: u8,
}

impl Context {
    fn new(ctx: Option<&[u8]>) -> Result<Self, SignatureError> {
        scheme::check_context(ctx)?;
        let ctx = ctx.unwrap_or(&[]);
        let mut octets = [0u8; CONTEXT_MAX_LEN];
        octets[..ctx.len()].copy_from_slice(ctx);
        // The check above bounds the length by 255.
        Ok(Self { octets, len: ctx.len() as u8 })
    }

    fn as_slice(&self) -> &[u8] {
        &self.octets[..usize::from(self.len)]
    }
}

/// An Ed25519ph signature in progress (RFC 8032 Section 5.1.6 with PH = SHA-512): the message
/// is hashed as it arrives and the digest signed at the end. Made by
/// [`DeterministicSigningKey::create_signer_deterministic`] on an [`Ed25519PrivateKey`], which
/// it borrows.
pub struct Ed25519phSigner<'k> {
    sk: &'k Ed25519PrivateKey,
    prehash: SHA512,
    context: Context,
}

impl Algorithm for Ed25519phSigner<'_> {
    const ALG_NAME: &'static str = Ed25519ph::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = Ed25519ph::MAX_SECURITY_STRENGTH;
}

impl SignatureSigner<SIGNATURE_LEN> for Ed25519phSigner<'_> {
    fn do_update(&mut self, msg_chunk: &[u8]) {
        self.prehash.do_update(msg_chunk);
    }

    fn finish_signature_into(
        &mut self,
        token: &FinishToken,
        output: &mut [u8; SIGNATURE_LEN],
    ) -> Result<usize, SignatureError> {
        // PH(M); the message is public, and so is its digest. `sign_ph` clears `output` first.
        let mut ph = [0u8; PREHASH_LEN];
        self.prehash.finish_into(token, &mut ph);
        scheme::sign_ph(&self.sk.expanded, self.context.as_slice(), &ph, output)?;
        Ok(SIGNATURE_LEN)
    }
}

/// An Ed25519ph verification in progress (RFC 8032 Section 5.1.7 with PH = SHA-512), by the
/// cofactored equation. Made by [`VerifyingKey::create_verifier`] on an [`Ed25519PublicKey`],
/// which it borrows.
pub struct Ed25519phVerifier<'k> {
    pk: &'k Ed25519PublicKey,
    prehash: SHA512,
    context: Context,
}

impl Algorithm for Ed25519phVerifier<'_> {
    const ALG_NAME: &'static str = Ed25519ph::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = Ed25519ph::MAX_SECURITY_STRENGTH;
}

impl SignatureVerifier for Ed25519phVerifier<'_> {
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

/// Ed25519ph signing, the message taken as it arrives.
///
/// The errors beyond the role's are [`KeyMaterialError::ActingOnZeroizedKey`] from the
/// constructor for a key that was never filled, and [`SignatureError::GenericError`] from the
/// signer's final if a computed point fails its check, which no input causes.
impl DeterministicSigningKey<Ed25519ph, SIGNATURE_LEN> for Ed25519PrivateKey {
    type Signer<'k>
        = Ed25519phSigner<'k>
    where
        Self: 'k;

    fn create_signer_deterministic<'k>(
        &'k self,
        ctx: Option<&[u8]>,
    ) -> Result<Self::Signer<'k>, SignatureError> {
        self.check_filled()?;
        Ok(Ed25519phSigner { sk: self, prehash: SHA512::new(), context: Context::new(ctx)? })
    }
}

impl DeterministicOneShotSigningKey<Ed25519ph, SIGNATURE_LEN> for Ed25519PrivateKey {
    fn sign_deterministic_out(
        &self,
        msg: &[u8],
        ctx: Option<&[u8]>,
        output: &mut [u8; SIGNATURE_LEN],
    ) -> Result<usize, SignatureError> {
        let signer =
            DeterministicSigningKey::<Ed25519ph, SIGNATURE_LEN>::create_signer_deterministic(
                self, ctx,
            );
        sign_out_with_signer(signer, msg, output)
    }
}

/// Ed25519ph verification, the message taken as it arrives.
impl VerifyingKey<Ed25519ph, SIGNATURE_LEN> for Ed25519PublicKey {
    type Verifier<'k>
        = Ed25519phVerifier<'k>
    where
        Self: 'k;

    fn create_verifier<'k>(
        &'k self,
        ctx: Option<&[u8]>,
    ) -> Result<Self::Verifier<'k>, SignatureError> {
        Ok(Ed25519phVerifier { pk: self, prehash: SHA512::new(), context: Context::new(ctx)? })
    }
}

impl OneShotVerifyingKey<Ed25519ph, SIGNATURE_LEN> for Ed25519PublicKey {
    fn verify(&self, msg: &[u8], ctx: Option<&[u8]>, sig: &[u8]) -> Result<(), SignatureError> {
        let verifier = VerifyingKey::<Ed25519ph, SIGNATURE_LEN>::create_verifier(self, ctx)?;
        verify_with_verifier(verifier, msg, sig)
    }
}
