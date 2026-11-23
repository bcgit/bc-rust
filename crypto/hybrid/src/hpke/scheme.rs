//! Hybrid Public Key Encryption (RFC 9180 Sections 5 and 6) in its four modes: the key
//! schedule, the sender's and the recipient's encryption context, secret export and the
//! single-shot forms, over any KEM whose keys carry the
//! [`EncapsulatingKey`] and [`DecapsulatingKey`] roles with `()` as their parameters and whose
//! algorithm is an [`HpkeKem`].
//!
//! A suite is the KEM of the key, a KDF ([`HpkeKdf`]: `SHA256`, `SHA384` or `SHA512`, for HKDF
//! over that hash) and an AEAD ([`HpkeAead`]: `AES128Key<GCM>`, `AES256Key<GCM>`,
//! `ChaCha20Poly1305Key`, or [`ExportOnly`]); the last two are named by [`HpkeParams`].
//!
//! The Base and PSK modes are [`HpkeSender`] and [`HpkeRecipient`]; the Auth and AuthPSK modes
//! (Sections 5.1.3 and 5.1.4), which also take the sender's key pair, are [`HpkeAuthSender`]
//! and [`HpkeAuthRecipient`], on keys whose KEM has `AuthEncap` and `AuthDecap`.

use bouncycastle_core::errors::{KEMError, KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey, FromKeyMaterial};
use bouncycastle_core::traits::{HashAlgParams, RNG};
use bouncycastle_dhkem::hazmat::{self as labeled, MAX_NH};
use bouncycastle_dhkem::{AuthDecapsulatingKey, AuthEncapsulatingKey, HpkeKem};
use bouncycastle_digest::hmac::HMACParams;
use bouncycastle_digest::sha2::{SHA256, SHA384, SHA512};
use bouncycastle_symmetric::aes::{AES128Key, AES256Key};
use bouncycastle_symmetric::chacha20_poly1305_aead::ChaCha20Poly1305Key;
use bouncycastle_symmetric::modes::GCM;
use bouncycastle_utils::secret::Secret;
use core::marker::PhantomData;

/// Nn, the nonce length of every AEAD of RFC 9180 Section 7.3, Table 5.
pub const NN: usize = 12;
/// Nt, the tag length of every AEAD of RFC 9180 Section 7.3, Table 5: a ciphertext is this much
/// longer than its plaintext.
pub const NT: usize = 16;

/// The largest Nk among the AEADs of RFC 9180 Section 7.3, Table 5.
const MAX_NK: usize = 32;

// The modes of RFC 9180 Section 5, Table 1.
const MODE_BASE: u8 = 0x00;
const MODE_PSK: u8 = 0x01;
const MODE_AUTH: u8 = 0x02;
const MODE_AUTH_PSK: u8 = 0x03;

// The labels of RFC 9180 Sections 5.1 and 5.3.
const LABEL_PSK_ID_HASH: &[u8] = b"psk_id_hash";
const LABEL_INFO_HASH: &[u8] = b"info_hash";
const LABEL_SECRET: &[u8] = b"secret";
const LABEL_KEY: &[u8] = b"key";
const LABEL_BASE_NONCE: &[u8] = b"base_nonce";
const LABEL_EXP: &[u8] = b"exp";
const LABEL_SEC: &[u8] = b"sec";

/// Errors of HPKE setup, encryption and decryption.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HpkeError {
    /// The KEM refused the encapsulation or the decapsulation.
    KEMError(KEMError),
    /// The AEAD failed: on the recipient's side, most often
    /// [`SymmetricCipherError::AEADTagCheckFailed`], for a ciphertext, `aad` or position in the
    /// sequence that is not the sender's.
    AEADError(SymmetricCipherError),
    /// The context has sealed or opened as many messages as its sequence number counts (RFC 9180
    /// Section 5.2's `MessageLimitReachedError`).
    MessageLimitReached,
    /// The pre-shared key or its identifier is not usable (RFC 9180 Sections 5.1 and 9.5).
    InvalidPsk(&'static str),
}

impl From<KEMError> for HpkeError {
    fn from(e: KEMError) -> Self {
        Self::KEMError(e)
    }
}

impl From<SymmetricCipherError> for HpkeError {
    fn from(e: SymmetricCipherError) -> Self {
        Self::AEADError(e)
    }
}

mod sealed {
    pub trait Sealed {}
}

/// A KDF of RFC 9180 Section 7.2, Table 3, named by its hash: HKDF over `SHA256`, `SHA384` or
/// `SHA512`.
pub trait HpkeKdf: HMACParams + sealed::Sealed {
    /// The `kdf_id`.
    const KDF_ID: u16;
}

impl sealed::Sealed for SHA256 {}
impl HpkeKdf for SHA256 {
    const KDF_ID: u16 = 0x0001;
}

impl sealed::Sealed for SHA384 {}
impl HpkeKdf for SHA384 {
    const KDF_ID: u16 = 0x0002;
}

impl sealed::Sealed for SHA512 {}
impl HpkeKdf for SHA512 {
    const KDF_ID: u16 = 0x0003;
}

/// An AEAD of RFC 9180 Section 7.3, Table 5, named by its key type, or [`ExportOnly`].
pub trait HpkeAead: Sized + sealed::Sealed {
    /// The `aead_id`.
    const AEAD_ID: u16;
    /// Nk, the key length; 0 for [`ExportOnly`].
    const NK: usize;

    /// The key object for the `NK` bytes the key schedule derived.
    #[doc(hidden)]
    fn from_key_bytes(key: &[u8]) -> Result<Self, SymmetricCipherError>;
}

/// An [`HpkeAead`] that encrypts: every one but [`ExportOnly`].
pub trait HpkeCipher: HpkeAead {
    /// `Seal(key, nonce, aad, pt)` (RFC 9180 Section 4) into `ct`; returns the bytes written.
    #[doc(hidden)]
    fn aead_seal_out(
        &self,
        nonce: &[u8; NN],
        aad: &[u8],
        pt: &[u8],
        ct: &mut [u8],
    ) -> Result<usize, SymmetricCipherError>;

    /// `Open(key, nonce, aad, ct)` (RFC 9180 Section 4) into `pt`; returns the bytes written.
    #[doc(hidden)]
    fn aead_open_out(
        &self,
        nonce: &[u8; NN],
        aad: &[u8],
        ct: &[u8],
        pt: &mut [u8],
    ) -> Result<usize, SymmetricCipherError>;
}

/// The key object of `K` over `key`, typed as `K` requires and at the strength its length
/// carries. The suite's own strength is what [`HpkeContext::export_out`] reports; this key never
/// leaves the context.
fn aead_key<K: FromKeyMaterial<N>, const N: usize>(key: &[u8]) -> Result<K, SymmetricCipherError> {
    let key = KeyMaterial::<N>::from_bytes_as_type(key, K::KEY_TYPE)?;
    K::from_key_material(&key)
}

impl sealed::Sealed for AES128Key<GCM> {}
impl HpkeAead for AES128Key<GCM> {
    const AEAD_ID: u16 = 0x0001;
    const NK: usize = 16;

    fn from_key_bytes(key: &[u8]) -> Result<Self, SymmetricCipherError> {
        aead_key::<Self, 16>(key)
    }
}

impl HpkeCipher for AES128Key<GCM> {
    fn aead_seal_out(
        &self,
        nonce: &[u8; NN],
        aad: &[u8],
        pt: &[u8],
        ct: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        self.encrypt_with_aad_nonce_out(nonce, aad, pt, ct)
    }

    fn aead_open_out(
        &self,
        nonce: &[u8; NN],
        aad: &[u8],
        ct: &[u8],
        pt: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        self.decrypt_with_aad_out(nonce, aad, ct, pt)
    }
}

impl sealed::Sealed for AES256Key<GCM> {}
impl HpkeAead for AES256Key<GCM> {
    const AEAD_ID: u16 = 0x0002;
    const NK: usize = 32;

    fn from_key_bytes(key: &[u8]) -> Result<Self, SymmetricCipherError> {
        aead_key::<Self, 32>(key)
    }
}

impl HpkeCipher for AES256Key<GCM> {
    fn aead_seal_out(
        &self,
        nonce: &[u8; NN],
        aad: &[u8],
        pt: &[u8],
        ct: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        self.encrypt_with_aad_nonce_out(nonce, aad, pt, ct)
    }

    fn aead_open_out(
        &self,
        nonce: &[u8; NN],
        aad: &[u8],
        ct: &[u8],
        pt: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        self.decrypt_with_aad_out(nonce, aad, ct, pt)
    }
}

impl sealed::Sealed for ChaCha20Poly1305Key {}
impl HpkeAead for ChaCha20Poly1305Key {
    const AEAD_ID: u16 = 0x0003;
    const NK: usize = 32;

    fn from_key_bytes(key: &[u8]) -> Result<Self, SymmetricCipherError> {
        aead_key::<Self, 32>(key)
    }
}

impl HpkeCipher for ChaCha20Poly1305Key {
    fn aead_seal_out(
        &self,
        nonce: &[u8; NN],
        aad: &[u8],
        pt: &[u8],
        ct: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        self.encrypt_with_aad_nonce_out(nonce, aad, pt, ct)
    }

    fn aead_open_out(
        &self,
        nonce: &[u8; NN],
        aad: &[u8],
        ct: &[u8],
        pt: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        self.decrypt_with_aad_out(nonce, aad, ct, pt)
    }
}

/// The export-only AEAD of RFC 9180 Section 7.3, Table 5 (`aead_id` 0xFFFF), "reserved for
/// applications that only use the Export interface": a context over it has no `seal_out` or
/// `open_out`, and its key schedule derives no key and no nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportOnly;

impl sealed::Sealed for ExportOnly {}
impl HpkeAead for ExportOnly {
    const AEAD_ID: u16 = 0xFFFF;
    const NK: usize = 0;

    fn from_key_bytes(_key: &[u8]) -> Result<Self, SymmetricCipherError> {
        Ok(ExportOnly)
    }
}

/// A pre-shared key and its identifier, for the PSK mode (RFC 9180 Section 5.1.2).
#[derive(Clone, Copy)]
pub struct Psk<'p> {
    psk: &'p dyn KeyMaterialTrait,
    psk_id: &'p [u8],
}

impl<'p> Psk<'p> {
    /// The pre-shared key `psk` under the identifier `psk_id`.
    ///
    /// # Errors
    /// [`HpkeError::InvalidPsk`] if `psk_id` is empty (Section 5.1: "the psk and psk_id fields
    /// MUST appear together or not at all"), or if `psk` is shorter than 32 bytes or carries
    /// less than [`SecurityStrength::_256bit`] (Section 9.5: "the PSK MUST have at least 32 bytes
    /// of entropy").
    pub fn new(psk: &'p dyn KeyMaterialTrait, psk_id: &'p [u8]) -> Result<Self, HpkeError> {
        if psk_id.is_empty() {
            return Err(HpkeError::InvalidPsk("the PSK identifier is empty"));
        }
        if psk.key_len() < 32 || psk.security_strength() < SecurityStrength::_256bit {
            return Err(HpkeError::InvalidPsk("the PSK must carry 32 bytes of entropy"));
        }
        Ok(Self { psk, psk_id })
    }
}

/// The parameters of an HPKE setup: the KDF `H` and the AEAD `A` of the suite, the application's
/// `info`, and the pre-shared key if there is one. The mode is Base without a PSK and PSK with
/// one (RFC 9180 Section 5, Table 1), or Auth and AuthPSK when the setup is one of
/// [`HpkeAuthSender`]'s or [`HpkeAuthRecipient`]'s.
pub struct HpkeParams<'p, H, A> {
    info: &'p [u8],
    psk: Option<Psk<'p>>,
    _suite: PhantomData<(H, A)>,
}

// Not derived: the derive would ask `H: Clone` and `A: Clone`, and an AEAD key need not be.
impl<H, A> Clone for HpkeParams<'_, H, A> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<H, A> Copy for HpkeParams<'_, H, A> {}

impl<'p, H: HpkeKdf, A: HpkeAead> HpkeParams<'p, H, A> {
    /// Base mode with the application-supplied `info` (RFC 9180 Section 5.1), which may be
    /// empty.
    pub fn new(info: &'p [u8]) -> Self {
        Self { info, psk: None, _suite: PhantomData }
    }

    /// PSK mode: the same parameters with the pre-shared key `psk`.
    pub fn with_psk(self, psk: Psk<'p>) -> Self {
        Self { psk: Some(psk), ..self }
    }
}

/// The sender's role of an [`HpkeContext`]: it seals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sender;

/// The recipient's role of an [`HpkeContext`]: it opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recipient;

/// The encryption context of RFC 9180 Section 5.2 in the role `Dir`, [`Sender`] or
/// [`Recipient`]: what a setup returns, and what seals or opens the messages of one exchange in
/// order and exports secrets from it.
///
/// A sender's context has `seal_out` and a recipient's `open_out`, so that neither can be used
/// in the other direction (Section 5.2: "the sender's context MUST NOT be used for decryption.
/// Similarly, the recipient's context MUST NOT be used for encryption"):
///
/// ```compile_fail
/// use bouncycastle_symmetric::aes::AES128Key;
/// use bouncycastle_symmetric::modes::GCM;
/// use bouncycastle_ed::x25519::keygen;
/// use bouncycastle_hybrid::hpke::{HpkeParams, HpkeSender};
/// use bouncycastle_rng::HashDRBG_SHA512;
/// use bouncycastle_digest::sha2::SHA256;
///
/// let mut rng = HashDRBG_SHA512::new_from_os();
/// let (pk, _sk) = keygen(&mut rng).unwrap();
/// let params = HpkeParams::<SHA256, AES128Key<GCM>>::new(b"");
/// let (_enc, mut sender) = pk.setup_sender(&mut rng, params).unwrap();
/// let mut pt = [0u8; 16];
/// sender.open_out(b"", &[0u8; 32], &mut pt);
/// ```
///
/// The key, the base nonce and the exporter secret are wiped when the context is dropped.
///
/// # 🚨 Security Considerations 🚨
///
/// The messages of a context must be opened in the order they were sealed: the nonce of each is
/// derived from its position, and nothing in a ciphertext says which position it had (Section
/// 5.2: "it is up to the application to ensure that encryptions and decryptions are done in the
/// proper sequence").
pub struct HpkeContext<Dir, H: HpkeKdf, A: HpkeAead> {
    aead: A,
    base_nonce: Secret<[u8; NN]>,
    // Section 5.2: "implementations MAY use a sequence number that is shorter than the nonce
    // length (padding on the left with zero), but MUST raise an error if the sequence number
    // overflows".
    seq: u64,
    // The PRK of Export's LabeledExpand, held as the MAC key that expand takes.
    exporter_secret: KeyMaterial<MAX_NH>,
    suite_id: [u8; 10],
    // What an exported secret is credited with: the lesser of the KEM's and the KDF's.
    strength: SecurityStrength,
    _role: PhantomData<(Dir, H)>,
}

impl<Dir, H: HpkeKdf, A: HpkeAead> HpkeContext<Dir, H, A> {
    /// Checked when a context is made, so a hash this module's buffers cannot hold fails to
    /// compile.
    const PARAMS_CHECK: () = {
        assert!(<H as HashAlgParams>::OUTPUT_LEN <= MAX_NH, "the KDF's hash exceeds MAX_NH");
        assert!(A::NK <= MAX_NK, "the AEAD's key exceeds MAX_NK");
    };

    /// `KeySchedule<ROLE>(mode, shared_secret, info, psk, psk_id)` (RFC 9180 Section 5.1) for
    /// the KEM `K`. `VerifyPSKInputs` has nothing to check: [`Psk`] holds the pair or there is
    /// none, and the mode is read off that and off `auth`, whether the shared secret came from
    /// the KEM's authenticated form.
    fn key_schedule<K: HpkeKem>(
        auth: bool,
        shared_secret: &[u8],
        params: &HpkeParams<'_, H, A>,
    ) -> Result<Self, HpkeError> {
        let () = Self::PARAMS_CHECK;
        // suite_id = concat("HPKE", I2OSP(kem_id, 2), I2OSP(kdf_id, 2), I2OSP(aead_id, 2))
        let kem_id = K::KEM_ID.to_be_bytes();
        let kdf_id = H::KDF_ID.to_be_bytes();
        let aead_id = A::AEAD_ID.to_be_bytes();
        #[rustfmt::skip]
        let suite_id = [
            b'H', b'P', b'K', b'E',
            kem_id[0], kem_id[1], kdf_id[0], kdf_id[1], aead_id[0], aead_id[1],
        ];
        // default_psk = "", default_psk_id = ""
        let (mode, psk, psk_id): (u8, &[u8], &[u8]) = match (&params.psk, auth) {
            (None, false) => (MODE_BASE, &[], &[]),
            (Some(psk), false) => (MODE_PSK, psk.psk.ref_to_bytes(), psk.psk_id),
            (None, true) => (MODE_AUTH, &[], &[]),
            (Some(psk), true) => (MODE_AUTH_PSK, psk.psk.ref_to_bytes(), psk.psk_id),
        };
        let nh = <H as HashAlgParams>::OUTPUT_LEN;
        let no_salt = labeled::salt_key::<H>(&[]);

        // psk_id_hash = LabeledExtract("", "psk_id_hash", psk_id)
        let mut psk_id_hash = [0u8; MAX_NH];
        labeled::labeled_extract_out(
            &suite_id,
            &no_salt,
            LABEL_PSK_ID_HASH,
            &[psk_id],
            &mut psk_id_hash,
        );
        // info_hash = LabeledExtract("", "info_hash", info)
        let mut info_hash = [0u8; MAX_NH];
        labeled::labeled_extract_out(
            &suite_id,
            &no_salt,
            LABEL_INFO_HASH,
            &[params.info],
            &mut info_hash,
        );
        // key_schedule_context = concat(mode, psk_id_hash, info_hash), kept as its parts.
        let key_schedule_context: [&[u8]; 3] = [&[mode], &psk_id_hash[..nh], &info_hash[..nh]];

        // secret = LabeledExtract(shared_secret, "secret", psk)
        let mut secret = KeyMaterial::<MAX_NH>::new();
        labeled::labeled_extract_prk_into(
            &suite_id,
            &labeled::salt_key::<H>(shared_secret),
            LABEL_SECRET,
            &[psk],
            &mut secret,
        );

        let mut key = Secret::<[u8; MAX_NK]>::new();
        let mut base_nonce = Secret::<[u8; NN]>::new();
        // Section 5.3: an export-only suite "can avoid computing the key and base_nonce values".
        if A::NK > 0 {
            // key = LabeledExpand(secret, "key", key_schedule_context, Nk)
            labeled::labeled_expand::<H>(
                &suite_id,
                &secret,
                LABEL_KEY,
                &key_schedule_context,
                &mut key[..A::NK],
            );
            // base_nonce = LabeledExpand(secret, "base_nonce", key_schedule_context, Nn)
            labeled::labeled_expand::<H>(
                &suite_id, &secret, LABEL_BASE_NONCE, &key_schedule_context, &mut *base_nonce,
            );
        }
        // exporter_secret = LabeledExpand(secret, "exp", key_schedule_context, Nh)
        let mut exp = Secret::<[u8; MAX_NH]>::new();
        labeled::labeled_expand::<H>(
            &suite_id,
            &secret,
            LABEL_EXP,
            &key_schedule_context,
            &mut exp[..nh],
        );
        let mut exporter_secret = KeyMaterial::<MAX_NH>::new();
        // Fails only for an all-zero value, one HMAC output in 2^(8 * Nh), which Export's HMAC
        // key would then refuse. Not reachable in practice; a panic is the right report for it.
        exporter_secret
            .set_bytes_as_type(&exp[..nh], KeyType::MACKey)
            .expect("an all-zero exporter secret, one HMAC output in 2^(8 * Nh)");

        let strength = if K::MAX_SECURITY_STRENGTH < H::HMAC_MAX_SECURITY_STRENGTH {
            K::MAX_SECURITY_STRENGTH
        } else {
            H::HMAC_MAX_SECURITY_STRENGTH
        };
        // return Context<ROLE>(key, base_nonce, 0, exporter_secret)
        Ok(Self {
            aead: A::from_key_bytes(&key[..A::NK])?,
            base_nonce,
            seq: 0,
            exporter_secret,
            suite_id,
            strength,
            _role: PhantomData,
        })
    }

    /// `Context.Export(exporter_context, L)` (RFC 9180 Section 5.3) into `out`: `L` bytes, a
    /// [`KeyType::CryptographicRandom`] key at the lesser of what `L` bytes carry and the suite's
    /// strength (the KEM's, capped by the KDF's). Returns `L`. The same context and
    /// `exporter_context` always give the same secret, whatever has been sealed or opened.
    ///
    /// `L` is at most 255*Nh (Section 5.3), which is checked when the call is compiled, so
    /// 8161 bytes under HKDF-SHA256 (255 * 32 = 8160) does not build:
    ///
    /// ```compile_fail
    /// use bouncycastle_symmetric::aes::AES128Key;
    /// use bouncycastle_symmetric::modes::GCM;
    /// use bouncycastle_core::key_material::KeyMaterial;
    /// use bouncycastle_ed::x25519::keygen;
    /// use bouncycastle_hybrid::hpke::{HpkeParams, HpkeSender};
    /// use bouncycastle_rng::HashDRBG_SHA512;
    /// use bouncycastle_digest::sha2::SHA256;
    ///
    /// let mut rng = HashDRBG_SHA512::new_from_os();
    /// let (pk, _sk) = keygen(&mut rng).unwrap();
    /// let params = HpkeParams::<SHA256, AES128Key<GCM>>::new(b"");
    /// let (_enc, sender) = pk.setup_sender(&mut rng, params).unwrap();
    /// sender.export_out(b"", &mut KeyMaterial::<8161>::new());
    /// ```
    pub fn export_out<const L: usize>(
        &self,
        exporter_context: &[u8],
        out: &mut KeyMaterial<L>,
    ) -> usize {
        const {
            assert!(L <= 255 * <H as HashAlgParams>::OUTPUT_LEN, "L is at most 255*Nh");
        }
        out.zeroize();
        // return LabeledExpand(self.exporter_secret, "sec", exporter_context, L)
        let mut bytes = Secret::<[u8; L]>::new();
        labeled::labeled_expand::<H>(
            &self.suite_id,
            &self.exporter_secret,
            LABEL_SEC,
            &[exporter_context],
            &mut *bytes,
        );
        // An all-zero output is typed Zeroized by the buffer and carries no strength; that is
        // not an error. Nothing else can fail: L bytes fit the buffer.
        match out.set_bytes_as_type(&*bytes, KeyType::CryptographicRandom) {
            Ok(()) | Err(KeyMaterialError::ActingOnZeroizedKey) => {}
            Err(_) => unreachable!("L bytes fit a KeyMaterial<L>"),
        }
        if out.security_strength() > self.strength {
            // Cannot fail: the strength is lowered from what the length carries, never raised.
            out.set_security_strength(self.strength).expect("a strength below the length's");
        }
        L
    }
}

impl<Dir, H: HpkeKdf, A: HpkeCipher> HpkeContext<Dir, H, A> {
    /// The length of the ciphertext of a `plaintext_len`-byte plaintext: Nt more.
    pub const fn seal_out_len(plaintext_len: usize) -> usize {
        plaintext_len + NT
    }

    /// The length of the plaintext of a `ciphertext_len`-byte ciphertext: Nt fewer, and zero
    /// for a ciphertext shorter than that, which does not open.
    pub const fn open_out_len(ciphertext_len: usize) -> usize {
        ciphertext_len.saturating_sub(NT)
    }

    /// `Context<ROLE>.ComputeNonce(seq)` (RFC 9180 Section 5.2).
    fn compute_nonce(&self) -> Secret<[u8; NN]> {
        // seq_bytes = I2OSP(seq, Nn); return xor(self.base_nonce, seq_bytes)
        // The sequence number is 8 bytes, so the first Nn - 8 bytes of seq_bytes are zero.
        let mut nonce = Secret::<[u8; NN]>::new();
        *nonce = *self.base_nonce;
        for (n, s) in nonce[NN - 8..].iter_mut().zip(self.seq.to_be_bytes()) {
            *n ^= s;
        }
        nonce
    }

    /// Whether another message may be sealed or opened. Section 5.2's `IncrementSeq` raises
    /// `MessageLimitReachedError` when `seq` is already the largest value, and "if
    /// ContextS.Seal() or ContextR.Open() would cause the seq field to overflow, then the
    /// implementation MUST fail with an error": the message at the largest value is refused,
    /// here before the AEAD runs.
    fn check_seq(&self) -> Result<(), HpkeError> {
        if self.seq == u64::MAX {
            return Err(HpkeError::MessageLimitReached);
        }
        Ok(())
    }
}

impl<H: HpkeKdf, A: HpkeCipher> HpkeContext<Sender, H, A> {
    /// `ContextS.Seal(aad, pt)` (RFC 9180 Section 5.2): encrypts `pt` under `aad` as the next
    /// message of the context into `ct`, which needs [`Self::seal_out_len`] bytes, and returns
    /// the number written. `ct` is zeroized first; a call that fails does not use up a position
    /// in the sequence.
    ///
    /// # Errors
    /// * [`HpkeError::MessageLimitReached`] after 2^64 - 1 messages.
    /// * [`HpkeError::AEADError`] with [`SymmetricCipherError::OutputBufferTooSmall`] if `ct`
    ///   is too short, or any other error of the AEAD.
    pub fn seal_out(&mut self, aad: &[u8], pt: &[u8], ct: &mut [u8]) -> Result<usize, HpkeError> {
        ct.fill(0);
        self.check_seq()?;
        // ct = Seal(self.key, self.ComputeNonce(self.seq), aad, pt)
        let written = self.aead.aead_seal_out(&self.compute_nonce(), aad, pt, ct)?;
        // self.IncrementSeq()
        self.seq += 1;
        Ok(written)
    }
}

impl<H: HpkeKdf, A: HpkeCipher> HpkeContext<Recipient, H, A> {
    /// `ContextR.Open(aad, ct)` (RFC 9180 Section 5.2): decrypts `ct` under `aad` as the next
    /// message of the context into `pt`, which needs [`Self::open_out_len`] bytes, and returns
    /// the number written. `pt` is zeroized first and left so on failure; a call that fails
    /// does not use up a position in the sequence.
    ///
    /// # Errors
    /// * [`HpkeError::MessageLimitReached`] after 2^64 - 1 messages.
    /// * [`HpkeError::AEADError`] with [`SymmetricCipherError::AEADTagCheckFailed`] if `ct` is
    ///   not the sender's next message under `aad`, with
    ///   [`SymmetricCipherError::OutputBufferTooSmall`] if `pt` is too short, or any other
    ///   error of the AEAD, such as the one for a `ct` shorter than a tag.
    pub fn open_out(&mut self, aad: &[u8], ct: &[u8], pt: &mut [u8]) -> Result<usize, HpkeError> {
        pt.fill(0);
        self.check_seq()?;
        // pt = Open(self.key, self.ComputeNonce(self.seq), aad, ct)
        // if pt == OpenError: raise OpenError
        let written = self.aead.aead_open_out(&self.compute_nonce(), aad, ct, pt)?;
        // self.IncrementSeq()
        self.seq += 1;
        Ok(written)
    }
}

/// The sender's side of HPKE, on the recipient's public key: `SetupBaseS` and `SetupPSKS` (RFC
/// 9180 Sections 5.1.1 and 5.1.2) and the single-shot forms of Section 6. Implemented for every
/// key with the [`EncapsulatingKey`] role over `()` whose algorithm is an [`HpkeKem`]; `N_ENC`
/// and `N_SECRET` are the KEM's Nenc and Nsecret.
pub trait HpkeSender<const N_ENC: usize, const N_SECRET: usize> {
    /// `SetupBaseS(pkR, info)`, or `SetupPSKS(pkR, info, psk, psk_id)` when `params` carry a
    /// PSK: `enc`, to send to the recipient, and the sender's context.
    ///
    /// # Errors
    /// [`HpkeError::KEMError`] as the key's encapsulation; [`HpkeError::AEADError`] if the AEAD
    /// refuses the derived key.
    fn setup_sender<H: HpkeKdf, A: HpkeAead>(
        &self,
        rng: &mut dyn RNG,
        params: HpkeParams<'_, H, A>,
    ) -> Result<([u8; N_ENC], HpkeContext<Sender, H, A>), HpkeError>;

    /// `Seal<MODE>(pkR, info, aad, pt, ...)` (RFC 9180 Section 6.1): a setup and one
    /// [`HpkeContext::seal_out`]. Returns `enc` and the number of bytes written to `ct`.
    ///
    /// # Errors
    /// As [`Self::setup_sender`] and [`HpkeContext::seal_out`].
    fn seal_out<H: HpkeKdf, A: HpkeCipher>(
        &self,
        rng: &mut dyn RNG,
        params: HpkeParams<'_, H, A>,
        aad: &[u8],
        pt: &[u8],
        ct: &mut [u8],
    ) -> Result<([u8; N_ENC], usize), HpkeError> {
        ct.fill(0);
        let (enc, mut context) = self.setup_sender(rng, params)?;
        let written = context.seal_out(aad, pt, ct)?;
        Ok((enc, written))
    }

    /// `SendExport<MODE>(pkR, info, exporter_context, L, ...)` (RFC 9180 Section 6.2): a setup
    /// and one [`HpkeContext::export_out`]. Returns `enc` and `L`.
    ///
    /// # Errors
    /// As [`Self::setup_sender`]; `out` is left zeroized.
    fn send_export_out<H: HpkeKdf, A: HpkeAead, const L: usize>(
        &self,
        rng: &mut dyn RNG,
        params: HpkeParams<'_, H, A>,
        exporter_context: &[u8],
        out: &mut KeyMaterial<L>,
    ) -> Result<([u8; N_ENC], usize), HpkeError> {
        out.zeroize();
        let (enc, context) = self.setup_sender(rng, params)?;
        Ok((enc, context.export_out(exporter_context, out)))
    }
}

impl<K, const N_ENC: usize, const N_SECRET: usize> HpkeSender<N_ENC, N_SECRET> for K
where
    K: EncapsulatingKey<(), N_ENC, N_SECRET>,
    K::Algorithm: HpkeKem,
{
    fn setup_sender<H: HpkeKdf, A: HpkeAead>(
        &self,
        rng: &mut dyn RNG,
        params: HpkeParams<'_, H, A>,
    ) -> Result<([u8; N_ENC], HpkeContext<Sender, H, A>), HpkeError> {
        // The shared secret is the salt of the key schedule's extract, held in a MAX_NH buffer.
        const { assert!(N_SECRET <= MAX_NH, "the KEM's Nsecret exceeds MAX_NH") }
        // shared_secret, enc = Encap(pkR)
        let mut enc = [0u8; N_ENC];
        let mut shared_secret = KeyMaterial::<N_SECRET>::new();
        self.encaps_out(rng, (), &mut enc, &mut shared_secret)?;
        // return enc, KeyScheduleS(mode, shared_secret, info, psk, psk_id)
        let context = HpkeContext::key_schedule::<K::Algorithm>(
            false,
            shared_secret.ref_to_bytes(),
            &params,
        )?;
        Ok((enc, context))
    }
}

/// The recipient's side of HPKE, on the recipient's private key: `SetupBaseR` and `SetupPSKR`
/// (RFC 9180 Sections 5.1.1 and 5.1.2) and the single-shot forms of Section 6. Implemented for
/// every key with the [`DecapsulatingKey`] role over `()` whose algorithm is an [`HpkeKem`];
/// `N_ENC` and `N_SECRET` are the KEM's Nenc and Nsecret.
pub trait HpkeRecipient<const N_ENC: usize, const N_SECRET: usize> {
    /// `SetupBaseR(enc, skR, info)`, or `SetupPSKR(enc, skR, info, psk, psk_id)` when `params`
    /// carry a PSK: the recipient's context. `params` must be the sender's; with any other, the
    /// setup succeeds and the first [`HpkeContext::open_out`] fails.
    ///
    /// # Errors
    /// [`HpkeError::KEMError`] as the key's decapsulation; [`HpkeError::AEADError`] if the AEAD
    /// refuses the derived key.
    fn setup_recipient<H: HpkeKdf, A: HpkeAead>(
        &self,
        enc: &[u8; N_ENC],
        params: HpkeParams<'_, H, A>,
    ) -> Result<HpkeContext<Recipient, H, A>, HpkeError>;

    /// `Open<MODE>(enc, skR, info, aad, ct, ...)` (RFC 9180 Section 6.1): a setup and one
    /// [`HpkeContext::open_out`]. Returns the number of bytes written to `pt`.
    ///
    /// # Errors
    /// As [`Self::setup_recipient`] and [`HpkeContext::open_out`].
    fn open_out<H: HpkeKdf, A: HpkeCipher>(
        &self,
        enc: &[u8; N_ENC],
        params: HpkeParams<'_, H, A>,
        aad: &[u8],
        ct: &[u8],
        pt: &mut [u8],
    ) -> Result<usize, HpkeError> {
        pt.fill(0);
        self.setup_recipient(enc, params)?.open_out(aad, ct, pt)
    }

    /// `ReceiveExport<MODE>(enc, skR, info, exporter_context, L, ...)` (RFC 9180 Section 6.2): a
    /// setup and one [`HpkeContext::export_out`]. Returns `L`.
    ///
    /// # Errors
    /// As [`Self::setup_recipient`]; `out` is left zeroized.
    fn receive_export_out<H: HpkeKdf, A: HpkeAead, const L: usize>(
        &self,
        enc: &[u8; N_ENC],
        params: HpkeParams<'_, H, A>,
        exporter_context: &[u8],
        out: &mut KeyMaterial<L>,
    ) -> Result<usize, HpkeError> {
        out.zeroize();
        Ok(self.setup_recipient(enc, params)?.export_out(exporter_context, out))
    }
}

impl<K, const N_ENC: usize, const N_SECRET: usize> HpkeRecipient<N_ENC, N_SECRET> for K
where
    K: DecapsulatingKey<(), N_ENC, N_SECRET>,
    K::Algorithm: HpkeKem,
{
    fn setup_recipient<H: HpkeKdf, A: HpkeAead>(
        &self,
        enc: &[u8; N_ENC],
        params: HpkeParams<'_, H, A>,
    ) -> Result<HpkeContext<Recipient, H, A>, HpkeError> {
        // The shared secret is the salt of the key schedule's extract, held in a MAX_NH buffer.
        const { assert!(N_SECRET <= MAX_NH, "the KEM's Nsecret exceeds MAX_NH") }
        // shared_secret = Decap(enc, skR)
        let mut shared_secret = KeyMaterial::<N_SECRET>::new();
        self.decaps_out(enc, (), &mut shared_secret)?;
        // return KeyScheduleR(mode, shared_secret, info, psk, psk_id)
        HpkeContext::key_schedule::<K::Algorithm>(false, shared_secret.ref_to_bytes(), &params)
    }
}

/// The sender's side of HPKE's authenticated modes, on the recipient's public key: `SetupAuthS`
/// and `SetupAuthPSKS` (RFC 9180 Sections 5.1.3 and 5.1.4) and their single-shot forms. As
/// [`HpkeSender`], with the sender's private key `sk_s`, whose public key the recipient must
/// hold. Implemented for every [`HpkeSender`] key that is also an [`AuthEncapsulatingKey`].
pub trait HpkeAuthSender<const N_ENC: usize, const N_SECRET: usize>:
    AuthEncapsulatingKey<N_ENC, N_SECRET>
{
    /// `SetupAuthS(pkR, info, skS)`, or `SetupAuthPSKS(pkR, info, psk, psk_id, skS)` when
    /// `params` carry a PSK: `enc`, to send to the recipient, and the sender's context.
    ///
    /// # Errors
    /// [`HpkeError::KEMError`] as the key's authenticated encapsulation;
    /// [`HpkeError::AEADError`] if the AEAD refuses the derived key.
    fn setup_auth_sender<H: HpkeKdf, A: HpkeAead>(
        &self,
        rng: &mut dyn RNG,
        sk_s: &Self::SenderPrivateKey,
        params: HpkeParams<'_, H, A>,
    ) -> Result<([u8; N_ENC], HpkeContext<Sender, H, A>), HpkeError>;

    /// `SealAuth` or `SealAuthPSK` (RFC 9180 Section 6.1): a setup and one
    /// [`HpkeContext::seal_out`]. Returns `enc` and the number of bytes written to `ct`.
    ///
    /// # Errors
    /// As [`Self::setup_auth_sender`] and [`HpkeContext::seal_out`].
    fn auth_seal_out<H: HpkeKdf, A: HpkeCipher>(
        &self,
        rng: &mut dyn RNG,
        sk_s: &Self::SenderPrivateKey,
        params: HpkeParams<'_, H, A>,
        aad: &[u8],
        pt: &[u8],
        ct: &mut [u8],
    ) -> Result<([u8; N_ENC], usize), HpkeError> {
        ct.fill(0);
        let (enc, mut context) = self.setup_auth_sender(rng, sk_s, params)?;
        let written = context.seal_out(aad, pt, ct)?;
        Ok((enc, written))
    }

    /// `SendExportAuth` or `SendExportAuthPSK` (RFC 9180 Section 6.2): a setup and one
    /// [`HpkeContext::export_out`]. Returns `enc` and `L`.
    ///
    /// # Errors
    /// As [`Self::setup_auth_sender`]; `out` is left zeroized.
    fn auth_send_export_out<H: HpkeKdf, A: HpkeAead, const L: usize>(
        &self,
        rng: &mut dyn RNG,
        sk_s: &Self::SenderPrivateKey,
        params: HpkeParams<'_, H, A>,
        exporter_context: &[u8],
        out: &mut KeyMaterial<L>,
    ) -> Result<([u8; N_ENC], usize), HpkeError> {
        out.zeroize();
        let (enc, context) = self.setup_auth_sender(rng, sk_s, params)?;
        Ok((enc, context.export_out(exporter_context, out)))
    }
}

impl<K, const N_ENC: usize, const N_SECRET: usize> HpkeAuthSender<N_ENC, N_SECRET> for K
where
    K: EncapsulatingKey<(), N_ENC, N_SECRET> + AuthEncapsulatingKey<N_ENC, N_SECRET>,
    K::Algorithm: HpkeKem,
{
    fn setup_auth_sender<H: HpkeKdf, A: HpkeAead>(
        &self,
        rng: &mut dyn RNG,
        sk_s: &Self::SenderPrivateKey,
        params: HpkeParams<'_, H, A>,
    ) -> Result<([u8; N_ENC], HpkeContext<Sender, H, A>), HpkeError> {
        const { assert!(N_SECRET <= MAX_NH, "the KEM's Nsecret exceeds MAX_NH") }
        // shared_secret, enc = AuthEncap(pkR, skS)
        let mut enc = [0u8; N_ENC];
        let mut shared_secret = KeyMaterial::<N_SECRET>::new();
        self.auth_encaps_out(rng, sk_s, &mut enc, &mut shared_secret)?;
        // return enc, KeyScheduleS(mode, shared_secret, info, psk, psk_id)
        let context =
            HpkeContext::key_schedule::<K::Algorithm>(true, shared_secret.ref_to_bytes(), &params)?;
        Ok((enc, context))
    }
}

/// The recipient's side of HPKE's authenticated modes, on the recipient's private key:
/// `SetupAuthR` and `SetupAuthPSKR` (RFC 9180 Sections 5.1.3 and 5.1.4) and their single-shot
/// forms. As [`HpkeRecipient`], with the sender's public key `pk_s`. Implemented for every
/// [`HpkeRecipient`] key that is also an [`AuthDecapsulatingKey`].
///
/// A context set up with a `pk_s` that is not the sender's is another context: the setup
/// succeeds and the first [`HpkeContext::open_out`] fails. A message that opens was sealed by
/// a holder of the private key of `pk_s`, or of the recipient's own (Section 9.1.1).
pub trait HpkeAuthRecipient<const N_ENC: usize, const N_SECRET: usize>:
    AuthDecapsulatingKey<N_ENC, N_SECRET>
{
    /// `SetupAuthR(enc, skR, info, pkS)`, or `SetupAuthPSKR(enc, skR, info, psk, psk_id, pkS)`
    /// when `params` carry a PSK: the recipient's context.
    ///
    /// # Errors
    /// [`HpkeError::KEMError`] as the key's authenticated decapsulation;
    /// [`HpkeError::AEADError`] if the AEAD refuses the derived key.
    fn setup_auth_recipient<H: HpkeKdf, A: HpkeAead>(
        &self,
        enc: &[u8; N_ENC],
        pk_s: &Self::SenderPublicKey,
        params: HpkeParams<'_, H, A>,
    ) -> Result<HpkeContext<Recipient, H, A>, HpkeError>;

    /// `OpenAuth` or `OpenAuthPSK` (RFC 9180 Section 6.1): a setup and one
    /// [`HpkeContext::open_out`]. Returns the number of bytes written to `pt`.
    ///
    /// # Errors
    /// As [`Self::setup_auth_recipient`] and [`HpkeContext::open_out`].
    fn auth_open_out<H: HpkeKdf, A: HpkeCipher>(
        &self,
        enc: &[u8; N_ENC],
        pk_s: &Self::SenderPublicKey,
        params: HpkeParams<'_, H, A>,
        aad: &[u8],
        ct: &[u8],
        pt: &mut [u8],
    ) -> Result<usize, HpkeError> {
        pt.fill(0);
        self.setup_auth_recipient(enc, pk_s, params)?.open_out(aad, ct, pt)
    }

    /// `ReceiveExportAuth` or `ReceiveExportAuthPSK` (RFC 9180 Section 6.2): a setup and one
    /// [`HpkeContext::export_out`]. Returns `L`.
    ///
    /// # Errors
    /// As [`Self::setup_auth_recipient`]; `out` is left zeroized.
    fn auth_receive_export_out<H: HpkeKdf, A: HpkeAead, const L: usize>(
        &self,
        enc: &[u8; N_ENC],
        pk_s: &Self::SenderPublicKey,
        params: HpkeParams<'_, H, A>,
        exporter_context: &[u8],
        out: &mut KeyMaterial<L>,
    ) -> Result<usize, HpkeError> {
        out.zeroize();
        Ok(self.setup_auth_recipient(enc, pk_s, params)?.export_out(exporter_context, out))
    }
}

impl<K, const N_ENC: usize, const N_SECRET: usize> HpkeAuthRecipient<N_ENC, N_SECRET> for K
where
    K: DecapsulatingKey<(), N_ENC, N_SECRET> + AuthDecapsulatingKey<N_ENC, N_SECRET>,
    K::Algorithm: HpkeKem,
{
    fn setup_auth_recipient<H: HpkeKdf, A: HpkeAead>(
        &self,
        enc: &[u8; N_ENC],
        pk_s: &Self::SenderPublicKey,
        params: HpkeParams<'_, H, A>,
    ) -> Result<HpkeContext<Recipient, H, A>, HpkeError> {
        const { assert!(N_SECRET <= MAX_NH, "the KEM's Nsecret exceeds MAX_NH") }
        // shared_secret = AuthDecap(enc, skR, pkS)
        let mut shared_secret = KeyMaterial::<N_SECRET>::new();
        self.auth_decaps_out(enc, pk_s, &mut shared_secret)?;
        // return KeyScheduleR(mode, shared_secret, info, psk, psk_id)
        HpkeContext::key_schedule::<K::Algorithm>(true, shared_secret.ref_to_bytes(), &params)
    }
}

// The sequence number's limit cannot be reached through the public API (2^64 - 1 messages), and
// the vectors' sequence numbers stay below 2^9, so the limit and the nonce's upper bytes are
// pinned here, on contexts whose private fields are set.
#[cfg(test)]
mod tests {
    use super::*;
    use bouncycastle_core::kem_key::KEMAlgorithm;
    use bouncycastle_core::traits::Algorithm;

    /// A KEM marker for a key schedule run on its own.
    struct TestKem;

    impl Algorithm for TestKem {
        const ALG_NAME: &'static str = "TestKem";
        const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
    }

    impl KEMAlgorithm for TestKem {}

    impl HpkeKem for TestKem {
        const KEM_ID: u16 = 0x0020;
    }

    type Aead = AES128Key<GCM>;

    fn contexts() -> (HpkeContext<Sender, SHA256, Aead>, HpkeContext<Recipient, SHA256, Aead>) {
        let params = HpkeParams::new(b"");
        (
            HpkeContext::key_schedule::<TestKem>(false, &[1u8; 32], &params).unwrap(),
            HpkeContext::key_schedule::<TestKem>(false, &[1u8; 32], &params).unwrap(),
        )
    }

    #[test]
    fn the_nonce_is_the_base_nonce_xor_the_sequence_number_right_aligned() {
        let (mut sender, _) = contexts();
        *sender.base_nonce =
            [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB];
        assert_eq!(*sender.compute_nonce(), *sender.base_nonce);
        sender.seq = 0x0102_0304_0506_0708;
        // The first four bytes are untouched; the last eight are XORed with the big-endian seq.
        assert_eq!(
            *sender.compute_nonce(),
            [0xA0, 0xA1, 0xA2, 0xA3, 0xA5, 0xA7, 0xA5, 0xA3, 0xAD, 0xAF, 0xAD, 0xA3]
        );
    }

    #[test]
    fn the_last_sequence_number_is_refused_on_both_sides() {
        let (mut sender, mut recipient) = contexts();
        sender.seq = u64::MAX - 1;
        recipient.seq = u64::MAX - 1;

        // The message at 2^64 - 2 goes through, and takes the contexts to the limit.
        let mut ct = [0u8; 2 + NT];
        assert_eq!(sender.seal_out(b"", b"hi", &mut ct), Ok(2 + NT));
        let mut pt = [0u8; 2 + NT];
        assert_eq!(recipient.open_out(b"", &ct, &mut pt), Ok(2));
        assert_eq!((sender.seq, recipient.seq), (u64::MAX, u64::MAX));

        let mut out = [0xFFu8; 2 + NT];
        assert_eq!(sender.seal_out(b"", b"hi", &mut out), Err(HpkeError::MessageLimitReached));
        assert_eq!(out, [0u8; 2 + NT]);
        let mut out = [0xFFu8; 2 + NT];
        assert_eq!(recipient.open_out(b"", &ct, &mut out), Err(HpkeError::MessageLimitReached));
        assert_eq!(out, [0u8; 2 + NT]);
        // The refusal does not move the sequence number.
        assert_eq!((sender.seq, recipient.seq), (u64::MAX, u64::MAX));
        // The export interface is not bounded by it.
        let mut exported = KeyMaterial::<32>::new();
        assert_eq!(sender.export_out(b"", &mut exported), 32);
    }
}
