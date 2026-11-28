//! `Display` and `core::error::Error` on the error types of `bouncycastle-core`.

use bouncycastle_core::base64::{self, Base64Error};
use bouncycastle_core::errors::*;
use bouncycastle_core::hex::{self, HexError};
use core::error::Error;

// Fails to compile if an error type stops being usable as `Box<dyn Error + Send + Sync>`.
const _: () = {
    const fn is_error<T: Error + Send + Sync + 'static>() {}
    is_error::<HashError>();
    is_error::<KeyMaterialError>();
    is_error::<KDFError>();
    is_error::<KEMError>();
    is_error::<KeyTransportError>();
    is_error::<PublicKeyEncryptionError>();
    is_error::<KeyAgreementError>();
    is_error::<MACError>();
    is_error::<RNGError>();
    is_error::<SuspendableError>();
    is_error::<SignatureError>();
    is_error::<SymmetricCipherError>();
    is_error::<PaddingError>();
    is_error::<KeyDecodingError>();
    is_error::<HexError>();
    is_error::<Base64Error>();
};

/// The message of a variant that wraps nothing, which must be non-empty.
fn leaf<E: Error>(e: E) -> String {
    assert!(e.source().is_none(), "{e:?} has a source");
    let s = e.to_string();
    assert!(!s.is_empty(), "{e:?} has an empty message");
    s
}

/// The message of a variant carrying a `&'static str`, which it must print.
fn carrying<E: Error>(e: E, payload: &str) -> String {
    let s = leaf(e);
    assert!(s.contains(payload), "{s:?} does not print {payload:?}");
    s
}

/// The message of a variant wrapping `inner`, which must be its `source()` and not its message.
fn wrapping<E: Error, I: Error + PartialEq + 'static>(e: E, inner: I) -> String {
    let source = e.source().expect("a wrapping variant has a source");
    assert_eq!(source.downcast_ref::<I>(), Some(&inner));
    let s = e.to_string();
    assert!(!s.is_empty(), "{e:?} has an empty message");
    assert_ne!(s, inner.to_string(), "{e:?} prints its inner error's message");
    s
}

fn distinct(messages: &[String]) {
    for (i, a) in messages.iter().enumerate() {
        for b in &messages[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

fn km() -> KeyMaterialError {
    KeyMaterialError::InvalidLength
}

fn rng() -> RNGError {
    RNGError::Uninitialized
}

fn kdf() -> KDFError {
    KDFError::InvalidLength("kdf-inner")
}

#[test]
fn hash_error() {
    distinct(&[
        carrying(HashError::GenericError("p-generic"), "p-generic"),
        carrying(HashError::InvalidLength("p-len"), "p-len"),
        carrying(HashError::InvalidState("p-state"), "p-state"),
        carrying(HashError::InvalidInput("p-input"), "p-input"),
        wrapping(HashError::KeyMaterialError(km()), km()),
    ]);
}

#[test]
fn key_material_error() {
    distinct(&[
        leaf(KeyMaterialError::ActingOnZeroizedKey),
        carrying(KeyMaterialError::GenericError("p-generic"), "p-generic"),
        leaf(KeyMaterialError::HazardousOperationNotPermitted),
        leaf(KeyMaterialError::InputDataLongerThanKeyCapacity),
        carrying(KeyMaterialError::InvalidKeyType("p-type"), "p-type"),
        leaf(KeyMaterialError::InvalidLength),
        carrying(KeyMaterialError::SecurityStrength("p-strength"), "p-strength"),
        carrying(KeyMaterialError::WeakKey("p-weak"), "p-weak"),
    ]);
}

#[test]
fn kdf_error() {
    let hash = || HashError::InvalidInput("hash-inner");
    let mac = || MACError::VerificationFailed;
    distinct(&[
        carrying(KDFError::GenericError("p-generic"), "p-generic"),
        wrapping(KDFError::HashError(hash()), hash()),
        carrying(KDFError::InvalidLength("p-len"), "p-len"),
        wrapping(KDFError::KeyMaterialError(km()), km()),
        wrapping(KDFError::MACError(mac()), mac()),
    ]);
}

#[test]
fn kem_error() {
    distinct(&[
        carrying(KEMError::GenericError("p-generic"), "p-generic"),
        carrying(KEMError::ConsistencyCheckFailed("p-pair"), "p-pair"),
        carrying(KEMError::EncodingError("p-enc"), "p-enc"),
        leaf(KEMError::DecapsulationFailed),
        carrying(KEMError::DecodingError("p-dec"), "p-dec"),
        carrying(KEMError::InvalidPublicKey("p-pk"), "p-pk"),
        carrying(KEMError::KeyGenError("p-keygen"), "p-keygen"),
        wrapping(KEMError::KeyMaterialError(km()), km()),
        wrapping(KEMError::RNGError(rng()), rng()),
        wrapping(KEMError::KDFError(kdf()), kdf()),
    ]);
}

#[test]
fn key_transport_error() {
    distinct(&[
        leaf(KeyTransportError::KeyTooLong),
        leaf(KeyTransportError::DecryptionFailed),
        wrapping(KeyTransportError::KeyMaterialError(km()), km()),
        wrapping(KeyTransportError::RNGError(rng()), rng()),
    ]);
}

#[test]
fn public_key_encryption_error() {
    let small = leaf(PublicKeyEncryptionError::OutputBufferTooSmall(97));
    assert!(!small.contains("97"), "{small:?} prints the length");
    distinct(&[
        leaf(PublicKeyEncryptionError::DecryptionFailed),
        leaf(PublicKeyEncryptionError::EncryptionFailed),
        carrying(PublicKeyEncryptionError::InvalidInputLength("p-len"), "p-len"),
        small,
        wrapping(PublicKeyEncryptionError::KeyMaterialError(km()), km()),
        wrapping(PublicKeyEncryptionError::RNGError(rng()), rng()),
    ]);
}

#[test]
fn key_agreement_error() {
    distinct(&[
        carrying(KeyAgreementError::GenericError("p-generic"), "p-generic"),
        leaf(KeyAgreementError::AgreementFailed),
        leaf(KeyAgreementError::ConsistencyCheckFailed),
        carrying(KeyAgreementError::DecodingError("p-dec"), "p-dec"),
        wrapping(KeyAgreementError::KeyMaterialError(km()), km()),
        wrapping(KeyAgreementError::RNGError(rng()), rng()),
        wrapping(KeyAgreementError::KDFError(kdf()), kdf()),
    ]);
}

#[test]
fn mac_error() {
    let hash = || HashError::InvalidInput("hash-inner");
    distinct(&[
        carrying(MACError::GenericError("p-generic"), "p-generic"),
        wrapping(MACError::HashError(hash()), hash()),
        carrying(MACError::InvalidLength("p-len"), "p-len"),
        carrying(MACError::InvalidState("p-state"), "p-state"),
        wrapping(MACError::KeyMaterialError(km()), km()),
        wrapping(MACError::RNGError(rng()), rng()),
        leaf(MACError::VerificationFailed),
    ]);
}

#[test]
fn rng_error() {
    distinct(&[
        carrying(RNGError::GenericError("p-generic"), "p-generic"),
        leaf(RNGError::Uninitialized),
        leaf(RNGError::InsufficientSeedEntropy),
        leaf(RNGError::ReseedRequired),
        leaf(RNGError::SecurityStrengthInsufficientForAlgorithm),
        wrapping(RNGError::KeyMaterialError(km()), km()),
    ]);
}

#[test]
fn signature_error() {
    distinct(&[
        carrying(SignatureError::GenericError("p-generic"), "p-generic"),
        leaf(SignatureError::ConsistencyCheckFailed),
        leaf(SignatureError::RejectionLimitExceeded),
        leaf(SignatureError::PreHashTooWeak),
        leaf(SignatureError::ComputationFault),
        carrying(SignatureError::EncodingError("p-enc"), "p-enc"),
        carrying(SignatureError::DecodingError("p-dec"), "p-dec"),
        carrying(SignatureError::KeyGenError("p-keygen"), "p-keygen"),
        wrapping(SignatureError::KeyMaterialError(km()), km()),
        carrying(SignatureError::LengthError("p-len"), "p-len"),
        leaf(SignatureError::SignatureVerificationFailed),
        wrapping(SignatureError::RNGError(rng()), rng()),
    ]);
}

#[test]
fn symmetric_cipher_error() {
    let small = leaf(SymmetricCipherError::OutputBufferTooSmall(97));
    assert!(!small.contains("97"), "{small:?} prints the length");
    distinct(&[
        carrying(SymmetricCipherError::GenericError("p-generic"), "p-generic"),
        leaf(SymmetricCipherError::AEADTagCheckFailed),
        leaf(SymmetricCipherError::DecryptionFailed),
        small,
        leaf(SymmetricCipherError::DataLimitExceeded),
        leaf(SymmetricCipherError::DataNotBlockAligned),
        carrying(SymmetricCipherError::InvalidInputLength("p-len"), "p-len"),
        wrapping(SymmetricCipherError::KeyMaterialError(km()), km()),
        wrapping(
            SymmetricCipherError::PaddingError(PaddingError::InvalidPadding),
            PaddingError::InvalidPadding,
        ),
        wrapping(SymmetricCipherError::RNGError(rng()), rng()),
        carrying(SymmetricCipherError::StateError("p-state"), "p-state"),
    ]);
}

#[test]
fn padding_error() {
    distinct(&[
        carrying(PaddingError::DataLengthTooLong(15), "15"),
        leaf(PaddingError::InvalidPadding),
        leaf(PaddingError::PaddingNotPermitted),
    ]);
}

#[test]
fn key_decoding_error() {
    carrying(KeyDecodingError("p-dec"), "p-dec");
}

#[test]
fn suspendable_error() {
    distinct(&[leaf(SuspendableError::IncompatibleVersion), leaf(SuspendableError::InvalidData)]);
}

#[test]
fn hex_error() {
    let bad = leaf(HexError::InvalidHexCharacter(5));
    assert!(!bad.contains('5'), "{bad:?} prints the index");
    distinct(&[bad, leaf(HexError::OddLengthInput), leaf(HexError::InsufficientOutputBufferSize)]);
}

#[test]
fn base64_error() {
    let bad = leaf(Base64Error::InvalidB64Character(5));
    let pad = leaf(Base64Error::InvalidPadding(5));
    assert!(!bad.contains('5') && !pad.contains('5'), "{bad:?} or {pad:?} prints the index");
    distinct(&[
        leaf(Base64Error::PaddingEncounteredDuringDoUpdate),
        bad,
        pad,
        leaf(Base64Error::TruncatedInput),
        leaf(Base64Error::DecoderFailed),
        leaf(Base64Error::InsufficientOutputBufferSize),
    ]);
}

/// A caller returning `Box<dyn std::error::Error>` takes a library error with `?`.
fn decode_hex(input: &str) -> Result<usize, Box<dyn std::error::Error>> {
    let mut out = [0u8; 8];
    let n = hex::decode_out(input, &mut out)?;
    let mut b64 = [0u8; 8];
    base64::decode_out("AAAA", &mut b64)?;
    Ok(n)
}

#[test]
fn question_mark_into_box_dyn_error() {
    assert_eq!(decode_hex("0102").unwrap(), 2);
    let err = decode_hex("012").unwrap_err();
    assert!(err.downcast_ref::<HexError>().is_some());
    assert_eq!(err.to_string(), HexError::OddLengthInput.to_string());
}
