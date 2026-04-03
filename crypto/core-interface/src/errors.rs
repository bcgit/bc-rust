#[derive(Debug)]
pub enum HashError {
    GenericError(&'static str),
    InvalidLength(&'static str),
    InvalidState(&'static str),
    InvalidInput(&'static str),
    KeyMaterialError(KeyMaterialError),
}

#[derive(Debug)]
pub enum KeyMaterialError {
    ActingOnZeroizedKey,
    GenericError(&'static str),
    HazardousOperationNotPermitted,
    InputDataLongerThanKeyCapacity,
    InvalidKeyType(&'static str),
    InvalidLength,
    SecurityStrength(&'static str),
}

#[derive(Debug)]
pub enum KDFError {
    GenericError(&'static str),
    HashError(HashError),
    InvalidLength(&'static str),
    KeyMaterialError(KeyMaterialError),
    MACError(MACError),
}

#[derive(Debug)]
pub enum MACError {
    GenericError(&'static str),
    HashError(HashError),
    InvalidLength(&'static str),
    InvalidState(&'static str),
    KeyMaterialError(KeyMaterialError),
}

#[derive(Debug)]
pub enum RNGError {
    GenericError(&'static str),

    /// Attempting to extract output before the RNG has been seeded.
    Uninitialized,

    /// The RNG has been seeded, but not sufficiently to support the requested generation operation.
    /// This includes uses in SP 800-90A mode where more output is requested than the security strength
    /// to which the RNG has been initialized.
    InsufficientSeedEntropy,

    /// Indicates that the RNG cannot produce any more output until it has been reseeded with fresh entropy.
    ReseedRequired,

    KeyMaterialError(KeyMaterialError),
}

#[derive(Debug)]
pub enum SignatureError {
    GenericError(&'static str),
    ConsistencyCheckFailed(),
    EncodingError(&'static str),
    DecodingError(&'static str),
    KeyGenError(&'static str),
    LengthError(&'static str),
    RNGError(RNGError),
    KeyMaterialError(KeyMaterialError),
    SignatureVerificationFailed,
}




/*** Promotion functions ***/
impl From<KeyMaterialError> for HashError {
    fn from(e: KeyMaterialError) -> HashError {
        Self::KeyMaterialError(e)
    }
}

impl From<HashError> for KDFError {
    fn from(e: HashError) -> KDFError {
        Self::HashError(e)
    }
}

impl From<MACError> for KDFError {
    fn from(e: MACError) -> KDFError {
        Self::MACError(e)
    }
}

impl From<KeyMaterialError> for KDFError {
    fn from(e: KeyMaterialError) -> KDFError {
        Self::KeyMaterialError(e)
    }
}

impl From<KeyMaterialError> for MACError {
    fn from(e: KeyMaterialError) -> MACError {
        Self::KeyMaterialError(e)
    }
}

impl From<HashError> for MACError {
    fn from(e: HashError) -> MACError {
        Self::HashError(e)
    }
}

impl From<KeyMaterialError> for RNGError {
    fn from(e: KeyMaterialError) -> RNGError {
        Self::KeyMaterialError(e)
    }
}

impl From<KeyMaterialError> for SignatureError {
    fn from(e: KeyMaterialError) -> SignatureError {
        Self::KeyMaterialError(e)
    }
}

impl From<RNGError> for SignatureError {
    fn from(e: RNGError) -> SignatureError { Self::RNGError(e) }
}
