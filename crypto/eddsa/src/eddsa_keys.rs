use std::fmt::{Debug, Display, Formatter};
use bouncycastle_core_interface::errors::SignatureError;
use bouncycastle_core_interface::traits::{Secret, SignaturePrivateKey, SignaturePublicKey};

pub struct Ed25519PublicKey {

}

impl PartialEq for Ed25519PublicKey {
    fn eq(&self, other: &Self) -> bool {
        todo!()
    }
}

impl Eq for Ed25519PublicKey {}

impl Clone for Ed25519PublicKey {
    fn clone(&self) -> Self {
        todo!()
    }
}

impl Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl Display for Ed25519PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl SignaturePublicKey for Ed25519PublicKey {
    fn encode(&self) -> Vec<u8> {
        todo!()
    }

    fn encode_out(&self, out: &mut [u8]) -> Result<usize, SignatureError> {
        todo!()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        todo!()
    }
}


pub struct Ed25519PrivateKey {

}

impl Drop for Ed25519PrivateKey {
    fn drop(&mut self) {
        todo!()
    }
}

impl Debug for Ed25519PrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl Display for Ed25519PrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl Secret for Ed25519PrivateKey {

}

impl PartialEq for Ed25519PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        todo!()
    }
}

impl Eq for Ed25519PrivateKey {}

impl Clone for Ed25519PrivateKey {
    fn clone(&self) -> Self {
        todo!()
    }
}

impl SignaturePrivateKey for Ed25519PrivateKey {
    fn encode(&self) -> Vec<u8> {
        todo!()
    }

    fn encode_out(&self, out: &mut [u8]) -> Result<usize, SignatureError> {
        todo!()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        todo!()
    }
}