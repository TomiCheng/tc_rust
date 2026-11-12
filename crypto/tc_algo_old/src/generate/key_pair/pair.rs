use crate::params::{AnyPrivateKey, AnyPublicKey};

// Bouncy Castle's AsymmetricCipherKeyPair, with named fields so the two keys cannot be swapped
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct KeyPair {
    pub public: AnyPublicKey,
    pub private: AnyPrivateKey,
}
