use super::KeyPair;
use crate::AlgoError;
use crate::params::SecretKey;

// Finds the generator by name and makes one key with its defaults and the operating system's
// randomness
pub fn generate_key(name: &str) -> Result<SecretKey, AlgoError> {
    todo!()
}

pub fn generate_key_pair(name: &str) -> Result<KeyPair, AlgoError> {
    todo!()
}
