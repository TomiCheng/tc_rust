use super::{KeyPair, get_by_name};
use crate::AlgoError;

// Finds the generator by name and makes one key pair with its defaults and the operating
// system's randomness; a generator without defaults, such as DH's, fails
pub fn generate(name: &str) -> Result<KeyPair, AlgoError> {
    get_by_name(name)?.generate()
}
