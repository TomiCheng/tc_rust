use super::get_by_name;
use crate::AlgoError;
use crate::params::SecretKey;

// Finds the generator by name and makes one key with its defaults and the operating system's
// randomness
pub fn generate(name: &str) -> Result<SecretKey, AlgoError> {
    get_by_name(name)?.generate()
}
