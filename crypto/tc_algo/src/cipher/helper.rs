use crate::AlgoError;
use crate::params::AnyParams;

// Finds the cipher by name, initializes it and runs the whole input through it
pub fn encrypt(name: &str, params: &AnyParams, input: &[u8]) -> Result<Vec<u8>, AlgoError> {
    todo!()
}

pub fn decrypt(name: &str, params: &AnyParams, input: &[u8]) -> Result<Vec<u8>, AlgoError> {
    todo!()
}
