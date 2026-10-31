use tc_buffered_cipher::CipherDirection;

use super::get_by_name;
use crate::AlgoError;
use crate::params::AnyParams;

// Finds the cipher by name, initializes it and runs the whole input through it
pub fn encrypt(name: &str, params: &AnyParams, input: &[u8]) -> Result<Vec<u8>, AlgoError> {
    run(name, CipherDirection::Encrypt, params, input)
}

pub fn decrypt(name: &str, params: &AnyParams, input: &[u8]) -> Result<Vec<u8>, AlgoError> {
    run(name, CipherDirection::Decrypt, params, input)
}

fn run(
    name: &str,
    direction: CipherDirection,
    params: &AnyParams,
    input: &[u8],
) -> Result<Vec<u8>, AlgoError> {
    let mut cipher = get_by_name(name)?;
    cipher.init(direction, params)?;
    let mut output = cipher.update(input)?;
    output.extend(cipher.finalize()?);
    Ok(output)
}
