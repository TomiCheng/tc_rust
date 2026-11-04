use super::{AnyMacParams, get_by_name};
use crate::AlgoError;

// Finds the MAC by name, initializes it and returns the tag of the whole input
pub fn calculate(name: &str, params: &AnyMacParams, input: &[u8]) -> Result<Vec<u8>, AlgoError> {
    let mut mac = get_by_name(name)?;
    mac.init(params)?;
    mac.update(input)?;
    mac.finalize()
}
