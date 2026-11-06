use tc_constant_time::fixed_time_eq;

use crate::{AlgoError, Params};

pub trait Mac {
    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError>;

    fn mac_size(&self) -> usize;

    fn update(&mut self, input: &[u8]) -> Result<(), AlgoError>;

    fn finalize(&mut self) -> Result<Vec<u8>, AlgoError>;

    // Whether `tag` is the message's tag, compared in constant time, since comparing with `==` stops
    // at the first difference and tells an attacker how much of a forged tag is right. Provided here
    // so that no implementation has to get this right itself
    fn verify(&mut self, tag: &[u8]) -> Result<bool, AlgoError> {
        Ok(fixed_time_eq(&self.finalize()?, tag))
    }

    fn reset(&mut self);
}
