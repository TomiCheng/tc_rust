use core::error::Error;

use tc_constant_time::fixed_time_eq;

use super::Params;

pub trait Mac {
    type Error: Error;

    fn init(&mut self, params: &dyn Params) -> Result<(), Self::Error>;

    fn mac_size(&self) -> usize;

    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error>;

    fn finalize(&mut self) -> Result<Vec<u8>, Self::Error>;

    // Whether `tag` is the message's tag, compared in constant time, since comparing with `==` stops
    // at the first difference and tells an attacker how much of a forged tag is right. Provided here
    // so that no implementation has to get this right itself
    fn verify(&mut self, tag: &[u8]) -> Result<bool, Self::Error> {
        Ok(fixed_time_eq(&self.finalize()?, tag))
    }

    fn reset(&mut self);
}
