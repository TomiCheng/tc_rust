use tc_constant_time::fixed_time_eq;

use crate::{AlgoError, Params};

pub trait Mac {
    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError>;

    fn mac_size(&self) -> usize;

    fn update(&mut self, input: &[u8]) -> Result<(), AlgoError>;

    fn update_byte(&mut self, input: u8) -> Result<(), AlgoError> {
        self.update(&[input])
    }

    // Writes the tag and returns its length. The output must hold mac_size bytes
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoError>;

    // do_final with an output of its own
    fn finalize(&mut self) -> Result<Vec<u8>, AlgoError> {
        let mut output = vec![0; self.mac_size()];
        let written = self.do_final(&mut output)?;
        output.truncate(written);
        Ok(output)
    }

    // Whether `tag` is the message's tag, compared in constant time, since comparing with `==` stops
    // at the first difference and tells an attacker how much of a forged tag is right. Provided here
    // so that no implementation has to get this right itself
    fn verify(&mut self, tag: &[u8]) -> Result<bool, AlgoError> {
        Ok(fixed_time_eq(&self.finalize()?, tag))
    }

    fn reset(&mut self);
}
