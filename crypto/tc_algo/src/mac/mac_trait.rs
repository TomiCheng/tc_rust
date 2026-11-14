use tc_constant_time::fixed_time_eq;
use tc_macs::MacInit;

use crate::{AlgoError, Params};

// A Mac of tc_macs, with AlgoError for its errors and an init taking any params, so that every row
// fits behind Box<dyn Mac> and still goes wherever a tc_macs Mac does
pub trait Mac: tc_macs::Mac<Error = AlgoError> + MacInit<dyn Params, Error = AlgoError> {
    fn update_byte(&mut self, input: u8) -> Result<(), AlgoError> {
        self.update(&[input])
    }

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
}
