use crate::{AlgoError, Params};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WrapDirection {
    Wrap,
    Unwrap,
}

pub trait Wrapper {
    fn init(&mut self, direction: WrapDirection, params: &dyn Params) -> Result<(), AlgoError>;

    // How much wrap_into writes for this much input
    fn wrapped_len(&self, input_len: usize) -> Result<usize, AlgoError>;

    // The most unwrap_into can write for this much input; what it returns can be less
    fn max_unwrapped_len(&self, input_len: usize) -> Result<usize, AlgoError>;

    // Writes the wrapped key and returns its length
    fn wrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, AlgoError>;

    // Writes the key and returns its length, leaving no key in the output if the check fails
    fn unwrap_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, AlgoError>;

    // wrap_into with an output of its own
    fn wrap(&mut self, input: &[u8]) -> Result<Vec<u8>, AlgoError> {
        let mut output = vec![0; self.wrapped_len(input.len())?];
        let written = self.wrap_into(input, &mut output)?;
        output.truncate(written);
        Ok(output)
    }

    // unwrap_into with an output of its own, which nothing wipes. To wipe the key, use unwrap_into
    fn unwrap(&mut self, input: &[u8]) -> Result<Vec<u8>, AlgoError> {
        let mut output = vec![0; self.max_unwrapped_len(input.len())?];
        let written = self.unwrap_into(input, &mut output)?;
        output.truncate(written);
        Ok(output)
    }
}
