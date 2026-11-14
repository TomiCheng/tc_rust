use tc_key_wrap::{KeyWrap, KeyWrapInit};

use crate::{AlgoError, Params};

pub use tc_key_wrap::WrapDirection;

// A KeyWrap of tc_key_wrap, with AlgoError for its errors and an init taking any params, so that
// every row fits behind Box<dyn Wrapper> and still goes wherever a KeyWrap does
pub trait Wrapper: KeyWrap<Error = AlgoError> + KeyWrapInit<dyn Params, Error = AlgoError> {
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
