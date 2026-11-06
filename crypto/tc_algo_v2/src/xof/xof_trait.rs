use crate::{AlgoError, ErrorKind, Params};

pub trait Xof {
    // Optional: update works without it. One with nothing to set refuses any params
    fn init(&mut self, _params: &dyn Params) -> Result<(), AlgoError> {
        Err(AlgoError::new(ErrorKind::InvalidParams))
    }

    // After output has begun, gives XofOutputStarted
    fn update(&mut self, input: &[u8]) -> Result<(), AlgoError>;

    // Fills `output` with the next bytes, and can be called again for more
    fn output(&mut self, output: &mut [u8]) -> Result<(), AlgoError>;

    // Gives the next `len` bytes and starts the next message
    fn finalize(&mut self, len: usize) -> Result<Vec<u8>, AlgoError>;

    fn reset(&mut self);
}
