use crate::digest::Digest;
use crate::{AlgoError, ErrorKind, Params};

// Bouncy Castle's IXof. As a Digest, update takes the message and do_final writes digest_size bytes.
// Output closes the input, after which update may panic until the next message
pub trait Xof: Digest {
    // Optional: update works without it. One with nothing to set refuses any params
    fn init(&mut self, _params: &dyn Params) -> Result<(), AlgoError> {
        Err(AlgoError::new(ErrorKind::InvalidParams))
    }

    // Fills `output` with the next bytes and returns their length, and can be called again for more
    fn output(&mut self, output: &mut [u8]) -> usize;

    // Fills `output` with the next bytes, returns their length and starts the next message
    fn output_final(&mut self, output: &mut [u8]) -> usize;

    // output_final with an output of its own, of this length
    fn finalize_len(&mut self, len: usize) -> Vec<u8> {
        let mut output = vec![0; len];
        let written = self.output_final(&mut output);
        output.truncate(written);
        output
    }
}
