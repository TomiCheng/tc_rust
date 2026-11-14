use tc_digest::TryXof;

use crate::digest::Digest;
use crate::{AlgoError, ErrorKind, Params};

// A TryXof of tc_digest, with AlgoError for its errors, as Bouncy Castle's IXof. As a Digest,
// try_update takes the message and try_do_final writes digest_size bytes. Output closes the input,
// after which try_update may panic until the next message
pub trait Xof: Digest + TryXof<Error = AlgoError> {
    // Sets what the XOF takes besides the message, such as the strings of cSHAKE, and starts a new
    // message. tc_digest has no trait for it: its XOFs take these when they are made, so the rows
    // make theirs again. Optional: one with nothing to set refuses any params
    fn init(&mut self, _params: &dyn Params) -> Result<(), AlgoError> {
        Err(AlgoError::new(ErrorKind::InvalidParams))
    }

    // try_output_final with an output of its own, of this length
    fn finalize_len(&mut self, len: usize) -> Result<Vec<u8>, AlgoError> {
        let mut output = vec![0; len];
        let written = self.try_output_final(&mut output)?;
        output.truncate(written);
        Ok(output)
    }
}
