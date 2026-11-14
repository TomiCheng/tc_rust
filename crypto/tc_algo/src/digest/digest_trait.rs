use tc_digest::TryDigest;

use crate::AlgoError;

// A TryDigest of tc_digest, with AlgoError for its errors, so that every row fits behind
// Box<dyn Digest> and still goes wherever a TryDigest does. try_do_final with an output shorter
// than digest_size is DataLength, and leaves the message in place, as Mac and Signer report it
pub trait Digest: TryDigest<Error = AlgoError> {
    // try_do_final with an output of its own, then the next message
    fn finalize(&mut self) -> Result<Vec<u8>, AlgoError> {
        let mut output = vec![0; self.digest_size()];
        let written = self.try_do_final(&mut output)?;
        output.truncate(written);
        Ok(output)
    }
}
