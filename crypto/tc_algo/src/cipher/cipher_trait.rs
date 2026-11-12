use crate::{AlgoError, Params};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherDirection {
    Encrypt,
    Decrypt,
}

// Bouncy Castle's IBufferedCipher, with a fixed error type and init taking any params, so that every
// row fits behind Box<dyn Cipher>
pub trait Cipher {
    fn init(&mut self, direction: CipherDirection, params: &dyn Params) -> Result<(), AlgoError>;

    // Zero for a stream cipher
    fn block_size(&self) -> usize;

    // How much process_bytes may write for this much further input
    fn update_output_len(&self, input_len: usize) -> Result<usize, AlgoError>;

    // How much process_bytes and do_final may write together for this much further input, so
    // output_len(0) sizes the buffer of do_final
    fn output_len(&self, input_len: usize) -> Result<usize, AlgoError>;

    fn process_byte(&mut self, input: u8, output: &mut [u8]) -> Result<usize, AlgoError> {
        self.process_bytes(&[input], output)
    }

    // Writes what this input completes and returns its length; a block cipher keeps a partial block
    // for later
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, AlgoError>;

    // Writes the rest, with the padding or the tag, and returns its length. What can follow differs
    // by row, so give the next message a new init, with a new IV or nonce
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoError>;

    // Discards the message so far. This goes back to the IV or the start of the keystream, so it is
    // for starting the same message over, not for sending another one
    fn reset(&mut self);

    // process_bytes with an output of its own
    fn update(&mut self, input: &[u8]) -> Result<Vec<u8>, AlgoError> {
        let mut output = vec![0; self.update_output_len(input.len())?];
        let written = self.process_bytes(input, &mut output)?;
        output.truncate(written);
        Ok(output)
    }

    // do_final with an output of its own
    fn finalize(&mut self) -> Result<Vec<u8>, AlgoError> {
        let mut output = vec![0; self.output_len(0)?];
        let written = self.do_final(&mut output)?;
        output.truncate(written);
        Ok(output)
    }
}
