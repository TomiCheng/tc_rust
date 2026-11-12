use crate::AlgoError;

pub trait Digest {
    // The length of the hash, in bytes
    fn digest_size(&self) -> usize;

    // The length of the block it works on, in bytes, which HMAC needs
    fn byte_length(&self) -> usize;

    fn update(&mut self, input: &[u8]);

    fn update_byte(&mut self, input: u8) {
        self.update(&[input]);
    }

    // Writes the hash and returns its length, after which the digest starts the next message. An
    // output shorter than digest_size is DataLength, and the message is left in place, as Mac and
    // Signer report it
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoError>;

    // do_final with an output of its own, which is always long enough, so it cannot fail
    fn finalize(&mut self) -> Vec<u8> {
        let mut output = vec![0; self.digest_size()];
        let written = self
            .do_final(&mut output)
            .expect("an output of digest_size bytes is long enough");
        output.truncate(written);
        output
    }

    fn reset(&mut self);
}
