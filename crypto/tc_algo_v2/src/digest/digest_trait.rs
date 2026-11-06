pub trait Digest {
    // The length of the hash, in bytes
    fn digest_size(&self) -> usize;

    // The length of the block it works on, in bytes, which HMAC needs
    fn byte_length(&self) -> usize;

    fn update(&mut self, input: &[u8]);

    fn update_byte(&mut self, input: u8) {
        self.update(&[input]);
    }

    // Writes the hash and returns its length, after which the digest starts the next message. The
    // output must hold digest_size bytes, or the digest may panic
    fn do_final(&mut self, output: &mut [u8]) -> usize;

    // do_final with an output of its own
    fn finalize(&mut self) -> Vec<u8> {
        let mut output = vec![0; self.digest_size()];
        let written = self.do_final(&mut output);
        output.truncate(written);
        output
    }

    fn reset(&mut self);
}
