pub trait Digest {
    // The length of the hash, in bytes
    fn digest_size(&self) -> usize;

    // The length of the block it works on, in bytes, which HMAC needs
    fn byte_length(&self) -> usize;

    fn update(&mut self, input: &[u8]);

    // The hash, after which the digest starts the next message
    fn finalize(&mut self) -> Vec<u8>;

    fn reset(&mut self);
}
