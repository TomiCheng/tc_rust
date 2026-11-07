use std::io;

// Takes the message through io::Write, so that it can be encoded straight into the digest
pub trait DigestCalculator: io::Write {
    // The hash of what was written, after which the calculator starts the next message
    fn finish(&mut self) -> Vec<u8>;
}
