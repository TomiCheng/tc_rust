use crate::{AlgoError, Params};

// Bouncy Castle's IDerivationFunction: a secret and its context in, as many key bytes as asked for
// out. It stands apart from Agreement, since which KDF follows which agreement is up to the protocol
pub trait Kdf {
    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError>;

    // Fills `output` with key bytes and returns their length
    fn generate_bytes(&mut self, output: &mut [u8]) -> Result<usize, AlgoError>;
}
