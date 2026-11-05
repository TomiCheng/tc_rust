use crate::{AlgoError, Params};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherDirection {
    Encrypt,
    Decrypt,
}

pub trait Cipher {
    fn init(&mut self, direction: CipherDirection, params: &dyn Params) -> Result<(), AlgoError>;

    // Returns what this input completes; a block cipher keeps a partial block for later
    fn update(&mut self, input: &[u8]) -> Result<Vec<u8>, AlgoError>;

    // Returns the rest, with the padding or the tag
    fn finalize(&mut self) -> Result<Vec<u8>, AlgoError>;
}
