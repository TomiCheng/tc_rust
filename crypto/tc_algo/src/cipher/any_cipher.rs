use core::fmt;

use tc_buffered_cipher::{BufferedCipher, BufferedCipherInit, CipherDirection};

use super::CipherEntry;
use super::dyn_cipher::DynCipher;
use crate::AlgoError;
use crate::params::AnyParams;

pub struct AnyCipher {
    entry: &'static CipherEntry,
    cipher: Box<dyn DynCipher>,
}

impl AnyCipher {
    pub fn entry(&self) -> &'static CipherEntry {
        todo!()
    }

    pub fn init(
        &mut self,
        direction: CipherDirection,
        params: &AnyParams,
    ) -> Result<(), AlgoError> {
        todo!()
    }

    pub fn update(&mut self, input: &[u8]) -> Result<Vec<u8>, AlgoError> {
        todo!()
    }

    pub fn finalize(&mut self) -> Result<Vec<u8>, AlgoError> {
        todo!()
    }
}

// Shows the cipher's name, never its key or state
impl fmt::Debug for AnyCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl fmt::Display for AnyCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl BufferedCipher for AnyCipher {
    type Error = AlgoError;

    fn block_size(&self) -> usize {
        todo!()
    }

    fn update_output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        todo!()
    }

    fn output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        todo!()
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        todo!()
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        todo!()
    }

    fn reset(&mut self) {
        todo!()
    }
}

impl BufferedCipherInit<AnyParams> for AnyCipher {
    type Error = AlgoError;

    fn init(&mut self, direction: CipherDirection, params: &AnyParams) -> Result<(), Self::Error> {
        todo!()
    }
}
