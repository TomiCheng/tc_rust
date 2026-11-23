use std::sync::Arc;

use tc_algo::Params;
use tc_algo::cipher::CipherDirection;
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_buffered_cipher::{BufferedCipher, BufferedCipherInit};

use crate::AlgoAsn1Error;
use crate::cipher::{Asn1Cipher, CipherEntry};

pub(crate) struct DefaultAsn1Cipher {
    row: Arc<dyn CipherEntry>,
    algorithm: AlgorithmIdentifier,
    // Made by name: the parameters are its own, drawn anew for each message after the first
    by_name: bool,
    used: bool,
    inner: Box<dyn tc_algo::cipher::Cipher>,
}

impl DefaultAsn1Cipher {
    pub(crate) fn new(
        row: Arc<dyn CipherEntry>,
        algorithm: AlgorithmIdentifier,
        by_name: bool,
        inner: Box<dyn tc_algo::cipher::Cipher>,
    ) -> Self {
        Self {
            row,
            algorithm,
            by_name,
            used: false,
            inner,
        }
    }
}

impl BufferedCipher for DefaultAsn1Cipher {
    type Error = AlgoAsn1Error;

    fn block_size(&self) -> usize {
        self.inner.block_size()
    }

    fn update_output_len(&self, input_len: usize) -> Result<usize, AlgoAsn1Error> {
        Ok(self.inner.update_output_len(input_len)?)
    }

    fn output_len(&self, input_len: usize) -> Result<usize, AlgoAsn1Error> {
        Ok(self.inner.output_len(input_len)?)
    }

    fn process_byte(&mut self, input: u8, output: &mut [u8]) -> Result<usize, AlgoAsn1Error> {
        Ok(self.inner.process_byte(input, output)?)
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, AlgoAsn1Error> {
        Ok(self.inner.process_bytes(input, output)?)
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, AlgoAsn1Error> {
        Ok(self.inner.do_final(output)?)
    }

    fn reset(&mut self) {
        self.inner.reset();
    }
}

// Encrypting with a cipher by name uses fresh parameters, those made with it for the first message
// and new ones for each after. A cipher by name has nothing to decrypt with, which is
// InvalidCipherParameters; one by AlgorithmIdentifier uses the parameters read, either way
impl BufferedCipherInit<dyn Params> for DefaultAsn1Cipher {
    type Error = AlgoAsn1Error;

    fn init(&mut self, direction: CipherDirection, key: &dyn Params) -> Result<(), AlgoAsn1Error> {
        if self.by_name {
            if direction == CipherDirection::Decrypt {
                return Err(AlgoAsn1Error::InvalidCipherParameters);
            }
            if self.used {
                self.algorithm = self.row.generate();
            }
        }
        let params = self.row.params(&self.algorithm, key)?;
        self.inner.init(direction, params.as_ref())?;
        self.used = true;
        Ok(())
    }
}

impl Asn1Cipher for DefaultAsn1Cipher {
    fn algorithm(&self) -> &AlgorithmIdentifier {
        &self.algorithm
    }
}
