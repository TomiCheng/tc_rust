use core::fmt;

use tc_buffered_cipher::{BufferedCipher, BufferedCipherInit, CipherDirection};

use super::CipherEntry;
use super::dyn_cipher::DynCipher;
use super::table;
use crate::AlgoError;
use crate::params::AnyParams;

pub struct AnyCipher {
    entry: CipherEntry,
    cipher: Box<dyn DynCipher>,
}

impl AnyCipher {
    pub(super) fn new(entry: CipherEntry) -> Self {
        let cipher = table::create(&entry);
        Self { entry, cipher }
    }

    pub fn entry(&self) -> &CipherEntry {
        &self.entry
    }

    // The entry checks the params against its mode first, so the layers underneath get only
    // fields that are there
    pub fn init(
        &mut self,
        direction: CipherDirection,
        params: &AnyParams,
    ) -> Result<(), AlgoError> {
        let params = self.entry.init_params(params)?;
        self.cipher.init(direction, &params)
    }

    // Returns what this input completes; a block cipher keeps a partial block for later
    pub fn update(&mut self, input: &[u8]) -> Result<Vec<u8>, AlgoError> {
        let mut output = vec![0; self.cipher.update_output_len(input.len())?];
        let written = self.cipher.process_bytes(input, &mut output)?;
        output.truncate(written);
        Ok(output)
    }

    // Returns the rest, with the padding or the tag. The cipher can then take a new message under
    // the same params, except after GCM encryption, which takes a new init with a new nonce
    pub fn finalize(&mut self) -> Result<Vec<u8>, AlgoError> {
        let mut output = vec![0; self.cipher.output_len(0)?];
        let written = self.cipher.do_final(&mut output)?;
        output.truncate(written);
        Ok(output)
    }
}

// Shows the cipher's name, never its key or state
impl fmt::Debug for AnyCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnyCipher")
            .field("name", &self.entry.name())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for AnyCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.entry.name())
    }
}

impl BufferedCipher for AnyCipher {
    type Error = AlgoError;

    fn block_size(&self) -> usize {
        self.cipher.block_size()
    }

    fn update_output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        self.cipher.update_output_len(input_len)
    }

    fn output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        self.cipher.output_len(input_len)
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        self.cipher.process_bytes(input, output)
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.cipher.do_final(output)
    }

    fn reset(&mut self) {
        self.cipher.reset();
    }
}

impl BufferedCipherInit<AnyParams> for AnyCipher {
    type Error = AlgoError;

    fn init(&mut self, direction: CipherDirection, params: &AnyParams) -> Result<(), Self::Error> {
        AnyCipher::init(self, direction, params)
    }
}
