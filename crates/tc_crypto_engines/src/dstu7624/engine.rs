//! DSTU 7624 block-cipher engine.

use tc_crypto_core::BlockCipher;

use super::{DSTU7624_BLOCK_BITS, Dstu7624Error, Dstu7624Params, cipher};

/// Portable DSTU 7624 (Kalyna) block cipher.
pub struct Dstu7624Engine {
    cipher: cipher::Dstu7624Cipher,
    for_encryption: bool,
    initialised: bool,
}

impl Dstu7624Engine {
    /// Creates an uninitialised engine for a 128-, 256-, or 512-bit block.
    pub fn new(block_size_bits: usize) -> Result<Self, Dstu7624Error> {
        if !DSTU7624_BLOCK_BITS.contains(&block_size_bits) {
            return Err(Dstu7624Error::InvalidBlockSize(block_size_bits));
        }
        Ok(Self {
            cipher: cipher::Dstu7624Cipher::new(block_size_bits / 64),
            for_encryption: false,
            initialised: false,
        })
    }
}

impl Default for Dstu7624Engine {
    fn default() -> Self {
        Self::new(128).unwrap()
    }
}

impl BlockCipher for Dstu7624Engine {
    type Params<'a> = Dstu7624Params;
    type Error = Dstu7624Error;

    fn algorithm_name(&self) -> &str {
        "DSTU7624"
    }

    fn block_size(&self) -> usize {
        self.cipher.block_bytes()
    }

    fn init(&mut self, for_encryption: bool, params: &Self::Params<'_>) -> Result<(), Self::Error> {
        self.initialised = false;
        let block_bytes = self.block_size();
        let key_bytes = params.key_len();
        if key_bytes != block_bytes && key_bytes != block_bytes * 2 {
            return Err(Dstu7624Error::UnsupportedKeyForBlock {
                block_bits: block_bytes * 8,
                key_bits: key_bytes * 8,
            });
        }

        self.cipher.set_key(params.key());
        self.for_encryption = for_encryption;
        self.initialised = true;
        Ok(())
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialised {
            return Err(Dstu7624Error::NotInitialised);
        }
        let block_bytes = self.block_size();
        if input.len() < block_bytes || output.len() < block_bytes {
            return Err(Dstu7624Error::BufferTooShort);
        }

        if self.for_encryption {
            self.cipher.encrypt_block(input, output);
        } else {
            self.cipher.decrypt_block(input, output);
        }
        Ok(block_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_block_size_and_key_pairing() {
        assert!(matches!(
            Dstu7624Engine::new(192),
            Err(Dstu7624Error::InvalidBlockSize(192))
        ));

        let mut engine = Dstu7624Engine::new(256).unwrap();
        assert_eq!(engine.algorithm_name(), "DSTU7624");
        assert_eq!(engine.block_size(), 32);
        assert_eq!(
            engine.init(true, &Dstu7624Params::new(&[0u8; 16]).unwrap()),
            Err(Dstu7624Error::UnsupportedKeyForBlock {
                block_bits: 256,
                key_bits: 128,
            })
        );

        engine
            .init(true, &Dstu7624Params::new(&[0u8; 32]).unwrap())
            .unwrap();
        assert!(
            engine
                .init(true, &Dstu7624Params::new(&[0u8; 16]).unwrap())
                .is_err()
        );
        assert_eq!(
            engine.process_block(&[0u8; 32], &mut [0u8; 32]),
            Err(Dstu7624Error::NotInitialised)
        );
    }

    #[test]
    fn processing_errors() {
        let mut engine = Dstu7624Engine::new(128).unwrap();
        assert_eq!(
            engine.process_block(&[0u8; 16], &mut [0u8; 16]),
            Err(Dstu7624Error::NotInitialised)
        );
        engine
            .init(true, &Dstu7624Params::new(&[0u8; 16]).unwrap())
            .unwrap();
        assert_eq!(
            engine.process_block(&[0u8; 15], &mut [0u8; 16]),
            Err(Dstu7624Error::BufferTooShort)
        );
        assert_eq!(
            engine.process_block(&[0u8; 16], &mut [0u8; 15]),
            Err(Dstu7624Error::BufferTooShort)
        );
    }
}
