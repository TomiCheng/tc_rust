//! DSTU 7564 MAC implementation.

use alloc::{vec, vec::Vec};
use core::fmt;

use tc_crypto::AlgorithmName;
use tc_digest::{Digest, TryDigest};
use tc_dstu7564::Dstu7564Digest;
use tc_macs::{Mac, MacError, MacInit, MacInitError};
use tc_params::KeyParams;

/// DSTU 7564 message authentication code.
pub struct Dstu7564Mac {
    digest: Dstu7564Digest,
    mac_size: usize,
    input_length: u64,
    padded_key: Vec<u8>,
    inverted_key: Vec<u8>,
    initialized: bool,
}

impl Dstu7564Mac {
    /// Creates an uninitialized MAC with a 256-, 384-, or 512-bit tag.
    ///
    /// # Panics
    ///
    /// Panics for unsupported tag lengths, matching [`Dstu7564Digest::new`].
    pub fn new(mac_bits: usize) -> Self {
        Self {
            digest: Dstu7564Digest::new(mac_bits),
            mac_size: mac_bits / 8,
            input_length: 0,
            padded_key: Vec::new(),
            inverted_key: Vec::new(),
            initialized: false,
        }
    }

    fn padded_key(key: &[u8], block_size: usize) -> Vec<u8> {
        let mut extra = block_size - key.len() % block_size;
        if extra < 13 {
            extra += block_size;
        }

        let mut padded = vec![0_u8; key.len() + extra];
        padded[..key.len()].copy_from_slice(key);
        padded[key.len()] = 0x80;

        let length_offset = padded.len() - 12;
        let bit_length = (key.len() as u32).wrapping_mul(8);
        padded[length_offset..length_offset + 4].copy_from_slice(&bit_length.to_le_bytes());
        padded
    }

    fn message_padding(&self) -> Vec<u8> {
        let block_size = self.digest.byte_length();
        let remainder = (self.input_length % block_size as u64) as usize;
        let mut extra = block_size - remainder;
        if extra < 13 {
            extra += block_size;
        }

        let mut padded = vec![0_u8; extra];
        padded[0] = 0x80;
        let length_offset = padded.len() - 12;
        let bit_length = self.input_length.wrapping_mul(8);
        padded[length_offset..length_offset + 8].copy_from_slice(&bit_length.to_le_bytes());
        padded
    }

    fn clear_key_material(&mut self) {
        self.padded_key.fill(0);
        self.inverted_key.fill(0);
    }
}

impl AlgorithmName for Dstu7564Mac {
    fn write_algo_name(&self, output: &mut dyn fmt::Write) -> fmt::Result {
        output.write_str("DSTU7564Mac")
    }
}

impl Mac for Dstu7564Mac {
    type Error = MacError;

    fn mac_size(&self) -> usize {
        self.mac_size
    }

    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }

        self.digest.update(input);
        self.input_length = self.input_length.wrapping_add(input.len() as u64);
        Ok(())
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialized {
            return Err(MacError::NotInitialised);
        }
        if output.len() < self.mac_size {
            return Err(MacError::OutputTooShort {
                required: self.mac_size,
                available: output.len(),
            });
        }

        self.digest.update(&self.message_padding());
        self.digest.update(&self.inverted_key);
        let written = self.digest.do_final(output);
        self.reset();
        Ok(written)
    }

    fn reset(&mut self) {
        self.input_length = 0;
        self.digest.reset();
        if self.initialized {
            self.digest.update(&self.padded_key);
        }
    }
}

impl<P> MacInit<P> for Dstu7564Mac
where
    P: KeyParams + ?Sized,
{
    type Error = MacInitError;

    fn init(&mut self, params: &P) -> Result<(), Self::Error> {
        self.initialized = false;
        self.input_length = 0;
        self.digest.reset();
        self.clear_key_material();
        self.padded_key.clear();
        self.inverted_key.clear();

        let key = params.key();
        if key.is_empty() {
            return Err(MacInitError::InvalidKeyLength(0));
        }

        let padded_key = Self::padded_key(key, self.digest.byte_length());
        let inverted_key = key.iter().map(|byte| !byte).collect();

        self.padded_key = padded_key;
        self.inverted_key = inverted_key;
        self.initialized = true;
        self.reset();
        Ok(())
    }
}

impl Drop for Dstu7564Mac {
    fn drop(&mut self) {
        self.clear_key_material();
    }
}
